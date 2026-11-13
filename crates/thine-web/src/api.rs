//! The endpoints. Thin: every decision lives in `thine-core`, and in
//! particular every refusal does, so the server cannot accidentally be more
//! permissive than the tool.

use std::sync::Arc;

use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use thine_core::{
    AccountReport, ProofLedger,
    migration::SigningRoute,
    webauthn::{BrowserAssertion, challenge_for, compressed_public_key, proof_from_browser},
};
use tokio::sync::Mutex;

use crate::{AppState, Pending, session::SessionState};

/// An error with a status code and a message the page can show.
pub struct ApiError(StatusCode, String);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(serde_json::json!({ "error": self.1 }))).into_response()
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        // A refusal is the tool working, not the server failing, so it reads as
        // 409 rather than 500. The page shows the message either way.
        let status = if e.downcast_ref::<thine_core::Refusal>().is_some() {
            StatusCode::CONFLICT
        } else {
            // Surface server-side too: on a host this log line is what exists.
            eprintln!("api error: {e:#}");
            StatusCode::INTERNAL_SERVER_ERROR
        };
        Self(status, format!("{e:#}"))
    }
}

type ApiResult<T> = Result<Json<T>, ApiError>;

fn bad(msg: impl Into<String>) -> ApiError {
    ApiError(StatusCode::BAD_REQUEST, msg.into())
}

/// The session a request addresses. The fixed mode registers one under
/// [`AppState::LOCAL_TOKEN`], which is also the default when no header is
/// sent, so the sandbox path works without the page thinking about sessions.
fn session_of(state: &AppState, headers: &HeaderMap) -> Result<Arc<Mutex<SessionState>>, ApiError> {
    let token = headers
        .get("x-thine-session")
        .and_then(|v| v.to_str().ok())
        .unwrap_or(AppState::LOCAL_TOKEN);
    state.session(token).ok_or_else(|| {
        ApiError(
            StatusCode::UNAUTHORIZED,
            "no such session; open one first".to_string(),
        )
    })
}

// ---------------------------------------------------------------------------
// Session-free reads
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct Meta {
    pub network: String,
    /// Whether this server hands out throwaway accounts to migrate.
    pub demo: bool,
    /// A real account id, for the entry screen's placeholder.
    pub example_account: String,
}

pub async fn meta(State(s): State<Arc<AppState>>) -> Json<Meta> {
    Json(Meta {
        network: s.chain_id.clone(),
        demo: s.demo,
        example_account: s.relayer_id.to_string(),
    })
}

/// Look at any account's authority, read-only. This is the entry screen:
/// nothing is signed and nothing is connected.
pub async fn inspect(
    State(s): State<Arc<AppState>>,
    Path(account_id): Path<String>,
) -> ApiResult<AccountReport> {
    let account_id: near_kit::AccountId = account_id
        .parse()
        .map_err(|_| bad("not a NEAR account id"))?;

    let facts = s.chain.account_facts(&account_id).await?;
    if !facts.exists {
        return Err(ApiError(
            StatusCode::NOT_FOUND,
            format!("no account with that id exists on {}", s.chain_id),
        ));
    }

    // A session's own account reads with its ledger, so proofs and removals
    // render; any other account reads with an empty one.
    let ledger = {
        let sessions = s.sessions.lock().expect("poisoned");
        let mut found = None;
        for session in sessions.values() {
            if let Ok(guard) = session.try_lock()
                && guard.user == account_id
            {
                found = Some(guard.ledger.clone());
                break;
            }
        }
        found.unwrap_or_else(|| ProofLedger::new(account_id.as_str()))
    };

    Ok(Json(s.chain.account_report(&account_id, &ledger).await?))
}

// ---------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct SessionOut {
    pub token: String,
    pub account_id: String,
    /// Demo accounts only: the words the account's key derives from, shown so
    /// the demo can prove what migration does to them.
    pub seed_phrase: Option<String>,
}

/// Open a demo session: a fresh, funded throwaway account to migrate.
pub async fn open_session(State(s): State<Arc<AppState>>) -> ApiResult<SessionOut> {
    if !s.demo {
        // Fixed mode has exactly one session, already open.
        let session = s.session(AppState::LOCAL_TOKEN).ok_or_else(|| {
            ApiError(
                StatusCode::CONFLICT,
                "this server is not in demo mode and has no fixed account either".to_string(),
            )
        })?;
        let guard = session.lock().await;
        return Ok(Json(SessionOut {
            token: AppState::LOCAL_TOKEN.to_string(),
            account_id: guard.user.to_string(),
            seed_phrase: guard.seed_phrase.clone(),
        }));
    }

    let (user, user_client, seed_phrase) = crate::session::create_demo_account(&s).await?;
    let token: String = URL_SAFE_NO_PAD
        .encode(near_kit::signer::SecretKey::generate_ed25519().to_string())
        .chars()
        .take(32)
        .collect();

    let mut session = SessionState::new(&s, user.clone(), user_client);
    session.seed_phrase = Some(seed_phrase.clone());
    s.insert_session(token.clone(), session);

    Ok(Json(SessionOut {
        token,
        account_id: user.to_string(),
        seed_phrase: Some(seed_phrase),
    }))
}

#[derive(Serialize)]
pub struct TrySeedOut {
    /// Whether the chain accepted a transaction signed with the phrase.
    pub accepted: bool,
    /// The chain's own words: a transaction hash when accepted, the exact
    /// rejection otherwise. Never paraphrased.
    pub detail: String,
}

/// Sign a one-yoctoNEAR self-transfer with the key the seed phrase derives,
/// and report what the chain said. Before migration the chain accepts it;
/// after, the key does not exist and the chain refuses. This endpoint is the
/// demo's proof that the phrase is dead, straight from the network rather
/// than from this server's opinion.
pub async fn try_seed(State(s): State<Arc<AppState>>, headers: HeaderMap) -> ApiResult<TrySeedOut> {
    let session = session_of(&s, &headers)?;
    let (phrase, user) = {
        let guard = session.lock().await;
        let Some(phrase) = guard.seed_phrase.clone() else {
            return Err(ApiError(
                StatusCode::CONFLICT,
                "this session has no seed phrase to try; only demo accounts carry one".to_string(),
            ));
        };
        (phrase, guard.user.clone())
    };

    let key = near_kit::signer::SecretKey::from_seed_phrase(&phrase).map_err(|e| {
        ApiError(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("derivation: {e}"),
        )
    })?;
    let client = near_kit::Near::custom(s.rpc.clone(), s.chain_id.clone())
        .credentials(key.to_string(), user.clone())
        .map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, format!("client: {e}")))?
        .build();

    use near_kit::transaction::Final;
    match client
        .transaction(user)
        .transfer(near_kit::NearToken::from_yoctonear(1))
        .wait_until::<Final>()
        .await
    {
        Ok(outcome) if outcome.is_success() => Ok(Json(TrySeedOut {
            accepted: true,
            detail: outcome.transaction_hash().to_string(),
        })),
        Ok(outcome) => Ok(Json(TrySeedOut {
            accepted: false,
            detail: format!("{:?}", outcome.status),
        })),
        Err(e) => Ok(Json(TrySeedOut {
            accepted: false,
            detail: format!("{e}"),
        })),
    }
}

// ---------------------------------------------------------------------------
// Session-scoped: the migration itself
// ---------------------------------------------------------------------------

/// The session's own authority view. Everything the page renders comes from
/// here.
pub async fn account(
    State(s): State<Arc<AppState>>,
    headers: HeaderMap,
) -> ApiResult<AccountReport> {
    let session = session_of(&s, &headers)?;
    let guard = session.lock().await;
    Ok(Json(
        s.chain.account_report(&guard.user, &guard.ledger).await?,
    ))
}

#[derive(Serialize)]
pub struct StepDone {
    pub step: &'static str,
    pub tx_hash: String,
    pub tgas: f64,
}

pub async fn step1(State(s): State<Arc<AppState>>, headers: HeaderMap) -> ApiResult<StepDone> {
    let session = session_of(&s, &headers)?;
    let guard = session.lock().await;
    let out = guard
        .migration
        .step1_become_wallet(&guard.user_client)
        .await?;
    Ok(Json(StepDone {
        step: out.step,
        tgas: out.tgas(),
        tx_hash: out.tx_hash,
    }))
}

#[derive(Deserialize)]
pub struct PublicKeyIn {
    /// The browser's `getPublicKey()` output, base64url. ES256 SPKI.
    pub public_key: String,
}

#[derive(Serialize)]
pub struct Derived {
    /// The `0s` account this passkey controls, derived before it exists.
    pub account_id: String,
    pub exists: bool,
}

fn decode(b64: &str) -> Result<Vec<u8>, ApiError> {
    URL_SAFE_NO_PAD
        .decode(b64.trim_end_matches('='))
        .map_err(|e| bad(format!("not base64url: {e}")))
}

/// Show the user the address their passkey will control, before creating it.
pub async fn derive(
    State(s): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(input): Json<PublicKeyIn>,
) -> ApiResult<Derived> {
    let session = session_of(&s, &headers)?;
    let guard = session.lock().await;
    let public_key = compressed_public_key(&decode(&input.public_key)?)?;
    let (wallet, _) = guard
        .migration
        .browser_passkey_wallet(public_key, &s.relayer);
    let account_id = wallet.real_account_id().clone();
    let exists = s.chain.account_facts(&account_id).await?.exists;

    Ok(Json(Derived {
        account_id: account_id.to_string(),
        exists,
    }))
}

#[derive(Deserialize)]
pub struct BeginIn {
    pub public_key: String,
    /// `"create"` to create the `0s` account, `"prove"` to prove the route.
    pub purpose: String,
}

#[derive(Serialize)]
pub struct BeginOut {
    pub token: String,
    /// What the browser must pass to `navigator.credentials.get()` as the
    /// challenge, base64url.
    pub challenge: String,
    pub account_id: String,
    pub creates_account: bool,
}

/// Build the request the passkey must sign, and hand out its challenge.
pub async fn begin(
    State(s): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(input): Json<BeginIn>,
) -> ApiResult<BeginOut> {
    let session = session_of(&s, &headers)?;
    let mut guard = session.lock().await;

    let is_proof = match input.purpose.as_str() {
        "create" => false,
        "prove" => true,
        other => {
            return Err(bad(format!(
                "purpose must be \"create\" or \"prove\", not {other:?}"
            )));
        }
    };

    let raw = decode(&input.public_key)?;
    let public_key = compressed_public_key(&raw)?;
    let (wallet, passkey) = guard
        .migration
        .browser_passkey_wallet(public_key, &s.relayer);
    let account_id = wallet.real_account_id().clone();

    let exists = s.chain.account_facts(&account_id).await?.exists;

    let route = if is_proof {
        SigningRoute::ThroughUser
    } else {
        SigningRoute::Direct
    };
    let (msg, challenge) = guard
        .migration
        .capture_signing_request(&wallet, &passkey, route)
        .await?;

    let token = URL_SAFE_NO_PAD.encode(challenge);
    guard.pending.insert(
        token.clone(),
        Pending {
            msg,
            challenge,
            passkey_account: account_id.clone(),
            public_key: raw,
            creates_account: !exists,
            is_proof,
        },
    );

    Ok(Json(BeginOut {
        token,
        challenge: challenge_for(&challenge),
        account_id: account_id.to_string(),
        creates_account: !exists,
    }))
}

#[derive(Deserialize)]
pub struct FinishIn {
    pub token: String,
    /// `response.authenticatorData`, base64url.
    pub authenticator_data: String,
    /// `response.clientDataJSON`, as its exact text.
    pub client_data_json: String,
    /// `response.signature`, base64url. DER.
    pub signature: String,
}

#[derive(Serialize)]
pub struct FinishOut {
    pub step: &'static str,
    pub tx_hash: String,
    pub tgas: f64,
    pub account_id: String,
    /// Whether this was recorded as a proof.
    pub recorded_as_proof: bool,
}

/// Take what the authenticator signed, and put it on chain.
pub async fn finish(
    State(s): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(input): Json<FinishIn>,
) -> ApiResult<FinishOut> {
    let session = session_of(&s, &headers)?;
    let mut guard = session.lock().await;

    let pending = guard
        .pending
        .remove(&input.token)
        .ok_or_else(|| bad("no pending request for that token; it may already have been used"))?;

    let assertion = BrowserAssertion {
        authenticator_data: decode(&input.authenticator_data)?,
        client_data_json: input.client_data_json,
        signature_der: decode(&input.signature)?,
    };

    // Checks the challenge and the type, and normalises the signature.
    let proof = proof_from_browser(&assertion, &pending.challenge)?;

    let public_key = compressed_public_key(&pending.public_key)?;
    let (wallet, _) = guard
        .migration
        .browser_passkey_wallet(public_key, &s.relayer);

    let (out, record) = guard
        .migration
        .submit_browser_proof(
            &s.relayer,
            &wallet,
            pending.msg,
            proof,
            pending.creates_account,
            pending.is_proof,
        )
        .await?;

    // Only a routed request is evidence of anything.
    if pending.is_proof {
        guard.ledger.record(record);
        let path = ProofLedger::path_for(&s.state_dir, guard.user.as_str());
        guard.ledger.save(path).ok();
    }

    Ok(Json(FinishOut {
        step: out.step,
        tgas: out.tgas(),
        tx_hash: out.tx_hash,
        account_id: pending.passkey_account.to_string(),
        recorded_as_proof: pending.is_proof,
    }))
}

#[derive(Deserialize)]
pub struct AccountIn {
    pub account_id: String,
}

pub async fn step3(
    State(s): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(input): Json<AccountIn>,
) -> ApiResult<StepDone> {
    let session = session_of(&s, &headers)?;
    let guard = session.lock().await;
    let account_id = input
        .account_id
        .parse()
        .map_err(|_| bad("not an account id"))?;

    let out = guard
        .migration
        .step3_add_extension(&guard.user_client, &account_id)
        .await?;

    Ok(Json(StepDone {
        step: out.step,
        tgas: out.tgas(),
        tx_hash: out.tx_hash,
    }))
}

#[derive(Serialize)]
pub struct FinalOut {
    pub steps: Vec<StepDone>,
}

async fn run_step5_part(
    s: &AppState,
    headers: &HeaderMap,
    which: &str,
) -> Result<Json<FinalOut>, ApiError> {
    let session = session_of(s, headers)?;
    let mut guard = session.lock().await;

    let ledger = guard.ledger.clone();
    let (outs, removals) = match which {
        "self-hold" => {
            guard
                .migration
                .step5_remove_self_hold(&guard.user_client, &ledger)
                .await?
        }
        _ => {
            guard
                .migration
                .step5_delete_keys(&guard.user_client, &ledger)
                .await?
        }
    };

    for removal in removals {
        guard.ledger.record_removal(removal);
    }
    let path = ProofLedger::path_for(&s.state_dir, guard.user.as_str());
    guard.ledger.save(path).ok();

    Ok(Json(FinalOut {
        steps: outs
            .into_iter()
            .map(|o| StepDone {
                step: o.step,
                tgas: o.tgas(),
                tx_hash: o.tx_hash,
            })
            .collect(),
    }))
}

/// Step 5, first part: stop the account delegating to itself.
pub async fn step5a(State(s): State<Arc<AppState>>, headers: HeaderMap) -> ApiResult<FinalOut> {
    run_step5_part(&s, &headers, "self-hold").await
}

/// Step 5, second part: delete every full access key. Irreversible.
pub async fn step5b(State(s): State<Arc<AppState>>, headers: HeaderMap) -> ApiResult<FinalOut> {
    run_step5_part(&s, &headers, "delete-keys").await
}

/// The irreversible step. Refuses from `thine-core`, not from here.
pub async fn step5(State(s): State<Arc<AppState>>, headers: HeaderMap) -> ApiResult<FinalOut> {
    let session = session_of(&s, &headers)?;
    let mut guard = session.lock().await;

    let ledger = guard.ledger.clone();
    let (outs, removals) = guard
        .migration
        .step5_finalise(&guard.user_client, &ledger)
        .await?;

    // Keep the pointers to what was removed. The view re-verifies each against
    // the chain before rendering it, so these are lookup keys, not assertions.
    for removal in removals {
        guard.ledger.record_removal(removal);
    }
    let path = ProofLedger::path_for(&s.state_dir, guard.user.as_str());
    guard.ledger.save(path).ok();

    Ok(Json(FinalOut {
        steps: outs
            .into_iter()
            .map(|o| StepDone {
                step: o.step,
                tgas: o.tgas(),
                tx_hash: o.tx_hash,
            })
            .collect(),
    }))
}
