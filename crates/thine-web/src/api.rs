//! The endpoints. Thin: every decision lives in `thine-core`, and in
//! particular every refusal does, so the server cannot accidentally be more
//! permissive than the tool.

use std::sync::Arc;

use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use thine_core::{
    AccountReport,
    migration::SigningRoute,
    webauthn::{BrowserAssertion, challenge_for, compressed_public_key, proof_from_browser},
};

use crate::{AppState, Pending};

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
            StatusCode::INTERNAL_SERVER_ERROR
        };
        Self(status, format!("{e:#}"))
    }
}

type ApiResult<T> = Result<Json<T>, ApiError>;

/// The authority view. Everything the page renders comes from here.
pub async fn account(State(s): State<Arc<AppState>>) -> ApiResult<AccountReport> {
    let ledger = s.ledger.lock().expect("poisoned").clone();
    Ok(Json(s.chain.account_report(&s.user, &ledger).await?))
}

#[derive(Serialize)]
pub struct StepDone {
    pub step: &'static str,
    pub tx_hash: String,
    pub tgas: f64,
}

pub async fn step1(State(s): State<Arc<AppState>>) -> ApiResult<StepDone> {
    let out = s.migration.step1_become_wallet(&s.user_client).await?;
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
        .map_err(|e| ApiError(StatusCode::BAD_REQUEST, format!("not base64url: {e}")))
}

/// Show the user the address their passkey will control, before creating it.
pub async fn derive(
    State(s): State<Arc<AppState>>,
    Json(input): Json<PublicKeyIn>,
) -> ApiResult<Derived> {
    let public_key = compressed_public_key(&decode(&input.public_key)?)?;
    let (wallet, _) = s.migration.browser_passkey_wallet(public_key, &s.relayer);
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
    Json(input): Json<BeginIn>,
) -> ApiResult<BeginOut> {
    let is_proof = match input.purpose.as_str() {
        "create" => false,
        "prove" => true,
        other => {
            return Err(ApiError(
                StatusCode::BAD_REQUEST,
                format!("purpose must be \"create\" or \"prove\", not {other:?}"),
            ));
        }
    };

    let raw = decode(&input.public_key)?;
    let public_key = compressed_public_key(&raw)?;
    let (wallet, passkey) = s.migration.browser_passkey_wallet(public_key, &s.relayer);
    let account_id = wallet.real_account_id().clone();

    let exists = s.chain.account_facts(&account_id).await?.exists;

    let route = if is_proof {
        SigningRoute::ThroughUser
    } else {
        SigningRoute::Direct
    };
    let (msg, challenge) = s
        .migration
        .capture_signing_request(&wallet, &passkey, route)
        .await?;

    let token = URL_SAFE_NO_PAD.encode(challenge);
    s.pending.lock().expect("poisoned").insert(
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
    Json(input): Json<FinishIn>,
) -> ApiResult<FinishOut> {
    let pending = s
        .pending
        .lock()
        .expect("poisoned")
        .remove(&input.token)
        .ok_or_else(|| {
            ApiError(
                StatusCode::BAD_REQUEST,
                "no pending request for that token; it may already have been used".to_string(),
            )
        })?;

    let assertion = BrowserAssertion {
        authenticator_data: decode(&input.authenticator_data)?,
        client_data_json: input.client_data_json,
        signature_der: decode(&input.signature)?,
    };

    // Checks the challenge and the type, and normalises the signature.
    let proof = proof_from_browser(&assertion, &pending.challenge)?;

    let public_key = compressed_public_key(&pending.public_key)?;
    let (wallet, _) = s.migration.browser_passkey_wallet(public_key, &s.relayer);

    let (out, record) = s
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
        let mut ledger = s.ledger.lock().expect("poisoned");
        ledger.record(record);
        ledger.save(&s.ledger_path)?;
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
    Json(input): Json<AccountIn>,
) -> ApiResult<StepDone> {
    let account_id = input
        .account_id
        .parse()
        .map_err(|_| ApiError(StatusCode::BAD_REQUEST, "not an account id".to_string()))?;

    let out = s
        .migration
        .step3_add_extension(&s.user_client, &account_id)
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

/// The irreversible step. Refuses from `thine-core`, not from here.
pub async fn step5(State(s): State<Arc<AppState>>) -> ApiResult<FinalOut> {
    let ledger = s.ledger.lock().expect("poisoned").clone();
    let (outs, removals) = s.migration.step5_finalise(&s.user_client, &ledger).await?;

    // Keep the pointers to what was removed. The view re-verifies each against
    // the chain before rendering it, so these are lookup keys, not assertions.
    {
        let mut ledger = s.ledger.lock().expect("poisoned");
        for removal in removals {
            ledger.record_removal(removal);
        }
        ledger.save(&s.ledger_path)?;
    }

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
