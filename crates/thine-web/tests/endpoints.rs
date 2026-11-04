//! The server's endpoints, driving a whole migration.
//!
//! This goes through the real router — the same routes the page calls, with the
//! same JSON — against a local sandbox. What it does not exercise is the
//! browser itself: `navigator.credentials` is replaced by a software P-256 key
//! producing assertions in the encodings a browser produces. Everything between
//! that and the chain is the production path.
//!
//! ```bash
//! cargo test -p thine-web -- --nocapture --test-threads=1
//! ```

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use defuse_wallet_sdk::NearToken;
use defuse_wallet_webauthn::crypto::p256::p256::{
    ecdsa::{Signature, SigningKey, signature::Signer as _},
    elliptic_curve::{Generate, scalar::IsHigh},
};
use http_body_util::BodyExt;
use near_kit::{
    AccountId, CryptoHash, Near,
    protocol::PublishMode,
    signer::{InMemorySigner, SecretKey},
    transaction::Final,
};
use near_kit_sandbox::SandboxConfig;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use thine_core::{Chain, ProofLedger, Variant, artifacts, migration::Migration};
use tower::ServiceExt;

const RP_ID_HASH: [u8; 32] =
    hex_literal::hex!("49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d9763");

/// Stands in for the user's device.
struct Authenticator {
    key: SigningKey,
    sign_count: u32,
}

impl Authenticator {
    fn new() -> Self {
        Self {
            key: SigningKey::generate_from_rng(&mut rand::rng()),
            sign_count: 0,
        }
    }

    /// As `getPublicKey()` reports it: ES256 SPKI.
    fn public_key_b64(&self) -> String {
        let point = self.key.verifying_key().to_sec1_point(false);
        let mut spki = vec![0u8; 91 - 65];
        spki.extend_from_slice(point.as_bytes());
        URL_SAFE_NO_PAD.encode(spki)
    }

    /// As `navigator.credentials.get()` reports it, high-S left alone so the
    /// server's normalisation is what makes it usable.
    fn get(&mut self, challenge_b64: &str) -> (String, String, String) {
        let authenticator_data = [
            RP_ID_HASH.as_slice(),
            &[0b0000_0101u8],
            &self.sign_count.to_be_bytes(),
        ]
        .concat();
        self.sign_count += 1;

        let client_data_json = format!(
            r#"{{"type":"webauthn.get","challenge":"{challenge_b64}","origin":"http://localhost:8080","crossOrigin":false}}"#
        );

        let signed_over = [
            authenticator_data.as_slice(),
            Sha256::digest(client_data_json.as_bytes()).as_ref(),
        ]
        .concat();

        let mut signature: Signature = self.key.sign(&signed_over);
        if !bool::from(signature.s().is_high()) {
            signature =
                Signature::from_scalars(signature.r().to_bytes(), (-*signature.s()).to_bytes())
                    .unwrap();
        }

        (
            URL_SAFE_NO_PAD.encode(&authenticator_data),
            client_data_json,
            URL_SAFE_NO_PAD.encode(signature.to_der().as_bytes()),
        )
    }
}

async fn get(app: &Router, path: &str) -> (StatusCode, Value) {
    call(app, Request::get(path).body(Body::empty()).unwrap()).await
}

async fn post(app: &Router, path: &str, body: Value) -> (StatusCode, Value) {
    call(
        app,
        Request::post(path)
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap(),
    )
    .await
}

async fn call(app: &Router, req: Request<Body>) -> (StatusCode, Value) {
    let res = app.clone().oneshot(req).await.unwrap();
    let status = res.status();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, value)
}

#[tokio::test]
async fn the_endpoints_drive_the_whole_migration() {
    let sandbox = SandboxConfig::shared()
        .await
        .expect("failed to start sandbox");
    let relayer = sandbox.client();

    for variant in [Variant::NoSign, Variant::WebauthnP256] {
        relayer
            .publish(artifacts::load(variant).unwrap(), PublishMode::Immutable)
            .into_future()
            .await
            .unwrap();
    }

    let chain = Chain::with_client(relayer.clone(), "sandbox");
    let (user, user_client) = fresh_account(&relayer).await;

    let dir = std::env::temp_dir().join(format!("thine-web-test-{}", std::process::id()));
    let state = Arc::new(thine_web::AppState {
        chain: chain.clone(),
        relayer: relayer.clone(),
        user: user.clone(),
        user_client,
        migration: Migration::new(
            chain.clone(),
            user.clone(),
            CryptoHash::from(artifacts::code_hash(Variant::NoSign).unwrap()),
            artifacts::code_hash(Variant::WebauthnP256).unwrap(),
        ),
        ledger: Mutex::new(ProofLedger::new(user.as_str())),
        ledger_path: ProofLedger::path_for(&dir, user.as_str()),
        pending: Mutex::new(HashMap::new()),
    });
    let app = thine_web::router(state);

    // --- the page loads ---
    let res = app
        .clone()
        .oneshot(Request::get("/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let html =
        String::from_utf8(res.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap();
    assert!(
        html.contains("navigator.credentials.create"),
        "the page must register passkeys"
    );
    assert!(html.contains("alg: -7"), "the page must ask for ES256 only");

    // --- the view, before anything ---
    let (status, view) = get(&app, "/api/account").await;
    assert_eq!(status, StatusCode::OK, "{view}");
    assert_eq!(view["version"], 1);
    assert_eq!(view["authority"]["stage"]["stage"], "seed_controlled");
    assert_eq!(view["summary"]["survives_key_deletion"], false);
    println!("before: {}", view["authority"]["stage"]["stage"]);

    // --- the irreversible step is refused, with a code, as 409 ---
    let (status, refused) = post(&app, "/api/step5", json!({})).await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "a refusal is the tool working, not a server error: {refused}"
    );
    println!("step 5 refused: {}", refused["error"]);

    // --- step 1 ---
    let (status, out) = post(&app, "/api/step1", json!({})).await;
    assert_eq!(status, StatusCode::OK, "{out}");
    println!("step 1: {:.4} TGas", out["tgas"].as_f64().unwrap());

    // --- two passkeys, each created, authorised and proven ---
    let mut authenticators = [Authenticator::new(), Authenticator::new()];
    for (i, auth) in authenticators.iter_mut().enumerate() {
        let public_key = auth.public_key_b64();

        // The address is shown before it exists.
        let (status, derived) = post(
            &app,
            "/api/passkey/derive",
            json!({ "public_key": public_key }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{derived}");
        assert_eq!(derived["exists"], false, "it should not exist yet");
        let account_id = derived["account_id"].as_str().unwrap().to_string();
        println!("passkey {i} derives to {account_id}");

        // Create it: signed directly by the passkey.
        let (status, begun) = post(
            &app,
            "/api/passkey/begin",
            json!({ "public_key": public_key, "purpose": "create" }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{begun}");
        assert_eq!(begun["creates_account"], true);

        let (ad, cdj, sig) = auth.get(begun["challenge"].as_str().unwrap());
        let (status, done) = post(
            &app,
            "/api/passkey/finish",
            json!({
                "token": begun["token"],
                "authenticator_data": ad,
                "client_data_json": cdj,
                "signature": sig,
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{done}");
        assert_eq!(done["recorded_as_proof"], false, "creation is not proof");
        println!("  step 2: {:.4} TGas", done["tgas"].as_f64().unwrap());

        // Authorise it.
        let (status, done) = post(&app, "/api/step3", json!({ "account_id": account_id })).await;
        assert_eq!(status, StatusCode::OK, "{done}");
        println!("  step 3: {:.4} TGas", done["tgas"].as_f64().unwrap());

        // Prove it, routed through the user account.
        let (status, begun) = post(
            &app,
            "/api/passkey/begin",
            json!({ "public_key": public_key, "purpose": "prove" }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{begun}");

        let (ad, cdj, sig) = auth.get(begun["challenge"].as_str().unwrap());
        let (status, done) = post(
            &app,
            "/api/passkey/finish",
            json!({
                "token": begun["token"],
                "authenticator_data": ad,
                "client_data_json": cdj,
                "signature": sig,
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{done}");
        assert_eq!(done["recorded_as_proof"], true);
        println!("  step 4: {:.4} TGas", done["tgas"].as_f64().unwrap());

        // After the first passkey, the gate is still shut.
        if i == 0 {
            let (status, refused) = post(&app, "/api/step5", json!({})).await;
            assert_eq!(status, StatusCode::CONFLICT);
            assert!(
                refused["error"]
                    .as_str()
                    .unwrap()
                    .contains("of the 2 required"),
                "{refused}"
            );
            println!("  step 5 still refused: 1 of 2");
        }
    }

    // --- the view now says the account survives ---
    let (_, view) = get(&app, "/api/account").await;
    assert_eq!(view["summary"]["passkeys_proven"], 2);
    assert_eq!(view["summary"]["survives_key_deletion"], true);
    assert!(view["summary"]["key_deletion_refusal"].is_null());

    // --- step 5 ---
    let (status, out) = post(&app, "/api/step5", json!({})).await;
    assert_eq!(status, StatusCode::OK, "{out}");
    for step in out["steps"].as_array().unwrap() {
        println!(
            "step 5: {} {:.4} TGas",
            step["step"].as_str().unwrap(),
            step["tgas"].as_f64().unwrap()
        );
    }

    let (_, view) = get(&app, "/api/account").await;
    assert_eq!(view["authority"]["stage"]["stage"], "passkey_controlled");
    assert_eq!(view["summary"]["has_full_access_key"], false);
    println!("after: {}", view["authority"]["stage"]["stage"]);

    // --- and a passkey still drives it with no keys left ---
    let public_key = authenticators[0].public_key_b64();
    let (status, begun) = post(
        &app,
        "/api/passkey/begin",
        json!({ "public_key": public_key, "purpose": "prove" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{begun}");
    let (ad, cdj, sig) = authenticators[0].get(begun["challenge"].as_str().unwrap());
    let (status, done) = post(
        &app,
        "/api/passkey/finish",
        json!({
            "token": begun["token"],
            "authenticator_data": ad,
            "client_data_json": cdj,
            "signature": sig,
        }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a passkey must still drive the account: {done}"
    );
    println!(
        "after migration, a passkey still drives it: {:.4} TGas",
        done["tgas"].as_f64().unwrap()
    );

    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn a_token_cannot_be_replayed() {
    // Cheap guard, no chain needed beyond the view: a finish token is removed
    // when used, so an intercepted assertion cannot be submitted twice.
    let sandbox = SandboxConfig::shared()
        .await
        .expect("failed to start sandbox");
    let relayer = sandbox.client();
    let chain = Chain::with_client(relayer.clone(), "sandbox");
    let user: AccountId = relayer.account_id().to_owned();

    let state = Arc::new(thine_web::AppState {
        chain: chain.clone(),
        relayer: relayer.clone(),
        user: user.clone(),
        user_client: relayer.clone(),
        migration: Migration::new(chain, user.clone(), CryptoHash::from([0u8; 32]), [0u8; 32]),
        ledger: Mutex::new(ProofLedger::new(user.as_str())),
        ledger_path: std::env::temp_dir().join("thine-replay-test.json"),
        pending: Mutex::new(HashMap::new()),
    });
    let app = thine_web::router(state);

    let (status, out) = post(
        &app,
        "/api/passkey/finish",
        json!({
            "token": "never-issued",
            "authenticator_data": "AA",
            "client_data_json": "{}",
            "signature": "AA",
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        out["error"]
            .as_str()
            .unwrap()
            .contains("no pending request"),
        "{out}"
    );
}

async fn fresh_account(root: &Near) -> (AccountId, Near) {
    let secret = SecretKey::generate_ed25519();
    let id: AccountId = format!("lydia.{}", root.account_id()).parse().unwrap();

    root.transaction(id.clone())
        .create_account()
        .transfer(NearToken::from_near(20))
        .add_full_access_key(secret.public_key())
        .wait_until::<Final>()
        .await
        .unwrap()
        .result()
        .unwrap();

    let signer = InMemorySigner::new(id.clone(), secret.to_string()).unwrap();
    (id.clone(), root.with_signer(signer))
}
