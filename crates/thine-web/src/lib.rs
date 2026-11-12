//! Thine's server: the authority view, and the endpoints a browser needs to
//! sign with a real passkey.
//!
//! # What this signs, and what it does not
//!
//! Steps 1, 3 and 5 are signed by the account's own full access key. In a real
//! deployment that key is in the user's wallet and those transactions are
//! signed in their browser. **Here the server holds it**, because the point of
//! the demo is the passkey half and a judge should not need a wallet to see it.
//! The accounts it holds keys for are throwaways it created.
//!
//! Steps 2 and 4 are the passkey steps, and those are genuinely the visitor's
//! own device: the server never sees a passkey private key and could not use
//! one if it did. It builds a challenge, the browser asks the authenticator,
//! and the assertion comes back.
//!
//! # Two modes
//!
//! **Fixed**: `--account` names one account whose key sits in the state
//! directory. This is the local path against a sandbox.
//!
//! **Demo** (`--demo`): any visitor can open a session, and the relayer
//! creates them a funded throwaway sub-account to migrate. This is the hosted
//! judge path. Sessions are capped so the relayer cannot be drained; every
//! session state lives in memory, so a restart forgets in-flight sessions and
//! a visitor starts a fresh one.

pub mod api;
pub mod session;

use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Mutex as StdMutex, atomic::AtomicUsize},
};

use axum::{
    Router,
    response::Html,
    routing::{get, post},
};
use near_kit::{AccountId, CryptoHash, Near};
use std::sync::Arc;
use thine_core::Chain;
use tokio::sync::Mutex;

use session::SessionState;

/// A request a browser has been asked to sign, held until it comes back.
pub struct Pending {
    pub msg: defuse_wallet_sdk::RequestMessage,
    pub challenge: [u8; 32],
    pub passkey_account: AccountId,
    pub public_key: Vec<u8>,
    /// Whether this request also creates the `0s` account.
    pub creates_account: bool,
    /// Whether this is a proof, routed through the user account, rather than a
    /// creation. Only a proof is evidence of anything.
    pub is_proof: bool,
}

pub struct AppState {
    pub chain: Chain,
    /// Endpoint and chain id the signing clients are built against.
    pub rpc: String,
    pub chain_id: String,
    pub relayer: Near,
    pub relayer_id: AccountId,
    pub no_sign_hash: CryptoHash,
    pub p256_hash: [u8; 32],
    pub state_dir: PathBuf,
    /// Whether visitors may open sessions that create throwaway accounts.
    pub demo: bool,
    pub session_cap: usize,
    pub sessions_created: AtomicUsize,
    /// token -> session. Each session has its own async lock, so one
    /// visitor's steps serialise without blocking another's.
    pub sessions: StdMutex<HashMap<String, Arc<Mutex<SessionState>>>>,
}

impl AppState {
    /// The token the fixed, single-account mode registers its session under.
    pub const LOCAL_TOKEN: &'static str = "local";

    pub fn insert_session(&self, token: impl Into<String>, state: SessionState) {
        self.sessions
            .lock()
            .expect("poisoned")
            .insert(token.into(), Arc::new(Mutex::new(state)));
    }

    pub fn session(&self, token: &str) -> Option<Arc<Mutex<SessionState>>> {
        self.sessions.lock().expect("poisoned").get(token).cloned()
    }
}

/// Every route the page uses.
pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route(
            "/",
            get(|| async { Html(include_str!("../static/index.html")) }),
        )
        .route(
            "/tokens.css",
            get(|| async {
                (
                    [("content-type", "text/css; charset=utf-8")],
                    include_str!("../static/tokens.css"),
                )
            }),
        )
        .route(
            "/app.js",
            get(|| async {
                (
                    [("content-type", "text/javascript; charset=utf-8")],
                    include_str!("../static/app.js"),
                )
            }),
        )
        .route("/api/meta", get(api::meta))
        .route("/api/inspect/{account_id}", get(api::inspect))
        .route("/api/session", post(api::open_session))
        .route("/api/account", get(api::account))
        .route("/api/step1", post(api::step1))
        .route("/api/passkey/derive", post(api::derive))
        .route("/api/passkey/begin", post(api::begin))
        .route("/api/passkey/finish", post(api::finish))
        .route("/api/step3", post(api::step3))
        .route("/api/step5a", post(api::step5a))
        .route("/api/step5b", post(api::step5b))
        .route("/api/step5", post(api::step5))
        .with_state(state)
}
