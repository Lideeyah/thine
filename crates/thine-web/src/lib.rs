//! Thine's server: the authority view, and the endpoints a browser needs to
//! sign with a real passkey.
//!
//! # What this signs, and what it does not
//!
//! Steps 1, 3 and 5 are signed by the account's own full access key. In a real
//! deployment that key is in the user's wallet and those transactions are
//! signed in their browser. **Here the server holds it**, because the point of
//! the demo is the passkey half and a judge should not need a wallet to see it.
//! The account it holds a key for is a throwaway.
//!
//! Steps 2 and 4 are the passkey steps, and those are genuinely the visitor's
//! own device: the server never sees a passkey private key and could not use
//! one if it did. It builds a challenge, the browser asks the authenticator,
//! and the assertion comes back.
//!
//! So the irreversible step is signed by a key this process holds, and the
//! proof that makes it safe is signed by hardware it does not.

pub mod api;

use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, Mutex},
};

use axum::{
    Router,
    response::Html,
    routing::{get, post},
};
use near_kit::{AccountId, Near};
use thine_core::{Chain, ProofLedger, migration::Migration};

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
    pub relayer: Near,
    pub user: AccountId,
    /// Signs steps 1, 3 and 5. See the module docs: in a real deployment this
    /// is the user's wallet, not us.
    pub user_client: Near,
    pub migration: Migration,
    pub ledger: Mutex<ProofLedger>,
    pub ledger_path: PathBuf,
    pub pending: Mutex<HashMap<String, Pending>>,
}

/// Every route the page uses.
pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route(
            "/",
            get(|| async { Html(include_str!("../static/index.html")) }),
        )
        .route("/api/account", get(api::account))
        .route("/api/step1", post(api::step1))
        .route("/api/passkey/derive", post(api::derive))
        .route("/api/passkey/begin", post(api::begin))
        .route("/api/passkey/finish", post(api::finish))
        .route("/api/step3", post(api::step3))
        .route("/api/step5", post(api::step5))
        .with_state(state)
}
