//! Prepare a locally running NEAR sandbox so `thine-web` can be pointed at it.
//!
//! The sandbox is the only network where the whole thing can be exercised
//! today without spending a day of faucet allowance, so this is how the demo
//! runs locally.
//!
//! ```bash
//! # 1. a sandbox, on the port this expects
//! docker run -d --name thine-sandbox -p 3030:3030 \
//!     -e NEAR_ROOT_ACCOUNT=sandbox nearprotocol/sandbox:2.14.0
//!
//! # 2. publish the contracts and make an account to migrate
//! cargo run -p thine-web --example setup_local
//!
//! # 3. serve it
//! cargo run -p thine-web --bin thine-web -- \
//!     --rpc http://localhost:3030 --chain-id sandbox --account lydia.sandbox
//! ```
//!
//! Then open <http://127.0.0.1:8080>. Passkeys need a secure context, and
//! `127.0.0.1` counts.
//!
//! Publishing on a sandbox is free in the sense that matters: the 68 NEAR burn
//! is real but the tokens are not, and the root account starts with far more.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use near_kit::{
    AccountId, Near, NearToken, protocol::PublishMode, signer::SecretKey, transaction::Final,
};
use thine_core::{Variant, artifacts};

/// The key every `nearprotocol/sandbox` root account is created with. Fixed and
/// public; it is a throwaway network.
const ROOT_SECRET: &str = "ed25519:3JoAjwLppjgvxkk6kNsu5wQj3FfUJnpBKWieC73hVTpBeA6FZiCc5tfyZL3a3tHeQJegQe4qGSv8FLsYp7TYd1r6";
const RPC: &str = "http://localhost:3030";
const CHAIN_ID: &str = "sandbox";
const ROOT: &str = "sandbox";

#[tokio::main]
async fn main() -> Result<()> {
    let state_dir = PathBuf::from(".thine");
    std::fs::create_dir_all(&state_dir)?;

    let root = Near::custom(RPC.to_string(), CHAIN_ID.to_string())
        .credentials(ROOT_SECRET, ROOT)
        .context("the sandbox root key was rejected")?
        .build();

    let root_id: AccountId = ROOT.parse()?;
    let balance = root
        .account(root_id.clone())
        .await
        .context(
            "could not reach a sandbox at http://localhost:3030. Start one first; see the \
             comment at the top of this file.",
        )?
        .amount;
    println!("sandbox root {ROOT} holds {balance}");

    // --- publish both wallet contracts by code hash ---
    for variant in [Variant::NoSign, Variant::WebauthnP256] {
        let code = artifacts::load(variant)?;
        let hash = near_kit::CryptoHash::from(artifacts::code_hash(variant)?);

        if root.global_contract(hash).exists().await.unwrap_or(false) {
            println!("already published  {}  {hash}", variant.file_name());
            continue;
        }

        let outcome = root
            .publish(code, PublishMode::Immutable)
            .wait_until::<Final>()
            .await
            .with_context(|| format!("publishing {}", variant.file_name()))?;
        anyhow::ensure!(
            outcome.is_success(),
            "publishing {} failed: {:?}",
            variant.file_name(),
            outcome.status
        );
        println!("published  {}  {hash}", variant.file_name());
    }

    // --- the relayer, which pays gas for passkey hops ---
    let relayer_secret = SecretKey::generate_ed25519();
    let relayer_id: AccountId = format!("relayer.{ROOT}").parse()?;
    create(&root, &relayer_id, &relayer_secret, 50).await?;
    write_key(
        &state_dir,
        "relayer-sandbox.json",
        &relayer_id,
        &relayer_secret,
    )?;
    println!("relayer    {relayer_id}");

    // --- the account to migrate: an ordinary account with one full access key ---
    let user_secret = SecretKey::generate_ed25519();
    let user_id: AccountId = format!("lydia.{ROOT}").parse()?;
    create(&root, &user_id, &user_secret, 20).await?;
    write_key(&state_dir, "user-sandbox.json", &user_id, &user_secret)?;
    println!("account    {user_id}");

    // A stale ledger from an earlier run would claim proofs for accounts that
    // no longer exist on a fresh sandbox.
    let ledger = thine_core::ProofLedger::path_for(&state_dir, user_id.as_str());
    if ledger.exists() {
        std::fs::remove_file(&ledger)?;
        println!("cleared    {}", ledger.display());
    }

    println!();
    println!("Now run:");
    println!(
        "  cargo run -p thine-web --bin thine-web -- --rpc {RPC} --chain-id {CHAIN_ID} \
         --account {user_id}"
    );
    Ok(())
}

async fn create(root: &Near, id: &AccountId, secret: &SecretKey, near: u128) -> Result<()> {
    if root.account_exists(id.clone()).await.unwrap_or(false) {
        anyhow::bail!(
            "{id} already exists on this sandbox. Restart the container for a clean run: \
             docker rm -f thine-sandbox"
        );
    }
    root.transaction(id.clone())
        .create_account()
        .transfer(NearToken::from_near(near))
        .add_full_access_key(secret.public_key())
        .wait_until::<Final>()
        .await
        .with_context(|| format!("creating {id}"))?
        .result()
        .with_context(|| format!("creating {id}"))?;
    Ok(())
}

fn write_key(dir: &Path, name: &str, id: &AccountId, secret: &SecretKey) -> Result<()> {
    let path = dir.join(name);
    std::fs::write(
        &path,
        serde_json::to_vec_pretty(&serde_json::json!({
            "network": CHAIN_ID,
            "account_id": id.to_string(),
            "secret_key": secret.to_string(),
        }))?,
    )?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}
