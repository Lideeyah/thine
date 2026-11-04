//! The `thine-web` binary. Everything it serves is in the library beside it.

use std::{
    collections::HashMap,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use anyhow::{Context, Result};
use clap::Parser;
use near_kit::{AccountId, CryptoHash, Near};
use thine_core::{Chain, ProofLedger, Variant, artifacts, migration::Migration};
use thine_web::{AppState, router};

#[derive(Parser)]
#[command(
    name = "thine-web",
    about = "Serve Thine's authority view and the passkey endpoints."
)]
struct Cli {
    /// The account to migrate. Its full access key must be in --state-dir.
    #[arg(long)]
    account: String,

    /// NEAR RPC url. Point this at a sandbox for local work.
    #[arg(long, default_value = "https://rpc.testnet.near.org")]
    rpc: String,

    /// Chain id, which the wallet contract checks against the signed message.
    #[arg(long, default_value = "testnet")]
    chain_id: String,

    /// Where Thine keeps the relayer key, the user key and the proof ledger.
    #[arg(long, default_value = ".thine")]
    state_dir: PathBuf,

    #[arg(long, default_value = "127.0.0.1:8080")]
    listen: SocketAddr,
}

/// A key pair on disk, as `thine faucet` writes one.
#[derive(serde::Deserialize)]
struct Keyed {
    account_id: String,
    secret_key: String,
}

fn client(rpc: &str, chain_id: &str, keyed: &Keyed) -> Result<Near> {
    Near::custom(rpc.to_string(), chain_id.to_string())
        .credentials(&keyed.secret_key, keyed.account_id.clone())
        .context("credentials are not usable")
        .map(near_kit::NearBuilder::build)
}

fn load_keyed(dir: &Path, name: &str) -> Result<Keyed> {
    let path = dir.join(name);
    let bytes = std::fs::read(&path)
        .with_context(|| format!("expected a key file at {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("parsing {}", path.display()))
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let user: AccountId = cli
        .account
        .parse()
        .with_context(|| format!("{} is not a NEAR account id", cli.account))?;

    let relayer = load_keyed(&cli.state_dir, &format!("relayer-{}.json", cli.chain_id))?;
    let relayer_client = client(&cli.rpc, &cli.chain_id, &relayer)?;

    let user_keyed = load_keyed(&cli.state_dir, &format!("user-{}.json", cli.chain_id))?;
    anyhow::ensure!(
        user_keyed.account_id == cli.account,
        "the key in user-{}.json is for {}, not {}",
        cli.chain_id,
        user_keyed.account_id,
        cli.account
    );
    let user_client = client(&cli.rpc, &cli.chain_id, &user_keyed)?;

    let chain = Chain::with_client(
        Near::custom(cli.rpc.clone(), cli.chain_id.clone()).build(),
        Box::leak(cli.chain_id.clone().into_boxed_str()),
    );

    let migration = Migration::new(
        chain.clone(),
        user.clone(),
        CryptoHash::from(artifacts::code_hash(Variant::NoSign)?),
        artifacts::code_hash(Variant::WebauthnP256)?,
    );

    let ledger_path = ProofLedger::path_for(&cli.state_dir, user.as_str());
    let ledger = ProofLedger::load_or_new(&ledger_path, user.as_str());

    let state = Arc::new(AppState {
        chain,
        relayer: relayer_client,
        user: user.clone(),
        user_client,
        migration,
        ledger: Mutex::new(ledger),
        ledger_path,
        pending: Mutex::new(HashMap::new()),
    });

    println!("Thine");
    println!("  account  {user}");
    println!("  network  {} via {}", cli.chain_id, cli.rpc);
    println!("  relayer  {}", relayer.account_id);
    println!("  http://{}", cli.listen);
    println!();
    println!("Open this on http://localhost:{}", cli.listen.port());
    println!();
    println!("Not on the IP address. A passkey needs a secure context, which plain http gives");
    println!("only on loopback, but it also needs a relying party id, and an IP address cannot");
    println!("be one: Chrome rejects 127.0.0.1 with \"This is an invalid domain.\" `localhost`");
    println!("satisfies both. Anywhere else needs https.");

    let listener = tokio::net::TcpListener::bind(cli.listen)
        .await
        .with_context(|| format!("could not bind {}", cli.listen))?;
    axum::serve(listener, router(state))
        .await
        .context("serving")?;
    Ok(())
}
