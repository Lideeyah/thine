//! The `thine-web` binary. Everything it serves is in the library beside it.

use std::{
    collections::HashMap,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{Arc, Mutex as StdMutex, atomic::AtomicUsize},
};

use anyhow::{Context, Result};
use clap::Parser;
use near_kit::{AccountId, CryptoHash, Near};
use thine_core::{Chain, ProofLedger, Variant, artifacts};
use thine_web::{AppState, router, session::SessionState};

#[derive(Parser)]
#[command(
    name = "thine-web",
    about = "Serve Thine's authority view and the passkey endpoints."
)]
struct Cli {
    /// Fixed mode: migrate this one account, whose full access key must be in
    /// --state-dir as user-<chain-id>.json. This is the local sandbox path.
    #[arg(long)]
    account: Option<String>,

    /// Demo mode: any visitor can open a session, and the relayer creates
    /// them a funded throwaway testnet account to migrate. This is the hosted
    /// judge path. Exactly one of --account and --demo is required.
    #[arg(long)]
    demo: bool,

    /// How many throwaway accounts this process will ever create, which caps
    /// what a hostile visitor can drain from the relayer.
    #[arg(long, default_value_t = 150)]
    session_cap: usize,

    /// NEAR RPC url. Point this at a sandbox for local work. The default is
    /// the archival endpoint so removed rows render from a clean clone: a
    /// non-archival node forgets the removal transactions after a few days.
    /// Verified to accept transaction sends as well as historical reads.
    #[arg(long, default_value = thine_core::chain::TESTNET_ARCHIVAL_RPC)]
    rpc: String,

    /// RPC url for transaction sends. Defaults to the read endpoint; set it
    /// separately on the public networks, where the archival host and the
    /// regular host draw on separate rate-limit budgets and a busy demo needs
    /// both.
    #[arg(long)]
    send_rpc: Option<String>,

    /// Chain id, which the wallet contract checks against the signed message.
    #[arg(long, default_value = "testnet")]
    chain_id: String,

    /// Where Thine keeps key files and proof ledgers.
    #[arg(long, default_value = ".thine")]
    state_dir: PathBuf,

    /// Overridden by the PORT environment variable when set, which is how the
    /// hosting platform assigns one.
    #[arg(long, default_value = "127.0.0.1:8080")]
    listen: SocketAddr,
}

/// A key pair on disk, as `thine faucet` writes one.
#[derive(serde::Deserialize)]
struct Keyed {
    account_id: String,
    secret_key: String,
}

fn client(rpc: &str, chain_id: &str, account_id: &str, secret_key: &str) -> Result<Near> {
    Near::custom(rpc.to_string(), chain_id.to_string())
        .credentials(secret_key, account_id)
        .context("credentials are not usable")
        .map(near_kit::NearBuilder::build)
}

fn load_keyed(dir: &Path, name: &str) -> Result<Keyed> {
    let path = dir.join(name);
    let bytes = std::fs::read(&path)
        .with_context(|| format!("expected a key file at {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("parsing {}", path.display()))
}

/// The relayer key: from the environment on a host, from the state directory
/// locally. Never from the repository.
fn relayer_credentials(cli: &Cli) -> Result<(String, String)> {
    match (
        std::env::var("THINE_RELAYER_ACCOUNT"),
        std::env::var("THINE_RELAYER_KEY"),
    ) {
        (Ok(account), Ok(key)) => Ok((account, key)),
        _ => {
            let keyed = load_keyed(&cli.state_dir, &format!("relayer-{}.json", cli.chain_id))?;
            Ok((keyed.account_id, keyed.secret_key))
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    anyhow::ensure!(
        cli.account.is_some() != cli.demo,
        "exactly one of --account (fixed) and --demo (hosted) is required"
    );

    let send_rpc = cli.send_rpc.clone().unwrap_or_else(|| cli.rpc.clone());
    let (relayer_account, relayer_key) = relayer_credentials(&cli)?;
    let relayer_id: AccountId = relayer_account
        .parse()
        .with_context(|| format!("{relayer_account} is not a NEAR account id"))?;
    let relayer = client(&send_rpc, &cli.chain_id, &relayer_account, &relayer_key)?;

    let chain = Chain::with_client(
        Near::custom(cli.rpc.clone(), cli.chain_id.clone()).build(),
        Box::leak(cli.chain_id.clone().into_boxed_str()),
    );

    let state = Arc::new(AppState {
        chain,
        rpc: send_rpc.clone(),
        chain_id: cli.chain_id.clone(),
        relayer,
        relayer_id: relayer_id.clone(),
        no_sign_hash: CryptoHash::from(artifacts::code_hash(Variant::NoSign)?),
        p256_hash: artifacts::code_hash(Variant::WebauthnP256)?,
        state_dir: cli.state_dir.clone(),
        demo: cli.demo,
        session_cap: cli.session_cap,
        sessions_created: AtomicUsize::new(0),
        sessions: StdMutex::new(HashMap::new()),
    });

    if let Some(account) = &cli.account {
        let user: AccountId = account
            .parse()
            .with_context(|| format!("{account} is not a NEAR account id"))?;
        let keyed = load_keyed(&cli.state_dir, &format!("user-{}.json", cli.chain_id))?;
        anyhow::ensure!(
            keyed.account_id == *account,
            "the key in user-{}.json is for {}, not {account}",
            cli.chain_id,
            keyed.account_id,
        );
        let user_client = client(
            &cli.rpc,
            &cli.chain_id,
            &keyed.account_id,
            &keyed.secret_key,
        )?;

        let mut session = SessionState::new(&state, user.clone(), user_client);
        session.ledger = ProofLedger::load_or_new(
            ProofLedger::path_for(&cli.state_dir, user.as_str()),
            user.as_str(),
        );
        state.insert_session(AppState::LOCAL_TOKEN, session);
    }

    let listen = match std::env::var("PORT") {
        Ok(port) => format!("0.0.0.0:{port}")
            .parse()
            .context("PORT is not a port number")?,
        Err(_) => cli.listen,
    };

    println!("Thine");
    match &cli.account {
        Some(account) => println!("  account  {account} (fixed)"),
        None => println!(
            "  demo     up to {} throwaway accounts under {relayer_id}",
            cli.session_cap
        ),
    }
    println!("  network  {} via {}", cli.chain_id, cli.rpc);
    println!("  relayer  {relayer_id}");
    println!("  http://{listen}");
    println!();
    println!("Open this on http://localhost:{}", listen.port());
    println!();
    println!("Not on the IP address. A passkey needs a secure context, which plain http gives");
    println!("only on loopback, but it also needs a relying party id, and an IP address cannot");
    println!("be one: Chrome rejects 127.0.0.1 with \"This is an invalid domain.\" `localhost`");
    println!("satisfies both. Anywhere else needs https.");

    let listener = tokio::net::TcpListener::bind(listen)
        .await
        .with_context(|| format!("could not bind {listen}"))?;
    axum::serve(listener, router(state))
        .await
        .context("serving")?;
    Ok(())
}
