//! `thine` — move a NEAR account from seed-phrase control to passkey control.
//!
//! The commands here are the operations. The authority view is the thing the
//! user actually looks at, and `thine inspect --json` is the data behind it.

mod faucet;
mod fund;
mod publish;
mod render;
mod state;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use near_kit::AccountId;
use thine_core::{Chain, ProofLedger};

#[derive(Parser)]
#[command(
    name = "thine",
    about = "Move a NEAR account from seed-phrase control to passkey control, keeping the same \
             account id and without moving assets.",
    version
)]
struct Cli {
    /// Network to act on.
    #[arg(long, global = true, default_value = "testnet")]
    network: Network,

    /// Where Thine keeps local state. Holds the relayer's secret key.
    #[arg(long, global = true, default_value = ".thine")]
    state_dir: std::path::PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum Network {
    Testnet,
    Mainnet,
}

impl Network {
    fn as_str(self) -> &'static str {
        match self {
            Self::Testnet => "testnet",
            Self::Mainnet => "mainnet",
        }
    }

    fn chain(self) -> Chain {
        match self {
            Self::Testnet => Chain::testnet(),
            Self::Mainnet => Chain::mainnet(),
        }
    }
}

#[derive(Subcommand)]
enum Command {
    /// Ask the testnet faucet for a funded account and keep it as the relayer.
    ///
    /// The relayer pays gas. It holds no authority over any account being
    /// migrated.
    Faucet {
        /// Prefix for the generated account id.
        #[arg(long, default_value = "thine")]
        prefix: String,
    },

    /// Top the relayer up to what publishing needs, from the faucet.
    ///
    /// The faucet grants 10 NEAR per request and publishing burns 67.8768, so
    /// this takes eight requests, each into a fresh account that is then swept
    /// into the relayer.
    Fund {
        /// Give up after this many faucet requests.
        #[arg(long, default_value_t = 16)]
        max_requests: usize,
    },

    /// Publish both wallet contracts as global contracts, by code hash.
    ///
    /// Burns roughly 68 NEAR at ten times the ordinary storage rate, and the
    /// burn is not refundable. By code hash rather than by account id, so the
    /// reference is immutable: it is the only way back into a migrated account,
    /// and it should not be something anyone can redeploy.
    Publish {
        /// Publish even if a record already exists for this network.
        #[arg(long)]
        force: bool,
    },

    /// Show who can currently open an account.
    ///
    /// This is the authority view. `--json` is the shape the interface
    /// consumes.
    Inspect {
        account_id: String,
        /// Emit the view as JSON rather than text.
        #[arg(long)]
        json: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match &cli.command {
        Command::Faucet { prefix } => {
            if cli.network != Network::Testnet {
                anyhow::bail!(
                    "there is no faucet on mainnet. Fund a relayer account yourself and write it \
                     to {}",
                    state::Relayer::path(&cli.state_dir, cli.network.as_str()).display()
                );
            }
            faucet::run(prefix, &cli.state_dir).await
        }

        Command::Fund { max_requests } => {
            if cli.network != Network::Testnet {
                anyhow::bail!("there is no faucet on mainnet");
            }
            fund::run(&cli.state_dir, *max_requests).await
        }

        Command::Publish { force } => {
            publish::run(cli.network.as_str(), &cli.state_dir, *force).await
        }

        Command::Inspect { account_id, json } => {
            let account_id: AccountId = account_id
                .parse()
                .with_context(|| format!("{account_id} is not a NEAR account id"))?;
            let chain = cli.network.chain();
            let ledger = ProofLedger::load_or_new(
                ProofLedger::path_for(&cli.state_dir, account_id.as_str()),
                account_id.as_str(),
            );

            let view = chain
                .authority_view(&account_id, &ledger)
                .await
                .with_context(|| format!("could not read authority for {account_id}"))?;

            if *json {
                println!("{}", serde_json::to_string_pretty(&view)?);
            } else {
                print!("{}", render::authority(&view, cli.network.as_str()));
            }
            Ok(())
        }
    }
}
