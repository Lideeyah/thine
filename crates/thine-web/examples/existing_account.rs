//! Build a genuinely pre-existing testnet account, then ask the chain what
//! its seed phrase is worth after migration.
//!
//! The migration's central claim is that it works on accounts that already
//! exist, with whatever past they carry. The sandbox proves the mechanism over
//! prior contract state; this tool produces the same situation on live
//! testnet, so the record can point at transactions anyone can fetch.
//!
//!   cargo run -p thine-web --example existing_account -- prepare [name]
//!
//! creates an account whose one full access key derives from a printed seed
//! phrase, then gives it a past signed by that key: it deploys an ordinary
//! near-sdk contract, writes state through it, and moves tokens. The key
//! lands in .thine/user-testnet.json, which is exactly what
//! `thine-web --account` expects.
//!
//! With a name, the account is `name.testnet`, registered through the
//! testnet registrar the way a wallet would register it, so it looks like
//! what it is standing in for. Without one, it is a generated sub-account of
//! the relayer.
//!
//!   cargo run -p thine-web --example existing_account -- enrich
//!
//! deepens the prepared account's history: more contract use, transfers out,
//! and transfers in from the relayer, so its explorer page reads like an
//! account that has been lived in rather than one set up in a single pass.
//! Age cannot be manufactured; activity is simply performed.
//!
//!   cargo run -p thine-web --example existing_account -- keyfile <id> <12 words>
//!
//! derives the account's key from a seed phrase and writes it to
//! .thine/user-testnet.json, which is what `thine-web --account` reads. This
//! is how someone who holds a phrase migrates their own account: locally,
//! with the phrase never leaving their machine. Thine's hosted interface
//! never asks for a phrase; a page that asks for twelve words is the
//! behaviour this product exists to end.
//!
//!   cargo run -p thine-web --example existing_account -- try-seed <id> <12 words>
//!
//! derives the key from the phrase and submits a one yoctoNEAR self transfer,
//! printing the chain's verbatim answer. Before migration it is accepted;
//! after, the chain refuses it, and that refusal is the product.

use anyhow::{Context, Result, bail};
use near_kit::{AccountId, Gas, Near, NearToken, signer::SecretKey, transaction::Final};

const RPC: &str = thine_core::chain::TESTNET_ARCHIVAL_RPC;
const CHAIN_ID: &str = "testnet";

/// Enough for the probe contract's storage and every transaction it signs.
const FUNDING: NearToken = NearToken::from_millinear(2500);

#[derive(serde::Serialize, serde::Deserialize)]
struct Keyed {
    account_id: String,
    secret_key: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("prepare") => prepare(args.get(1).map(String::as_str)).await,
        Some("enrich") => enrich().await,
        Some("keyfile") if args.len() >= 3 => keyfile(&args[1], &args[2..].join(" ")),
        Some("try-seed") if args.len() >= 3 => try_seed(&args[1], &args[2..].join(" ")).await,
        _ => bail!(
            "usage: existing_account prepare [name] | enrich | keyfile <account_id> <seed \
             phrase> | try-seed <account_id> <seed phrase>"
        ),
    }
}

async fn prepare(name: Option<&str>) -> Result<()> {
    let relayer_keyed: Keyed = serde_json::from_slice(
        &std::fs::read(".thine/relayer-testnet.json")
            .context("expected .thine/relayer-testnet.json")?,
    )?;
    let relayer_id: AccountId = relayer_keyed.account_id.parse()?;
    let relayer = Near::custom(RPC.to_string(), CHAIN_ID.to_string())
        .credentials(relayer_keyed.secret_key.as_str(), relayer_id.clone())
        .context("relayer credentials")?
        .build();

    // The one full access key derives from a seed phrase at NEAR's standard
    // path, the way a wallet's would.
    let phrase = thine_web::session::generate_seed_phrase()?;
    let secret = SecretKey::from_seed_phrase(&phrase)
        .map_err(|e| anyhow::anyhow!("deriving from the seed phrase: {e}"))?;

    let id: AccountId = match name {
        Some(n) => {
            let full = if n.contains('.') {
                n.to_string()
            } else {
                format!("{n}.testnet")
            };
            full.parse()?
        }
        None => {
            let secs = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs();
            format!("v{}.{relayer_id}", secs % 1_000_000_000).parse()?
        }
    };

    if relayer.account_exists(id.clone()).await.unwrap_or(false) {
        bail!("{id} already exists; pick another name");
    }

    println!("account      {id}");
    println!("seed phrase  {phrase}");

    // A sub-account of the relayer is created directly; a top-level
    // `name.testnet` goes through the testnet registrar, the same call a
    // wallet makes when someone picks a name.
    let outcome = if id.as_str().ends_with(&format!(".{relayer_id}")) {
        relayer
            .transaction(id.clone())
            .create_account()
            .transfer(FUNDING)
            .add_full_access_key(secret.public_key())
            .wait_until::<Final>()
            .await
            .context("creating the account")?
    } else {
        relayer
            .transaction("testnet".parse::<AccountId>()?)
            .call("create_account")
            .args(serde_json::json!({
                "new_account_id": id.to_string(),
                "new_public_key": secret.public_key().to_string(),
            }))
            .deposit(FUNDING)
            .gas(Gas::from_tgas(100))
            .finish()
            .wait_until::<Final>()
            .await
            .context("registering the account")?
    };
    if !outcome.is_success() {
        bail!("creating {id} failed: {:?}", outcome.status);
    }
    if !relayer.account_exists(id.clone()).await.unwrap_or(false) {
        bail!("the registrar did not create {id}; the name may be reserved");
    }
    println!("created      {}", outcome.transaction_hash());

    let user = Near::custom(RPC.to_string(), CHAIN_ID.to_string())
        .credentials(secret.to_string(), id.clone())
        .context("user credentials")?
        .build();

    // A past, all of it signed by the phrase-derived key: an ordinary
    // near-sdk contract, state written through it, and tokens moved. This is
    // the shape of an account that has been used, not one made for a demo.
    let wasm = std::fs::read("res/thine-probe.wasm").context("res/thine-probe.wasm")?;
    let outcome = user.deploy(wasm).wait_until::<Final>().await?;
    if !outcome.is_success() {
        bail!("deploying the probe failed: {:?}", outcome.status);
    }
    println!("deployed     {}", outcome.transaction_hash());

    for round in 0..3u32 {
        let outcome = user
            .transaction(id.clone())
            .call("bump")
            .gas(Gas::from_tgas(10))
            .finish()
            .call("put")
            .args(serde_json::json!({
                "key": format!("record-{round}"),
                "value": "x".repeat(64 * (round as usize + 1)),
            }))
            .gas(Gas::from_tgas(10))
            .finish()
            .wait_until::<Final>()
            .await?;
        if !outcome.is_success() {
            bail!("state write {round} failed: {:?}", outcome.status);
        }
        println!("state write  {}", outcome.transaction_hash());
    }

    let outcome = user
        .transaction(relayer_id.clone())
        .transfer(NearToken::from_millinear(10))
        .wait_until::<Final>()
        .await?;
    if !outcome.is_success() {
        bail!("transfer failed: {:?}", outcome.status);
    }
    println!("transfer     {}", outcome.transaction_hash());

    std::fs::write(
        ".thine/user-testnet.json",
        serde_json::to_vec_pretty(&Keyed {
            account_id: id.to_string(),
            secret_key: secret.to_string(),
        })?,
    )?;
    println!();
    println!("key written to .thine/user-testnet.json; migrate with");
    println!("  thine-web --account {id}");
    Ok(())
}

/// More life for the prepared account, all of it real: contract calls and
/// outgoing transfers signed by its own key, incoming transfers from the
/// relayer.
async fn enrich() -> Result<()> {
    let user_keyed: Keyed = serde_json::from_slice(
        &std::fs::read(".thine/user-testnet.json").context("run prepare first")?,
    )?;
    let relayer_keyed: Keyed =
        serde_json::from_slice(&std::fs::read(".thine/relayer-testnet.json")?)?;
    let id: AccountId = user_keyed.account_id.parse()?;
    let relayer_id: AccountId = relayer_keyed.account_id.parse()?;
    let user = Near::custom(RPC.to_string(), CHAIN_ID.to_string())
        .credentials(user_keyed.secret_key.as_str(), id.clone())
        .context("user credentials")?
        .build();
    let relayer = Near::custom(RPC.to_string(), CHAIN_ID.to_string())
        .credentials(relayer_keyed.secret_key.as_str(), relayer_id.clone())
        .context("relayer credentials")?
        .build();

    for round in 0..4u32 {
        let outcome = user
            .transaction(id.clone())
            .call("bump")
            .gas(Gas::from_tgas(10))
            .finish()
            .call("put")
            .args(serde_json::json!({
                "key": format!("note-{round}"),
                "value": "y".repeat(24 + 16 * round as usize),
            }))
            .gas(Gas::from_tgas(10))
            .finish()
            .wait_until::<Final>()
            .await?;
        if !outcome.is_success() {
            bail!("contract use {round} failed: {:?}", outcome.status);
        }
        println!("contract use {}", outcome.transaction_hash());

        let outcome = user
            .transaction(relayer_id.clone())
            .transfer(NearToken::from_millinear(3 + u128::from(round)))
            .wait_until::<Final>()
            .await?;
        if !outcome.is_success() {
            bail!("transfer out {round} failed: {:?}", outcome.status);
        }
        println!("sent         {}", outcome.transaction_hash());

        let outcome = relayer
            .transaction(id.clone())
            .transfer(NearToken::from_millinear(5 + 2 * u128::from(round)))
            .wait_until::<Final>()
            .await?;
        if !outcome.is_success() {
            bail!("transfer in {round} failed: {:?}", outcome.status);
        }
        println!("received     {}", outcome.transaction_hash());
    }
    println!();
    println!("12 more transactions on {id}");
    Ok(())
}

/// The phrase-holder's door into fixed mode, entirely local.
fn keyfile(account: &str, phrase: &str) -> Result<()> {
    let id: AccountId = account.parse()?;
    let secret = SecretKey::from_seed_phrase(phrase)
        .map_err(|e| anyhow::anyhow!("deriving from the seed phrase: {e}"))?;
    std::fs::create_dir_all(".thine")?;
    std::fs::write(
        ".thine/user-testnet.json",
        serde_json::to_vec_pretty(&Keyed {
            account_id: id.to_string(),
            secret_key: secret.to_string(),
        })?,
    )?;
    println!("key written to .thine/user-testnet.json; migrate with");
    println!("  thine-web --account {id}");
    println!("The phrase was used locally and sent nowhere.");
    Ok(())
}

async fn try_seed(account: &str, phrase: &str) -> Result<()> {
    let id: AccountId = account.parse()?;
    let secret = SecretKey::from_seed_phrase(phrase)
        .map_err(|e| anyhow::anyhow!("deriving from the seed phrase: {e}"))?;
    let user = Near::custom(RPC.to_string(), CHAIN_ID.to_string())
        .credentials(secret.to_string(), id.clone())
        .context("credentials")?
        .build();

    // One yoctoNEAR, from the account to itself: the smallest thing the
    // chain would accept from a key it still honours.
    let sent = user
        .transaction(id.clone())
        .transfer(NearToken::from_yoctonear(1))
        .wait_until::<Final>()
        .await;
    match sent {
        Ok(outcome) if outcome.is_success() => {
            println!(
                "the chain accepted a transaction signed with the phrase: {}",
                outcome.transaction_hash()
            );
        }
        Ok(outcome) => println!("the chain answered: {:?}", outcome.status),
        // The chain's own words, never paraphrased.
        Err(e) => println!("the chain refused it: {e:#}"),
    }
    Ok(())
}
