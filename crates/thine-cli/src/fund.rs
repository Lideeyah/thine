//! Accumulating enough testnet NEAR to publish the wallet contracts.
//!
//! Publishing both contracts burns 67.8768 NEAR and the burn is not
//! refundable. The testnet faucet grants **10 NEAR per request**, so this
//! cannot be done in one request: it takes eight, each into a fresh account,
//! swept into the relayer.
//!
//! NEAR's documentation publishes neither the grant nor any rate limit; it says
//! only "a small amount". Both figures here were measured.
//!
//! Sweeping is a plain transfer, not a `DeleteAccount` with a beneficiary.
//! Deleting would recover the last fraction of a NEAR as well, but Thine is a
//! tool whose whole purpose is being careful with irreversible account
//! operations, and it should not perform one casually on its own plumbing.
//! The dust left behind is a few thousandths of a NEAR per account.

use std::time::Instant;

use anyhow::{Context, Result, bail};
use near_kit::{AccountId, Near, NearToken, signer::SecretKey, transaction::Final};
use thine_core::{Variant, near_of};

use crate::state::Relayer;

const FAUCET: &str = "https://helper.testnet.near.org/account";

/// Left in each throwaway account: its storage stake plus transfer gas.
const DUST_RESERVE: NearToken = NearToken::from_millinear(10);

/// Headroom above the publication burn, for the publishing gas itself.
const MARGIN: NearToken = NearToken::from_millinear(500);

/// What publishing both contracts needs, with margin.
pub fn required() -> u128 {
    Variant::NoSign.publish_burn_yocto()
        + Variant::WebauthnP256.publish_burn_yocto()
        + MARGIN.as_yoctonear()
}

pub async fn run(state_dir: &std::path::Path, max_requests: usize) -> Result<()> {
    let relayer = Relayer::load(state_dir, "testnet")?;
    let relayer_id: AccountId = relayer.account_id.parse()?;
    let near = Near::testnet().build();

    let target = required();
    let started = Instant::now();
    let mut requests = 0usize;

    println!("relayer  {}", relayer.account_id);
    println!("target   {:.6} NEAR", near_of(target));
    println!(
        "faucet   10 NEAR per request, measured; NEAR documents no figure and no rate limit\n"
    );

    loop {
        let balance = near
            .account(relayer_id.clone())
            .await
            .with_context(|| format!("relayer {relayer_id} not found"))?
            .amount
            .as_yoctonear();

        println!(
            "[{:>2} requests] relayer holds {:.6} NEAR of {:.6}",
            requests,
            near_of(balance),
            near_of(target)
        );

        if balance >= target {
            println!(
                "\nfunded in {requests} faucet request{} and {:.1}s",
                if requests == 1 { "" } else { "s" },
                started.elapsed().as_secs_f64()
            );
            println!("Run `thine publish` next.");
            return Ok(());
        }

        if requests >= max_requests {
            bail!(
                "stopped after {max_requests} faucet requests with {:.6} NEAR of {:.6}. Raise \
                 --max-requests, or the faucet may be out of tokens.",
                near_of(balance),
                near_of(target)
            );
        }

        requests += 1;
        match sweep_one(&near, &relayer_id, requests).await {
            Ok(moved) => println!("            swept {:.6} NEAR in", near_of(moved)),
            Err(e) => println!("            request failed: {e}"),
        }
    }
}

/// Create one faucet account and move its balance to the relayer.
async fn sweep_one(near: &Near, relayer_id: &AccountId, n: usize) -> Result<u128> {
    let secret = SecretKey::generate_ed25519();
    let public = secret.public_key();
    let id = format!(
        "thine-fund-{n}-{:x}.testnet",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_millis()
    );

    let response = reqwest::Client::new()
        .post(FAUCET)
        .json(&serde_json::json!({
            "newAccountId": id,
            "newAccountPublicKey": public.to_string(),
        }))
        .send()
        .await
        .context("could not reach the testnet faucet")?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        bail!("faucet refused ({status}): {}", trim(&body));
    }

    let account_id: AccountId = id.parse()?;

    // Wait for the account to appear before trying to spend from it.
    let mut balance = 0u128;
    for _ in 0..12 {
        if let Ok(v) = near.account(account_id.clone()).await {
            if v.amount.as_yoctonear() > 0 {
                balance = v.amount.as_yoctonear();
                break;
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(1200)).await;
    }
    if balance == 0 {
        bail!("{account_id} never showed a balance");
    }

    let movable = balance.saturating_sub(DUST_RESERVE.as_yoctonear());
    if movable == 0 {
        bail!("{account_id} funded with only {:.6} NEAR", near_of(balance));
    }

    let signer = near_kit::signer::InMemorySigner::new(account_id.clone(), secret.to_string())
        .context("could not build a signer for the funding account")?;

    let outcome = near
        .with_signer(signer)
        .transaction(relayer_id.clone())
        .transfer(NearToken::from_yoctonear(movable))
        .wait_until::<Final>()
        .await
        .with_context(|| format!("sweeping {account_id} into {relayer_id}"))?;

    if !outcome.is_success() {
        bail!("sweep from {account_id} failed: {:?}", outcome.status);
    }

    Ok(movable)
}

fn trim(s: &str) -> String {
    s.chars().take(300).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_target_covers_the_measured_publication_burn() {
        // 30.850628 + 37.031503 NEAR of burn, measured in the sandbox against
        // the real mainnet bytes, plus gas headroom.
        let burn =
            Variant::NoSign.publish_burn_yocto() + Variant::WebauthnP256.publish_burn_yocto();
        assert!(required() > burn);
        assert!(near_of(required()) > 67.87 && near_of(required()) < 68.5);
    }

    #[test]
    fn seven_faucet_requests_in_total_are_enough_and_six_are_not() {
        // The faucet grants 10 NEAR. `thine faucet` keeps the first grant as
        // the relayer's own balance; every later request lands in a throwaway
        // account and is swept in, less the dust left behind.
        let grant = NearToken::from_near(10).as_yoctonear();
        let swept = grant - DUST_RESERVE.as_yoctonear();

        let total_after = |sweeps: u128| grant + sweeps * swept;

        assert!(
            total_after(5) < required(),
            "five sweeps, six requests in total, should not be enough"
        );
        assert!(
            total_after(6) >= required(),
            "six sweeps, seven requests in total, should be enough"
        );
    }
}
