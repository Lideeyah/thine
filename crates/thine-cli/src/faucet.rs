//! Getting a funded relayer on testnet.
//!
//! NEAR's documentation does not publish what the faucet gives or whether it is
//! rate limited; it says only "a small amount". Measured on 4 November 2026 it
//! creates and funds an account with **10 NEAR** per request, in about three
//! seconds, with no rate limit observed across consecutive requests.
//!
//! Publishing both wallet contracts burns 67.8768 NEAR, so one request is
//! nowhere near enough and balances have to be consolidated. `thine fund` does
//! that; this command only establishes the relayer.

use anyhow::{Context, Result, bail};
use near_kit::{Near, signer::SecretKey};
use thine_core::near_of;

use crate::state::Relayer;

/// The account-creation endpoint NEAR's own tooling uses.
const FAUCET: &str = "https://helper.testnet.near.org/account";

pub async fn run(prefix: &str, state_dir: &std::path::Path) -> Result<()> {
    let secret = SecretKey::generate_ed25519();
    let public = secret.public_key();
    let account_id = format!(
        "{prefix}-{:x}.testnet",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_millis()
    );

    println!("requesting {account_id} from the testnet faucet");

    let response = reqwest::Client::new()
        .post(FAUCET)
        .json(&serde_json::json!({
            "newAccountId": account_id,
            "newAccountPublicKey": public.to_string(),
        }))
        .send()
        .await
        .context("could not reach the testnet faucet")?;

    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    if !status.is_success() {
        bail!(
            "the faucet refused the request ({status}): {}\n\nThe faucet is sometimes out of \
             tokens. Try again, or fund an account yourself and write it to {}",
            body.chars().take(400).collect::<String>(),
            Relayer::path(state_dir, "testnet").display()
        );
    }

    let relayer = Relayer {
        network: "testnet".to_string(),
        account_id: account_id.clone(),
        secret_key: secret.to_string(),
    };
    relayer.save(state_dir)?;

    // Confirm against the chain rather than trusting the faucet's 200.
    let near = Near::testnet().build();
    let mut balance = 0u128;
    for _ in 0..10 {
        if let Ok(view) = near.account(account_id.clone()).await {
            balance = view.amount.as_yoctonear();
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
    }
    if balance == 0 {
        bail!(
            "the faucet accepted the request but {account_id} has no balance yet. Check it with \
             `thine inspect {account_id}` before publishing."
        );
    }

    println!("\nrelayer   {account_id}");
    println!("balance   {:.4} NEAR", near_of(balance));
    println!("saved to  {}", Relayer::path(state_dir, "testnet").display());
    println!("\nThat file holds a private key. It is gitignored; keep it that way.");

    let needed = thine_core::Variant::NoSign.publish_burn_yocto()
        + thine_core::Variant::WebauthnP256.publish_burn_yocto();
    println!(
        "\nPublishing both contracts burns {:.6} NEAR, and the faucet grants 10 NEAR a request,",
        near_of(needed)
    );
    println!("so run `thine fund` next to top this account up.");
    Ok(())
}
