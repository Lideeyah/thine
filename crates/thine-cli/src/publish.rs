//! Publishing the wallet contracts as global contracts, by code hash.
//!
//! This is the one irreversible, expensive thing Thine does to a network.
//! NEP-591 charges publication at ten times the ordinary storage rate, the burn
//! is not refundable, and on testnet the faucet grants 10 NEAR per request
//! against a ceiling of roughly ten requests a day. Publishing the pair costs
//! 67.88 NEAR, so **getting it wrong costs another 68 NEAR and another day.**
//!
//! So the bytes are checked before anything is sent, not after:
//!
//! 1. each artefact must match the SHA-256 recorded in the source, and
//! 2. it must be byte-for-byte identical to what NEAR mainnet currently serves.
//!
//! Both are hard refusals. A code hash reference is immutable, which is the
//! point of using one, and it also means a wrong byte cannot be corrected in
//! place: it can only be abandoned and paid for again.

use anyhow::{Context, Result, bail};
use near_kit::{Near, protocol::PublishMode, transaction::Final};
use thine_core::{Chain, Variant, artifacts, near_of, now_rfc3339};

use crate::state::{PublishedContracts, Relayer};

/// The contracts Thine publishes, in order.
const WALLETS: [Variant; 2] = [Variant::NoSign, Variant::WebauthnP256];

/// One verified artefact, ready to publish.
struct Checked {
    variant: Variant,
    code: Vec<u8>,
    code_hash: near_kit::CryptoHash,
}

/// Check every artefact against its recorded digest and against mainnet.
///
/// Returns the bytes only if both hold for all of them, so a partial failure
/// cannot leave one contract published and the other not.
async fn check_bytes(verify_against_mainnet: bool) -> Result<Vec<Checked>> {
    let mainnet = Chain::mainnet();
    let mut checked = Vec::new();

    for variant in WALLETS {
        // 1. The committed artefact is what the source says it is. `load`
        //    fails on a digest mismatch rather than returning the bytes.
        let code = artifacts::load(variant)?;
        let code_hash = near_kit::CryptoHash::from(artifacts::code_hash(variant)?);
        println!(
            "  {} — {} bytes, sha256 {}",
            variant.file_name(),
            code.len(),
            variant.sha256_hex()
        );
        println!("      digest matches the recorded value");

        // 2. The bytes are what the live network runs.
        if verify_against_mainnet {
            let reference = variant
                .mainnet_reference()
                .ok_or_else(|| anyhow::anyhow!("{} has no mainnet reference", variant.file_name()))?
                .parse()
                .context("mainnet reference is not an account id")?;

            let live = mainnet
                .global_contract_code(&reference)
                .await
                .context("could not read the reference contract from mainnet")?;

            if live != code {
                bail!(
                    "refusing to publish {}: the committed artefact is not what mainnet serves.\n\
                     \x20 mainnet ({reference}): {} bytes\n\
                     \x20 committed:            {} bytes\n\
                     Publishing is irreversible and costs {:.2} NEAR, so this is a hard stop. \
                     Re-fetch the artefact before trying again.",
                    variant.file_name(),
                    live.len(),
                    code.len(),
                    near_of(variant.publish_burn_yocto())
                );
            }
            println!("      identical to what mainnet serves from {reference}");
        }

        checked.push(Checked {
            variant,
            code,
            code_hash,
        });
    }

    Ok(checked)
}

pub async fn run(
    network: &str,
    state_dir: &std::path::Path,
    force: bool,
    dry_run: bool,
    skip_mainnet_check: bool,
) -> Result<()> {
    if let Ok(existing) = PublishedContracts::load(state_dir, network) {
        if !force && !dry_run {
            println!("already published on {network}:");
            println!("  wallet-no-sign        {}", existing.no_sign);
            println!("  wallet-webauthn-p256  {}", existing.webauthn_p256);
            println!(
                "\nPublished by {} on {}. Burned {:.6} NEAR.",
                existing.published_by,
                existing.published_at,
                near_of(existing.burned_yocto)
            );
            println!(
                "\nA code hash reference is immutable, so republishing the same bytes would \
                 produce the same hash and burn the NEAR again for nothing. Pass --force only if \
                 you know the record is wrong."
            );
            return Ok(());
        }
    }

    println!("checking the bytes before anything is sent");
    if skip_mainnet_check {
        println!("  WARNING: --skip-mainnet-check given; only local digests are checked");
    }
    let checked = check_bytes(!skip_mainnet_check).await?;

    let required: u128 = checked
        .iter()
        .map(|c| c.variant.publish_burn_yocto())
        .sum();

    // Dry run stops here, having done every check and sent nothing.
    if dry_run {
        println!("\n--- dry run, nothing sent ---");
        println!("would publish {} contracts on {network}:", checked.len());
        for c in &checked {
            println!(
                "  {}  ->  code hash {}  ({:.6} NEAR)",
                c.variant.file_name(),
                c.code_hash,
                near_of(c.variant.publish_burn_yocto())
            );
        }
        println!("total burn {:.6} NEAR, not refundable", near_of(required));

        match Relayer::load(state_dir, network) {
            Ok(relayer) => {
                let near = client(network, &relayer)?;
                let id: near_kit::AccountId = relayer.account_id.parse()?;
                let balance = near.account(id).await?.amount.as_yoctonear();
                println!(
                    "relayer {} holds {:.6} NEAR",
                    relayer.account_id,
                    near_of(balance)
                );
                if balance < required {
                    println!(
                        "short by {:.6} NEAR. On testnet the faucet grants 10 NEAR a request; \
                         run `thine fund`.",
                        near_of(required - balance)
                    );
                } else {
                    println!("enough to publish. Re-run without --dry-run to send it.");
                }
            }
            Err(e) => println!("no relayer yet: {e}"),
        }
        return Ok(());
    }

    let relayer = Relayer::load(state_dir, network)?;
    let near = client(network, &relayer)?;
    let account_id: near_kit::AccountId = relayer.account_id.parse()?;
    let before = near
        .account(account_id.clone())
        .await
        .with_context(|| format!("relayer {} not found on {network}", relayer.account_id))?
        .amount
        .as_yoctonear();

    println!("\nrelayer  {} on {network}", relayer.account_id);
    println!("balance  {:.6} NEAR", near_of(before));
    println!(
        "needed   {:.6} NEAR, burned at ten times the ordinary storage rate and not refundable",
        near_of(required)
    );

    if before < required {
        bail!(
            "the relayer holds {:.6} NEAR but publishing needs {:.6}, short by {:.6}. On testnet \
             the faucet grants 10 NEAR a request against a ceiling of roughly ten a day; run \
             `thine fund`.",
            near_of(before),
            near_of(required),
            near_of(required - before)
        );
    }

    let mut hashes = Vec::new();
    for c in checked {
        println!("\npublishing {}", c.variant.file_name());
        let outcome = near
            .publish(c.code, PublishMode::Immutable)
            .wait_until::<Final>()
            .await
            .with_context(|| format!("publishing {}", c.variant.file_name()))?;

        if !outcome.is_success() {
            bail!(
                "publishing {} failed: {:?}",
                c.variant.file_name(),
                outcome.status
            );
        }

        println!(
            "  code hash {}   {:.4} TGas",
            c.code_hash,
            outcome.total_gas_used().as_gas() as f64 / 1e12
        );
        hashes.push(c.code_hash.to_string());
    }

    let after = near.account(account_id).await?.amount.as_yoctonear();
    let spent = before.saturating_sub(after);

    let record = PublishedContracts {
        network: network.to_string(),
        no_sign: hashes[0].clone(),
        webauthn_p256: hashes[1].clone(),
        published_by: relayer.account_id.clone(),
        published_at: now_rfc3339(),
        burned_yocto: spent,
    };
    record.save(state_dir)?;

    println!("\nspent    {:.6} NEAR", near_of(spent));
    println!("left     {:.6} NEAR", near_of(after));
    println!(
        "recorded {}",
        PublishedContracts::path(state_dir, network).display()
    );
    Ok(())
}

fn client(network: &str, relayer: &Relayer) -> Result<Near> {
    Ok(match network {
        "testnet" => Near::testnet(),
        "mainnet" => Near::mainnet(),
        other => bail!("unknown network {other}"),
    }
    .credentials(&relayer.secret_key, relayer.account_id.clone())
    .context("relayer credentials are not usable")?
    .build())
}
