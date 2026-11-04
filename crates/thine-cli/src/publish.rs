//! Publishing the wallet contracts as global contracts, by code hash.

use anyhow::{Context, Result, bail};
use near_kit::{Near, protocol::PublishMode, transaction::Final};
use thine_core::{Variant, artifacts, near_of};

use crate::state::{PublishedContracts, Relayer};

pub async fn run(network: &str, state_dir: &std::path::Path, force: bool) -> Result<()> {
    if let Ok(existing) = PublishedContracts::load(state_dir, network) {
        if !force {
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

    let relayer = Relayer::load(state_dir, network)?;
    let near = match network {
        "testnet" => Near::testnet(),
        "mainnet" => Near::mainnet(),
        other => bail!("unknown network {other}"),
    }
    .credentials(&relayer.secret_key, relayer.account_id.clone())
    .context("relayer credentials are not usable")?
    .build();

    let account_id: near_kit::AccountId = relayer.account_id.parse()?;
    let before = near
        .account(account_id.clone())
        .await
        .with_context(|| format!("relayer {} not found on {network}", relayer.account_id))?
        .amount
        .as_yoctonear();

    let wallets = [Variant::NoSign, Variant::WebauthnP256];
    let required: u128 = wallets.iter().map(|v| v.publish_burn_yocto()).sum();

    println!("relayer  {} on {network}", relayer.account_id);
    println!("balance  {:.6} NEAR", near_of(before));
    println!(
        "needed   {:.6} NEAR, burned at ten times the ordinary storage rate and not refundable",
        near_of(required)
    );

    if before < required {
        bail!(
            "the relayer holds {:.6} NEAR but publishing needs {:.6}. On testnet, `thine faucet` \
             grants 10,000 NEAR per request.",
            near_of(before),
            near_of(required)
        );
    }

    let mut hashes = Vec::new();
    for variant in wallets {
        let code = artifacts::load(variant)?;
        let expected = artifacts::code_hash(variant)?;
        println!(
            "\npublishing {} ({} bytes, sha256 {})",
            variant.file_name(),
            code.len(),
            variant.sha256_hex()
        );

        let outcome = near
            .publish(code, PublishMode::Immutable)
            .wait_until::<Final>()
            .await
            .with_context(|| format!("publishing {}", variant.file_name()))?;

        if !outcome.is_success() {
            bail!(
                "publishing {} failed: {:?}",
                variant.file_name(),
                outcome.status
            );
        }

        let hash = near_kit::CryptoHash::from(expected);
        println!(
            "  code hash {hash}   {:.4} TGas",
            outcome.total_gas_used().as_gas() as f64 / 1e12
        );
        hashes.push(hash.to_string());
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

/// A timestamp good enough for a local record, without pulling in a date crate.
fn now_rfc3339() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Days since the Unix epoch, converted with the civil-from-days algorithm.
    let (days, rem) = ((secs / 86_400) as i64, secs % 86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = era * 400 + yoe + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_timestamp_is_a_plausible_rfc3339_instant() {
        let s = super::now_rfc3339();
        assert_eq!(s.len(), 20, "{s}");
        assert!(s.ends_with('Z'), "{s}");
        let year: i32 = s[..4].parse().expect("year");
        assert!((2026..2100).contains(&year), "{s}");
        assert_eq!(&s[4..5], "-");
        assert_eq!(&s[10..11], "T");
    }
}
