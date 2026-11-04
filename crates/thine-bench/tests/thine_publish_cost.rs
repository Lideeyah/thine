//! Thine check 3 (cost half): measure what publishing the two wallet WASMs as
//! global contracts by code hash actually burns.
//!
//! Uses the exact bytes deployed on NEAR mainnet, fetched with
//! `view_global_contract_code_by_account_id` and committed under `res/`, so
//! the measured cost is the cost for the real artefacts rather than for a
//! local rebuild.
//!
//! ```bash
//! cargo test -p thine-bench --test thine_publish_cost -- --nocapture --test-threads=1
//! ```

use std::sync::LazyLock;

use near_kit::{protocol::PublishMode, transaction::Final};
use near_kit_sandbox::SandboxConfig;
use sha2::{Digest, Sha256};
use thine_core::{Variant, artifacts};

const YOCTO_PER_NEAR: f64 = 1e24;
/// Ordinary storage staking rate: 1e19 yoctoNEAR per byte.
const STORAGE_COST_PER_BYTE: u128 = 10_000_000_000_000_000_000;

#[tokio::test]
async fn publish_cost_by_code_hash() {
    let near = SandboxConfig::shared()
        .await
        .expect("failed to start sandbox")
        .client();
    let me = near.account_id().to_owned();

    for (name, wasm) in [
        ("wallet-no-sign", &*NO_SIGN),
        ("wallet-webauthn-p256", &*P256),
    ] {
        let size = wasm.len();
        let hash: [u8; 32] = Sha256::digest(wasm).into();
        let before = near
            .account(me.clone())
            .await
            .unwrap()
            .amount
            .as_yoctonear();

        let out = near
            .publish(wasm.clone(), PublishMode::Immutable)
            .wait_until::<Final>()
            .await
            .expect("publish send failed");
        assert!(out.is_success(), "publish failed: {:?}", out.status);

        let after = near
            .account(me.clone())
            .await
            .unwrap()
            .amount
            .as_yoctonear();
        let spent = before - after;
        let gas = out.total_gas_used().as_gas();
        let tokens_for_gas: u128 = out.transaction_outcome.outcome.tokens_burnt.as_yoctonear()
            + out
                .receipts_outcome
                .iter()
                .map(|r| r.outcome.tokens_burnt.as_yoctonear())
                .sum::<u128>();
        // NEP-591: publishing burns storage at 10x the ordinary rate. The
        // burn is levied as part of `tokens_burnt`, not as refundable storage
        // stake, so the account's storage_usage does not grow and the NEAR is
        // gone for good.
        let expected_burn = size as u128 * STORAGE_COST_PER_BYTE * 10;

        println!("\n=============== publish {name} ===============");
        println!("  wasm size             : {size} bytes");
        println!("  sha256                : {}", hex_of(&hash));
        println!("  gas burnt             : {:.4} TGas", gas as f64 / 1e12);
        println!(
            "  TOTAL BALANCE SPENT   : {:.6} NEAR  (not refundable)",
            spent as f64 / YOCTO_PER_NEAR
        );
        println!(
            "  reported tokens_burnt : {:.6} NEAR",
            tokens_for_gas as f64 / YOCTO_PER_NEAR
        );
        println!(
            "  predicted 10x burn    : {:.6} NEAR   (size x 1e20 yocto/byte)",
            expected_burn as f64 / YOCTO_PER_NEAR
        );
        println!(
            "  spent - predicted     : {:.6} NEAR   (ordinary tx gas)",
            (spent as f64 - expected_burn as f64) / YOCTO_PER_NEAR
        );
        println!(
            "  ordinary 1x rate      : {:.6} NEAR   => effective multiplier {:.3}x",
            (size as u128 * STORAGE_COST_PER_BYTE) as f64 / YOCTO_PER_NEAR,
            spent as f64 / (size as u128 * STORAGE_COST_PER_BYTE) as f64
        );
        let storage_after = near.account(me.clone()).await.unwrap().storage_usage;
        println!("  publisher storage_usage after: {storage_after} bytes");
    }
}

fn hex_of(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

static NO_SIGN: LazyLock<Vec<u8>> =
    LazyLock::new(|| artifacts::load(Variant::NoSign).expect("no-sign artefact"));
static P256: LazyLock<Vec<u8>> =
    LazyLock::new(|| artifacts::load(Variant::WebauthnP256).expect("p256 artefact"));
