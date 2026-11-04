//! Thine check 1: measure the gas cost of the P-256 (WebAuthn passkey)
//! execution hop on a `wallet-webauthn-p256` wallet contract.
//!
//! Run with:
//!
//! ```bash
//! cargo test -p thine-bench --test thine_p256_gas -- --nocapture --test-threads=1
//! ```
//!
//! The contract artefacts are committed under `res/` and digest-checked on
//! load, so nothing needs building. A running Docker daemon is required,
//! because `near-kit-sandbox` runs `neard` in a container.

use std::{collections::BTreeMap, sync::LazyLock};

use defuse_wallet_sdk::{
    Gas, NearPromise, NearToken, Request, Wallet, WalletBuilder, WalletOp, actions::FunctionCall,
    client::WalletContract,
};
use defuse_wallet_webauthn::{
    WalletWebauthn,
    crypto::p256::p256::{ecdsa::SigningKey, elliptic_curve::Generate},
    mock::MockWalletWebauthnSigner,
    p256::P256,
    webauthn::IgnoreUserVerification,
};
use near_kit::{
    CryptoHash, Near, protocol::PublishMode, rpc::FinalExecutionOutcome, transaction::Final,
};
use near_kit_sandbox::SandboxConfig;
use rand::{rand_core::UnwrapErr, rngs::SysRng};
use sha2::{Digest, Sha256};
use thine_core::{Variant, artifacts};

type P256Schema = WalletWebauthn<P256, IgnoreUserVerification>;
type P256Wallet = Wallet<P256Schema>;
type P256Signer = MockWalletWebauthnSigner<P256, IgnoreUserVerification, SigningKey>;

const TGAS: f64 = 1_000_000_000_000.0;
const YOCTO_PER_NEAR: f64 = 1e24;

/// One receipt's contribution, flattened for reporting.
struct ReceiptRow {
    index: usize,
    executor: String,
    gas: u64,
    tokens: u128,
    /// `true` when the receipt carries no gas profile, which is how NEAR's
    /// system-generated gas refund receipts appear.
    is_refund: bool,
    profile: BTreeMap<String, u64>,
}

fn rows(out: &FinalExecutionOutcome) -> Vec<ReceiptRow> {
    out.receipts_outcome
        .iter()
        .enumerate()
        .map(|(index, r)| {
            let profile: BTreeMap<String, u64> = r
                .outcome
                .metadata
                .as_ref()
                .and_then(|m| m.gas_profile.as_ref())
                .map(|entries| {
                    entries
                        .iter()
                        .map(|e| (e.cost.clone(), e.gas_used.as_gas()))
                        .collect()
                })
                .unwrap_or_default();

            ReceiptRow {
                index,
                executor: r.outcome.executor_id.to_string(),
                gas: r.outcome.gas_burnt.as_gas(),
                tokens: r.outcome.tokens_burnt.as_yoctonear(),
                is_refund: profile.is_empty() && r.outcome.logs.is_empty(),
                profile,
            }
        })
        .collect()
}

/// Print a full gas breakdown for one measured transaction.
fn report(label: &str, out: &FinalExecutionOutcome) {
    let conv_gas = out.transaction_outcome.outcome.gas_burnt.as_gas();
    let conv_tokens = out.transaction_outcome.outcome.tokens_burnt.as_yoctonear();
    let receipts = rows(out);

    let total_gas = conv_gas + receipts.iter().map(|r| r.gas).sum::<u64>();
    let total_tokens = conv_tokens + receipts.iter().map(|r| r.tokens).sum::<u128>();
    let refund_gas: u64 = receipts.iter().filter(|r| r.is_refund).map(|r| r.gas).sum();

    println!("\n================ {label} ================");
    println!("status: {:?}", out.status);
    println!(
        "transaction conversion : {:>8.4} TGas  ({} gas)  {:.9} NEAR",
        conv_gas as f64 / TGAS,
        conv_gas,
        conv_tokens as f64 / YOCTO_PER_NEAR
    );
    println!("receipts: {}", receipts.len());

    for r in &receipts {
        println!(
            "  [{}] {:<46} {:>8.4} TGas  {:.9} NEAR{}",
            r.index,
            r.executor,
            r.gas as f64 / TGAS,
            r.tokens as f64 / YOCTO_PER_NEAR,
            if r.is_refund { "   <- refund" } else { "" }
        );
        if !r.profile.is_empty() {
            // Largest cost categories first; these are the per-receipt
            // breakdown (signature verification, JSON parsing, promise
            // construction all land in distinct cost names).
            let mut entries: Vec<_> = r.profile.iter().collect();
            entries.sort_by(|a, b| b.1.cmp(a.1));
            for (cost, gas) in entries.iter().take(12) {
                println!(
                    "        {:<34} {:>8.4} TGas  ({})",
                    cost,
                    **gas as f64 / TGAS,
                    gas
                );
            }
            let profiled: u64 = r.profile.values().sum();
            println!(
                "        {:<34} {:>8.4} TGas  (profiled subtotal)",
                "--",
                profiled as f64 / TGAS
            );
        }
    }

    println!(
        "TOTAL                  : {:>8.4} TGas   {:.9} NEAR   (refunds {:.4} TGas)",
        total_gas as f64 / TGAS,
        total_tokens as f64 / YOCTO_PER_NEAR,
        refund_gas as f64 / TGAS
    );
    println!(
        "JSON {}",
        serde_json::json!({
            "label": label,
            "conversion_gas": conv_gas,
            "total_gas": total_gas,
            "total_tgas": total_gas as f64 / TGAS,
            "total_near_burnt": total_tokens as f64 / YOCTO_PER_NEAR,
            "receipt_count": receipts.len(),
            "refund_gas": refund_gas,
            "receipts": receipts.iter().map(|r| serde_json::json!({
                "executor": r.executor,
                "gas": r.gas,
                "tgas": r.gas as f64 / TGAS,
                "is_refund": r.is_refund,
                "profile": r.profile,
            })).collect::<Vec<_>>(),
        })
    );
}

fn p256_wallet(near: &Near) -> P256Wallet {
    WalletBuilder::new()
        .build(
            *WALLET_P256_CODE_HASH,
            P256Signer::new(SigningKey::generate_from_rng(&mut UnwrapErr(SysRng))),
        )
        .with_client(near.clone())
        .with_relayer(near.clone())
}

#[tokio::test]
async fn p256_execution_hop_gas() {
    let near = sandbox().await;

    // ---------------------------------------------------------------
    // Setup: the user's own account becomes a `wallet-no-sign` wallet,
    // which is step 1 of the Thine migration.
    // ---------------------------------------------------------------
    let user = near.account_id().to_owned();

    let init = near
        .deploy_from(CryptoHash::from(*WALLET_NO_SIGN_CODE_HASH))
        .add_action(
            near_kit::transaction::FunctionCall::new("w_init")
                .gas(Gas::from_tgas(5))
                .deposit(NearToken::from_yoctonear(1)),
        )
        .wait_until::<Final>()
        .await
        .unwrap();
    assert!(init.is_success(), "w_init failed: {:?}", init.status);
    report("setup: UseGlobalContract(no-sign) + w_init", &init);

    // The passkey wallet, and a second account used only as the target of
    // the outgoing promise.
    let passkey = p256_wallet(&near);
    let target = p256_wallet(&near);

    println!("\nuser account    : {user}");
    println!("passkey 0s      : {}", passkey.real_account_id());
    println!("promise target  : {}", target.real_account_id());

    // ---------------------------------------------------------------
    // Measurement 0: creating the 0s passkey wallet (DeterministicStateInit
    // plus the first w_execute_signed carrying an empty request).
    // ---------------------------------------------------------------
    let state_init = passkey
        .sign_and_send(Request::new())
        .await
        .unwrap()
        .status(&near)
        .wait_until::<Final>()
        .await
        .unwrap();
    assert!(
        state_init.is_success(),
        "state init failed: {:?}",
        state_init.status
    );
    report(
        "0: DeterministicStateInit + w_execute_signed (empty request)",
        &state_init,
    );
    passkey.initialize().await.unwrap();
    target.initialize().await.unwrap();

    // The outgoing promise used by both the one-hop and two-hop cases, so
    // the two numbers are directly comparable.
    let outgoing = || {
        NearPromise::new(target.real_account_id())
            .function_call(FunctionCall::name("w_subwallet_id").gas(Gas::from_tgas(5)))
    };

    // ---------------------------------------------------------------
    // Measurement 1 (one hop): w_execute_signed on the 0s passkey wallet
    // with one outgoing promise FunctionCall to a second account.
    // ---------------------------------------------------------------
    let one_hop = passkey
        .sign_and_send(outgoing())
        .await
        .unwrap()
        .status(&near)
        .wait_until::<Final>()
        .await
        .unwrap();
    assert!(one_hop.is_success(), "one hop failed: {:?}", one_hop.status);
    report(
        "1: ONE HOP  w_execute_signed(0s) -> FunctionCall(second account)",
        &one_hop,
    );

    // ---------------------------------------------------------------
    // Setup for two hops: authorise the passkey wallet as an extension of
    // the user's account (step 3 of the Thine migration).
    // ---------------------------------------------------------------
    let add_ext = near
        .contract::<WalletContract>(&user)
        .w_execute_extension(
            Request::new()
                .internal([WalletOp::AddExtension {
                    account_id: passkey.real_account_id().clone(),
                }])
                .into(),
        )
        .deposit(NearToken::from_yoctonear(1))
        .await
        .unwrap();
    assert!(
        add_ext.is_success(),
        "AddExtension failed: {:?}",
        add_ext.status
    );
    report("setup: AddExtension(passkey 0s)", &add_ext);

    // ---------------------------------------------------------------
    // Measurement 2 (two hops): w_execute_signed on the 0s wallet, a promise
    // to the user account's w_execute_extension, and a further promise out.
    // ---------------------------------------------------------------
    let two_hop = passkey
        .clone()
        .as_extension_of(user.clone())
        .sign_and_send(outgoing())
        .await
        .unwrap()
        .status(&near)
        .wait_until::<Final>()
        .await
        .unwrap();
    assert!(two_hop.is_success(), "two hop failed: {:?}", two_hop.status);
    report(
        "2: TWO HOP  w_execute_signed(0s) -> w_execute_extension(user) -> FunctionCall",
        &two_hop,
    );

    // Repeat both, to show the numbers are stable rather than one-off.
    for i in 0..2 {
        let o = passkey
            .sign_and_send(outgoing())
            .await
            .unwrap()
            .status(&near)
            .wait_until::<Final>()
            .await
            .unwrap();
        report(&format!("1r{i}: ONE HOP repeat"), &o);

        let t = passkey
            .clone()
            .as_extension_of(user.clone())
            .sign_and_send(outgoing())
            .await
            .unwrap()
            .status(&near)
            .wait_until::<Final>()
            .await
            .unwrap();
        report(&format!("2r{i}: TWO HOP repeat"), &t);
    }
}

async fn sandbox() -> Near {
    let near = SandboxConfig::shared()
        .await
        .expect("failed to start sandbox")
        .client();

    near.publish(&**WALLET_P256_WASM, PublishMode::Immutable)
        .into_future()
        .await
        .expect("failed to publish wallet-webauthn-p256 by code hash");
    near.publish(&**WALLET_NO_SIGN_WASM, PublishMode::Immutable)
        .into_future()
        .await
        .expect("failed to publish wallet-no-sign by code hash");

    near
}

static WALLET_P256_WASM: LazyLock<Vec<u8>> =
    LazyLock::new(|| artifacts::load(Variant::WebauthnP256).expect("p256 artefact"));
static WALLET_P256_CODE_HASH: LazyLock<[u8; 32]> =
    LazyLock::new(|| Sha256::digest(&*WALLET_P256_WASM).into());

static WALLET_NO_SIGN_WASM: LazyLock<Vec<u8>> =
    LazyLock::new(|| artifacts::load(Variant::NoSign).expect("no-sign artefact"));
static WALLET_NO_SIGN_CODE_HASH: LazyLock<[u8; 32]> =
    LazyLock::new(|| Sha256::digest(&*WALLET_NO_SIGN_WASM).into());
