//! Thine check 2: what happens when the account being migrated already has
//! contract code and contract state.
//!
//! Step 1 of the Thine migration is a single receipt containing
//! `UseGlobalContract(wallet-no-sign)` plus a `FunctionCall` to `w_init`.
//! This test runs that receipt against three starting states.
//!
//! Run with:
//!
//! ```bash
//! cargo test -p thine-bench --test thine_migration_state -- --nocapture --test-threads=1
//! ```

use std::sync::LazyLock;

use defuse_wallet_sdk::{Gas, NearToken};
use near_kit::{
    AccountId, CryptoHash, Near,
    protocol::PublishMode,
    rpc::FinalExecutionOutcome,
    rpc::{BlockReference, Finality},
    signer::{InMemorySigner, SecretKey},
    transaction::Final,
};
use near_kit_sandbox::SandboxConfig;
use sha2::{Digest, Sha256};
use thine_core::{Variant, artifacts};

/// `1e19` yoctoNEAR per byte of storage staked.
const STORAGE_COST_PER_BYTE: u128 = 10_000_000_000_000_000_000;
const YOCTO_PER_NEAR: f64 = 1e24;

#[derive(Debug, Clone, Copy)]
struct Snapshot {
    storage_usage: u64,
    amount: u128,
    has_code: bool,
}

async fn snapshot(near: &Near, id: &AccountId) -> Snapshot {
    let v = near.account(id.clone()).await.expect("view_account failed");
    Snapshot {
        storage_usage: v.storage_usage,
        amount: v.amount.as_yoctonear(),
        has_code: !v.code_hash.is_zero(),
    }
}

/// Enumerate every data key still present on the account.
async fn state_keys(near: &Near, id: &AccountId) -> Vec<(String, usize)> {
    near.rpc()
        .view_state_all(id, b"", 0, BlockReference::Finality(Finality::Final))
        .await
        .expect("view_state failed")
        .into_values()
        .into_iter()
        .map(|item| {
            let key = if item.key.is_empty() {
                "<empty key b\"\">".to_string()
            } else {
                String::from_utf8(item.key.clone())
                    .unwrap_or_else(|_| format!("0x{}", hex_of(&item.key)))
            };
            (key, item.value.len())
        })
        .collect()
}

fn hex_of(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Create a funded sub-account of the sandbox root and return a client that
/// signs as it.
async fn fresh_account(root: &Near, label: &str) -> (AccountId, Near) {
    let secret = SecretKey::generate_ed25519();
    let public = secret.public_key();
    let id: AccountId = format!("{label}.{}", root.account_id())
        .parse()
        .expect("bad account id");

    root.transaction(id.clone())
        .create_account()
        .transfer(NearToken::from_near(50))
        .add_full_access_key(public)
        .wait_until::<Final>()
        .await
        .expect("create_account send failed")
        .result()
        .expect("create_account failed");

    let signer =
        InMemorySigner::new(id.clone(), secret.to_string()).expect("failed to build signer");
    (id.clone(), root.with_signer(signer))
}

/// Thine migration step 1: `UseGlobalContract` + `w_init`, one receipt.
async fn step1(client: &Near) -> FinalExecutionOutcome {
    client
        .deploy_from(CryptoHash::from(*WALLET_NO_SIGN_CODE_HASH))
        .add_action(
            near_kit::transaction::FunctionCall::new("w_init")
                .gas(Gas::from_tgas(10))
                .deposit(NearToken::from_yoctonear(1)),
        )
        .wait_until::<Final>()
        .await
        .expect("step 1 send failed")
}

fn print_snapshot(label: &str, s: Snapshot) {
    println!(
        "    {label:<28} storage_usage = {:>6} bytes  ({:.6} NEAR staked)  balance {:.6} NEAR  code: {}",
        s.storage_usage,
        (s.storage_usage as u128 * STORAGE_COST_PER_BYTE) as f64 / YOCTO_PER_NEAR,
        s.amount as f64 / YOCTO_PER_NEAR,
        if s.has_code { "yes" } else { "no" },
    );
}

fn delta(before: Snapshot, after: Snapshot) {
    let d = after.storage_usage as i64 - before.storage_usage as i64;
    let yocto = d.unsigned_abs() as u128 * STORAGE_COST_PER_BYTE;
    println!(
        "    {:<28} {d:+} bytes  ({}{:.6} NEAR)",
        "storage delta",
        if d < 0 { "-" } else { "+" },
        yocto as f64 / YOCTO_PER_NEAR
    );
}

async fn report_keys(near: &Near, id: &AccountId, label: &str) {
    let keys = state_keys(near, id).await;
    println!("    {label} ({} data keys):", keys.len());
    for (k, len) in &keys {
        println!("        {k:<24} {len} value bytes");
    }
}

#[tokio::test]
async fn migration_over_existing_contract_state() {
    let near = sandbox().await;

    // ===============================================================
    // Case 1: plain account, no contract.
    // ===============================================================
    println!("\n==================== CASE 1: plain account, no contract ====================");
    let (id1, c1) = fresh_account(&near, "case1").await;
    let before1 = snapshot(&near, &id1).await;
    print_snapshot("before step 1", before1);

    let out1 = step1(&c1).await;
    println!("    status: {:?}", out1.status);
    assert!(out1.is_success(), "case 1 should succeed");
    let after1 = snapshot(&near, &id1).await;
    print_snapshot("after step 1", after1);
    delta(before1, after1);
    report_keys(&near, &id1, "state after migration").await;
    // Baseline: an account carrying nothing but wallet state.
    let wallet_only_storage = after1.storage_usage;

    // ===============================================================
    // Case 2: ordinary near-sdk contract holding data, including b"STATE".
    // ===============================================================
    println!(
        "\n==================== CASE 2: ordinary near-sdk contract with data ===================="
    );
    let (id2, c2) = fresh_account(&near, "case2").await;
    let empty2 = snapshot(&near, &id2).await;
    print_snapshot("empty account", empty2);

    c2.deploy(PROBE_WASM.clone())
        .wait_until::<Final>()
        .await
        .expect("probe deploy send failed")
        .result()
        .expect("probe deploy failed");

    // `bump` mutates state, so near-sdk persists it under b"STATE".
    c2.transaction(id2.clone())
        .call("bump")
        .gas(Gas::from_tgas(10))
        .finish()
        .call("put")
        .args(serde_json::json!({ "key": "alpha", "value": "a".repeat(64) }))
        .gas(Gas::from_tgas(10))
        .finish()
        .call("put")
        .args(serde_json::json!({ "key": "beta", "value": "b".repeat(128) }))
        .gas(Gas::from_tgas(10))
        .finish()
        .call("put")
        .args(serde_json::json!({ "key": "gamma", "value": "c".repeat(256) }))
        .gas(Gas::from_tgas(10))
        .finish()
        .wait_until::<Final>()
        .await
        .expect("probe writes send failed")
        .result()
        .expect("probe writes failed");

    let before2 = snapshot(&near, &id2).await;
    print_snapshot("with probe code + data", before2);
    report_keys(&near, &id2, "state before migration").await;
    let probe_code_bytes = before2.storage_usage - empty2.storage_usage;

    let out2 = step1(&c2).await;
    println!("    status: {:?}", out2.status);
    assert!(
        out2.is_success(),
        "case 2: w_init should succeed over an ordinary contract's state"
    );
    let after2 = snapshot(&near, &id2).await;
    print_snapshot("after step 1", after2);
    delta(before2, after2);
    report_keys(&near, &id2, "state after migration").await;

    let orphaned = after2.storage_usage as i64 - wallet_only_storage as i64;
    println!("\n    --- case 2 storage accounting ---");
    println!(
        "    probe code + data added      {probe_code_bytes} bytes ({:.6} NEAR)",
        (probe_code_bytes as u128 * STORAGE_COST_PER_BYTE) as f64 / YOCTO_PER_NEAR
    );
    println!(
        "    wallet-only baseline         {wallet_only_storage} bytes ({:.6} NEAR)",
        (wallet_only_storage as u128 * STORAGE_COST_PER_BYTE) as f64 / YOCTO_PER_NEAR
    );
    println!(
        "    ORPHANED, still paid for     {orphaned} bytes ({:.6} NEAR)",
        (orphaned.unsigned_abs() as u128 * STORAGE_COST_PER_BYTE) as f64 / YOCTO_PER_NEAR
    );

    // ===============================================================
    // Case 3: contract that uses the empty storage key b"".
    // ===============================================================
    println!(
        "\n==================== CASE 3: contract using the empty key b\"\" ===================="
    );
    let (id3, c3) = fresh_account(&near, "case3").await;
    c3.deploy(PROBE_WASM.clone())
        .wait_until::<Final>()
        .await
        .expect("probe deploy send failed")
        .result()
        .expect("probe deploy failed");

    c3.transaction(id3.clone())
        .call("put_empty_key")
        .args(serde_json::json!({ "value": "squatting on the wallet state key" }))
        .gas(Gas::from_tgas(10))
        .finish()
        .wait_until::<Final>()
        .await
        .expect("put_empty_key send failed")
        .result()
        .expect("put_empty_key failed");

    let before3 = snapshot(&near, &id3).await;
    print_snapshot("with b\"\" occupied", before3);
    report_keys(&near, &id3, "state before migration").await;
    let probe_code_hash = near.account(id3.clone()).await.unwrap().code_hash;

    let out3 = step1(&c3).await;
    println!("    status: {:?}", out3.status);
    assert!(
        out3.is_failure(),
        "case 3: w_init must fail when b\"\" is already occupied"
    );
    println!("    failure: {:?}", out3.failure_message());

    // Does the failed w_init revert the UseGlobalContract from the same receipt?
    let after3 = snapshot(&near, &id3).await;
    print_snapshot("after failed step 1", after3);
    let code_hash_after = near.account(id3.clone()).await.unwrap().code_hash;
    println!("\n    --- case 3: did UseGlobalContract revert? ---");
    println!("    probe code hash before : {probe_code_hash}");
    println!("    code hash after        : {code_hash_after}");
    println!(
        "    wallet-no-sign hash    : {}",
        CryptoHash::from(*WALLET_NO_SIGN_CODE_HASH)
    );
    if code_hash_after == probe_code_hash {
        println!("    => REVERTED: the account still runs its original contract.");
    } else {
        println!(
            "    => NOT REVERTED: the account's code changed despite w_init failing. \
             A failed migration would leave wallet code with no wallet state."
        );
    }
    report_keys(&near, &id3, "state after failed migration").await;

    // Is the original contract still callable?
    let still_works = c3
        .transaction(id3.clone())
        .call("bump")
        .gas(Gas::from_tgas(10))
        .finish()
        .wait_until::<Final>()
        .await
        .map(|o| o.is_success())
        .unwrap_or(false);
    println!("    original contract still callable after failed step 1: {still_works}");
}

async fn sandbox() -> Near {
    let near = SandboxConfig::shared()
        .await
        .expect("failed to start sandbox")
        .client();

    near.publish(&**WALLET_NO_SIGN_WASM, PublishMode::Immutable)
        .into_future()
        .await
        .expect("failed to publish wallet-no-sign by code hash");

    near
}

static WALLET_NO_SIGN_WASM: LazyLock<Vec<u8>> =
    LazyLock::new(|| artifacts::load(Variant::NoSign).expect("no-sign artefact"));
static WALLET_NO_SIGN_CODE_HASH: LazyLock<[u8; 32]> =
    LazyLock::new(|| Sha256::digest(&*WALLET_NO_SIGN_WASM).into());
static PROBE_WASM: LazyLock<Vec<u8>> =
    LazyLock::new(|| artifacts::load(Variant::Probe).expect("probe artefact"));
