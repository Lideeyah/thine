//! The whole migration, end to end, plus every refusal.
//!
//! This is the judge path: it runs against a local `near-sandbox`, needs no
//! funds, no wallet and no faucet, and takes well under a minute. It migrates
//! an account from full-access-key control to passkey control and then proves
//! the account still works, with no keys left.
//!
//! The passkey is a software P-256 key driven through NEAR's own
//! `MockWalletWebauthnSigner`, which produces real WebAuthn assertions
//! (`authenticator_data`, `client_data_json`, a P-256 signature over the
//! correct challenge). The contract verifies them exactly as it would verify a
//! hardware authenticator's; nothing about the on-chain path is mocked.
//!
//! ```bash
//! cargo test -p thine-bench --test thine_migration_e2e -- --nocapture --test-threads=1
//! ```

use std::sync::LazyLock;

use defuse_wallet_sdk::{Gas, NearToken, WalletBuilder};
use defuse_wallet_webauthn::{
    crypto::p256::p256::{ecdsa::SigningKey, elliptic_curve::Generate},
    mock::MockWalletWebauthnSigner,
    p256::P256,
    webauthn::IgnoreUserVerification,
};
use near_kit::{
    AccountId, CryptoHash, Near,
    protocol::PublishMode,
    signer::{InMemorySigner, SecretKey},
    transaction::Final,
};
use near_kit_sandbox::SandboxConfig;
use rand::{rand_core::UnwrapErr, rngs::SysRng};
use sha2::{Digest, Sha256};
use thine_core::{
    Chain, ProofLedger, Variant,
    artifacts,
    authority::{HolderKind, HolderStatus, Refusal, Stage},
    migration::{Migration, PasskeyWallet},
    near_of,
};

type Signer = MockWalletWebauthnSigner<P256, IgnoreUserVerification, SigningKey>;

#[tokio::test]
async fn the_whole_migration_and_every_refusal() {
    let sandbox = SandboxConfig::shared()
        .await
        .expect("failed to start sandbox");
    let root = sandbox.client();

    for variant in [Variant::NoSign, Variant::WebauthnP256] {
        root.publish(artifacts::load(variant).unwrap(), PublishMode::Immutable)
            .into_future()
            .await
            .unwrap_or_else(|e| panic!("publishing {}: {e}", variant.file_name()));
    }
    let chain = Chain::with_client(root.clone(), "sandbox");

    // ===============================================================
    // Refusal 1: an account whose contract squats on the empty key
    // cannot be migrated, and nothing is sent.
    // ===============================================================
    println!("\n--- refusal 1: the empty storage key is occupied ---");
    let (blocked_id, blocked_client) = fresh_account(&root, "blocked").await;
    blocked_client
        .deploy(artifacts::load(Variant::Probe).unwrap())
        .wait_until::<Final>()
        .await
        .unwrap()
        .result()
        .unwrap();
    blocked_client
        .transaction(blocked_id.clone())
        .call("put_empty_key")
        .args(serde_json::json!({ "value": "squatting on the wallet state key" }))
        .gas(Gas::from_tgas(10))
        .finish()
        .wait_until::<Final>()
        .await
        .unwrap()
        .result()
        .unwrap();

    let blocked = migration(&chain, &blocked_id);
    let err = blocked
        .step1_become_wallet(&blocked_client)
        .await
        .expect_err("migrating over an occupied empty key must be refused");
    let refusal = err
        .downcast_ref::<Refusal>()
        .expect("should be a Refusal, not a generic error");
    assert!(
        matches!(refusal, Refusal::EmptyStateKeyOccupied { .. }),
        "got {refusal:?}"
    );
    println!("refused: {refusal}");
    // The account is untouched: still its own contract.
    assert!(
        chain
            .account_facts(&blocked_id)
            .await
            .unwrap()
            .has_code,
        "the blocked account should still carry its original contract"
    );

    // ===============================================================
    // The account we actually migrate.
    // ===============================================================
    let (user_id, user_client) = fresh_account(&root, "lydia").await;
    let m = migration(&chain, &user_id);
    let ledger_path = std::env::temp_dir().join(format!("thine-e2e-{}.json", std::process::id()));
    let mut ledger = ProofLedger::new(user_id.as_str());

    println!("\n=== migrating {user_id} ===");
    let before = chain.authority_view(&user_id, &ledger).await.unwrap();
    assert_eq!(before.stage, Stage::SeedControlled);
    assert!(before.has_full_access_key());
    assert!(!before.survives_key_deletion());
    println!("start: {:?}, {} holder(s)", before.stage, before.holders.len());

    // --- step 1 ---
    let s1 = m.step1_become_wallet(&user_client).await.expect("step 1");
    println!("step 1: {:.4} TGas, {:.6} NEAR", s1.tgas(), near_of(s1.near_burnt));
    let v = chain.authority_view(&user_id, &ledger).await.unwrap();
    assert_eq!(v.stage, Stage::WalletDeployed);
    assert!(
        v.holders
            .iter()
            .any(|h| matches!(h.kind, HolderKind::SelfExtension)),
        "the account should now be its own extension"
    );
    assert!(
        !chain.signature_allowed(&user_id).await.unwrap(),
        "w_init must disable signatures"
    );

    // ===============================================================
    // Refusal 2: an extension that is not a live wallet is refused.
    // ===============================================================
    println!("\n--- refusal 2: the extension is not a live wallet ---");
    let ghost: AccountId = "0sdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef".parse().unwrap();
    let err = m
        .step3_add_extension(&user_client, &ghost)
        .await
        .expect_err("adding an unreachable extension must be refused");
    let refusal = err.downcast_ref::<Refusal>().expect("should be a Refusal");
    assert!(
        matches!(refusal, Refusal::ExtensionNotLive { .. }),
        "got {refusal:?}"
    );
    println!("refused: {refusal}");
    assert!(
        !chain
            .wallet_extensions(&user_id)
            .await
            .unwrap()
            .contains(&ghost),
        "the ghost must not have been added"
    );

    // ===============================================================
    // Steps 2 and 3, twice.
    // ===============================================================
    let passkey_a = passkey_wallet(&root, &m);
    let passkey_b = passkey_wallet(&root, &m);
    println!("\npasskey A derives to {}", passkey_a.real_account_id());
    println!("passkey B derives to {}", passkey_b.real_account_id());

    for (label, wallet) in [("A", &passkey_a), ("B", &passkey_b)] {
        let account = m.step2_create_passkey_wallet(wallet).await.expect("step 2");
        let facts = chain.account_facts(&account).await.unwrap();
        println!(
            "step 2{label}: {account} exists, {} bytes of storage",
            facts.storage_usage
        );
        assert!(facts.storage_usage <= 770, "must stay a zero-balance account");

        let s3 = m
            .step3_add_extension(&user_client, &account)
            .await
            .expect("step 3");
        println!("step 3{label}: {:.4} TGas", s3.tgas());
        for l in &s3.logs {
            println!("        log: {l}");
        }
        println!(
            "        extensions now: {:?}",
            chain.wallet_extensions(&user_id).await.unwrap()
        );
    }

    // ===============================================================
    // Refusal 3: key deletion with passkeys added but not proven.
    // This is the gap the contract leaves open. The extension set is
    // non-empty and both entries are live, so the contract is satisfied.
    // ===============================================================
    println!("\n--- refusal 3: two passkeys added, neither has signed ---");
    let v = chain.authority_view(&user_id, &ledger).await.unwrap();
    assert_eq!(v.stage, Stage::PasskeysAdded { added: 2, proven: 0 });
    assert_eq!(v.passkeys().count(), 2, "both are present");
    assert_eq!(v.independent_proven_count(), 0, "neither has signed");
    assert!(v.passkeys().all(|h| h.status == HolderStatus::Live));

    let err = m
        .step5_finalise(&user_client, &ledger)
        .await
        .expect_err("key deletion with no proofs must be refused");
    let refusal = err.downcast_ref::<Refusal>().expect("should be a Refusal");
    assert!(
        matches!(
            refusal,
            Refusal::NotEnoughProvenPasskeys { proven: 0, required: 2, .. }
        ),
        "got {refusal:?}"
    );
    println!("refused: {refusal}");
    assert_eq!(
        chain.full_access_keys(&user_id).await.unwrap().len(),
        1,
        "the key must still be there"
    );

    // --- step 4, passkey A only ---
    let relayer: AccountId = root.account_id().to_owned();
    let (s4a, proof_a) = m
        .step4_prove_passkey(&passkey_a, &relayer)
        .await
        .expect("step 4A");
    println!("\nstep 4A: {:.4} TGas, tx {}", s4a.tgas(), s4a.tx_hash);
    ledger.record(proof_a);
    ledger.save(&ledger_path).unwrap();

    // ===============================================================
    // Refusal 3b: one proven passkey is still not enough.
    // ===============================================================
    println!("\n--- refusal 3b: one passkey proven, two required ---");
    let v = chain.authority_view(&user_id, &ledger).await.unwrap();
    assert_eq!(v.independent_proven_count(), 1, "A is proven, B is not");
    let err = m
        .step5_finalise(&user_client, &ledger)
        .await
        .expect_err("one proven passkey must be refused");
    let refusal = err.downcast_ref::<Refusal>().expect("should be a Refusal");
    assert!(
        matches!(
            refusal,
            Refusal::NotEnoughProvenPasskeys { proven: 1, required: 2, .. }
        ),
        "got {refusal:?}"
    );
    println!("refused: {refusal}");

    // --- step 4, passkey B ---
    let (s4b, proof_b) = m
        .step4_prove_passkey(&passkey_b, &relayer)
        .await
        .expect("step 4B");
    println!("step 4B: {:.4} TGas, tx {}", s4b.tgas(), s4b.tx_hash);
    ledger.record(proof_b);
    ledger.save(&ledger_path).unwrap();

    // ===============================================================
    // Step 5. Irreversible.
    // ===============================================================
    let v = chain.authority_view(&user_id, &ledger).await.unwrap();
    assert_eq!(v.independent_proven_count(), 2);
    assert!(v.survives_key_deletion(), "both passkeys have proven");
    v.guard_key_deletion().expect("the gate should now open");

    println!("\n--- step 5: irreversible ---");
    let outcomes = m
        .step5_finalise(&user_client, &ledger)
        .await
        .expect("step 5");
    for o in &outcomes {
        println!("  {}: {:.4} TGas", o.step, o.tgas());
    }

    // ===============================================================
    // What is true afterwards.
    // ===============================================================
    assert!(
        chain.full_access_keys(&user_id).await.unwrap().is_empty(),
        "no full access keys may remain"
    );
    let after = chain.authority_view(&user_id, &ledger).await.unwrap();
    println!("\nend: {:?}", after.stage);
    assert_eq!(after.stage, Stage::PasskeyControlled { proven: 2 });
    assert!(!after.has_full_access_key());
    assert_eq!(after.independent_proven_count(), 2);
    assert!(
        after.unreachable().count() == 0,
        "nothing unreachable should be left behind"
    );

    // The account id never changed, and the account still works: the passkey
    // can still drive it with no keys left anywhere.
    assert_eq!(after.account_id, user_id.to_string());
    let (post, _) = m
        .step4_prove_passkey(&passkey_a, &relayer)
        .await
        .expect("the passkey must still drive the account after migration");
    println!(
        "after migration, passkey A still drives {user_id}: {:.4} TGas, tx {}",
        post.tgas(),
        post.tx_hash
    );

    std::fs::remove_file(&ledger_path).ok();
}

fn migration(chain: &Chain, user: &AccountId) -> Migration {
    Migration::new(
        chain.clone(),
        user.clone(),
        CryptoHash::from(*NO_SIGN_HASH),
        *P256_HASH,
    )
}

fn passkey_wallet(relayer: &Near, m: &Migration) -> PasskeyWallet {
    WalletBuilder::new()
        .build(
            m.p256_code_hash(),
            Signer::new(SigningKey::generate_from_rng(&mut UnwrapErr(SysRng))),
        )
        .with_client(relayer.clone())
        .with_relayer(relayer.clone())
}

/// A funded account with one full access key: an ordinary, seed-phrase-style
/// NEAR account, which is what Thine migrates.
async fn fresh_account(root: &Near, label: &str) -> (AccountId, Near) {
    let secret = SecretKey::generate_ed25519();
    let id: AccountId = format!("{label}.{}", root.account_id()).parse().unwrap();

    root.transaction(id.clone())
        .create_account()
        .transfer(NearToken::from_near(20))
        .add_full_access_key(secret.public_key())
        .wait_until::<Final>()
        .await
        .unwrap()
        .result()
        .unwrap();

    let signer = InMemorySigner::new(id.clone(), secret.to_string()).unwrap();
    (id.clone(), root.with_signer(signer))
}

static NO_SIGN_HASH: LazyLock<[u8; 32]> =
    LazyLock::new(|| Sha256::digest(artifacts::load(Variant::NoSign).unwrap()).into());
static P256_HASH: LazyLock<[u8; 32]> =
    LazyLock::new(|| Sha256::digest(artifacts::load(Variant::WebauthnP256).unwrap()).into());
