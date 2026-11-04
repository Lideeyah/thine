//! The migration driven the way a browser drives it.
//!
//! The local end-to-end test proves the chain works. This proves the *browser
//! path* works: the same migration, but every passkey signature goes through
//! exactly the conversions a real `navigator.credentials.get()` response needs
//! — a DER-encoded signature, a `clientDataJSON` document, base64url
//! `authenticatorData` — and nothing takes the shortcut of handing the SDK a
//! native signature.
//!
//! What stands in for the authenticator is a software P-256 key. That is the
//! only part that is not real, and it is the part a judge's own device replaces.
//! Everything downstream of it here is the production path: the assertion is
//! assembled as WebAuthn specifies, the signature is DER and deliberately
//! high-S half the time, and the proof is built by the same
//! `thine_core::webauthn` code a browser's bytes go through.
//!
//! ```bash
//! cargo test -p thine-bench --test thine_browser_passkey_e2e -- --nocapture --test-threads=1
//! ```

use std::sync::LazyLock;

use defuse_wallet_sdk::NearToken;
use defuse_wallet_webauthn::crypto::p256::p256::{
    ecdsa::{Signature, SigningKey, signature::Signer as _},
    elliptic_curve::{Generate, scalar::IsHigh},
};
use near_kit::{
    AccountId, CryptoHash, Near,
    protocol::PublishMode,
    signer::{InMemorySigner, SecretKey},
    transaction::Final,
};
use near_kit_sandbox::SandboxConfig;
use sha2::{Digest, Sha256};
use thine_core::{
    Chain, ProofLedger, Variant, artifacts,
    authority::Stage,
    migration::{Migration, SigningRoute},
    webauthn::{BrowserAssertion, challenge_for, compressed_public_key, proof_from_browser},
};

/// SHA-256 of the relying party id for `http://localhost`, as an authenticator
/// would put in `authenticatorData`.
const RP_ID_HASH: [u8; 32] =
    hex_literal::hex!("49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d9763");

/// A software stand-in for an authenticator, producing genuine WebAuthn
/// assertions in the exact encodings a browser hands over.
struct Authenticator {
    key: SigningKey,
    sign_count: u32,
    /// Whether to leave the signature high-S, which real authenticators are
    /// free to do and the contract rejects outright.
    emit_high_s: bool,
}

impl Authenticator {
    fn new(emit_high_s: bool) -> Self {
        Self {
            key: SigningKey::generate_from_rng(&mut rand::rng()),
            sign_count: 0,
            emit_high_s,
        }
    }

    /// The public key as `getPublicKey()` would report it: ES256 SPKI, whose
    /// trailing 65 bytes are the uncompressed point.
    fn spki_public_key(&self) -> Vec<u8> {
        let point = self.key.verifying_key().to_sec1_point(false);
        let mut spki = vec![0u8; 91 - 65];
        spki.extend_from_slice(point.as_bytes());
        spki
    }

    /// What `navigator.credentials.get({ challenge })` returns.
    fn get(&mut self, challenge: &[u8; 32]) -> BrowserAssertion {
        let authenticator_data = [
            RP_ID_HASH.as_slice(),
            // UP (user present) and UV (user verified), as a platform
            // authenticator with biometrics set up would report.
            &[0b0000_0101u8],
            &self.sign_count.to_be_bytes(),
        ]
        .concat();
        self.sign_count += 1;

        let client_data_json = format!(
            r#"{{"type":"webauthn.get","challenge":"{}","origin":"http://localhost","crossOrigin":false}}"#,
            challenge_for(challenge)
        );

        // WebAuthn: the authenticator signs authenticatorData concatenated with
        // SHA-256 of clientDataJSON.
        let signed_over = [
            authenticator_data.as_slice(),
            Sha256::digest(client_data_json.as_bytes()).as_ref(),
        ]
        .concat();

        let mut signature: Signature = self.key.sign(&signed_over);
        if self.emit_high_s && !bool::from(signature.s().is_high()) {
            // Flip to the other, equally valid, high-S form. A real
            // authenticator may hand this over and the contract will refuse it
            // unless it is normalised on the way in.
            signature =
                Signature::from_scalars(signature.r().to_bytes(), (-*signature.s()).to_bytes())
                    .unwrap();
        }

        BrowserAssertion {
            authenticator_data,
            client_data_json,
            // A browser returns DER, never raw r || s.
            signature_der: signature.to_der().as_bytes().to_vec(),
        }
    }
}

#[tokio::test]
async fn the_migration_driven_entirely_through_the_browser_path() {
    let sandbox = SandboxConfig::shared()
        .await
        .expect("failed to start sandbox");
    let relayer = sandbox.client();

    for variant in [Variant::NoSign, Variant::WebauthnP256] {
        relayer
            .publish(artifacts::load(variant).unwrap(), PublishMode::Immutable)
            .into_future()
            .await
            .unwrap_or_else(|e| panic!("publishing {}: {e}", variant.file_name()));
    }
    let chain = Chain::with_client(relayer.clone(), "sandbox");

    let (user_id, user_client) = fresh_account(&relayer, "lydia").await;
    let m = Migration::new(
        chain.clone(),
        user_id.clone(),
        CryptoHash::from(*NO_SIGN_HASH),
        *P256_HASH,
    );
    let mut ledger = ProofLedger::new(user_id.as_str());

    println!("\n=== migrating {user_id} with browser passkeys ===");

    // --- step 1, unchanged: the account becomes a wallet ---
    let s1 = m.step1_become_wallet(&user_client).await.expect("step 1");
    println!("step 1: {:.4} TGas", s1.tgas());

    // One authenticator emits low-S, the other high-S, so both paths through
    // the normalisation are exercised on chain rather than only in a unit test.
    let mut authenticators = [Authenticator::new(false), Authenticator::new(true)];

    let mut passkey_accounts = Vec::new();

    for (i, auth) in authenticators.iter_mut().enumerate() {
        let label = if i == 0 { "A (low-S)" } else { "B (high-S)" };
        println!("\n--- passkey {label} ---");

        // Registration: the browser reports a public key as ES256 SPKI.
        let public_key = compressed_public_key(&auth.spki_public_key())
            .expect("the browser's public key should convert");
        let (wallet, passkey) = m.browser_passkey_wallet(public_key, &relayer);
        let account = wallet.real_account_id().clone();
        println!("derives to {account} before it exists");

        // --- step 2: create the account, signed directly by the passkey ---
        let (msg, challenge) = m
            .capture_signing_request(&wallet, &passkey, SigningRoute::Direct)
            .await
            .expect("capturing the creation request");
        let assertion = auth.get(&challenge);
        let proof = proof_from_browser(&assertion, &challenge).expect("building the proof");
        let (create, _) = m
            .submit_browser_proof(&relayer, &wallet, msg, proof, true, false)
            .await
            .expect("step 2 through the browser path");
        println!("step 2: {:.4} TGas, account created", create.tgas());

        let facts = chain.account_facts(&account).await.unwrap();
        assert!(facts.exists, "the 0s account should exist now");
        assert!(
            facts.storage_usage <= 770,
            "must stay a zero-balance account"
        );

        // --- step 3: authorise it ---
        let s3 = m
            .step3_add_extension(&user_client, &account)
            .await
            .expect("step 3");
        println!("step 3: {:.4} TGas", s3.tgas());

        // --- step 4: prove it, routed through the user account ---
        let (msg, challenge) = m
            .capture_signing_request(&wallet, &passkey, SigningRoute::ThroughUser)
            .await
            .expect("capturing the proof request");
        let assertion = auth.get(&challenge);
        let proof = proof_from_browser(&assertion, &challenge).expect("building the proof");
        let (prove, record) = m
            .submit_browser_proof(&relayer, &wallet, msg, proof, false, true)
            .await
            .expect("step 4 through the browser path");
        println!("step 4: {:.4} TGas, tx {}", prove.tgas(), prove.tx_hash);

        ledger.record(record);
        passkey_accounts.push(account);
    }

    // Both proven, from the chain's point of view rather than the ledger's.
    let view = chain.authority_view(&user_id, &ledger).await.unwrap();
    assert_eq!(
        view.stage,
        Stage::PasskeysAdded {
            added: 2,
            proven: 2
        }
    );
    assert_eq!(
        view.independent_proven_count(),
        2,
        "both browser-signed proofs must verify against the chain"
    );
    view.guard_key_deletion()
        .expect("the gate should open once both have proven through the browser");

    // --- step 5 ---
    println!("\n--- step 5: irreversible ---");
    for o in m
        .step5_finalise(&user_client, &ledger)
        .await
        .expect("step 5")
    {
        println!("  {}: {:.4} TGas", o.step, o.tgas());
    }

    assert!(
        chain.full_access_keys(&user_id).await.unwrap().is_empty(),
        "no full access keys may remain"
    );

    // --- and the account still works, driven from the browser path alone ---
    let public_key = compressed_public_key(&authenticators[0].spki_public_key()).unwrap();
    let (wallet, passkey) = m.browser_passkey_wallet(public_key, &relayer);
    let (msg, challenge) = m
        .capture_signing_request(&wallet, &passkey, SigningRoute::ThroughUser)
        .await
        .unwrap();
    let assertion = authenticators[0].get(&challenge);
    let proof = proof_from_browser(&assertion, &challenge).unwrap();
    let (after, _) = m
        .submit_browser_proof(&relayer, &wallet, msg, proof, false, true)
        .await
        .expect("a browser passkey must still drive the account with no keys left");

    println!(
        "\nafter migration, a browser passkey still drives {user_id}: {:.4} TGas, tx {}",
        after.tgas(),
        after.tx_hash
    );

    let end = chain.authority_view(&user_id, &ledger).await.unwrap();
    assert_eq!(end.stage, Stage::PasskeyControlled { proven: 2 });
    assert!(!end.has_full_access_key());
}

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
