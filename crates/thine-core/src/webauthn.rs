//! Turning what a browser's WebAuthn API hands back into what the contract
//! accepts.
//!
//! The browser gives three things from `navigator.credentials.get()`:
//! `authenticatorData` and `signature` as `ArrayBuffer`s, and
//! `clientDataJSON` as the raw bytes of a JSON document. None of the three is
//! in the shape the wallet contract wants, and two of the conversions are
//! places to get it quietly wrong.
//!
//! **The signature is DER, the contract wants raw.** WebAuthn returns an
//! ASN.1 DER-encoded ECDSA signature. `P256Signature` is the fixed 64-byte
//! `r || s`.
//!
//! **The signature may be high-S, and the contract rejects high-S.**
//! `defuse_crypto`'s P-256 verification refuses a signature whose `s` is above
//! half the curve order, as a guard against malleability. Nothing in WebAuthn
//! or CTAP requires an authenticator to produce low-S, and some do not. An
//! unnormalised signature from such a device would be a valid ECDSA signature
//! that the contract rejects, which would look like a broken passkey rather
//! than an encoding problem. So every signature is normalised here.
//!
//! The public key conversion is the third: registration yields a key in one of
//! several encodings depending on how it is read, and the contract wants the
//! 33-byte SEC1 compressed form.

use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use defuse_wallet_webauthn::{
    WalletWebauthnProof,
    crypto::p256::{
        P256CompressedPublicKey, P256Signature,
        p256::ecdsa::{Signature, VerifyingKey},
    },
    webauthn::WebauthnAssertion,
};

/// The challenge the browser must be asked to sign.
///
/// The wallet contract uses the request message's own hash as the WebAuthn
/// challenge, rather than a random nonce, because authenticators are
/// general-purpose blind signers and this keeps the proof small. WebAuthn
/// carries the challenge as base64url without padding.
pub fn challenge_for(hash: &[u8; 32]) -> String {
    URL_SAFE_NO_PAD.encode(hash)
}

/// A P-256 public key as a browser reports it at registration.
///
/// Accepts, in order of how likely each is to turn up:
///
/// - **91 bytes** — the SPKI DER that `getPublicKey()` returns for ES256. For
///   P-256 this encoding is fixed-length, so the uncompressed point is the
///   trailing 65 bytes.
/// - **65 bytes** — an uncompressed SEC1 point, `0x04 || x || y`. This is what
///   you get from the COSE key's `x` and `y` coordinates concatenated behind an
///   `0x04` tag.
/// - **33 bytes** — already SEC1 compressed; passed through after validation.
pub fn compressed_public_key(bytes: &[u8]) -> Result<P256CompressedPublicKey> {
    let point: &[u8] = match bytes.len() {
        91 => &bytes[91 - 65..],
        65 | 33 => bytes,
        other => bail!(
            "a P-256 public key should be 33, 65 or 91 bytes (compressed SEC1, uncompressed \
             SEC1, or ES256 SPKI); got {other}"
        ),
    };

    ensure!(
        matches!(point.first(), Some(0x02 | 0x03 | 0x04)),
        "not a SEC1 point: first byte is {:?}, expected 0x02, 0x03 or 0x04",
        point.first()
    );

    // Round-tripping through VerifyingKey both validates that the point is on
    // the curve and performs the compression, rather than trusting the bytes.
    let key = VerifyingKey::from_sec1_bytes(point)
        .context("the public key is not a valid point on the P-256 curve")?;

    Ok(P256CompressedPublicKey::from(key))
}

/// What `navigator.credentials.get()` produced, decoded from transport.
#[derive(Debug, Clone)]
pub struct BrowserAssertion {
    /// `response.authenticatorData`.
    pub authenticator_data: Vec<u8>,
    /// `response.clientDataJSON`, as its UTF-8 text. Kept as the exact string
    /// the browser produced, because it is hashed byte-for-byte during
    /// verification and re-serialising the JSON would change it.
    pub client_data_json: String,
    /// `response.signature`, ASN.1 DER.
    pub signature_der: Vec<u8>,
}

/// The proof to hand to `w_execute_signed`, as its JSON string.
///
/// `expected_challenge` is the hash the request message was supposed to commit
/// to. It is checked against what the browser actually signed, so a mismatch is
/// caught here rather than spending gas to be rejected on chain.
pub fn proof_from_browser(
    assertion: &BrowserAssertion,
    expected_challenge: &[u8; 32],
) -> Result<String> {
    check_challenge(&assertion.client_data_json, expected_challenge)?;

    let signature = normalised_signature(&assertion.signature_der)?;

    let proof: WalletWebauthnProof<P256Signature> = WalletWebauthnProof {
        assertion: WebauthnAssertion {
            authenticator_data: assertion.authenticator_data.clone(),
            client_data_json: assertion.client_data_json.clone(),
        },
        signature: signature.into(),
    };

    serde_json::to_string(&proof).context("serialising the proof")
}

/// Parse a DER signature and force it into the low-S form the contract accepts.
fn normalised_signature(der: &[u8]) -> Result<Signature> {
    let signature =
        Signature::from_der(der).context("the signature is not a DER-encoded ECDSA signature")?;

    // `normalize_s` is a no-op on a signature that is already low-S.
    Ok(signature.normalize_s())
}

/// Confirm the browser signed the challenge we asked for.
fn check_challenge(client_data_json: &str, expected: &[u8; 32]) -> Result<()> {
    #[derive(serde::Deserialize)]
    struct ClientData {
        #[serde(rename = "type")]
        typ: String,
        challenge: String,
    }

    let data: ClientData =
        serde_json::from_str(client_data_json).context("clientDataJSON is not JSON")?;

    ensure!(
        data.typ == "webauthn.get",
        "clientDataJSON type is {:?}, expected \"webauthn.get\". A registration assertion \
         cannot be used to authorise a request.",
        data.typ
    );

    let signed = URL_SAFE_NO_PAD
        .decode(data.challenge.trim_end_matches('='))
        .context("the challenge in clientDataJSON is not base64url")?;

    ensure!(
        signed == expected,
        "the browser signed a different challenge than the one requested. Expected {}, got {}.",
        URL_SAFE_NO_PAD.encode(expected),
        URL_SAFE_NO_PAD.encode(&signed),
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use defuse_wallet_sdk::{
        AccountId, Gas, NearPromise, NearToken, RequestMessage, SignatureSchema,
        actions::FunctionCall,
    };
    use defuse_wallet_webauthn::{
        WalletWebauthn,
        crypto::p256::p256::{
            ecdsa::{Signature, signature::Signer as _},
            elliptic_curve::scalar::IsHigh,
        },
        p256::P256,
        webauthn::IgnoreUserVerification,
    };

    use super::*;

    type Schema = WalletWebauthn<P256, IgnoreUserVerification>;

    /// A real assertion, produced by a real browser at `http://localhost:5173`
    /// against a real P-256 authenticator. Taken from NEAR's own test vector in
    /// `contracts/wallet/signatures/webauthn/src/p256.rs`, so it is evidence
    /// about browsers rather than about our own mock.
    const FIXTURE_PUBLIC_KEY: [u8; 33] =
        hex_literal::hex!("02c0cad83d84b6bf228366971ddcb1738b9af862c64446a9feea85964743a5b390");
    const FIXTURE_AUTH_DATA_B64: &str = "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MdAAAAAA==";
    const FIXTURE_CLIENT_DATA: &str = r#"{"type":"webauthn.get","challenge":"fIVgtROAVRZ2pU2sSdzB4AmvMCBVbN6OHiFyeC_9Z3U","origin":"http://localhost:5173","crossOrigin":false}"#;
    const FIXTURE_SIGNATURE: &str = "p256:2S9WKwvKY7zgLaC9ihYDMQmbGtCvqqYy6RvvpgqRs7VXBR3GKXke4LKLNKyvtWRRB3dmU3awuCh2EYY7Sfk34qmh";

    fn fixture_message() -> RequestMessage {
        RequestMessage {
            pay_for_gas: false,
            chain_id: "mainnet".to_string(),
            signer_id: "0se5eba21e8f191e1880e453794bc551dfa50a3419".parse().unwrap(),
            nonce: 2845491008,
            created_at: "2026-07-07T11:13:29Z".parse().unwrap(),
            timeout: Duration::from_secs(3600),
            request: NearPromise::new("v1.signer".parse::<AccountId>().unwrap())
                .function_call(
                    FunctionCall::name("sign")
                        .args(hex_literal::hex!("7b2272657175657374223a7b227061796c6f61645f7632223a7b224563647361223a2230303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030227d2c22646f6d61696e5f6964223a302c2270617468223a22227d7d"))
                        .attach_deposit(NearToken::from_yoctonear(1))
                        .gas(Gas::from_gas(0)),
                )
                .into(),
        }
    }

    fn fixture_raw_signature() -> Signature {
        let b58 = FIXTURE_SIGNATURE.strip_prefix("p256:").unwrap();
        let bytes = bs58::decode(b58).into_vec().unwrap();
        Signature::from_slice(&bytes).unwrap()
    }

    fn fixture_auth_data() -> Vec<u8> {
        base64::engine::general_purpose::URL_SAFE
            .decode(FIXTURE_AUTH_DATA_B64)
            .unwrap()
    }

    #[test]
    fn the_challenge_we_ask_for_is_the_message_hash_in_base64url() {
        let msg = fixture_message();
        let challenge = challenge_for(&msg.hash());

        // The browser's clientDataJSON must contain exactly this.
        assert_eq!(challenge, "fIVgtROAVRZ2pU2sSdzB4AmvMCBVbN6OHiFyeC_9Z3U");
        assert!(FIXTURE_CLIENT_DATA.contains(&challenge));
    }

    /// The whole browser path, end to end, against a real browser assertion:
    /// DER signature in, contract-accepted proof out.
    #[test]
    fn a_real_browser_assertion_converts_into_a_proof_the_contract_accepts() {
        let msg = fixture_message();

        // Re-encode the fixture's raw signature as DER, which is the form a
        // browser actually hands over.
        let der = fixture_raw_signature().to_der();

        let proof = proof_from_browser(
            &BrowserAssertion {
                authenticator_data: fixture_auth_data(),
                client_data_json: FIXTURE_CLIENT_DATA.to_string(),
                signature_der: der.as_bytes().to_vec(),
            },
            &msg.hash(),
        )
        .expect("the browser assertion should convert");

        let public_key = compressed_public_key(&FIXTURE_PUBLIC_KEY).unwrap();

        assert!(
            Schema::verify_request_msg(&public_key, &msg, &proof),
            "the contract must accept a proof built from a real browser assertion:\n{proof}"
        );
    }

    #[test]
    fn a_high_s_signature_is_normalised_rather_than_rejected_on_chain() {
        // Authenticators are not required to emit low-S, and the contract
        // refuses high-S outright. An unnormalised signature would look like a
        // broken passkey instead of an encoding problem.
        let low = fixture_raw_signature();
        let high = Signature::from_scalars(
            low.r().to_bytes(),
            (-*low.s()).to_bytes(), // n - s, the other valid form
        )
        .unwrap();
        assert!(bool::from(high.s().is_high()), "the test input must be high-S");

        let normalised = normalised_signature(high.to_der().as_bytes()).unwrap();
        assert!(!bool::from(normalised.s().is_high()), "must come back low-S");
        assert_eq!(normalised, low, "and must be the same signature");

        // And it verifies, where the high-S form would not have.
        let msg = fixture_message();
        let proof = proof_from_browser(
            &BrowserAssertion {
                authenticator_data: fixture_auth_data(),
                client_data_json: FIXTURE_CLIENT_DATA.to_string(),
                signature_der: high.to_der().as_bytes().to_vec(),
            },
            &msg.hash(),
        )
        .unwrap();
        assert!(
            Schema::verify_request_msg(
                &compressed_public_key(&FIXTURE_PUBLIC_KEY).unwrap(),
                &msg,
                &proof
            ),
            "a high-S signature from the browser must still produce a usable proof"
        );
    }

    #[test]
    fn a_browser_that_signs_the_wrong_challenge_is_caught_before_any_gas_is_spent() {
        let wrong = [7u8; 32];
        let der = fixture_raw_signature().to_der();

        let err = proof_from_browser(
            &BrowserAssertion {
                authenticator_data: fixture_auth_data(),
                client_data_json: FIXTURE_CLIENT_DATA.to_string(),
                signature_der: der.as_bytes().to_vec(),
            },
            &wrong,
        )
        .expect_err("a mismatched challenge must be refused");
        assert!(
            err.to_string().contains("signed a different challenge"),
            "{err}"
        );
    }

    #[test]
    fn a_registration_assertion_cannot_be_replayed_as_an_authorisation() {
        let msg = fixture_message();
        let client_data = FIXTURE_CLIENT_DATA.replace("webauthn.get", "webauthn.create");
        let der = fixture_raw_signature().to_der();

        let err = proof_from_browser(
            &BrowserAssertion {
                authenticator_data: fixture_auth_data(),
                client_data_json: client_data,
                signature_der: der.as_bytes().to_vec(),
            },
            &msg.hash(),
        )
        .expect_err("webauthn.create must not be accepted");
        assert!(err.to_string().contains("webauthn.get"), "{err}");
    }

    #[test]
    fn public_keys_convert_from_every_encoding_a_browser_might_report() {
        let expected = compressed_public_key(&FIXTURE_PUBLIC_KEY).unwrap();

        // Uncompressed SEC1, which is what COSE x and y concatenate to.
        let key = VerifyingKey::from_sec1_bytes(&FIXTURE_PUBLIC_KEY).unwrap();
        let uncompressed = key.to_sec1_point(false);
        assert_eq!(uncompressed.as_bytes().len(), 65);
        assert_eq!(
            compressed_public_key(uncompressed.as_bytes()).unwrap(),
            expected
        );

        // ES256 SPKI, which is what getPublicKey() returns: 91 bytes for
        // P-256, with the point in the last 65.
        let mut spki = vec![0u8; 91 - 65];
        spki.extend_from_slice(uncompressed.as_bytes());
        assert_eq!(compressed_public_key(&spki).unwrap(), expected);
    }

    #[test]
    fn a_public_key_that_is_not_on_the_curve_is_refused() {
        let mut bad = FIXTURE_PUBLIC_KEY;
        bad[20] ^= 0xff;
        assert!(compressed_public_key(&bad).is_err());

        assert!(
            compressed_public_key(&[0u8; 40]).is_err(),
            "an implausible length must be refused"
        );
    }

    #[test]
    fn a_signature_that_is_not_der_is_refused_with_a_useful_message() {
        let err = normalised_signature(&[1, 2, 3]).unwrap_err();
        assert!(err.to_string().contains("DER"), "{err}");
    }

    /// Guard against the round trip being vacuous: a freshly generated key and
    /// signature must also pass, so the fixture test is not the only evidence.
    #[test]
    fn a_freshly_signed_assertion_also_converts_and_verifies() {
        use defuse_wallet_webauthn::crypto::p256::p256::{
            ecdsa::SigningKey, elliptic_curve::Generate,
        };
        use sha2::{Digest, Sha256};

        let signing = SigningKey::generate_from_rng(&mut rand::rng());
        let msg = fixture_message();
        let challenge = challenge_for(&msg.hash());

        let client_data = format!(
            r#"{{"type":"webauthn.get","challenge":"{challenge}","origin":"http://localhost:5173","crossOrigin":false}}"#
        );
        let auth_data = fixture_auth_data();

        // What the authenticator signs: authData || SHA256(clientDataJSON).
        let signed_over =
            [auth_data.as_slice(), Sha256::digest(client_data.as_bytes()).as_ref()].concat();
        let signature: Signature = signing.sign(&signed_over);

        let proof = proof_from_browser(
            &BrowserAssertion {
                authenticator_data: auth_data,
                client_data_json: client_data,
                signature_der: signature.to_der().as_bytes().to_vec(),
            },
            &msg.hash(),
        )
        .unwrap();

        let public_key =
            compressed_public_key(signing.verifying_key().to_sec1_point(false).as_bytes())
                .unwrap();

        assert!(Schema::verify_request_msg(&public_key, &msg, &proof));
    }
}
