//! The wallet contract artefacts Thine deploys, and their verification.
//!
//! These WASM files are NEAR's own wallet contracts from
//! [`github.com/near/intents`](https://github.com/near/intents) (MIT). The
//! copies committed under `res/` are the exact bytes deployed on NEAR mainnet,
//! fetched with the `view_global_contract_code_by_account_id` RPC method.
//!
//! They are committed rather than built so that a clean checkout can run every
//! measurement in this repository with one command and no WASM toolchain. Every
//! load is checked against the SHA-256 digest recorded here, so a corrupted or
//! substituted artefact is a hard error rather than a silent difference.

use std::{fs, path::PathBuf};

use sha2::{Digest, Sha256};

/// A wallet contract variant Thine deploys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Variant {
    /// `wallet-no-sign`. Deployed onto the user's own account in step 1. It
    /// holds no public key of its own and verifies no signatures; all authority
    /// comes from its extension set.
    NoSign,
    /// `wallet-webauthn-p256`. Runs on each zero-balance `0s` account that a
    /// passkey controls.
    WebauthnP256,
    /// An ordinary near-sdk contract used only by the check 2 tests to put a
    /// test account into a given pre-migration state. Built from
    /// `contracts/thine-probe` in this repository.
    Probe,
}

impl Variant {
    /// The file name under `res/`.
    pub const fn file_name(self) -> &'static str {
        match self {
            Self::NoSign => "defuse-wallet-no-sign.mainnet.wasm",
            Self::WebauthnP256 => "defuse-wallet-webauthn-p256.mainnet.wasm",
            Self::Probe => "thine-probe.wasm",
        }
    }

    /// Expected SHA-256 of the artefact, lowercase hex.
    ///
    /// For the two wallet variants this is also the digest of the code deployed
    /// on NEAR mainnet, so it doubles as a check that we are measuring and
    /// deploying the same code the live network runs.
    pub const fn sha256_hex(self) -> &'static str {
        match self {
            Self::NoSign => "4fcc9ee27c9d5a0411b0cca84abadfda9ebe27fe388d92949ca8597b6212ab17",
            Self::WebauthnP256 => {
                "0c599d85e52c08ec644c950a8749b398a30eec23dcddfd70fe3633826aa5de37"
            }
            Self::Probe => "d3433dc1738d81a136811f8d153df61d944b5b377f2d456f7d989ff666771c42",
        }
    }

    /// Size in bytes, used to state publication cost without reading the file.
    pub const fn size_bytes(self) -> u64 {
        match self {
            Self::NoSign => 308_482,
            Self::WebauthnP256 => 370_286,
            Self::Probe => 112_789,
        }
    }

    /// What publishing this artefact as a global contract burns, in yoctoNEAR.
    ///
    /// NEP-591 charges publication at ten times the ordinary storage staking
    /// rate of 1e19 yoctoNEAR per byte, and the burn is not refundable. The
    /// `thine_publish_cost` test in `thine-bench` measures this against a
    /// sandbox and confirms the figure to six decimal places.
    pub const fn publish_burn_yocto(self) -> u128 {
        self.size_bytes() as u128 * 10_000_000_000_000_000_000 * 10
    }

    /// The account that serves this contract as a global contract on NEAR
    /// mainnet, for the two variants that are NEAR's rather than ours.
    ///
    /// These are global-deployer instances: `UseGlobalContract` with the
    /// account id resolves to the wallet WASM. The same bytes are **not**
    /// available by code hash on mainnet — `view_global_contract_code` for
    /// either digest returns `NO_GLOBAL_CONTRACT_CODE` — so this account id is
    /// the only on-chain reference to compare against.
    pub const fn mainnet_reference(self) -> Option<&'static str> {
        match self {
            Self::NoSign => Some("0sfa7a4d20c9b28a23fcd85930593ed3974c3fb38e"),
            Self::WebauthnP256 => Some("0saf343be226341c0eca7dba6d0b29d49bdff3ad03"),
            // Ours. Nothing on mainnet to compare it to.
            Self::Probe => None,
        }
    }

    /// Every artefact this crate knows about.
    pub const ALL: [Self; 3] = [Self::NoSign, Self::WebauthnP256, Self::Probe];
}

/// Failure to load a committed artefact.
#[derive(Debug, thiserror::Error)]
pub enum ArtifactError {
    #[error("could not read artefact {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error(
        "artefact {name} is not the expected bytes: sha256 was {actual}, expected {expected}. \
         The copy in res/ has been modified or corrupted; restore it from git."
    )]
    Digest {
        name: &'static str,
        actual: String,
        expected: &'static str,
    },
}

/// The directory holding the committed artefacts.
///
/// Resolved relative to this crate's manifest so it works from any working
/// directory, which matters because `cargo test` runs with the crate directory
/// as the working directory, not the workspace root.
pub fn res_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("res")
}

/// Load an artefact and verify its digest.
pub fn load(variant: Variant) -> Result<Vec<u8>, ArtifactError> {
    let path = res_dir().join(variant.file_name());
    let bytes = fs::read(&path).map_err(|source| ArtifactError::Read {
        path: path.clone(),
        source,
    })?;

    let actual = hex(&Sha256::digest(&bytes));
    if actual != variant.sha256_hex() {
        return Err(ArtifactError::Digest {
            name: variant.file_name(),
            actual,
            expected: variant.sha256_hex(),
        });
    }

    Ok(bytes)
}

/// The SHA-256 of an artefact as raw bytes, which is also the NEAR global
/// contract code hash it will be published under.
pub fn code_hash(variant: Variant) -> Result<[u8; 32], ArtifactError> {
    Ok(Sha256::digest(load(variant)?).into())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_artefact_loads_and_matches_its_digest() {
        for variant in Variant::ALL {
            let bytes = load(variant).expect("artefact should load and verify");
            assert_eq!(
                bytes.len() as u64,
                variant.size_bytes(),
                "{} size changed",
                variant.file_name()
            );
        }
    }

    #[test]
    fn both_wallet_variants_have_a_mainnet_reference_to_check_against() {
        assert!(Variant::NoSign.mainnet_reference().is_some());
        assert!(Variant::WebauthnP256.mainnet_reference().is_some());
        assert!(
            Variant::Probe.mainnet_reference().is_none(),
            "the probe is ours; there is nothing on mainnet to compare it to"
        );
    }

    #[test]
    fn publish_burn_matches_the_measured_figures() {
        // Measured in the sandbox by `thine-bench`'s `thine_publish_cost`:
        // 30.850628 NEAR and 37.031503 NEAR spent, of which these are the
        // 10x storage burn component.
        assert_eq!(
            Variant::NoSign.publish_burn_yocto(),
            30_848_200_000_000_000_000_000_000
        );
        assert_eq!(
            Variant::WebauthnP256.publish_burn_yocto(),
            37_028_600_000_000_000_000_000_000
        );

        // The pair, which is what a testnet deployment of Thine costs. The
        // testnet faucet grants 10 NEAR per request, measured, so reaching
        // this takes eight requests and consolidation into one account.
        let total = Variant::NoSign.publish_burn_yocto() + Variant::WebauthnP256.publish_burn_yocto();
        assert_eq!(total, 67_876_800_000_000_000_000_000_000);
    }
}
