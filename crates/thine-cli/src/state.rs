//! Thine's local state: the relayer account it sends from, and the code hashes
//! it has published.
//!
//! All of it lives under `.thine/`, which is gitignored. The relayer secret key
//! is written here, so this directory must never be committed.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// A funded account Thine relays transactions from.
///
/// On testnet this is whatever the faucet handed us. It pays gas for the
/// migration and for every passkey hop; it holds no authority over the account
/// being migrated.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Relayer {
    pub network: String,
    pub account_id: String,
    /// Secret key, `ed25519:...`. Local only.
    pub secret_key: String,
}

impl Relayer {
    pub fn path(dir: impl AsRef<Path>, network: &str) -> PathBuf {
        dir.as_ref().join(format!("relayer-{network}.json"))
    }

    pub fn load(dir: impl AsRef<Path>, network: &str) -> Result<Self> {
        let path = Self::path(&dir, network);
        let bytes = std::fs::read(&path).with_context(|| {
            format!(
                "no relayer for {network} at {}. Run `thine faucet` first.",
                path.display()
            )
        })?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    pub fn save(&self, dir: impl AsRef<Path>) -> Result<()> {
        let path = Self::path(&dir, &self.network);
        std::fs::create_dir_all(path.parent().unwrap())?;
        std::fs::write(&path, serde_json::to_vec_pretty(self)?)?;
        // The file holds a private key. Keep it to the owner.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }
}

/// The wallet contract code hashes Thine has published on a network.
///
/// Published by code hash rather than by account id: same cost, no deployer
/// account needed, and the reference is immutable, which matters when the thing
/// being referenced is the only way back into someone's account.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublishedContracts {
    pub network: String,
    /// `wallet-no-sign` code hash, base58 as NEAR renders it.
    pub no_sign: String,
    /// `wallet-webauthn-p256` code hash, base58.
    pub webauthn_p256: String,
    pub published_by: String,
    pub published_at: String,
    /// What the publication burned, in yoctoNEAR. Not refundable.
    pub burned_yocto: u128,
}

impl PublishedContracts {
    pub fn path(dir: impl AsRef<Path>, network: &str) -> PathBuf {
        dir.as_ref().join(format!("contracts-{network}.json"))
    }

    pub fn load(dir: impl AsRef<Path>, network: &str) -> Result<Self> {
        let path = Self::path(&dir, network);
        let bytes = std::fs::read(&path).with_context(|| {
            format!(
                "no published contracts for {network} at {}. Run `thine publish` first.",
                path.display()
            )
        })?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    pub fn save(&self, dir: impl AsRef<Path>) -> Result<()> {
        let path = Self::path(&dir, &self.network);
        std::fs::create_dir_all(path.parent().unwrap())?;
        std::fs::write(&path, serde_json::to_vec_pretty(self)?)?;
        Ok(())
    }
}
