//! Evidence that a passkey can still sign.
//!
//! Adding an extension to an account proves nothing about whether anyone still
//! holds the corresponding passkey. The only thing that proves it is a
//! completed `w_execute_signed`: a transaction in which that `0s` wallet
//! verified a real P-256 signature and acted on it.
//!
//! Thine records those transactions here. The record is a pointer, not the
//! evidence itself — every proof is re-verified against the chain before it
//! counts, by fetching the transaction and checking that it really was a
//! successful `w_execute_signed` on that exact account. A hand-edited ledger
//! therefore buys nothing.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// A claim that a given passkey wallet completed a `w_execute_signed`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofRecord {
    /// The `0s` account whose passkey signed.
    pub extension_account_id: String,
    /// Transaction hash of the `w_execute_signed`, base58.
    pub tx_hash: String,
    /// The account that relayed it, needed to look the transaction up.
    pub relayed_by: String,
    /// RFC 3339 timestamp, for display only. Never trusted.
    pub recorded_at: String,
}

/// Thine's local record of proofs, one file per user account.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofLedger {
    /// The account being migrated.
    pub account_id: String,
    pub proofs: Vec<ProofRecord>,
}

impl ProofLedger {
    pub fn new(account_id: impl Into<String>) -> Self {
        Self {
            account_id: account_id.into(),
            proofs: Vec::new(),
        }
    }

    /// Where a ledger for `account_id` lives.
    pub fn path_for(dir: impl AsRef<Path>, account_id: &str) -> PathBuf {
        dir.as_ref().join(format!("proofs-{account_id}.json"))
    }

    pub fn load(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let path = path.as_ref();
        if !path.exists() {
            anyhow::bail!("no proof ledger at {}", path.display());
        }
        Ok(serde_json::from_slice(&std::fs::read(path)?)?)
    }

    /// Load, or start an empty ledger if there is none yet.
    pub fn load_or_new(path: impl AsRef<Path>, account_id: &str) -> Self {
        Self::load(path).unwrap_or_else(|_| Self::new(account_id))
    }

    pub fn save(&self, path: impl AsRef<Path>) -> anyhow::Result<()> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, serde_json::to_vec_pretty(self)?)?;
        Ok(())
    }

    /// Record a proof, replacing any earlier one for the same account so a
    /// passkey cannot be counted twice by accumulating entries.
    pub fn record(&mut self, record: ProofRecord) {
        self.proofs
            .retain(|p| p.extension_account_id != record.extension_account_id);
        self.proofs.push(record);
    }

    pub fn for_account(&self, extension_account_id: &str) -> Option<&ProofRecord> {
        self.proofs
            .iter()
            .find(|p| p.extension_account_id == extension_account_id)
    }

    /// Distinct `0s` accounts with a recorded proof. Still unverified at this
    /// point; [`crate::chain`] is what makes a proof count.
    pub fn claimed_count(&self) -> usize {
        self.proofs
            .iter()
            .map(|p| p.extension_account_id.as_str())
            .collect::<std::collections::BTreeSet<_>>()
            .len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(acct: &str, tx: &str) -> ProofRecord {
        ProofRecord {
            extension_account_id: acct.to_string(),
            tx_hash: tx.to_string(),
            relayed_by: "relayer.testnet".to_string(),
            recorded_at: "2026-11-04T00:00:00Z".to_string(),
        }
    }

    #[test]
    fn recording_the_same_account_twice_does_not_inflate_the_count() {
        let mut l = ProofLedger::new("lydia.testnet");
        l.record(rec("0saaa", "tx1"));
        l.record(rec("0saaa", "tx2"));
        assert_eq!(l.proofs.len(), 1, "replaced, not appended");
        assert_eq!(l.claimed_count(), 1);
        assert_eq!(l.for_account("0saaa").unwrap().tx_hash, "tx2");
    }

    #[test]
    fn two_distinct_accounts_count_as_two() {
        let mut l = ProofLedger::new("lydia.testnet");
        l.record(rec("0saaa", "tx1"));
        l.record(rec("0sbbb", "tx2"));
        assert_eq!(l.claimed_count(), 2);
    }

    #[test]
    fn round_trips_through_disk() {
        let dir = std::env::temp_dir().join(format!("thine-test-{}", std::process::id()));
        let path = ProofLedger::path_for(&dir, "lydia.testnet");
        let mut l = ProofLedger::new("lydia.testnet");
        l.record(rec("0saaa", "tx1"));
        l.save(&path).unwrap();

        let back = ProofLedger::load(&path).unwrap();
        assert_eq!(back, l);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_missing_ledger_starts_empty_rather_than_failing() {
        let l = ProofLedger::load_or_new("/nonexistent/path/x.json", "lydia.testnet");
        assert_eq!(l.account_id, "lydia.testnet");
        assert!(l.proofs.is_empty());
    }
}
