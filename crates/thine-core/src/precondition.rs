//! The checks that run before Thine sends anything.
//!
//! Pure functions over a snapshot of an account's contract state, so they can
//! be tested without a network. [`crate::chain`] fetches the snapshot.

use serde::{Deserialize, Serialize};

use crate::authority::{OrphanedStorage, Refusal};

/// Bytes NEAR charges per data record on top of the key and value.
///
/// Derived from the check 2 measurement rather than assumed: a probe contract
/// holding four records with 19 bytes of keys and 456 bytes of values accounted
/// for 635 bytes of storage. 635 - 475 = 160 = 4 x 40.
pub const STORAGE_OVERHEAD_PER_RECORD: u64 = 40;

/// One contract state record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateRecord {
    pub key: Vec<u8>,
    pub value_len: usize,
}

impl StateRecord {
    pub fn is_empty_key(&self) -> bool {
        self.key.is_empty()
    }

    /// How much storage this record accounts for.
    pub fn storage_bytes(&self) -> u64 {
        self.key.len() as u64 + self.value_len as u64 + STORAGE_OVERHEAD_PER_RECORD
    }

    /// The key rendered for a human: UTF-8 when it is text, hex otherwise, and
    /// named explicitly when it is the empty key, since an empty string renders
    /// as nothing at all and that is exactly the case that matters most.
    pub fn display_key(&self) -> String {
        if self.key.is_empty() {
            return r#"<empty key b"">"#.to_string();
        }
        match std::str::from_utf8(&self.key) {
            Ok(s) if s.chars().all(|c| !c.is_control()) => s.to_string(),
            _ => format!(
                "0x{}",
                self.key
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>()
            ),
        }
    }
}

/// Everything in an account's contract state, as returned by a `view_state`
/// query with an empty prefix.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateSnapshot {
    pub records: Vec<StateRecord>,
}

impl StateSnapshot {
    pub fn new(records: Vec<StateRecord>) -> Self {
        Self { records }
    }

    /// The record stored under the empty key, if any.
    ///
    /// This is the one that decides whether a migration is possible at all. The
    /// wallet contract keeps its own state under `b""`, and `w_init` is a plain
    /// `#[init]`, so near-sdk panics with "The contract has already been
    /// initialized" if anything is there. Confirmed empirically in check 2
    /// case 3.
    pub fn empty_key_record(&self) -> Option<&StateRecord> {
        self.records.iter().find(|r| r.is_empty_key())
    }

    /// The hard refusal. Not a warning.
    ///
    /// A failed `w_init` does roll back the `UseGlobalContract` in the same
    /// receipt, so sending it anyway would be survivable rather than
    /// catastrophic. We still refuse: spending a user's gas on a transaction we
    /// already know will fail is not acceptable behaviour, and the whole point
    /// of this tool is that it does not guess.
    pub fn check(&self) -> Result<(), Refusal> {
        match self.empty_key_record() {
            Some(r) => Err(Refusal::EmptyStateKeyOccupied { bytes: r.value_len }),
            None => Ok(()),
        }
    }

    /// Records that will survive the migration unreachable.
    ///
    /// `UseGlobalContract` removes the account's code and leaves every data key
    /// untouched, so anything already here stays, minus the empty key which the
    /// wallet contract itself will own. The user keeps paying storage stake on
    /// all of it with no code left that can read it.
    pub fn orphaned(&self) -> Option<OrphanedStorage> {
        let records: Vec<&StateRecord> =
            self.records.iter().filter(|r| !r.is_empty_key()).collect();
        if records.is_empty() {
            return None;
        }
        Some(OrphanedStorage {
            bytes: records.iter().map(|r| r.storage_bytes()).sum(),
            keys: records.iter().map(|r| r.display_key()).collect(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(key: &str, value_len: usize) -> StateRecord {
        StateRecord {
            key: key.as_bytes().to_vec(),
            value_len,
        }
    }

    #[test]
    fn a_plain_account_passes() {
        assert!(StateSnapshot::default().check().is_ok());
        assert_eq!(StateSnapshot::default().orphaned(), None);
    }

    #[test]
    fn an_ordinary_contract_passes_but_orphans_its_data() {
        // Exactly the check 2 case 2 account: near-sdk's own b"STATE" plus
        // three data keys. Measured on chain at 635 orphaned bytes.
        let snap = StateSnapshot::new(vec![
            rec("STATE", 8),
            rec("alpha", 64),
            rec("beta", 128),
            rec("gamma", 256),
        ]);
        assert!(
            snap.check().is_ok(),
            "b\"STATE\" must not collide with b\"\""
        );

        let orphaned = snap.orphaned().expect("should report orphaned storage");
        assert_eq!(
            orphaned.bytes, 635,
            "must match the figure measured on chain"
        );
        assert_eq!(orphaned.staked_yocto(), 6_350_000_000_000_000_000_000);
        assert_eq!(orphaned.keys.len(), 4);
    }

    #[test]
    fn an_occupied_empty_key_is_refused() {
        let snap = StateSnapshot::new(vec![
            StateRecord {
                key: Vec::new(),
                value_len: 33,
            },
            rec("STATE", 8),
        ]);
        assert!(matches!(
            snap.check(),
            Err(Refusal::EmptyStateKeyOccupied { bytes: 33 })
        ));
    }

    #[test]
    fn the_empty_key_is_not_counted_as_orphaned() {
        let snap = StateSnapshot::new(vec![StateRecord {
            key: Vec::new(),
            value_len: 46,
        }]);
        // A migrated wallet account holds exactly this one record and nothing
        // is orphaned.
        assert_eq!(snap.orphaned(), None);
    }

    #[test]
    fn the_empty_key_renders_visibly() {
        let r = StateRecord {
            key: Vec::new(),
            value_len: 1,
        };
        assert_eq!(r.display_key(), r#"<empty key b"">"#);
    }

    #[test]
    fn binary_keys_render_as_hex() {
        let r = StateRecord {
            key: vec![0x00, 0xff, 0x10],
            value_len: 1,
        };
        assert_eq!(r.display_key(), "0x00ff10");
    }
}
