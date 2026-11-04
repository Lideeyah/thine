//! Who can currently open an account.
//!
//! This is the model behind Thine's main screen. It is deliberately pure: it
//! holds no client and performs no network access, so the refusals below can be
//! unit tested exhaustively. [`crate::chain`] reads a real account over RPC and
//! produces one of these.
//!
//! The reason this model exists at all is that the last step of a migration
//! deletes the account's final full access key. That is irreversible, and the
//! wallet contract's own lockout guard is weaker than it looks: `w_init` and
//! `RemoveExtension` only check that the extension set is **non-empty**. They
//! never check that anything in that set is reachable. An account whose only
//! extension is a `0s` address that was never initialised, or whose passkey has
//! been lost, passes the contract's guard and is permanently unopenable.
//!
//! Closing that gap is this crate's job, not the contract's.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

/// How many independent passkeys must have *proven* control before Thine will
/// delete an account's full access keys.
///
/// Two, not one. A single passkey is a single point of failure: lose the device
/// and the account is gone, with no seed phrase left to fall back on.
pub const MIN_PROVEN_PASSKEYS: usize = 2;

/// A party that can act for the account, and on what evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Holder {
    pub kind: HolderKind,
    pub status: HolderStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum HolderKind {
    /// A NEAR full access key on the account itself. Can do anything, including
    /// deleting every other key. Before migration this is what the seed phrase
    /// controls.
    FullAccessKey { public_key: String },

    /// The account listed as its own extension. This is what `w_init` installs,
    /// and it means "whatever holds a full access key on this account still has
    /// authority". Removing it is what makes the migration final.
    SelfExtension,

    /// A separate `0s` account running `wallet-webauthn-p256`, whose authority
    /// is a passkey. Listed in the user account's extension set.
    PasskeyExtension {
        account_id: String,
        /// The P-256 public key the `0s` account reports from `w_public_key`,
        /// present only once the account has actually been reached.
        public_key: Option<String>,
    },
}

impl HolderKind {
    /// Whether this holder, as a matter of protocol, could delete the account's
    /// keys and so end the migration.
    pub fn has_full_authority(&self) -> bool {
        match self {
            Self::FullAccessKey { .. } => true,
            // An extension executes arbitrary requests on the account's behalf,
            // key deletion included.
            Self::SelfExtension | Self::PasskeyExtension { .. } => true,
        }
    }

    pub fn label(&self) -> String {
        match self {
            Self::FullAccessKey { public_key } => {
                format!("full access key {}", abbreviate(public_key))
            }
            Self::SelfExtension => "the account itself, via its full access keys".to_string(),
            Self::PasskeyExtension { account_id, .. } => format!("passkey {account_id}"),
        }
    }
}

/// What we actually know about a holder, as opposed to what the extension set
/// claims. The distinction is the whole point of the view.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum HolderStatus {
    /// Present on-chain and self-evidently usable: a full access key, or the
    /// self-extension while full access keys remain.
    Present,

    /// Listed as an extension, and confirmed to be a live account that answers
    /// `w_public_key`. Necessary before adding, but **not** sufficient to rely
    /// on: answering a view call proves the account exists, not that anyone
    /// still holds the passkey.
    Live,

    /// Live, and has completed a successful `w_execute_signed`. This is the only
    /// status that proves a human can still sign with this passkey.
    Proven {
        /// Transaction hash of the successful `w_execute_signed`.
        tx_hash: String,
    },

    /// Listed as an extension but not reachable. This is the lockout case the
    /// contract does not catch.
    Unreachable { reason: String },
}

impl HolderStatus {
    pub fn is_proven(&self) -> bool {
        matches!(self, Self::Proven { .. })
    }
}

/// Storage the account pays for but can no longer read, because
/// `UseGlobalContract` removed the code that understood it while leaving every
/// data key in place.
///
/// Measured for a representative account by the check 2 test: a contract with
/// four data keys left 635 orphaned bytes, 0.00635 NEAR, staked permanently.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrphanedStorage {
    pub bytes: u64,
    pub keys: Vec<String>,
}

impl OrphanedStorage {
    /// Ordinary storage staking is 1e19 yoctoNEAR per byte.
    pub fn staked_yocto(&self) -> u128 {
        self.bytes as u128 * 10_000_000_000_000_000_000
    }
}

/// Where an account is in the five-step migration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "stage", rename_all = "snake_case")]
pub enum Stage {
    /// An ordinary account. Whoever holds the seed phrase holds everything.
    SeedControlled,
    /// Step 1 done: `wallet-no-sign` in place, `signature_enabled = false`, and
    /// the account is its own only extension.
    WalletDeployed,
    /// Steps 2 to 4: passkey `0s` accounts exist and have been added. `proven`
    /// counts those that have completed a `w_execute_signed`.
    PasskeysAdded { added: usize, proven: usize },
    /// Step 5 done. The self-extension is gone and no full access keys remain.
    PasskeyControlled { proven: usize },
}

/// One picture of who can open the account.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorityView {
    pub account_id: String,
    pub stage: Stage,
    pub holders: Vec<Holder>,
    /// `None` until the account has been inspected for pre-existing data.
    pub orphaned: Option<OrphanedStorage>,
}

impl AuthorityView {
    pub fn passkeys(&self) -> impl Iterator<Item = &Holder> {
        self.holders
            .iter()
            .filter(|h| matches!(h.kind, HolderKind::PasskeyExtension { .. }))
    }

    /// Passkeys that have proven a human can still sign with them.
    pub fn proven_passkeys(&self) -> impl Iterator<Item = &Holder> {
        self.passkeys().filter(|h| h.status.is_proven())
    }

    pub fn proven_count(&self) -> usize {
        self.proven_passkeys().count()
    }

    /// Distinct `0s` accounts among the proven passkeys.
    ///
    /// Counted distinctly because two entries naming the same account are one
    /// passkey, and would not survive the loss of that one device.
    pub fn independent_proven_count(&self) -> usize {
        self.proven_passkeys()
            .filter_map(|h| match &h.kind {
                HolderKind::PasskeyExtension { account_id, .. } => Some(account_id.as_str()),
                _ => None,
            })
            .collect::<BTreeSet<_>>()
            .len()
    }

    pub fn has_full_access_key(&self) -> bool {
        self.holders
            .iter()
            .any(|h| matches!(h.kind, HolderKind::FullAccessKey { .. }))
    }

    pub fn unreachable(&self) -> impl Iterator<Item = &Holder> {
        self.holders
            .iter()
            .filter(|h| matches!(h.status, HolderStatus::Unreachable { .. }))
    }

    /// Whether the account would still be openable if every full access key
    /// were deleted right now. This is the question the final step turns on.
    pub fn survives_key_deletion(&self) -> bool {
        self.independent_proven_count() >= MIN_PROVEN_PASSKEYS
    }

    /// The gate in front of step 5. Returns the reason to refuse, if any.
    ///
    /// Thine does not warn here. It refuses.
    pub fn guard_key_deletion(&self) -> Result<(), Refusal> {
        if !matches!(
            self.stage,
            Stage::PasskeysAdded { .. } | Stage::WalletDeployed
        ) {
            return Err(Refusal::WrongStage {
                stage: self.stage.clone(),
            });
        }

        let unreachable: Vec<String> = self
            .unreachable()
            .map(|h| match (&h.kind, &h.status) {
                (kind, HolderStatus::Unreachable { reason }) => {
                    format!("{} ({reason})", kind.label())
                }
                (kind, _) => kind.label(),
            })
            .collect();
        if !unreachable.is_empty() {
            return Err(Refusal::UnreachableExtensions {
                holders: unreachable,
            });
        }

        let independent = self.independent_proven_count();
        if independent < MIN_PROVEN_PASSKEYS {
            return Err(Refusal::NotEnoughProvenPasskeys {
                proven: independent,
                added: self.passkeys().count(),
                required: MIN_PROVEN_PASSKEYS,
            });
        }

        Ok(())
    }
}

/// A refusal. Every variant is a hard stop, not advice.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Refusal {
    #[error(
        "this account's contract already uses the empty storage key, which is where the wallet \
         contract keeps its own state. Migrating would fail at w_init. Occupied by {bytes} bytes \
         of existing data."
    )]
    EmptyStateKeyOccupied { bytes: usize },

    #[error(
        "{proven} of {added} passkeys have proven they can sign; {required} are required before \
         any key is deleted. Adding a passkey is not evidence that anyone can still use it: each \
         must complete a w_execute_signed of its own."
    )]
    NotEnoughProvenPasskeys {
        proven: usize,
        added: usize,
        required: usize,
    },

    #[error(
        "refusing to add an extension that is not a live wallet account: {account_id} did not \
         answer w_public_key ({reason})"
    )]
    ExtensionNotLive { account_id: String, reason: String },

    #[error(
        "the extension set contains entries that cannot be reached, so deleting keys would lock \
         this account permanently: {}", holders.join("; ")
    )]
    UnreachableExtensions { holders: Vec<String> },

    #[error("this account is not at a stage where keys can be deleted (stage: {stage:?})")]
    WrongStage { stage: Stage },
}

impl Refusal {
    /// A stable identifier for this refusal.
    ///
    /// The interface branches on this. The message is free to be reworded; this
    /// is not, and renaming one is a breaking change to the view contract.
    pub fn code(&self) -> &'static str {
        match self {
            Self::EmptyStateKeyOccupied { .. } => "empty_state_key_occupied",
            Self::NotEnoughProvenPasskeys { .. } => "not_enough_proven_passkeys",
            Self::ExtensionNotLive { .. } => "extension_not_live",
            Self::UnreachableExtensions { .. } => "unreachable_extensions",
            Self::WrongStage { .. } => "wrong_stage",
        }
    }
}

fn abbreviate(key: &str) -> String {
    // "ed25519:ABCDEF...WXYZ" -> "ed25519:ABCD…WXYZ"
    match key.split_once(':') {
        Some((scheme, body)) if body.len() > 12 => {
            format!("{scheme}:{}…{}", &body[..4], &body[body.len() - 4..])
        }
        _ => key.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn passkey(id: &str, status: HolderStatus) -> Holder {
        Holder {
            kind: HolderKind::PasskeyExtension {
                account_id: id.to_string(),
                public_key: Some("p256:stub".to_string()),
            },
            status,
        }
    }

    fn proven(id: &str) -> Holder {
        passkey(
            id,
            HolderStatus::Proven {
                tx_hash: format!("tx-for-{id}"),
            },
        )
    }

    fn view(holders: Vec<Holder>) -> AuthorityView {
        let added = holders
            .iter()
            .filter(|h| matches!(h.kind, HolderKind::PasskeyExtension { .. }))
            .count();
        let proven = holders.iter().filter(|h| h.status.is_proven()).count();
        AuthorityView {
            account_id: "lydia.testnet".to_string(),
            stage: Stage::PasskeysAdded { added, proven },
            holders,
            orphaned: None,
        }
    }

    #[test]
    fn two_proven_passkeys_pass_the_gate() {
        let v = view(vec![proven("0saaa"), proven("0sbbb")]);
        assert_eq!(v.independent_proven_count(), 2);
        assert!(v.survives_key_deletion());
        assert!(v.guard_key_deletion().is_ok());
    }

    #[test]
    fn one_proven_passkey_is_refused() {
        let v = view(vec![proven("0saaa")]);
        assert!(!v.survives_key_deletion());
        assert!(matches!(
            v.guard_key_deletion(),
            Err(Refusal::NotEnoughProvenPasskeys {
                proven: 1,
                required: 2,
                ..
            })
        ));
    }

    #[test]
    fn merely_added_passkeys_are_not_proven() {
        // This is the gap the contract's own guard leaves open: two extensions
        // are present and the extension set is non-empty, so the contract is
        // satisfied. Neither has ever signed anything.
        let v = view(vec![
            passkey("0saaa", HolderStatus::Live),
            passkey("0sbbb", HolderStatus::Live),
        ]);
        assert_eq!(v.passkeys().count(), 2);
        assert_eq!(v.independent_proven_count(), 0);
        assert!(matches!(
            v.guard_key_deletion(),
            Err(Refusal::NotEnoughProvenPasskeys { proven: 0, .. })
        ));
    }

    #[test]
    fn the_same_passkey_twice_is_one_passkey() {
        let v = view(vec![proven("0saaa"), proven("0saaa")]);
        assert_eq!(v.proven_count(), 2, "two entries");
        assert_eq!(v.independent_proven_count(), 1, "but one device");
        assert!(matches!(
            v.guard_key_deletion(),
            Err(Refusal::NotEnoughProvenPasskeys { proven: 1, .. })
        ));
    }

    #[test]
    fn an_unreachable_extension_blocks_deletion_even_with_two_proven() {
        let v = view(vec![
            proven("0saaa"),
            proven("0sbbb"),
            passkey(
                "0sccc",
                HolderStatus::Unreachable {
                    reason: "account does not exist".to_string(),
                },
            ),
        ]);
        assert!(matches!(
            v.guard_key_deletion(),
            Err(Refusal::UnreachableExtensions { .. })
        ));
    }

    #[test]
    fn orphaned_storage_converts_to_the_measured_figure() {
        // The check 2 test measured 635 bytes orphaned on a representative
        // account, which is 0.00635 NEAR staked forever.
        let o = OrphanedStorage {
            bytes: 635,
            keys: vec!["STATE".into(), "alpha".into(), "beta".into(), "gamma".into()],
        };
        assert_eq!(o.staked_yocto(), 6_350_000_000_000_000_000_000);
    }

    #[test]
    fn full_access_key_labels_are_abbreviated_not_truncated_to_nothing() {
        let k = HolderKind::FullAccessKey {
            public_key: "ed25519:Hs8WVWVKGVGcFLpFRRCfPhhVNrQ6j8pTzrPEa9Fq5gMz".to_string(),
        };
        let label = k.label();
        assert!(label.starts_with("full access key ed25519:Hs8W"), "{label}");
        assert!(label.ends_with("5gMz"), "{label}");
    }
}
