//! Thine moves an existing NEAR account from seed-phrase control to passkey
//! control, keeping the same account id and without moving any assets.
//!
//! A passkey signs with P-256, which is not a NEAR access key scheme, so
//! passkey control cannot be expressed as an access key. It has to be
//! contract-mediated: the user's own account becomes a `wallet-no-sign`
//! contract that delegates authority to separate passkey-controlled accounts.
//! That single fact determines the whole architecture.
//!
//! This crate holds the parts of that which are worth testing without a
//! network: what the committed contract artefacts are ([`artifacts`]), who can
//! currently open an account ([`authority`]), and what must be true before
//! anything is sent ([`precondition`]).
//!
//! # The safety property this crate exists to enforce
//!
//! The final step of a migration deletes the account's last full access key.
//! The wallet contract's own lockout guard only checks that the extension set
//! is non-empty; it never checks that anything in that set can actually be
//! reached. So the contract will happily let an account be locked forever.
//!
//! Thine therefore refuses to delete keys until at least
//! [`authority::MIN_PROVEN_PASSKEYS`] independent passkeys have each completed
//! a successful `w_execute_signed` — proof that a human can still sign, rather
//! than proof that an entry exists in a set.

pub mod artifacts;
pub mod authority;
pub mod chain;
pub mod precondition;
pub mod proof;

pub use artifacts::Variant;
pub use authority::{
    AuthorityView, Holder, HolderKind, HolderStatus, MIN_PROVEN_PASSKEYS, OrphanedStorage, Refusal,
    Stage,
};
pub use chain::{AccountFacts, Chain, WalletProbe};
pub use precondition::{StateRecord, StateSnapshot};
pub use proof::{ProofLedger, ProofRecord};

/// Ordinary storage staking rate: 1e19 yoctoNEAR per byte.
pub const STORAGE_COST_PER_BYTE: u128 = 10_000_000_000_000_000_000;

/// Render a yoctoNEAR amount as NEAR, for display.
pub fn near_of(yocto: u128) -> f64 {
    yocto as f64 / 1e24
}
