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
pub mod migration;
pub mod plan;
pub mod precondition;
pub mod proof;
pub mod view;
pub mod webauthn;

pub use artifacts::Variant;
pub use authority::{
    AuthorityView, Holder, HolderKind, HolderStatus, MIN_PROVEN_PASSKEYS, OrphanedStorage, Refusal,
    Stage,
};
pub use chain::{AccountFacts, Chain, WalletProbe};
pub use plan::{Plan, Step, StepState};
pub use precondition::{StateRecord, StateSnapshot};
pub use proof::{ProofLedger, ProofRecord};
pub use view::{AccountReport, Amount, VIEW_SCHEMA_VERSION};

/// Ordinary storage staking rate: 1e19 yoctoNEAR per byte.
pub const STORAGE_COST_PER_BYTE: u128 = 10_000_000_000_000_000_000;

/// Render a yoctoNEAR amount as NEAR, for display.
pub fn near_of(yocto: u128) -> f64 {
    yocto as f64 / 1e24
}

/// An RFC 3339 timestamp, for local records. Display only; never trusted.
pub fn now_rfc3339() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let (days, rem) = ((secs / 86_400) as i64, secs % 86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = era * 400 + yoe + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_timestamp_is_a_plausible_rfc3339_instant() {
        let s = super::now_rfc3339();
        assert_eq!(s.len(), 20, "{s}");
        assert!(s.ends_with('Z'), "{s}");
        let year: i32 = s[..4].parse().expect("year");
        assert!((2026..2100).contains(&year), "{s}");
        assert_eq!(&s[4..5], "-");
        assert_eq!(&s[10..11], "T");
    }

    #[test]
    fn near_of_converts_yocto_at_the_right_scale() {
        // The faucet grant, which an earlier measuring script got wrong by a
        // factor of a thousand by dividing at 1e21 instead of 1e24. Compared
        // with a tolerance: 1e25 / 1e24 is 10.000000000000002 in f64, not 10,
        // which is why this conversion is for display only and every amount
        // that has to be exact stays in yoctoNEAR as a u128.
        assert!((super::near_of(10_000_000_000_000_000_000_000_000) - 10.0).abs() < 1e-9);
        assert!((super::near_of(super::STORAGE_COST_PER_BYTE) - 1e-5).abs() < 1e-18);
        // The scale that matters: a thousand times off would show 10,000.
        assert!(super::near_of(10_000_000_000_000_000_000_000_000) < 11.0);
    }
}
