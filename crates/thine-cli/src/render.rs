//! Text rendering of the authority view, for the command line.
//!
//! The view's real home is the browser, and `thine inspect --json` is the shape
//! that feeds it. This module exists so the same information is legible without
//! one, and so the structure can be checked by a test rather than by eye.
//!
//! Layout only. No colour, no boxes, no opinions about presentation: those
//! decisions belong to the interface.

use thine_core::{
    MIN_PROVEN_PASSKEYS, STORAGE_COST_PER_BYTE,
    authority::{AuthorityView, HolderStatus, Stage},
    near_of,
};

pub fn authority(view: &AuthorityView, network: &str) -> String {
    let mut out = String::new();

    out.push_str(&format!("{}  on {network}\n", view.account_id));
    out.push_str(&format!("{}\n\n", stage_line(&view.stage)));

    out.push_str("Who can open this account\n");
    if view.holders.is_empty() {
        out.push_str("  nobody. This account has no keys and no reachable extensions.\n");
    }
    for holder in &view.holders {
        let (mark, note) = match &holder.status {
            HolderStatus::Present => ("yes", String::new()),
            HolderStatus::Proven { tx_hash } => {
                ("yes", format!("has signed, tx {}", abbreviate(tx_hash)))
            }
            HolderStatus::Live => (
                "untested",
                "reachable, but has never signed; cannot be relied on".to_string(),
            ),
            HolderStatus::Unreachable { reason } => ("NO", reason.clone()),
        };
        out.push_str(&format!("  [{mark:>8}]  {}\n", holder.kind.label()));
        if !note.is_empty() {
            out.push_str(&format!("              {note}\n"));
        }
    }

    // The question the last step turns on.
    let proven = view.independent_proven_count();
    out.push_str("\nIf every key were deleted now\n");
    if view.survives_key_deletion() {
        out.push_str(&format!(
            "  the account stays openable: {proven} independent passkeys have each signed.\n"
        ));
    } else {
        out.push_str(&format!(
            "  the account would be lost. {proven} of {MIN_PROVEN_PASSKEYS} required passkeys \
             have proven they can sign.\n"
        ));
    }

    match view.guard_key_deletion() {
        Ok(()) => out.push_str("  key deletion is permitted.\n"),
        Err(refusal) => out.push_str(&format!("  key deletion is refused: {refusal}\n")),
    }

    if let Some(orphaned) = &view.orphaned {
        out.push_str("\nStorage you keep paying for\n");
        out.push_str(&format!(
            "  {} bytes, {:.6} NEAR staked, in {} key{} nothing can read any more:\n",
            orphaned.bytes,
            near_of(orphaned.bytes as u128 * STORAGE_COST_PER_BYTE),
            orphaned.keys.len(),
            if orphaned.keys.len() == 1 { "" } else { "s" },
        ));
        for key in &orphaned.keys {
            out.push_str(&format!("    {key}\n"));
        }
        out.push_str(
            "  Replacing the account's code frees the old contract's bytes but leaves its data.\n",
        );
        out.push_str("  This stake is not recoverable.\n");
    }

    out
}

fn stage_line(stage: &Stage) -> String {
    match stage {
        Stage::SeedControlled => {
            "Not migrated. Whoever holds the seed phrase holds everything.".to_string()
        }
        Stage::WalletDeployed => {
            "Step 1 done: the account is a wallet contract and signs nothing itself. No passkey \
             has been added."
                .to_string()
        }
        Stage::PasskeysAdded { added, proven } => format!(
            "Steps 2 to 4: {added} passkey{} added, {proven} proven.",
            if *added == 1 { "" } else { "s" }
        ),
        Stage::PasskeyControlled { proven } => format!(
            "Migrated. Passkey controlled by {proven} proven passkey{}; no full access keys \
             remain.",
            if *proven == 1 { "" } else { "s" }
        ),
    }
}

fn abbreviate(s: &str) -> String {
    if s.len() > 12 {
        format!("{}…{}", &s[..6], &s[s.len() - 4..])
    } else {
        s.to_string()
    }
}

#[cfg(test)]
mod tests {
    use thine_core::authority::{Holder, HolderKind, OrphanedStorage};

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

    #[test]
    fn an_unmigrated_account_says_so_and_refuses_deletion() {
        let view = AuthorityView {
            account_id: "lydia.testnet".to_string(),
            stage: Stage::SeedControlled,
            holders: vec![Holder {
                kind: HolderKind::FullAccessKey {
                    public_key: "ed25519:Hs8WVWVKGVGcFLpFRRCfPhhVNrQ6j8pTzrPEa9Fq5gMz".to_string(),
                },
                status: HolderStatus::Present,
            }],
            orphaned: None,
        };
        let out = authority(&view, "testnet");
        assert!(out.contains("Not migrated"), "{out}");
        assert!(out.contains("would be lost"), "{out}");
        assert!(out.contains("refused"), "{out}");
    }

    #[test]
    fn an_untested_passkey_is_not_presented_as_working() {
        let view = AuthorityView {
            account_id: "lydia.testnet".to_string(),
            stage: Stage::PasskeysAdded { added: 1, proven: 0 },
            holders: vec![passkey("0saaa", HolderStatus::Live)],
            orphaned: None,
        };
        let out = authority(&view, "testnet");
        assert!(out.contains("untested"), "{out}");
        assert!(out.contains("never signed"), "{out}");
        assert!(!out.contains("key deletion is permitted"), "{out}");
    }

    #[test]
    fn two_proven_passkeys_report_the_account_as_survivable() {
        let view = AuthorityView {
            account_id: "lydia.testnet".to_string(),
            stage: Stage::PasskeysAdded { added: 2, proven: 2 },
            holders: vec![
                passkey(
                    "0saaa",
                    HolderStatus::Proven {
                        tx_hash: "4KLMnopQRstuVWXyz1234567890abcdefGHIJ".to_string(),
                    },
                ),
                passkey(
                    "0sbbb",
                    HolderStatus::Proven {
                        tx_hash: "9ZYXwvuTSRqpONMlkjihgfedcba0987654321".to_string(),
                    },
                ),
            ],
            orphaned: None,
        };
        let out = authority(&view, "testnet");
        assert!(out.contains("stays openable"), "{out}");
        assert!(out.contains("key deletion is permitted"), "{out}");
    }

    #[test]
    fn orphaned_storage_is_surfaced_with_the_measured_figure() {
        let view = AuthorityView {
            account_id: "lydia.testnet".to_string(),
            stage: Stage::WalletDeployed,
            holders: vec![],
            orphaned: Some(OrphanedStorage {
                bytes: 635,
                keys: vec!["STATE".into(), "alpha".into(), "beta".into(), "gamma".into()],
            }),
        };
        let out = authority(&view, "testnet");
        assert!(out.contains("635 bytes"), "{out}");
        assert!(out.contains("0.006350 NEAR"), "{out}");
        assert!(out.contains("not recoverable"), "{out}");
    }

    #[test]
    fn an_unreachable_extension_is_marked_and_explained() {
        let view = AuthorityView {
            account_id: "lydia.testnet".to_string(),
            stage: Stage::PasskeysAdded { added: 1, proven: 0 },
            holders: vec![passkey(
                "0sccc",
                HolderStatus::Unreachable {
                    reason: "account does not exist".to_string(),
                },
            )],
            orphaned: None,
        };
        let out = authority(&view, "testnet");
        assert!(out.contains("[      NO]"), "{out}");
        assert!(out.contains("account does not exist"), "{out}");
    }
}
