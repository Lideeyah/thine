//! The data contract the interface consumes.
//!
//! This is what `thine inspect --json` emits and what a browser front end reads.
//! **Its shape is frozen.** Adding a field is safe; renaming, removing or
//! retyping one is a breaking change, and [`VIEW_SCHEMA_VERSION`] exists to
//! make that visible rather than silent. The test at the bottom pins the key
//! set at every level, so a change cannot happen by accident.
//!
//! Two conventions, both there because the consumer is JavaScript:
//!
//! - **Every yoctoNEAR amount is an [`Amount`]**, carrying the exact value as a
//!   decimal string and a pre-divided float for display. A yoctoNEAR balance
//!   does not fit in a JavaScript number: 10 NEAR is 1e25, and
//!   `Number.MAX_SAFE_INTEGER` is about 9e15, so a bare integer would arrive
//!   silently wrong. Anything that must be exact uses the string.
//! - **Every refusal carries a stable `code`** as well as its message, so the
//!   interface can branch on the code and show the message, rather than
//!   matching on prose that is free to be reworded.
//!
//! The interface should not have to recompute anything to render this. Derived
//! answers (whether the account survives key deletion, how many passkeys are
//! required, what a step costs) are fields, not exercises.

use serde::Serialize;

use crate::{
    STORAGE_COST_PER_BYTE,
    authority::{AuthorityView, MIN_PROVEN_PASSKEYS, Refusal, Stage},
    chain::AccountFacts,
    plan::Plan,
};

/// Version of the shape below. Bumped only on a breaking change.
pub const VIEW_SCHEMA_VERSION: u32 = 1;

/// A NEAR amount, exact and displayable.
///
/// `yocto` is the authoritative value. `near` is for rendering and is lossy:
/// `1e25 / 1e24` is `10.000000000000002` in a 64-bit float, not `10`.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Amount {
    /// Exact value in yoctoNEAR, as a decimal string.
    pub yocto: String,
    /// The same value in NEAR, for display only.
    pub near: f64,
}

impl Amount {
    pub fn from_yocto(yocto: u128) -> Self {
        Self {
            yocto: yocto.to_string(),
            near: yocto as f64 / 1e24,
        }
    }

    pub fn from_bytes_staked(bytes: u64) -> Self {
        Self::from_yocto(bytes as u128 * STORAGE_COST_PER_BYTE)
    }
}

/// A refusal, in a form the interface can act on.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RefusalInfo {
    /// Stable identifier. Safe to branch on.
    pub code: &'static str,
    /// Human-readable text. Free to be reworded; do not match on it.
    pub message: String,
}

impl From<&Refusal> for RefusalInfo {
    fn from(r: &Refusal) -> Self {
        Self {
            code: r.code(),
            message: r.to_string(),
        }
    }
}

/// Which block the view was read at.
///
/// The interface re-reads between every step, so it needs to be able to tell a
/// stale read from a current one. A step that appears not to have happened
/// because the read was a block early is the exact failure this exists to make
/// visible.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ReadAt {
    pub block_height: u64,
    pub block_hash: String,
}

/// The account itself, independent of whether it is a wallet.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Account {
    pub account_id: String,
    pub exists: bool,
    /// Whether the account has contract code. False for an ordinary account.
    pub has_code: bool,
    pub code_hash: String,
    pub storage_usage_bytes: u64,
    /// What that storage costs to stake.
    pub storage_staked: Amount,
    pub balance: Amount,
}

impl Account {
    fn of(facts: &AccountFacts) -> Self {
        Self {
            account_id: facts.account_id.clone(),
            exists: facts.exists,
            has_code: facts.has_code,
            code_hash: facts.code_hash.clone(),
            storage_usage_bytes: facts.storage_usage,
            storage_staked: Amount::from_bytes_staked(facts.storage_usage),
            balance: Amount::from_yocto(facts.balance_yocto),
        }
    }
}

/// The answers the interface would otherwise have to derive.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Summary {
    /// Passkeys listed as extensions.
    pub passkeys_added: usize,
    /// Of those, how many have proven they can still sign, counted by distinct
    /// account so two entries for one device count once.
    pub passkeys_proven: usize,
    /// How many are required before any key is deleted.
    pub passkeys_required: usize,
    /// Whether the account would still be openable if every full access key
    /// were deleted right now. The question the last step turns on.
    pub survives_key_deletion: bool,
    /// Whether any full access key remains.
    pub has_full_access_key: bool,
    /// Extensions that are listed but cannot be reached. Non-empty here is the
    /// lockout risk the wallet contract does not catch.
    pub unreachable: Vec<String>,
    /// Why key deletion is currently refused, if it is.
    pub key_deletion_refusal: Option<RefusalInfo>,
}

/// Storage the account pays for and nothing can read.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Orphaned {
    pub bytes: u64,
    pub staked: Amount,
    pub keys: Vec<String>,
}

/// What a step costs, measured rather than estimated.
///
/// From the committed tests in `thine-bench`, at protocol version 88, which is
/// what testnet and the sandbox run. Mainnet is at 87, so these are indicative
/// there rather than exact.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct StepCost {
    pub step_id: &'static str,
    pub tgas: f64,
    pub burnt: Amount,
    /// What the figure was measured by, so a reader can re-run it.
    pub measured_by: &'static str,
}

/// Everything the interface needs for one account.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AccountReport {
    pub version: u32,
    pub network: String,
    pub read_at: ReadAt,
    pub account: Account,
    pub authority: AuthorityView,
    pub plan: Plan,
    pub summary: Summary,
    pub orphaned: Option<Orphaned>,
    pub costs: Vec<StepCost>,
}

impl AccountReport {
    pub fn assemble(
        network: impl Into<String>,
        read_at: ReadAt,
        facts: &AccountFacts,
        authority: AuthorityView,
    ) -> Self {
        let plan = Plan::of(&authority);
        let refusal = authority.guard_key_deletion().err();

        let summary = Summary {
            passkeys_added: authority.passkeys().count(),
            passkeys_proven: authority.independent_proven_count(),
            passkeys_required: MIN_PROVEN_PASSKEYS,
            survives_key_deletion: authority.survives_key_deletion(),
            has_full_access_key: authority.has_full_access_key(),
            unreachable: authority.unreachable().map(|h| h.kind.label()).collect(),
            key_deletion_refusal: refusal.as_ref().map(RefusalInfo::from),
        };

        let orphaned = authority.orphaned.as_ref().map(|o| Orphaned {
            bytes: o.bytes,
            staked: Amount::from_bytes_staked(o.bytes),
            keys: o.keys.clone(),
        });

        Self {
            version: VIEW_SCHEMA_VERSION,
            network: network.into(),
            read_at,
            account: Account::of(facts),
            authority,
            plan,
            summary,
            orphaned,
            costs: measured_costs(),
        }
    }
}

/// The measured cost of each step.
pub fn measured_costs() -> Vec<StepCost> {
    vec![
        StepCost {
            step_id: "become-wallet",
            tgas: 2.2886,
            burnt: Amount::from_yocto(207_000_000_000_000_000_000),
            measured_by: "thine-bench --test thine_migration_e2e",
        },
        StepCost {
            step_id: "add-passkeys",
            // Creating the 0s account and authorising it: the state init plus
            // the first w_execute_signed, then AddExtension. Most of the NEAR
            // here is the new account's storage stake, not gas.
            tgas: 12.5626 + 1.8001,
            burnt: Amount::from_yocto(7_514_000_000_000_000_000_000),
            measured_by: "thine-bench --test thine_p256_gas, --test thine_migration_e2e",
        },
        StepCost {
            step_id: "prove-passkeys",
            tgas: 6.3164,
            burnt: Amount::from_yocto(604_000_000_000_000_000_000),
            measured_by: "thine-bench --test thine_p256_gas",
        },
        StepCost {
            step_id: "drop-self-extension",
            tgas: 1.8006,
            burnt: Amount::from_yocto(184_000_000_000_000_000_000),
            measured_by: "thine-bench --test thine_migration_e2e",
        },
        StepCost {
            step_id: "delete-keys",
            tgas: 0.6292,
            burnt: Amount::from_yocto(63_000_000_000_000_000_000),
            measured_by: "thine-bench --test thine_migration_e2e",
        },
    ]
}

/// The stage, as a stable string, for consumers that want one.
pub fn stage_code(stage: &Stage) -> &'static str {
    match stage {
        Stage::SeedControlled => "seed_controlled",
        Stage::WalletDeployed => "wallet_deployed",
        Stage::PasskeysAdded { .. } => "passkeys_added",
        Stage::PasskeyControlled { .. } => "passkey_controlled",
    }
}

#[cfg(test)]
mod tests {
    use crate::authority::{Holder, HolderKind, HolderStatus, OrphanedStorage};

    use super::*;

    fn facts() -> AccountFacts {
        AccountFacts {
            account_id: "lydia.testnet".to_string(),
            exists: true,
            has_code: false,
            code_hash: "11111111111111111111111111111111".to_string(),
            storage_usage: 182,
            balance_yocto: 10_000_000_000_000_000_000_000_000,
        }
    }

    fn authority() -> AuthorityView {
        AuthorityView {
            account_id: "lydia.testnet".to_string(),
            stage: Stage::PasskeysAdded {
                added: 2,
                proven: 1,
            },
            holders: vec![
                Holder {
                    kind: HolderKind::FullAccessKey {
                        public_key: "ed25519:stub".to_string(),
                    },
                    status: HolderStatus::Present,
                },
                Holder {
                    kind: HolderKind::PasskeyExtension {
                        account_id: "0saaa".to_string(),
                        public_key: Some("p256:stub".to_string()),
                    },
                    status: HolderStatus::Proven {
                        tx_hash: "tx".to_string(),
                    },
                },
                Holder {
                    kind: HolderKind::PasskeyExtension {
                        account_id: "0sbbb".to_string(),
                        public_key: Some("p256:stub".to_string()),
                    },
                    status: HolderStatus::Live,
                },
            ],
            orphaned: Some(OrphanedStorage {
                bytes: 635,
                keys: vec!["STATE".into()],
            }),
        }
    }

    fn report() -> AccountReport {
        AccountReport::assemble(
            "testnet",
            ReadAt {
                block_height: 1,
                block_hash: "h".to_string(),
            },
            &facts(),
            authority(),
        )
    }

    /// The shape is frozen. If this test fails, the interface breaks, so the
    /// version must be bumped and Lydia told.
    #[test]
    fn the_contract_shape_is_what_the_interface_was_built_against() {
        let v = serde_json::to_value(report()).unwrap();

        let keys = |value: &serde_json::Value| -> Vec<String> {
            let mut k: Vec<String> = value.as_object().unwrap().keys().cloned().collect();
            k.sort();
            k
        };

        assert_eq!(v["version"], 1, "schema version changed");
        assert_eq!(
            keys(&v),
            [
                "account",
                "authority",
                "costs",
                "network",
                "orphaned",
                "plan",
                "read_at",
                "summary",
                "version",
            ]
        );
        assert_eq!(
            keys(&v["account"]),
            [
                "account_id",
                "balance",
                "code_hash",
                "exists",
                "has_code",
                "storage_staked",
                "storage_usage_bytes",
            ]
        );
        assert_eq!(
            keys(&v["summary"]),
            [
                "has_full_access_key",
                "key_deletion_refusal",
                "passkeys_added",
                "passkeys_proven",
                "passkeys_required",
                "survives_key_deletion",
                "unreachable",
            ]
        );
        assert_eq!(keys(&v["read_at"]), ["block_hash", "block_height"]);
        assert_eq!(keys(&v["orphaned"]), ["bytes", "keys", "staked"]);
        assert_eq!(keys(&v["account"]["balance"]), ["near", "yocto"]);
        assert_eq!(
            keys(&v["costs"][0]),
            ["burnt", "measured_by", "step_id", "tgas"]
        );
        assert_eq!(
            keys(&v["plan"]["steps"][0]),
            [
                "blocked_by",
                "effect",
                "id",
                "irreversible",
                "progress",
                "state",
                "title",
            ]
        );
    }

    #[test]
    fn every_amount_is_a_string_because_javascript_cannot_hold_it() {
        let v = serde_json::to_value(report()).unwrap();

        // 10 NEAR is 1e25. Number.MAX_SAFE_INTEGER is about 9.007e15, so a
        // bare integer here would reach the browser already wrong.
        assert_eq!(
            v["account"]["balance"]["yocto"],
            "10000000000000000000000000"
        );
        assert!(
            v["account"]["balance"]["yocto"].is_string(),
            "exact amounts must be strings"
        );
        assert!(v["account"]["balance"]["near"].is_number());
        assert!(v["orphaned"]["staked"]["yocto"].is_string());
        assert!(v["costs"][0]["burnt"]["yocto"].is_string());
    }

    #[test]
    fn a_function_call_key_serialises_with_its_contract_and_a_string_allowance() {
        let mut a = authority();
        a.holders.push(Holder {
            kind: HolderKind::FunctionCallKey {
                public_key: "ed25519:stub".to_string(),
                receiver_id: "some-dapp.testnet".to_string(),
                method_names: vec!["set_greeting".to_string()],
                allowance_yocto: Some("250000000000000000000000".to_string()),
            },
            status: HolderStatus::Present,
        });
        let r = AccountReport::assemble(
            "testnet",
            ReadAt {
                block_height: 1,
                block_hash: "h".to_string(),
            },
            &facts(),
            a,
        );
        let v = serde_json::to_value(&r).unwrap();
        let fc = v["authority"]["holders"]
            .as_array()
            .unwrap()
            .iter()
            .find(|h| h["kind"]["kind"] == "function_call_key")
            .expect("the function call key must be in the view");
        assert_eq!(fc["kind"]["receiver_id"], "some-dapp.testnet");
        assert_eq!(fc["kind"]["method_names"][0], "set_greeting");
        assert!(
            fc["kind"]["allowance_yocto"].is_string(),
            "the allowance does not fit a JavaScript number, so it is a string"
        );
        // It changes none of the answers.
        assert_eq!(r.summary.passkeys_added, 2);
        assert!(r.summary.has_full_access_key);
    }

    #[test]
    fn a_refusal_carries_a_code_the_interface_can_branch_on() {
        let v = serde_json::to_value(report()).unwrap();
        let refusal = &v["summary"]["key_deletion_refusal"];
        assert_eq!(refusal["code"], "not_enough_proven_passkeys");
        assert!(
            refusal["message"]
                .as_str()
                .unwrap()
                .contains("1 of the 2 required"),
            "{refusal}"
        );
    }

    #[test]
    fn the_summary_answers_are_derived_so_the_interface_does_not_reimplement_them() {
        let r = report();
        assert_eq!(r.summary.passkeys_added, 2);
        assert_eq!(r.summary.passkeys_proven, 1);
        assert_eq!(r.summary.passkeys_required, MIN_PROVEN_PASSKEYS);
        assert!(!r.summary.survives_key_deletion);
        assert!(r.summary.has_full_access_key);
        assert!(r.summary.unreachable.is_empty());
    }

    #[test]
    fn orphaned_storage_carries_the_near_figure_so_the_interface_need_not_know_the_rate() {
        let r = report();
        let o = r.orphaned.unwrap();
        assert_eq!(o.bytes, 635);
        assert_eq!(o.staked.yocto, "6350000000000000000000");
    }

    #[test]
    fn there_is_a_measured_cost_for_every_step_in_the_plan() {
        let r = report();
        for step in &r.plan.steps {
            assert!(
                r.costs.iter().any(|c| c.step_id == step.id),
                "no measured cost for step {}",
                step.id
            );
        }
        assert_eq!(r.costs.len(), r.plan.steps.len());
    }
}
