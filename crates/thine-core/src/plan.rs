//! The migration as a sequence the user moves through, derived from what the
//! chain currently says.
//!
//! This is the other half of the view's data. [`crate::authority::AuthorityView`]
//! answers "who can open this account"; this answers "where am I, what happens
//! next, and which step is the one I cannot undo".
//!
//! It is derived, never stored. Every field comes from the authority view,
//! which comes from the chain, so the sequence cannot drift out of step with
//! reality or claim a step is done when it is not.
//!
//! No presentation decisions are made here: no ordering for display, no
//! wording for buttons, no colour. Titles are plain descriptions of what the
//! step does to the account.

use serde::Serialize;

use crate::authority::{AuthorityView, HolderKind, MIN_PROVEN_PASSKEYS, Stage};

/// A refusal is only worth showing when it is actually what stands in the way.
/// A step the user cannot reach yet is pending, not blocked.
fn blocked_reason(state: StepState, refusal: &Option<crate::authority::Refusal>) -> Option<String> {
    match state {
        StepState::Blocked => refusal.as_ref().map(ToString::to_string),
        _ => None,
    }
}

/// Where a step stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StepState {
    /// Already true on chain.
    Done,
    /// The next thing to do, and nothing prevents it.
    Current,
    /// The next thing to do, but a refusal stands in the way.
    Blocked,
    /// Not reachable yet; an earlier step comes first.
    Pending,
}

/// One step of the migration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Step {
    /// Stable identifier. Safe to key off; the titles are not.
    pub id: &'static str,
    /// What this step does to the account.
    pub title: &'static str,
    /// What changes about who can open the account.
    pub effect: &'static str,
    pub state: StepState,
    /// True for the step after which the account can never be recovered by its
    /// original owner's seed phrase.
    pub irreversible: bool,
    /// Why this step cannot be taken, when `state` is `Blocked`.
    pub blocked_by: Option<String>,
    /// Progress for steps that repeat, as (done, needed).
    pub progress: Option<(usize, usize)>,
}

/// The five steps, with the current one marked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Plan {
    pub account_id: String,
    pub steps: Vec<Step>,
    /// Index into `steps` of the step the user is on, if any remain.
    pub current: Option<usize>,
    /// True once the account is passkey-controlled and nothing is left to do.
    pub complete: bool,
}

impl Plan {
    /// Derive the plan from the authority view.
    pub fn of(view: &AuthorityView) -> Self {
        let proven = view.independent_proven_count();
        let added = view.passkeys().count();
        let has_self_extension = view
            .holders
            .iter()
            .any(|h| matches!(h.kind, HolderKind::SelfExtension));

        let is_wallet = !matches!(view.stage, Stage::SeedControlled);
        let keys_gone = !view.has_full_access_key();

        // Step 1.
        let s1 = Step {
            id: "become-wallet",
            title: "Turn the account into a wallet contract",
            effect: "Nothing changes about who can open it. The account stops signing for \
                     itself and starts delegating, with itself as its only delegate.",
            state: if is_wallet {
                StepState::Done
            } else {
                StepState::Current
            },
            irreversible: false,
            blocked_by: None,
            progress: None,
        };

        // Step 2 and 3 are one thing from the user's point of view: add a
        // passkey. Creating the 0s account and authorising it are separate
        // transactions but never separate decisions.
        let s2 = Step {
            id: "add-passkeys",
            title: "Add passkeys",
            effect: "Each passkey becomes able to act for the account, alongside the seed \
                     phrase. Nothing is taken away.",
            state: if !is_wallet {
                StepState::Pending
            } else if added < MIN_PROVEN_PASSKEYS {
                StepState::Current
            } else {
                StepState::Done
            },
            irreversible: false,
            blocked_by: None,
            progress: Some((added, MIN_PROVEN_PASSKEYS)),
        };

        // Step 4.
        let s3 = Step {
            id: "prove-passkeys",
            title: "Prove each passkey can drive the account",
            effect: "Each passkey signs a real request through the account. This is the only \
                     evidence that a passkey still works; being listed is not.",
            state: if !is_wallet || added == 0 {
                StepState::Pending
            } else if proven < MIN_PROVEN_PASSKEYS {
                StepState::Current
            } else {
                StepState::Done
            },
            irreversible: false,
            blocked_by: None,
            progress: Some((proven, MIN_PROVEN_PASSKEYS)),
        };

        // Step 5, in two parts. The order of these tests matters: an account
        // that is not a wallet yet has no self-extension, and "has no
        // self-extension" must not be mistaken for "already dropped it".
        let refusal = view.guard_key_deletion().err();
        let late_state = |already_done: bool| {
            if !is_wallet {
                StepState::Pending
            } else if already_done {
                StepState::Done
            } else if refusal.is_some() {
                StepState::Blocked
            } else {
                StepState::Current
            }
        };

        let s4_state = late_state(keys_gone || !has_self_extension);
        let s4 = Step {
            id: "drop-self-extension",
            title: "Stop the account delegating to itself",
            effect: "The seed phrase keeps its keys but loses its authority through the \
                     wallet. Still recoverable while a key exists.",
            state: s4_state,
            irreversible: false,
            // A reason is only a reason when it is actually in the way.
            blocked_by: blocked_reason(s4_state, &refusal),
            progress: None,
        };

        let s5_state = late_state(keys_gone);
        let s5 = Step {
            id: "delete-keys",
            title: "Delete every full access key",
            effect: "The seed phrase stops being able to open the account. Only the passkeys \
                     can, and there is no way back.",
            state: s5_state,
            // This is where irreversibility actually falls. Not at step 1,
            // which changes nothing about authority, and not at the previous
            // step, which is still recoverable while a key exists.
            irreversible: true,
            blocked_by: blocked_reason(s5_state, &refusal),
            progress: None,
        };

        let steps = vec![s1, s2, s3, s4, s5];
        let current = steps
            .iter()
            .position(|s| matches!(s.state, StepState::Current | StepState::Blocked));

        Self {
            account_id: view.account_id.clone(),
            complete: steps.iter().all(|s| s.state == StepState::Done),
            steps,
            current,
        }
    }

    /// The step the user is on.
    pub fn current_step(&self) -> Option<&Step> {
        self.current.and_then(|i| self.steps.get(i))
    }

    /// The one step that cannot be undone.
    pub fn irreversible_step(&self) -> &Step {
        self.steps
            .iter()
            .find(|s| s.irreversible)
            .expect("the plan always has exactly one irreversible step")
    }
}

#[cfg(test)]
mod tests {
    use crate::authority::{Holder, HolderKind, HolderStatus, Stage};

    use super::*;

    fn key() -> Holder {
        Holder {
            kind: HolderKind::FullAccessKey {
                public_key: "ed25519:stub".to_string(),
            },
            status: HolderStatus::Present,
        }
    }

    fn self_ext() -> Holder {
        Holder {
            kind: HolderKind::SelfExtension,
            status: HolderStatus::Present,
        }
    }

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
                tx_hash: format!("tx-{id}"),
            },
        )
    }

    fn view(stage: Stage, holders: Vec<Holder>) -> AuthorityView {
        AuthorityView {
            account_id: "lydia.testnet".to_string(),
            stage,
            holders,
            orphaned: None,
        }
    }

    #[test]
    fn exactly_one_step_is_irreversible_and_it_is_key_deletion() {
        let plan = Plan::of(&view(Stage::SeedControlled, vec![key()]));
        assert_eq!(plan.steps.iter().filter(|s| s.irreversible).count(), 1);
        assert_eq!(plan.irreversible_step().id, "delete-keys");
    }

    #[test]
    fn an_unmigrated_account_starts_at_step_one() {
        let plan = Plan::of(&view(Stage::SeedControlled, vec![key()]));
        assert_eq!(plan.current_step().unwrap().id, "become-wallet");
        assert_eq!(plan.steps[0].state, StepState::Current);
        assert_eq!(plan.steps[1].state, StepState::Pending);
        assert!(!plan.complete);
    }

    #[test]
    fn after_step_one_the_next_thing_is_adding_passkeys() {
        let plan = Plan::of(&view(Stage::WalletDeployed, vec![key(), self_ext()]));
        assert_eq!(plan.steps[0].state, StepState::Done);
        assert_eq!(plan.current_step().unwrap().id, "add-passkeys");
        assert_eq!(plan.steps[1].progress, Some((0, 2)));
    }

    #[test]
    fn with_two_added_but_unproven_the_next_thing_is_proving_them() {
        let plan = Plan::of(&view(
            Stage::PasskeysAdded {
                added: 2,
                proven: 0,
            },
            vec![
                key(),
                self_ext(),
                passkey("0saaa", HolderStatus::Live),
                passkey("0sbbb", HolderStatus::Live),
            ],
        ));
        assert_eq!(plan.steps[1].state, StepState::Done);
        assert_eq!(plan.current_step().unwrap().id, "prove-passkeys");
        assert_eq!(plan.steps[2].progress, Some((0, 2)));
    }

    #[test]
    fn the_irreversible_step_is_blocked_and_says_why_until_both_are_proven() {
        let plan = Plan::of(&view(
            Stage::PasskeysAdded {
                added: 2,
                proven: 1,
            },
            vec![
                key(),
                self_ext(),
                proven("0saaa"),
                passkey("0sbbb", HolderStatus::Live),
            ],
        ));
        let last = plan.irreversible_step();
        assert_eq!(last.state, StepState::Blocked);
        let reason = last.blocked_by.as_deref().expect("should say why");
        assert!(reason.contains("1 of 2"), "{reason}");
    }

    #[test]
    fn with_both_proven_the_irreversible_step_becomes_available() {
        let plan = Plan::of(&view(
            Stage::PasskeysAdded {
                added: 2,
                proven: 2,
            },
            vec![key(), self_ext(), proven("0saaa"), proven("0sbbb")],
        ));
        assert_eq!(plan.steps[2].state, StepState::Done);
        assert_eq!(plan.current_step().unwrap().id, "drop-self-extension");
        assert_eq!(plan.irreversible_step().state, StepState::Current);
        assert!(plan.irreversible_step().blocked_by.is_none());
    }

    #[test]
    fn a_migrated_account_has_nothing_left_to_do() {
        let plan = Plan::of(&view(
            Stage::PasskeyControlled { proven: 2 },
            vec![proven("0saaa"), proven("0sbbb")],
        ));
        assert!(plan.complete);
        assert_eq!(plan.current, None);
        assert!(plan.steps.iter().all(|s| s.state == StepState::Done));
    }

    #[test]
    fn an_unmigrated_account_has_no_done_steps_and_no_blocked_reasons() {
        // A live run against testnet showed "Stop the account delegating to
        // itself" as already done on an account that was not a wallet at all,
        // because having no self-extension looked like having dropped it. It
        // also printed a refusal under steps the user could not yet reach.
        let plan = Plan::of(&view(Stage::SeedControlled, vec![key()]));
        assert!(
            !plan.steps.iter().any(|s| s.state == StepState::Done),
            "nothing is done yet: {:?}",
            plan.steps
                .iter()
                .map(|s| (s.id, s.state))
                .collect::<Vec<_>>()
        );
        assert_eq!(plan.steps[3].state, StepState::Pending);
        assert_eq!(plan.steps[4].state, StepState::Pending);
        assert!(
            plan.steps.iter().all(|s| s.blocked_by.is_none()),
            "a pending step is not blocked"
        );
        assert_eq!(plan.current_step().unwrap().id, "become-wallet");
    }

    #[test]
    fn a_reason_is_only_attached_to_a_step_that_is_actually_blocked() {
        let plan = Plan::of(&view(
            Stage::PasskeysAdded {
                added: 2,
                proven: 1,
            },
            vec![
                key(),
                self_ext(),
                proven("0saaa"),
                passkey("0sbbb", HolderStatus::Live),
            ],
        ));
        for step in &plan.steps {
            assert_eq!(
                step.blocked_by.is_some(),
                step.state == StepState::Blocked,
                "{} carries a reason but is {:?}",
                step.id,
                step.state
            );
        }
    }

    #[test]
    fn step_one_is_never_marked_irreversible_even_though_it_replaces_the_code() {
        // It replaces the account's contract, which sounds drastic, but it
        // takes nothing away: the seed phrase still opens the account.
        let plan = Plan::of(&view(Stage::SeedControlled, vec![key()]));
        assert!(!plan.steps[0].irreversible);
    }
}
