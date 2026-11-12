//! Reading an account's real authority off the chain.
//!
//! Everything here is a read. Nothing in this module signs or sends.

use std::collections::BTreeSet;

use anyhow::{Context, Result, anyhow};
use defuse_wallet_sdk::client::WalletContract;
use near_kit::{
    AccountId, CryptoHash, Near,
    rpc::{AccessKeyPermissionView, ActionView, BlockReference, ExecutionStatus, Finality},
    transaction::Final,
};

use crate::{
    authority::{AuthorityView, Holder, HolderKind, HolderStatus, Stage},
    precondition::{StateRecord, StateSnapshot},
    proof::{ProofLedger, ProofRecord},
};

/// The facts about an account that do not depend on it being a wallet.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AccountFacts {
    pub account_id: String,
    pub exists: bool,
    pub has_code: bool,
    pub code_hash: String,
    pub storage_usage: u64,
    pub balance_yocto: u128,
}

/// What happened when we tried to reach a `0s` wallet.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "probe", rename_all = "snake_case")]
pub enum WalletProbe {
    /// It answered `w_public_key`.
    Live { public_key: String },
    /// It did not. The account may not exist, may not be a wallet, or the RPC
    /// may have failed; the reason is carried through verbatim so the view can
    /// show it rather than flattening everything to "broken".
    Unreachable { reason: String },
}

/// A read-only view of a NEAR network.
#[derive(Clone)]
pub struct Chain {
    near: Near,
    network: &'static str,
}

impl Chain {
    pub fn testnet() -> Self {
        Self {
            near: Near::testnet().build(),
            network: "testnet",
        }
    }

    pub fn mainnet() -> Self {
        Self {
            near: Near::mainnet().build(),
            network: "mainnet",
        }
    }

    /// Wrap an existing client, so a signing client or a sandbox can be read
    /// through the same code the CLI uses.
    pub fn with_client(near: Near, network: &'static str) -> Self {
        Self { near, network }
    }

    pub fn network(&self) -> &'static str {
        self.network
    }

    pub fn client(&self) -> &Near {
        &self.near
    }

    pub async fn account_facts(&self, account_id: &AccountId) -> Result<AccountFacts> {
        match self.near.account(account_id.clone()).await {
            Ok(v) => Ok(AccountFacts {
                account_id: account_id.to_string(),
                exists: true,
                // An all-ones code hash is how NEAR reports "no contract".
                has_code: !v.code_hash.is_zero(),
                code_hash: v.code_hash.to_string(),
                storage_usage: v.storage_usage,
                balance_yocto: v.amount.as_yoctonear(),
            }),
            Err(e) => {
                // An account that does not exist yet is the ordinary case, not
                // an error: every passkey address is read before it is created.
                //
                // Which error means that is decided by a typed existence query
                // rather than by matching on the message. An earlier version
                // matched the text, and missed it: the sandbox says "Account
                // not found" where the pattern expected "does not exist", so a
                // freshly derived address came back as a 500 instead of as
                // `exists: false`.
                if !self
                    .near
                    .account_exists(account_id.clone())
                    .await
                    .unwrap_or(false)
                {
                    Ok(AccountFacts {
                        account_id: account_id.to_string(),
                        exists: false,
                        has_code: false,
                        code_hash: String::new(),
                        storage_usage: 0,
                        balance_yocto: 0,
                    })
                } else {
                    Err(anyhow!("view_account {account_id}: {e}"))
                }
            }
        }
    }

    /// Every contract state record on the account, with the block it was read
    /// at.
    ///
    /// The block matters: the interface re-reads between every step, and a read
    /// taken a block early would show the state from before the user's own
    /// action.
    pub async fn state_snapshot_at(
        &self,
        account_id: &AccountId,
    ) -> Result<(StateSnapshot, crate::view::ReadAt)> {
        let result = self
            .near
            .rpc()
            .view_state_all(
                account_id,
                b"",
                0,
                BlockReference::Finality(Finality::Final),
            )
            .await
            .with_context(|| format!("view_state {account_id}"))?;

        let read_at = crate::view::ReadAt {
            block_height: result.block_height,
            block_hash: result.block_hash.to_string(),
        };

        Ok((
            StateSnapshot::new(
                result
                    .into_values()
                    .into_iter()
                    .map(|item| StateRecord {
                        key: item.key,
                        value_len: item.value.len(),
                    })
                    .collect(),
            ),
            read_at,
        ))
    }

    /// Every contract state record on the account.
    ///
    /// This is the `view_state` query with an empty prefix that the migration
    /// precondition turns on.
    pub async fn state_snapshot(&self, account_id: &AccountId) -> Result<StateSnapshot> {
        let result = self
            .near
            .rpc()
            .view_state_all(
                account_id,
                b"",
                0,
                BlockReference::Finality(Finality::Final),
            )
            .await
            .with_context(|| format!("view_state {account_id}"))?;

        Ok(StateSnapshot::new(
            result
                .into_values()
                .into_iter()
                .map(|item| StateRecord {
                    key: item.key,
                    value_len: item.value.len(),
                })
                .collect(),
        ))
    }

    /// Try to reach a `0s` wallet by asking it for its public key.
    ///
    /// This is the check that must pass *before* an extension is added. It
    /// proves the account exists and is a wallet. It does not prove anyone
    /// still holds the passkey; only a `w_execute_signed` does that.
    pub async fn probe_wallet(&self, account_id: &AccountId) -> WalletProbe {
        match self
            .near
            .contract::<WalletContract>(account_id.clone())
            .w_public_key()
            .await
        {
            Ok(public_key) => WalletProbe::Live { public_key },
            Err(e) => WalletProbe::Unreachable {
                reason: short_reason(&e.to_string()),
            },
        }
    }

    pub async fn wallet_extensions(&self, account_id: &AccountId) -> Result<BTreeSet<AccountId>> {
        self.near
            .contract::<WalletContract>(account_id.clone())
            .w_extensions()
            .await
            .with_context(|| format!("w_extensions on {account_id}"))
    }

    pub async fn signature_allowed(&self, account_id: &AccountId) -> Result<bool> {
        self.near
            .contract::<WalletContract>(account_id.clone())
            .w_is_signature_allowed()
            .await
            .with_context(|| format!("w_is_signature_allowed on {account_id}"))
    }

    /// Full access keys currently on the account.
    ///
    /// Includes gas keys with full access: a gas key pays its own gas but can
    /// do everything an ordinary full access key can, so a view of who can
    /// open the account that skipped it would be wrong, and step 5 would
    /// leave it holding the account after claiming the keys were gone.
    pub async fn full_access_keys(&self, account_id: &AccountId) -> Result<Vec<String>> {
        let list = self
            .near
            .access_keys(account_id.clone())
            .await
            .with_context(|| format!("view_access_key_list {account_id}"))?;

        Ok(list
            .keys
            .into_iter()
            .filter(|k| {
                matches!(
                    k.access_key.permission,
                    AccessKeyPermissionView::FullAccess
                        | AccessKeyPermissionView::GasKeyFullAccess { .. }
                )
            })
            .map(|k| k.public_key.to_string())
            .collect())
    }

    /// Every access key on the account, as holders for the authority view:
    /// full access keys with full authority, function call keys with their
    /// contract, methods and remaining allowance. Gas keys map to whichever of
    /// the two their permission grants.
    pub async fn key_holders(&self, account_id: &AccountId) -> Result<(Vec<Holder>, Vec<String>)> {
        let list = self
            .near
            .access_keys(account_id.clone())
            .await
            .with_context(|| format!("view_access_key_list {account_id}"))?;

        let mut holders = Vec::new();
        let mut full_keys = Vec::new();

        for key in list.keys {
            let public_key = key.public_key.to_string();
            let kind = match key.access_key.permission {
                AccessKeyPermissionView::FullAccess
                | AccessKeyPermissionView::GasKeyFullAccess { .. } => {
                    full_keys.push(public_key.clone());
                    HolderKind::FullAccessKey { public_key }
                }
                AccessKeyPermissionView::FunctionCall {
                    allowance,
                    receiver_id,
                    method_names,
                }
                | AccessKeyPermissionView::GasKeyFunctionCall {
                    allowance,
                    receiver_id,
                    method_names,
                    ..
                } => HolderKind::FunctionCallKey {
                    public_key,
                    receiver_id: receiver_id.to_string(),
                    method_names,
                    allowance_yocto: allowance.map(|a| a.as_yoctonear().to_string()),
                },
            };
            holders.push(Holder {
                kind,
                status: HolderStatus::Present,
            });
        }

        Ok((holders, full_keys))
    }

    /// Fetch the WASM a global contract account serves.
    ///
    /// Used to check the artefacts about to be published against the bytes the
    /// live network runs, before anything irreversible happens.
    pub async fn global_contract_code(&self, account_id: &AccountId) -> Result<Vec<u8>> {
        Ok(self
            .near
            .global_contract(account_id.clone())
            .await
            .with_context(|| {
                format!(
                    "fetching the global contract served by {account_id} on {}",
                    self.network
                )
            })?
            .code)
    }

    /// Re-verify a recorded proof against the chain.
    ///
    /// A proof counts only if the transaction it names really exists, really
    /// succeeded, really was a `w_execute_signed` sent to the `0s` account it
    /// claims, **and** produced a successful receipt executed by the user's own
    /// account. That last condition is what makes it proof of the path rather
    /// than proof of a signature: it is the two-hop route that will be the only
    /// route once the full access keys are gone. Anything else is rejected.
    pub async fn verify_proof(&self, record: &ProofRecord, user: &AccountId) -> Result<bool> {
        let tx_hash: CryptoHash = record
            .tx_hash
            .parse()
            .with_context(|| format!("proof tx hash {} is not a hash", record.tx_hash))?;
        let relayer: AccountId = record
            .relayed_by
            .parse()
            .with_context(|| format!("proof relayer {} is not an account id", record.relayed_by))?;

        let outcome = match self
            .near
            .tx_status(&tx_hash, relayer)
            .wait_until::<Final>()
            .await
        {
            Ok(o) => o,
            // A proof we cannot look up does not count, but it is not an error
            // in the tool: the transaction may have been garbage collected.
            Err(_) => return Ok(false),
        };

        if !outcome.is_success() {
            return Ok(false);
        }

        if outcome.transaction.receiver_id.as_str() != record.extension_account_id {
            return Ok(false);
        }

        let is_execute_signed = outcome.transaction.actions.iter().any(|a| {
            matches!(
                a,
                ActionView::FunctionCall { method_name, .. } if method_name == "w_execute_signed"
            )
        });
        if !is_execute_signed {
            return Ok(false);
        }

        // The hop must have landed on the user's account and succeeded there.
        Ok(outcome.receipts_outcome.iter().any(|r| {
            r.outcome.executor_id == *user
                && matches!(r.outcome.status, ExecutionStatus::SuccessValue(_))
        }))
    }

    /// Build the authority view: one picture of who can open this account.
    ///
    /// Every passkey's status is established by reading the chain, not by
    /// trusting the ledger. The ledger only says which transactions to go and
    /// check.
    pub async fn authority_view(
        &self,
        account_id: &AccountId,
        ledger: &ProofLedger,
    ) -> Result<AuthorityView> {
        let facts = self.account_facts(account_id).await?;
        if !facts.exists {
            return Err(anyhow!(
                "account {account_id} does not exist on {}",
                self.network
            ));
        }

        let snapshot = self.state_snapshot(account_id).await?;
        let (mut holders, full_keys) = self.key_holders(account_id).await?;

        // Is this already a wallet? If w_extensions answers, it is.
        let extensions = self.wallet_extensions(account_id).await.ok();

        let stage = match &extensions {
            None => Stage::SeedControlled,
            Some(exts) => {
                let mut added = 0usize;
                let mut proven = 0usize;

                for ext in exts {
                    if ext == account_id {
                        holders.push(Holder {
                            kind: HolderKind::SelfExtension,
                            status: if full_keys.is_empty() {
                                HolderStatus::Unreachable {
                                    reason: "the account has no full access keys left, so this \
                                             entry grants nobody anything"
                                        .to_string(),
                                }
                            } else {
                                HolderStatus::Present
                            },
                        });
                        continue;
                    }

                    added += 1;
                    let probe = self.probe_wallet(ext).await;
                    let (public_key, status) = match probe {
                        WalletProbe::Unreachable { reason } => {
                            (None, HolderStatus::Unreachable { reason })
                        }
                        WalletProbe::Live { public_key } => {
                            // Live. Now: has it ever actually signed?
                            let verified = match ledger.for_account(ext.as_str()) {
                                None => None,
                                Some(record) => {
                                    if self.verify_proof(record, account_id).await.unwrap_or(false)
                                    {
                                        Some(record.tx_hash.clone())
                                    } else {
                                        None
                                    }
                                }
                            };
                            match verified {
                                Some(tx_hash) => {
                                    proven += 1;
                                    (Some(public_key), HolderStatus::Proven { tx_hash })
                                }
                                None => (Some(public_key), HolderStatus::Live),
                            }
                        }
                    };

                    holders.push(Holder {
                        kind: HolderKind::PasskeyExtension {
                            account_id: ext.to_string(),
                            public_key,
                        },
                        status,
                    });
                }

                let self_listed = exts.contains(account_id);
                if !self_listed && full_keys.is_empty() {
                    Stage::PasskeyControlled { proven }
                } else if added == 0 {
                    Stage::WalletDeployed
                } else {
                    Stage::PasskeysAdded { added, proven }
                }
            }
        };

        // The screen shows how much power each holder has, so power is the
        // order: full access keys, then the self-extension, then passkey
        // extensions, then function call keys. The sort is stable, so holders
        // of equal rank keep the chain's own order.
        holders.sort_by_key(|h| h.kind.authority_rank());

        Ok(AuthorityView {
            account_id: account_id.to_string(),
            stage,
            holders,
            orphaned: snapshot.orphaned(),
        })
    }
}

impl Chain {
    /// Everything the interface needs for one account, in the frozen shape.
    pub async fn account_report(
        &self,
        account_id: &AccountId,
        ledger: &ProofLedger,
    ) -> Result<crate::view::AccountReport> {
        let facts = self.account_facts(account_id).await?;
        if !facts.exists {
            return Err(anyhow!(
                "account {account_id} does not exist on {}",
                self.network
            ));
        }
        let (_, read_at) = self.state_snapshot_at(account_id).await?;
        let authority = self.authority_view(account_id, ledger).await?;

        Ok(crate::view::AccountReport::assemble(
            self.network,
            read_at,
            &facts,
            authority,
        ))
    }
}

/// RPC errors arrive as long nested strings. Keep the useful part.
fn short_reason(msg: &str) -> String {
    for marker in [
        "does not exist",
        "MethodNotFound",
        "CodeDoesNotExist",
        "is not initialized",
        "UNKNOWN_ACCOUNT",
    ] {
        if msg.contains(marker) {
            return match marker {
                "does not exist" | "UNKNOWN_ACCOUNT" => "account does not exist".to_string(),
                "MethodNotFound" => "not a wallet contract (no w_public_key)".to_string(),
                "CodeDoesNotExist" => "account has no contract".to_string(),
                _ => "wallet state is not initialised".to_string(),
            };
        }
    }
    let one_line: String = msg.split_whitespace().collect::<Vec<_>>().join(" ");
    one_line.chars().take(160).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rpc_noise_is_reduced_to_something_showable() {
        assert_eq!(
            short_reason("handler error: account thing.testnet does not exist while viewing"),
            "account does not exist"
        );
        assert_eq!(
            short_reason("wasm execution failed: MethodNotFound"),
            "not a wallet contract (no w_public_key)"
        );
        assert_eq!(short_reason("CodeDoesNotExist"), "account has no contract");
    }

    #[test]
    fn an_unrecognised_error_is_kept_but_bounded() {
        let long = "x ".repeat(400);
        let out = short_reason(&long);
        assert!(out.len() <= 160, "got {} chars", out.len());
    }
}
