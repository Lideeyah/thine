//! The five steps, and the refusals in front of them.
//!
//! Each step is a separate method that sends one transaction, because the user
//! moves through them one at a time and the authority view has to be re-read
//! between each. Nothing here batches steps together.
//!
//! The guards are not advice. Every one of them returns `Err` and sends
//! nothing.

use anyhow::{Context, Result, bail};
use std::sync::Arc;

use defuse_wallet_sdk::{
    Gas, NearPromise, NearToken, Request, RequestMessage, Wallet, WalletBuilder, WalletOp,
    actions::FunctionCall,
    client::{WExecuteExtensionArgs, WalletContract},
    relayer::{WalletRelayRequest, WalletRelayer},
};
use defuse_wallet_webauthn::crypto::p256::P256CompressedPublicKey;
use defuse_wallet_webauthn::{WalletWebauthn, p256::P256, webauthn::IgnoreUserVerification};
use near_kit::{AccountId, CryptoHash, Near, rpc::FinalExecutionOutcome, transaction::Final};

use crate::{
    authority::Refusal,
    chain::{Chain, WalletProbe},
    proof::{ProofLedger, ProofRecord, RemovalKind, RemovalRecord},
    webauthn::BrowserPasskey,
};

/// The signature schema a passkey-controlled `0s` wallet runs.
///
/// `IgnoreUserVerification` because the FIDO U2F authenticators on older
/// hardware keys set only the User Present flag and never User Verified. This
/// matches the variant NEAR publishes.
pub type PasskeySchema = WalletWebauthn<P256, IgnoreUserVerification>;

/// A passkey-controlled wallet handle.
pub type PasskeyWallet = Wallet<PasskeySchema>;

/// Which shape of request a browser passkey is being asked to sign.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningRoute {
    /// Signed for the `0s` wallet itself. Creates the account.
    Direct,
    /// Signed to travel on to the user account. Proves the route.
    ThroughUser,
}

/// What one step did.
#[derive(Debug, Clone)]
pub struct StepOutcome {
    pub step: &'static str,
    pub tx_hash: String,
    pub gas_burnt: u64,
    pub near_burnt: u128,
    /// Every log line the transaction emitted. The wallet contract emits an
    /// event per operation, so this is what actually happened rather than what
    /// was asked for.
    pub logs: Vec<String>,
}

impl StepOutcome {
    pub fn tgas(&self) -> f64 {
        self.gas_burnt as f64 / 1e12
    }
}

/// Drives one account's migration.
pub struct Migration {
    chain: Chain,
    user: AccountId,
    no_sign_code_hash: CryptoHash,
    p256_code_hash: [u8; 32],
}

impl Migration {
    pub fn new(
        chain: Chain,
        user: AccountId,
        no_sign_code_hash: CryptoHash,
        p256_code_hash: [u8; 32],
    ) -> Self {
        Self {
            chain,
            user,
            no_sign_code_hash,
            p256_code_hash,
        }
    }

    pub fn user(&self) -> &AccountId {
        &self.user
    }

    pub fn chain(&self) -> &Chain {
        &self.chain
    }

    /// The `wallet-webauthn-p256` code hash passkey wallets are derived from.
    /// Callers need it to build a [`PasskeyWallet`] before the account exists.
    pub fn p256_code_hash(&self) -> [u8; 32] {
        self.p256_code_hash
    }

    /// Step 1. The account becomes a wallet that signs nothing itself.
    ///
    /// `UseGlobalContract` and a `FunctionCall` to `w_init` go out in one
    /// receipt, signed by the account's existing full access key. `w_init` sets
    /// `signature_enabled = false` and adds the account as its own only
    /// extension, so authority is unchanged at this point: whoever holds a full
    /// access key still holds everything.
    ///
    /// Refuses if the account's contract already occupies the empty storage
    /// key, which is where the wallet keeps its own state.
    pub async fn step1_become_wallet(&self, user_client: &Near) -> Result<StepOutcome> {
        // Hard refusal, before anything is sent.
        let snapshot = self.chain.state_snapshot(&self.user).await?;
        snapshot.check()?;

        let outcome = user_client
            .deploy_from(self.no_sign_code_hash)
            .add_action(
                near_kit::transaction::FunctionCall::new("w_init")
                    .gas(Gas::from_tgas(10))
                    .deposit(NearToken::from_yoctonear(1)),
            )
            .wait_until::<Final>()
            .await
            .context("step 1: UseGlobalContract + w_init")?;

        if !outcome.is_success() {
            bail!("step 1 failed: {:?}", outcome.status);
        }
        settle(user_client, &outcome).await?;
        Ok(summarise("1: become a wallet", &outcome))
    }

    /// Step 2. Derive and create a passkey-controlled `0s` account.
    ///
    /// The account id is a NEP-616 deterministic address derived from the
    /// contract code and the initial state, so it is fixed by the passkey's
    /// public key before anything is sent. It is created by
    /// `DeterministicStateInit` with zero balance, which stays inside the
    /// NEP-448 zero-balance limit of 770 bytes.
    ///
    /// This also performs the wallet's first `w_execute_signed`, which is the
    /// first evidence the passkey can sign at all. It is not yet proof of the
    /// path that will matter: see [`Self::step4_prove_passkey`].
    pub async fn step2_create_passkey_wallet(&self, passkey: &PasskeyWallet) -> Result<AccountId> {
        passkey
            .initialize()
            .await
            .context("step 2: creating the passkey wallet account")?;
        Ok(passkey.real_account_id().clone())
    }

    /// Step 3. Authorise a passkey as an extension of the user's account.
    ///
    /// Refuses unless the `0s` account is live and answers `w_public_key`.
    /// Adding an extension that cannot be reached is how an account gets
    /// locked, and the contract will not stop you: `AddExtension` does not
    /// check that its argument exists.
    pub async fn step3_add_extension(
        &self,
        user_client: &Near,
        passkey_account: &AccountId,
    ) -> Result<StepOutcome> {
        // Hard refusal: never add an extension we cannot reach.
        match self.chain.probe_wallet(passkey_account).await {
            WalletProbe::Live { .. } => {}
            WalletProbe::Unreachable { reason } => {
                return Err(Refusal::ExtensionNotLive {
                    account_id: passkey_account.to_string(),
                    reason,
                }
                .into());
            }
        }

        let outcome = user_client
            .contract::<WalletContract>(self.user.clone())
            .w_execute_extension(
                Request::new()
                    .internal([WalletOp::AddExtension {
                        account_id: passkey_account.clone(),
                    }])
                    .into(),
            )
            .deposit(NearToken::from_yoctonear(1))
            .await
            .context("step 3: AddExtension")?;

        if !outcome.is_success() {
            bail!("step 3 failed: {:?}", outcome.status);
        }
        settle(user_client, &outcome).await?;
        Ok(summarise("3: authorise a passkey", &outcome))
    }

    /// Step 4. Prove the passkey can drive the account.
    ///
    /// A `w_execute_signed` on the `0s` wallet carrying a promise to the user
    /// account's `w_execute_extension`. This is deliberately the full two-hop
    /// path, not a bare signature: it exercises exactly the route that will be
    /// the only route once the full access keys are gone. A passkey that can
    /// sign but whose extension entry is wrong would pass a weaker test and
    /// fail here, which is the entire point.
    ///
    /// The returned record is a pointer to the transaction. It is re-verified
    /// against the chain before it ever counts.
    pub async fn step4_prove_passkey(
        &self,
        passkey: &PasskeyWallet,
        relayer_id: &AccountId,
    ) -> Result<(StepOutcome, ProofRecord)> {
        let passkey_account = passkey.real_account_id().clone();

        // A no-op request routed through the user account. It changes nothing;
        // succeeding is the whole payload.
        let sent = passkey
            .clone()
            .as_extension_of(self.user.clone())
            .sign_and_send(Request::new())
            .await
            .context("step 4: signing the proof request")?;

        let outcome = sent
            .status(self.chain.client())
            .wait_until::<Final>()
            .await
            .context("step 4: waiting for the proof transaction")?;

        if !outcome.is_success() {
            bail!(
                "step 4 failed: the passkey could not drive the account: {:?}",
                outcome.status
            );
        }

        // The user account must actually have executed something, or the hop
        // did not happen.
        let reached_user = outcome
            .receipts_outcome
            .iter()
            .any(|r| r.outcome.executor_id == self.user);
        if !reached_user {
            bail!(
                "step 4 failed: the transaction succeeded but never reached {}",
                self.user
            );
        }

        let record = ProofRecord {
            extension_account_id: passkey_account.to_string(),
            tx_hash: outcome.transaction_hash().to_string(),
            relayed_by: relayer_id.to_string(),
            recorded_at: crate::now_rfc3339(),
        };

        Ok((summarise("4: prove a passkey", &outcome), record))
    }

    /// Step 5. Make it final: remove the self-extension, then delete every full
    /// access key.
    ///
    /// Irreversible. Refuses unless at least
    /// [`crate::authority::MIN_PROVEN_PASSKEYS`] independent passkeys have each
    /// completed step 4, verified against the chain rather than taken from the
    /// ledger, and refuses if any listed extension is unreachable.
    /// Also returns a [`RemovalRecord`] per holder removed, pointing at the
    /// transaction that removed it, so the view can later render the removal
    /// from chain evidence rather than from memory.
    pub async fn step5_finalise(
        &self,
        user_client: &Near,
        ledger: &ProofLedger,
    ) -> Result<(Vec<StepOutcome>, Vec<RemovalRecord>)> {
        let (mut outcomes, mut removals) = self.step5_remove_self_hold(user_client, ledger).await?;
        let (more_outcomes, more_removals) = self.step5_delete_keys(user_client, ledger).await?;
        outcomes.extend(more_outcomes);
        removals.extend(more_removals);
        Ok((outcomes, removals))
    }

    /// Step 5, first part: the account stops delegating to itself.
    ///
    /// Still recoverable while a key exists, but gated exactly as hard as the
    /// deletion, because its only purpose is to be followed by it.
    pub async fn step5_remove_self_hold(
        &self,
        user_client: &Near,
        ledger: &ProofLedger,
    ) -> Result<(Vec<StepOutcome>, Vec<RemovalRecord>)> {
        // Hard refusal. Re-read the chain; do not trust a cached view.
        let view = self.chain.authority_view(&self.user, ledger).await?;
        view.guard_key_deletion()?;

        let mut outcomes = Vec::new();
        let mut removals = Vec::new();

        // Remove the account as its own extension. After this, full access keys
        // still exist but no longer carry wallet authority.
        let outcome = user_client
            .contract::<WalletContract>(self.user.clone())
            .w_execute_extension(
                Request::new()
                    .internal([WalletOp::RemoveExtension {
                        account_id: self.user.clone(),
                    }])
                    .into(),
            )
            .deposit(NearToken::from_yoctonear(1))
            .await
            .context("step 5: RemoveExtension")?;
        if !outcome.is_success() {
            bail!("step 5 (RemoveExtension) failed: {:?}", outcome.status);
        }
        settle(user_client, &outcome).await?;
        removals.push(RemovalRecord {
            kind: RemovalKind::RemoveExtension,
            subject: self.user.to_string(),
            tx_hash: outcome.transaction_hash().to_string(),
            signer_id: outcome.transaction.signer_id.to_string(),
            recorded_at: crate::now_rfc3339(),
        });
        outcomes.push(summarise("5a: drop the self-extension", &outcome));
        Ok((outcomes, removals))
    }

    /// Step 5, second part: delete every full access key. Irreversible.
    pub async fn step5_delete_keys(
        &self,
        user_client: &Near,
        ledger: &ProofLedger,
    ) -> Result<(Vec<StepOutcome>, Vec<RemovalRecord>)> {
        // The same hard refusal, re-read again: the gate holds for each part
        // on the chain's current state, not on what the last part saw.
        let view = self.chain.authority_view(&self.user, ledger).await?;
        view.guard_key_deletion()?;

        let keys = self.chain.full_access_keys(&self.user).await?;
        if keys.is_empty() {
            bail!(
                "{} has no full access keys left; step 5 is already done",
                self.user
            );
        }

        let mut outcomes = Vec::new();
        let mut removals = Vec::new();

        // The keys themselves.
        for key in &keys {
            let public_key: near_kit::signer::PublicKey = key
                .parse()
                .with_context(|| format!("{key} is not a public key"))?;
            let outcome = user_client
                .transaction(self.user.clone())
                .delete_key(public_key)
                .wait_until::<Final>()
                .await
                .with_context(|| format!("step 5: DeleteKey {key}"))?;
            if !outcome.is_success() {
                bail!("step 5 (DeleteKey {key}) failed: {:?}", outcome.status);
            }
            settle(user_client, &outcome).await?;
            removals.push(RemovalRecord {
                kind: RemovalKind::DeleteKey,
                subject: key.clone(),
                tx_hash: outcome.transaction_hash().to_string(),
                signer_id: outcome.transaction.signer_id.to_string(),
                recorded_at: crate::now_rfc3339(),
            });
            outcomes.push(summarise("5b: delete a full access key", &outcome));
        }

        Ok((outcomes, removals))
    }

    /// Build a wallet handle for a passkey held in a browser, from its public
    /// key alone.
    ///
    /// The `0s` account id this derives is fixed by the public key and the
    /// contract code, so it can be shown to the user before the account
    /// exists.
    pub fn browser_passkey_wallet(
        &self,
        public_key: P256CompressedPublicKey,
        relayer: &Near,
    ) -> (PasskeyWallet, Arc<BrowserPasskey>) {
        let passkey = Arc::new(BrowserPasskey::new(public_key));
        let wallet = WalletBuilder::new()
            .build(self.p256_code_hash, Arc::clone(&passkey))
            .with_client(relayer.clone())
            .with_relayer(relayer.clone());
        (wallet, passkey)
    }

    /// Get the exact message a browser passkey must sign, and its challenge.
    ///
    /// The message is built by the SDK, not by us, so nonce generation and the
    /// recursive extension wrapping cannot drift from what the contract
    /// expects. [`BrowserPasskey`] captures it and declines to sign, which is
    /// the mechanism rather than a failure.
    ///
    /// `route` decides the shape, and the two are not interchangeable:
    ///
    /// - [`SigningRoute::Direct`] signs for the `0s` wallet itself. This is
    ///   what creates the account, and it is the only shape that works before
    ///   the passkey has been authorised, because a routed request would be
    ///   refused by a user account that does not yet list it.
    /// - [`SigningRoute::ThroughUser`] signs a request that travels on to the
    ///   user account's `w_execute_extension`. That is the two-hop path which
    ///   will be the only path after step 5, so it is the shape that proves
    ///   anything.
    pub async fn capture_signing_request(
        &self,
        wallet: &PasskeyWallet,
        passkey: &BrowserPasskey,
        route: SigningRoute,
    ) -> Result<(RequestMessage, [u8; 32])> {
        let handle = match route {
            SigningRoute::Direct => wallet.clone(),
            SigningRoute::ThroughUser => wallet.clone().as_extension_of(self.user.clone()),
        };

        if handle.sign(Request::new()).await.is_ok() {
            bail!(
                "a browser passkey produced a signature locally, which should be impossible; \
                 refusing to continue"
            );
        }

        let msg = passkey.captured().ok_or_else(|| {
            anyhow::anyhow!("the SDK did not hand the passkey a request message to capture")
        })?;

        let hash = msg.hash();
        Ok((msg, hash))
    }

    /// Phase 2 of step 4: submit what the browser signed.
    ///
    /// `create_account` initialises the `0s` account in the same transaction,
    /// which is needed only the first time a passkey is used. Submission goes
    /// through the SDK's own relayer, which validates the chain id, checks the
    /// state init derives the account being called, attaches the right deposit
    /// and gas, and refuses an expired message.
    pub async fn submit_browser_proof(
        &self,
        relayer: &Near,
        wallet: &PasskeyWallet,
        msg: RequestMessage,
        proof: String,
        create_account: bool,
        require_reaching_user: bool,
    ) -> Result<(StepOutcome, ProofRecord)> {
        let passkey_account = wallet.real_account_id().clone();

        let mut request = WalletRelayRequest::new(msg, proof);
        if create_account {
            request = request.deterministic_state_init(wallet.deterministic_state_init().clone());
        }

        let sent = relayer
            .relay_wallet_msg(request)
            .await
            .map_err(|e| anyhow::anyhow!("relaying the browser-signed request: {e}"))?;

        let outcome = sent
            .status(relayer)
            .wait_until::<Final>()
            .await
            .context("waiting for the browser-signed transaction")?;

        if !outcome.is_success() {
            bail!(
                "the passkey could not drive the account: {:?}",
                outcome.status
            );
        }

        // Same condition as the local path: for a routed request the hop must
        // have landed on the user's account, or the passkey has proven a
        // signature rather than a route. Creating the `0s` account is not
        // routed and is not held to this.
        if require_reaching_user {
            let reached_user = outcome
                .receipts_outcome
                .iter()
                .any(|r| r.outcome.executor_id == self.user);
            if !reached_user {
                bail!(
                    "the transaction succeeded but never reached {}, so this is not proof that \
                     the passkey can drive the account",
                    self.user
                );
            }
        }

        let record = ProofRecord {
            extension_account_id: passkey_account.to_string(),
            tx_hash: outcome.transaction_hash().to_string(),
            relayed_by: relayer.account_id().to_string(),
            recorded_at: crate::now_rfc3339(),
        };

        Ok((summarise("4: prove a passkey (browser)", &outcome), record))
    }

    /// The promise shape step 4 proves, exposed so the benchmark and the view
    /// can describe the same thing.
    pub fn proof_request(&self) -> NearPromise {
        NearPromise::new(self.user.clone()).function_call(
            FunctionCall::name("w_execute_extension")
                .attach_deposit(NearToken::from_yoctonear(1))
                .args_json(WExecuteExtensionArgs::from(Request::new()))
                .gas(Gas::from_tgas(10)),
        )
    }
}

/// Wait until a transaction is final.
///
/// The typed contract client returns as soon as the call has executed, which is
/// not the same as final. Reads at final finality then miss it, and since the
/// user is shown the authority view between every step, a step that returned
/// early would show them the state before their own action. So each step
/// settles before it returns.
async fn settle(client: &Near, outcome: &FinalExecutionOutcome) -> Result<()> {
    client
        .tx_status(
            outcome.transaction_hash(),
            outcome.transaction.signer_id.clone(),
        )
        .wait_until::<Final>()
        .await
        .context("waiting for the transaction to become final")?;
    Ok(())
}

fn summarise(step: &'static str, outcome: &FinalExecutionOutcome) -> StepOutcome {
    let near_burnt = outcome
        .transaction_outcome
        .outcome
        .tokens_burnt
        .as_yoctonear()
        + outcome
            .receipts_outcome
            .iter()
            .map(|r| r.outcome.tokens_burnt.as_yoctonear())
            .sum::<u128>();

    StepOutcome {
        step,
        tx_hash: outcome.transaction_hash().to_string(),
        gas_burnt: outcome.total_gas_used().as_gas(),
        near_burnt,
        logs: outcome.logs().map(str::to_owned).collect(),
    }
}

/// Derive the `0s` account id a passkey will control, without sending anything.
///
/// Useful for showing the user the address before it exists.
pub fn derive_passkey_account(wallet: &PasskeyWallet) -> &AccountId {
    wallet.real_account_id()
}
