//! Demo sessions: a throwaway testnet account per visitor.
//!
//! The hosted judge path has to let someone run the whole migration with no
//! wallet and no funds of their own. A session gives them an account to do it
//! to: the relayer creates a fresh sub-account of itself, funds it with a few
//! tenths of a NEAR for its own gas, and holds its key for the duration, the
//! same way the local demo holds the key of `lydia.sandbox`. The passkeys the
//! visitor registers are their own device's; the server never sees those.
//!
//! The throwaway's key living server-side is the same deliberate split as the
//! local demo and is stated in the interface copy: steps 1, 3 and 5 are what
//! the user's wallet would sign in a real deployment, and the passkey steps
//! are genuinely the visitor's hardware.

use std::collections::HashMap;

use anyhow::{Context, Result, bail};
use near_kit::{AccountId, Near, NearToken, signer::SecretKey, transaction::Final};
use thine_core::{Chain, ProofLedger, migration::Migration};

use crate::{AppState, Pending};

/// What each demo account is funded with. Covers its own gas for the whole
/// migration many times over; the relayer pays the passkey hops separately.
const SESSION_FUNDING: NearToken = NearToken::from_millinear(300);

/// Everything one visitor's migration touches, behind one lock so a session's
/// steps serialise.
pub struct SessionState {
    pub user: AccountId,
    pub user_client: Near,
    pub migration: Migration,
    pub ledger: ProofLedger,
    pub pending: HashMap<String, Pending>,
    /// The 12 words the demo account's full access key derives from, shown in
    /// the demo so the migration's claim is demonstrable: before, the chain
    /// accepts what this phrase signs; after, it refuses it. `None` in fixed
    /// mode. A real migration never displays anyone's phrase.
    pub seed_phrase: Option<String>,
}

impl SessionState {
    pub fn new(state: &AppState, user: AccountId, user_client: Near) -> Self {
        let migration = Migration::new(
            state.chain.clone(),
            user.clone(),
            state.no_sign_hash,
            state.p256_hash,
        );
        let ledger = ProofLedger::new(user.as_str());
        Self {
            user,
            user_client,
            migration,
            ledger,
            pending: HashMap::new(),
            seed_phrase: None,
        }
    }
}

/// Twelve words, from CSPRNG entropy, exactly as a wallet would make them.
pub fn generate_seed_phrase() -> anyhow::Result<String> {
    use sha2::{Digest, Sha256};
    // The CSPRNG this process already trusts, folded to 128 bits of entropy.
    let seed = SecretKey::generate_ed25519().to_string();
    let digest = Sha256::digest(seed.as_bytes());
    let mnemonic = bip39::Mnemonic::from_entropy(&digest[..16])
        .map_err(|e| anyhow::anyhow!("mnemonic generation: {e}"))?;
    Ok(mnemonic.to_string())
}

/// Create and fund a fresh throwaway account under the relayer.
pub async fn create_demo_account(state: &AppState) -> Result<(AccountId, Near, String)> {
    let created = state
        .sessions_created
        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    if created >= state.session_cap {
        bail!(
            "this demo has handed out its budget of {} accounts; the relayer keeps the rest of \
             its balance for the judge path",
            state.session_cap
        );
    }

    // The account's one full access key derives from a seed phrase at NEAR's
    // standard path, the way a wallet's would, so the demo can show the exact
    // words that open the account and later show the chain refusing them.
    let seed_phrase = generate_seed_phrase()?;
    let secret = SecretKey::from_seed_phrase(&seed_phrase)
        .map_err(|e| anyhow::anyhow!("deriving from the seed phrase: {e}"))?;
    let suffix: u32 = rand_suffix();
    let id: AccountId = format!(
        "d{}{suffix:06}.{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs()
            % 1_000_000,
        state.relayer_id
    )
    .parse()
    .context("derived demo account id is not valid")?;

    let outcome = state
        .relayer
        .transaction(id.clone())
        .create_account()
        .transfer(SESSION_FUNDING)
        .add_full_access_key(secret.public_key())
        .wait_until::<Final>()
        .await
        .with_context(|| format!("creating demo account {id}"))?;
    if !outcome.is_success() {
        bail!("creating demo account {id} failed: {:?}", outcome.status);
    }

    let client = Near::custom(state.rpc.clone(), state.chain_id.clone())
        .credentials(secret.to_string(), id.clone())
        .context("demo account credentials")?
        .build();

    Ok((id, client, seed_phrase))
}

fn rand_suffix() -> u32 {
    // Collision resistance across concurrent visitors, not cryptography: the
    // account id also carries the clock, and creation fails loudly on a clash.
    let mut bytes = [0u8; 4];
    getrandom_fill(&mut bytes);
    u32::from_le_bytes(bytes) % 1_000_000
}

fn getrandom_fill(out: &mut [u8]) {
    use std::time::{SystemTime, UNIX_EPOCH};
    // SecretKey::generate_ed25519 is the real entropy user in this module;
    // this suffix only needs to differ between two visitors in the same
    // second, so a hash of the nanosecond clock and the address of a fresh
    // allocation is enough.
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let unique = Box::new(0u8);
    let addr = &*unique as *const u8 as usize as u64;
    let mix = (u64::from(nanos)).wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ addr.rotate_left(17);
    out.copy_from_slice(&mix.to_le_bytes()[..out.len()]);
}

/// Chain handle for building per-session state outside a request, in tests and
/// at startup.
pub fn chain_of(state: &AppState) -> Chain {
    state.chain.clone()
}
