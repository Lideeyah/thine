//! Recent activity for an account, so its past is legible inside the product
//! rather than on an explorer tab.
//!
//! The node cannot answer this: RPC proves any transaction it is handed but
//! cannot enumerate an account's transactions. Enumeration is what indexers
//! exist for, so these rows come from the NearBlocks indexer for the
//! network. That makes them display, not evidence: every hash shown here can
//! be taken to the archival RPC or an explorer and checked, and the product's
//! own claims (the holder rows, the removals) never rest on this module. When
//! the indexer is unreachable, or the network has none, the section is
//! absent; nothing is guessed and nothing is read from local memory.

use std::{
    collections::HashMap,
    sync::{Mutex, OnceLock},
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use axum::{
    Json,
    extract::{Path, State},
};
use serde::Serialize;
use std::sync::Arc;

use crate::AppState;
use crate::api::ApiError;

#[derive(Clone, Serialize)]
pub struct HistoryRow {
    pub hash: String,
    /// RFC 3339, from the indexer's block timestamp. Display only.
    pub when: String,
    /// What happened, composed from the transaction's actions.
    pub what: String,
    /// The other account involved, when there is one.
    pub counterparty: Option<String>,
}

#[derive(Clone, Serialize)]
pub struct History {
    pub account_id: String,
    /// Where the rows came from, stated so the page can say so.
    pub source: String,
    pub rows: Vec<HistoryRow>,
}

/// The indexer is rate limited and the page re-reads the view after every
/// step, so answers are held briefly.
const CACHE_FOR: Duration = Duration::from_secs(20);

fn cache() -> &'static Mutex<HashMap<String, (Instant, History)>> {
    static CACHE: OnceLock<Mutex<HashMap<String, (Instant, History)>>> = OnceLock::new();
    CACHE.get_or_init(Default::default)
}

pub async fn history(
    State(state): State<Arc<AppState>>,
    Path(account_id): Path<String>,
) -> Result<Json<History>, ApiError> {
    let host = match state.chain_id.as_str() {
        "testnet" => "api-testnet.nearblocks.io",
        "mainnet" => "api.nearblocks.io",
        other => {
            return Err(anyhow::anyhow!("no indexer serves the {other} network").into());
        }
    };

    if let Some((at, held)) = cache().lock().expect("poisoned").get(&account_id)
        && at.elapsed() < CACHE_FOR
    {
        return Ok(Json(held.clone()));
    }

    let fetched = fetch(host, &account_id).await?;
    cache()
        .lock()
        .expect("poisoned")
        .insert(account_id, (Instant::now(), fetched.clone()));
    Ok(Json(fetched))
}

#[derive(serde::Deserialize)]
struct Page {
    #[serde(default)]
    txns: Vec<Txn>,
}

#[derive(serde::Deserialize)]
struct Txn {
    transaction_hash: Option<String>,
    predecessor_account_id: Option<String>,
    receiver_account_id: Option<String>,
    block_timestamp: Option<String>,
    #[serde(default)]
    actions: Vec<Action>,
}

#[derive(serde::Deserialize)]
struct Action {
    action: Option<String>,
    method: Option<String>,
}

async fn fetch(host: &str, account_id: &str) -> Result<History> {
    let url = format!("https://{host}/v1/account/{account_id}/txns?per_page=25");
    let page: Page = reqwest::Client::new()
        .get(&url)
        .header("accept", "application/json")
        .timeout(Duration::from_secs(8))
        .send()
        .await
        .context("reaching the indexer")?
        .error_for_status()
        .context("the indexer's answer")?
        .json()
        .await
        .context("reading the indexer's answer")?;

    // The indexer lists receipt-level rows: one transaction can appear
    // several times, and gas refunds arrive from `system`. Refunds are
    // dropped; the rest merge by transaction hash, keeping the indexer's
    // newest-first order.
    let mut order: Vec<String> = Vec::new();
    let mut by_hash: HashMap<String, Vec<&Txn>> = HashMap::new();
    for t in &page.txns {
        let Some(hash) = t.transaction_hash.as_deref() else {
            continue;
        };
        if t.predecessor_account_id.as_deref() == Some("system") {
            continue;
        }
        if !by_hash.contains_key(hash) {
            order.push(hash.to_string());
        }
        by_hash.entry(hash.to_string()).or_default().push(t);
    }

    let rows = order
        .iter()
        .map(|hash| compose(hash, &by_hash[hash], account_id))
        .collect();

    Ok(History {
        account_id: account_id.to_string(),
        source: host.to_string(),
        rows,
    })
}

fn compose(hash: &str, parts: &[&Txn], account_id: &str) -> HistoryRow {
    let when = parts
        .iter()
        .filter_map(|t| t.block_timestamp.as_deref())
        .filter_map(|ns| ns.parse::<u128>().ok())
        .map(|ns| thine_core::rfc3339_of((ns / 1_000_000_000) as u64))
        .next_back()
        .unwrap_or_default();

    // The other party, from the first part that names one.
    let mut counterparty = None;
    let mut incoming = false;
    for t in parts {
        let pred = t.predecessor_account_id.as_deref().unwrap_or_default();
        let recv = t.receiver_account_id.as_deref().unwrap_or_default();
        if pred == account_id && !recv.is_empty() && recv != account_id {
            counterparty = Some(recv.to_string());
            break;
        }
        if recv == account_id && !pred.is_empty() && pred != account_id {
            counterparty = Some(pred.to_string());
            incoming = true;
            break;
        }
    }

    // Labels in a fixed precedence, methods merged into one call label.
    let mut methods: Vec<String> = Vec::new();
    let mut labels: Vec<&str> = Vec::new();
    for t in parts {
        for a in &t.actions {
            match a.action.as_deref().unwrap_or_default() {
                "FUNCTION_CALL" => {
                    if let Some(m) = &a.method
                        && !methods.contains(m)
                    {
                        methods.push(m.clone());
                    }
                }
                "DEPLOY_CONTRACT" => push_once(&mut labels, "Contract deployed"),
                "CREATE_ACCOUNT" => push_once(&mut labels, "Account created"),
                "ADD_KEY" => push_once(&mut labels, "Key added"),
                "DELETE_KEY" => push_once(&mut labels, "Key deleted"),
                "DELETE_ACCOUNT" => push_once(&mut labels, "Account deleted"),
                "TRANSFER" => {
                    push_once(&mut labels, if incoming { "Received" } else { "Sent" });
                }
                _ => {}
            }
        }
    }
    let mut what: Vec<String> = Vec::new();
    if !methods.is_empty() {
        what.push(format!("Call: {}", methods.join(", ")));
    }
    what.extend(labels.iter().map(ToString::to_string));
    if what.is_empty() {
        what.push("Transaction".to_string());
    }

    HistoryRow {
        hash: hash.to_string(),
        when,
        what: what.join(", "),
        counterparty,
    }
}

fn push_once<'a>(labels: &mut Vec<&'a str>, label: &'a str) {
    if !labels.contains(&label) {
        labels.push(label);
    }
}
