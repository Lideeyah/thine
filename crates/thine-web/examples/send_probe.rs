//! Does the archival endpoint accept sends? One 1-yoctoNEAR transfer from the
//! relayer to itself answers it. Run manually; not part of any judge path.
use near_kit::{Near, NearToken, transaction::Final};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let keyed: serde_json::Value =
        serde_json::from_slice(&std::fs::read(".thine/relayer-testnet.json")?)?;
    let account = keyed["account_id"].as_str().unwrap().to_string();
    let secret = keyed["secret_key"].as_str().unwrap().to_string();

    for rpc in [
        "https://archival-rpc.testnet.fastnear.com",
        "https://rpc.testnet.fastnear.com",
    ] {
        let near = Near::custom(rpc, "testnet")
            .credentials(&secret, account.clone())?
            .build();
        let out = near
            .transaction(account.clone())
            .transfer(NearToken::from_yoctonear(1))
            .wait_until::<Final>()
            .await;
        match out {
            Ok(o) => println!(
                "{rpc} -> sent ok, success={} tx={}",
                o.is_success(),
                o.transaction_hash()
            ),
            Err(e) => println!("{rpc} -> SEND FAILED: {e}"),
        }
    }
    Ok(())
}
