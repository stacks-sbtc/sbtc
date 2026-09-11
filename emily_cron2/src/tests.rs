use clap::Parser as _;
use mockito::{Matcher, Server};
use serde_json::{Value, json};

use crate::{
    config::Config,
    model::{Rbf, expired, lock_time},
    processor::Processor,
};

fn processor(server: &Server, dry_run: bool) -> Processor {
    let mut config = Config::parse_from(["emily-cron2"]);
    config.private_emily_endpoint = server.url();
    config.mempool_api_url = server.url();
    config.electrs_api_url = server.url();
    config.hiro_api_url = server.url();
    config.emily_api_key = "test-key".into();
    config.min_block_confirmations = 6;
    config.max_unconfirmed_time = 86400;
    config.dry_run = dry_run;
    Processor::new(config).unwrap()
}

fn deposit(status: &str) -> Value {
    json!({"bitcoinTxid": "original", "bitcoinTxOutputIndex": 2,
        "status": status, "lastUpdateBlockHash": "block", "reclaimScript": "0160b27551",
        "amount": 1000, "depositScript": "", "lastUpdateHeight": 1, "recipient": "recipient"})
}

async fn setup(server: &mut Server, status: &str, tip: u64) -> Vec<mockito::Mock> {
    let mut mocks = vec![
        server
            .mock("GET", "/v1/blocks/tip/height")
            .match_header("x-api-key", Matcher::Missing)
            .with_body(tip.to_string())
            .create_async()
            .await,
    ];
    for filter in ["pending", "accepted"] {
        mocks.push(
            server
                .mock("GET", "/deposit")
                .with_header("content-type", "application/json")
                .match_query(Matcher::UrlEncoded("status".into(), filter.into()))
                .match_header("x-api-key", "test-key")
                .with_body(
                    json!({"deposits": if status == filter {vec![deposit(status)]} else {vec![]}, "nextToken": null})
                        .to_string(),
                )
                .create_async()
                .await,
        );
    }
    mocks
}

async fn update_mock(
    server: &mut Server,
    status: &str,
    message: &str,
    replacement: Option<&str>,
    count: usize,
) -> mockito::Mock {
    let mut update = json!({
        "bitcoinTxid": "original", "bitcoinTxOutputIndex": 2,
        "status": status, "statusMessage": message
    });
    if let Some(txid) = replacement {
        update["replacedByTx"] = json!(txid);
    }
    server
        .mock("PUT", "/deposit_private")
        .with_header("content-type", "application/json")
        .match_header("x-api-key", "test-key")
        .match_body(Matcher::Json(json!({"deposits": [update]})))
        .with_body(r#"{"deposits":[{"status":200,"error":null}]}"#)
        .expect(count)
        .create_async()
        .await
}

#[test]
fn locktime_and_expiry_boundaries() {
    for (script, expected) in [
        ("00b2", 0),
        ("51b2", 1),
        ("60b2", 16),
        ("0160b27551", 96),
        ("02b603b2", 950),
    ] {
        assert_eq!(lock_time(script).unwrap(), expected);
    }
    for script in [
        "",
        "zz",
        "4fb2",
        "0181b2",
        "03600040b2",
        "050000008000b2",
        "016051",
        "0260",
    ] {
        assert!(lock_time(script).is_err(), "{script}");
    }
    assert!(!expired(100, 96, 6, 201));
    assert!(expired(100, 96, 6, 202));
    assert!(!expired(u64::MAX, 1, 6, u64::MAX));
}

#[test]
fn reclaim_scripts_use_shared_sbtc_validation() {
    use crate::error::Error;
    use bitcoin::ScriptBuf;
    use sbtc::deposits::ReclaimScriptInputs;

    let user_script = ScriptBuf::from_hex("7551").unwrap();
    let reclaim = ReclaimScriptInputs::try_new(96, user_script).unwrap();
    let script = reclaim.reclaim_script().to_hex_string();
    assert_eq!(lock_time(&script).unwrap(), 96);

    // The old prefix-only parser accepted OP_SUCCESSx in the user script.
    let error = lock_time("0160b250").unwrap_err();
    assert!(matches!(
        error,
        Error::Sbtc(sbtc::error::Error::ReclaimScriptWithSuccessOp(_))
    ));

    // Shared validation also enforces the length of the user-supplied script.
    let user_script = "51".repeat(sbtc::MAX_RECLAIM_SCRIPT_LENGTH + 1);
    let error = lock_time(&format!("0160b2{user_script}")).unwrap_err();
    assert!(matches!(
        error,
        Error::Sbtc(sbtc::error::Error::InvalidReclaimScriptLength(_))
    ));
}

#[test]
fn python_rbf_fixtures() {
    let empty: Rbf = serde_json::from_str(include_str!(
        "../../emily_cron/test/fixtures/fixture-mempool-rbf-empty.json"
    ))
    .unwrap();
    assert!(empty.replacements.is_none());
    let multi: Rbf = serde_json::from_str(include_str!(
        "../../emily_cron/test/fixtures/fixture-mempool-rbf-multi.json"
    ))
    .unwrap();
    let mut txids = vec![];
    multi.replacements.unwrap().txids(&mut txids);
    assert!(txids.len() > 1);
    assert_eq!(
        txids[0],
        "afe18f246b9624b17b21f2ebf84594bb75b582209d55dfc0b6edb34bfb785c3a"
    );
}

#[tokio::test]
async fn expiry_unspent_reclaim_and_signer_sweep() {
    for (spent, witness, expected) in [
        (
            false,
            "",
            Some("Locktime expired at height 202 and UTXO unspent"),
        ),
        (
            true,
            "0160b27551",
            Some("Depositor reclaim detected in tx spender"),
        ),
        (true, "signature", None),
        (true, "aa0160b27551bb", None),
    ] {
        let mut server = Server::new_async().await;
        let mocks = setup(&mut server, "accepted", 202).await;
        let tx = server
            .mock("GET", "/v1/tx/original")
            .with_body(r#"{"status":{"confirmed":true,"block_height":100}}"#)
            .create_async()
            .await;
        let outspend = server
            .mock("GET", "/tx/original/outspend/2")
            .with_body(json!({"spent":spent,"txid":"spender","vin":0}).to_string())
            .create_async()
            .await;
        let spending = server
            .mock("GET", "/v1/tx/spender")
            .with_body(
                json!({"status":{"confirmed":true},"vin":[{"witness":[witness]}]}).to_string(),
            )
            .expect(usize::from(spent))
            .create_async()
            .await;
        let update = update_mock(
            &mut server,
            "failed",
            expected.unwrap_or(""),
            None,
            usize::from(expected.is_some()),
        )
        .await;
        processor(&server, false).run().await.unwrap();
        for mock in mocks {
            mock.assert_async().await;
        }
        tx.assert_async().await;
        outspend.assert_async().await;
        spending.assert_async().await;
        update.assert_async().await;
    }
}

#[tokio::test]
async fn rbf_fetches_replacement_outside_emily_and_waits_for_confirmations() {
    for tip in [105, 106] {
        let mut server = Server::new_async().await;
        let _mocks = setup(&mut server, "pending", tip).await;
        let original = server
            .mock("GET", "/v1/tx/original")
            .with_status(404)
            .create_async()
            .await;
        let rbf = server.mock("GET", "/v1/tx/original/rbf")
            .with_body(r#"{"replacements":{"tx":{"txid":"replacement"},"replaces":[{"tx":{"txid":"original"}}]}}"#)
            .create_async().await;
        let replacement = server
            .mock("GET", "/v1/tx/replacement")
            .with_body(r#"{"status":{"confirmed":true,"block_height":100}}"#)
            .create_async()
            .await;
        let block = server
            .mock("GET", "/extended/v2/blocks/block")
            .with_body(r#"{"block_time":18446744073709551615}"#)
            .expect(usize::from(tip == 105))
            .create_async()
            .await;
        let update = update_mock(
            &mut server,
            "rbf",
            "Replaced by confirmed tx replacement",
            Some("replacement"),
            usize::from(tip == 106),
        )
        .await;
        processor(&server, false).run().await.unwrap();
        original.assert_async().await;
        rbf.assert_async().await;
        replacement.assert_async().await;
        block.assert_async().await;
        update.assert_async().await;
    }
}

#[tokio::test]
async fn only_missing_old_pending_transactions_fail() {
    for (status, missing, old, expected) in [
        ("pending", true, true, true),
        ("pending", true, false, false),
        ("pending", false, true, false),
        ("accepted", true, true, false),
    ] {
        let mut server = Server::new_async().await;
        let _mocks = setup(&mut server, status, 100).await;
        let tx = server
            .mock("GET", "/v1/tx/original")
            .with_status(if missing { 404 } else { 200 })
            .with_body(r#"{"status":{"confirmed":false}}"#)
            .create_async()
            .await;
        let rbf = server
            .mock("GET", "/v1/tx/original/rbf")
            .with_body(r#"{"replacements":null}"#)
            .create_async()
            .await;
        let block = server
            .mock("GET", "/extended/v2/blocks/block")
            .with_body(json!({"block_time": if old {0} else {u64::MAX}}).to_string())
            .expect(usize::from(missing && status == "pending"))
            .create_async()
            .await;
        let update = update_mock(
            &mut server,
            "failed",
            "Pending for too long (86400 seconds)",
            None,
            usize::from(expected),
        )
        .await;
        processor(&server, false).run().await.unwrap();
        tx.assert_async().await;
        rbf.assert_async().await;
        block.assert_async().await;
        update.assert_async().await;
    }
}

#[tokio::test]
async fn upstream_failures_never_become_deposit_failures() {
    for endpoint in [
        "/v1/tx/original",
        "/tx/original/outspend/2",
        "/extended/v2/blocks/block",
    ] {
        let mut server = Server::new_async().await;
        let _mocks = setup(&mut server, "pending", 202).await;
        if endpoint != "/v1/tx/original" {
            server
                .mock("GET", "/v1/tx/original")
                .with_status(if endpoint.contains("blocks") {
                    404
                } else {
                    200
                })
                .with_body(r#"{"status":{"confirmed":true,"block_height":100}}"#)
                .create_async()
                .await;
        }
        server
            .mock("GET", "/v1/tx/original/rbf")
            .with_body(r#"{"replacements":null}"#)
            .expect_at_most(1)
            .create_async()
            .await;
        let failure = server
            .mock("GET", endpoint)
            .with_status(503)
            .create_async()
            .await;
        let writes = server
            .mock("PUT", "/deposit_private")
            .with_header("content-type", "application/json")
            .expect(0)
            .create_async()
            .await;
        assert!(processor(&server, false).run().await.is_err());
        failure.assert_async().await;
        writes.assert_async().await;
    }
}

#[tokio::test]
async fn pagination_dry_run_and_batch_errors() {
    for (dry_run, update_status) in [(true, 200), (false, 400), (false, 503)] {
        let mut server = Server::new_async().await;
        server
            .mock("GET", "/v1/blocks/tip/height")
            .match_header("x-api-key", Matcher::Missing)
            .with_body("202")
            .create_async()
            .await;
        let first = server
            .mock("GET", "/deposit")
            .with_header("content-type", "application/json")
            .match_query(Matcher::UrlEncoded("status".into(), "pending".into()))
            .with_body(r#"{"deposits":[],"nextToken":"a+b/c="}"#)
            .create_async()
            .await;
        let second = server
            .mock("GET", "/deposit")
            .with_header("content-type", "application/json")
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("status".into(), "pending".into()),
                Matcher::UrlEncoded("nextToken".into(), "a+b/c=".into()),
            ]))
            .with_body(json!({"deposits":[deposit("pending")]}).to_string())
            .create_async()
            .await;
        server
            .mock("GET", "/deposit")
            .with_header("content-type", "application/json")
            .match_query(Matcher::UrlEncoded("status".into(), "accepted".into()))
            .with_body(r#"{"deposits":[]}"#)
            .create_async()
            .await;
        server
            .mock("GET", "/v1/tx/original")
            .with_body(r#"{"status":{"confirmed":true,"block_height":100}}"#)
            .create_async()
            .await;
        server
            .mock("GET", "/tx/original/outspend/2")
            .with_body(r#"{"spent":false}"#)
            .create_async()
            .await;
        let update = server
            .mock("PUT", "/deposit_private")
            .with_header("content-type", "application/json")
            .with_status(if update_status == 503 { 503 } else { 200 })
            .with_body(
                json!({"deposits":[{"status":update_status,"error":"rejected"}]}).to_string(),
            )
            .expect(usize::from(!dry_run))
            .create_async()
            .await;
        assert_eq!(processor(&server, dry_run).run().await.is_ok(), dry_run);
        first.assert_async().await;
        second.assert_async().await;
        update.assert_async().await;
    }
}

#[tokio::test]
async fn emily_read_errors_retain_generated_client_errors() {
    use crate::error::Error;
    use private_emily_client::apis;

    for status in [200, 503] {
        let mut server = Server::new_async().await;
        let tip = server
            .mock("GET", "/v1/blocks/tip/height")
            .match_header("x-api-key", Matcher::Missing)
            .with_body("202")
            .create_async()
            .await;
        let read = server
            .mock("GET", "/deposit")
            .match_query(Matcher::UrlEncoded("status".into(), "pending".into()))
            .match_header("x-api-key", "test-key")
            .with_header("content-type", "application/json")
            .with_status(status)
            .with_body("invalid JSON")
            .create_async()
            .await;
        let writes = server
            .mock("PUT", "/deposit_private")
            .expect(0)
            .create_async()
            .await;

        let error = processor(&server, false).run().await.unwrap_err();
        if status == 200 {
            assert!(matches!(
                error,
                Error::EmilyGetDeposits(apis::Error::Serde(_))
            ));
        } else {
            assert!(matches!(
                error,
                Error::EmilyGetDeposits(apis::Error::ResponseError(_))
            ));
        }
        tip.assert_async().await;
        read.assert_async().await;
        writes.assert_async().await;
    }
}
