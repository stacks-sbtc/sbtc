//! Requires the Emily integration environment (`make integration-env-up`).

use std::str::FromStr as _;

use bitcoin::AddressType;
use bitcoin::OutPoint;
use bitcoin::ScriptBuf;
use bitcoin::Sequence;
use bitcoin::Transaction;
use bitcoin::TxIn;
use bitcoin::Witness;
use bitcoin::consensus::encode::serialize_hex;
use bitcoincore_rpc::RpcApi as _;
use clap::Parser as _;
use emily_cron2::config::Config;
use emily_cron2::processor::Processor;
use reqwest::header::HeaderMap;
use reqwest::header::HeaderName;
use reqwest::header::HeaderValue;
use sbtc::testing::containers::TestContainersBuilder;
use sbtc::testing::deposits::TxSetup;
use sbtc::testing::emily::EmilyTables;
use sbtc::testing::regtest::Recipient;
use sbtc::testing::regtest::p2tr_sign_transaction;
use testing_emily_client::apis::configuration::ApiKey;
use testing_emily_client::apis::configuration::Configuration;
use testing_emily_client::apis::deposit_api;
use testing_emily_client::models::CreateDepositRequestBody;
use testing_emily_client::models::DepositStatus;

use crate::bitcoin_api;

const EMILY_URL: &str = "http://127.0.0.1:3031";
const EMILY_API_KEY: &str = "testApiKey";
const LOCK_TIME: u32 = 1;
const CONFIRMATIONS: u64 = 1;
const AMOUNT_SATS: u64 = 49_900_000;

/// This test checks that we mark a deposit as failed after it has been
/// confirmed and unspent for [`CONFIRMATIONS`] blocks after it's
/// confirmation.
#[tokio::test]
async fn expired_unspent_deposit_is_failed() {
    let stack = TestContainersBuilder::start_bitcoin().await;
    let bitcoin = stack.bitcoin().await;
    let rpc = bitcoin.rpc();
    let faucet = bitcoin.get_faucet();
    let bitcoin_api = bitcoin_api::serve(bitcoin.url().as_str()).await;

    let depositor = Recipient::new(AddressType::P2tr);
    let mut setup: TxSetup = sbtc::testing::deposits::tx_setup(LOCK_TIME, 15_000, &[AMOUNT_SATS]);
    let outpoint = faucet.send_to(50_000_000, &depositor.address);
    faucet.generate_block();

    setup.tx.input = vec![TxIn {
        previous_output: outpoint,
        sequence: Sequence::ZERO,
        script_sig: ScriptBuf::new(),
        witness: Witness::new(),
    }];
    p2tr_sign_transaction(
        &mut setup.tx,
        0,
        &depositor.get_utxos(rpc, None),
        &depositor.keypair,
    );
    rpc.send_raw_transaction(&setup.tx).unwrap();
    faucet.generate_block();
    faucet.generate_blocks(u64::from(LOCK_TIME) + CONFIRMATIONS);

    let tables = EmilyTables::new().await;
    let emily = emily_config(&tables);
    let deposit = create_emily_deposit(&emily, &setup.tx, &setup).await;

    let mut config = Config::parse_from(["emily-cron2"]);
    config.private_emily_endpoint = EMILY_URL.to_owned();
    config.emily_api_key = EMILY_API_KEY.to_owned();
    config.mempool_api_url = bitcoin_api.clone();
    config.electrs_api_url = bitcoin_api;
    config.min_block_confirmations = CONFIRMATIONS;
    config.emily_extra_headers = emily_table_headers(&tables);

    Processor::new(config).unwrap().run().await.unwrap();

    let updated = deposit_api::get_deposit(
        &emily,
        &deposit.bitcoin_txid,
        &deposit.bitcoin_tx_output_index.to_string(),
    )
    .await
    .unwrap();
    assert_eq!(updated.status, DepositStatus::Failed);
    tables.delete().await;
}

fn emily_config(tables: &EmilyTables) -> Configuration {
    Configuration {
        base_path: EMILY_URL.to_owned(),
        api_key: Some(ApiKey {
            prefix: None,
            key: EMILY_API_KEY.to_owned(),
        }),
        client: reqwest::Client::builder()
            .default_headers(emily_table_headers(tables))
            .build()
            .unwrap(),
        ..Configuration::default()
    }
}

fn emily_table_headers(tables: &EmilyTables) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for (shortname, table_name) in [
        ("deposit", &tables.deposit),
        ("withdrawal", &tables.withdrawal),
        ("chainstate", &tables.chainstate),
        ("limit", &tables.limit),
        ("throttle", &tables.throttle),
    ] {
        headers.insert(
            HeaderName::from_str(&format!("x-context-{shortname}")).unwrap(),
            HeaderValue::from_str(table_name).unwrap(),
        );
    }
    headers
}

async fn create_emily_deposit(
    emily: &Configuration,
    tx: &Transaction,
    setup: &TxSetup,
) -> testing_emily_client::models::Deposit {
    let outpoint = OutPoint::new(tx.compute_txid(), 0);
    deposit_api::create_deposit(
        emily,
        CreateDepositRequestBody::new(
            outpoint.vout,
            outpoint.txid.to_string(),
            setup.deposits[0].deposit_script().to_hex_string(),
            setup.reclaims[0].reclaim_script().to_hex_string(),
            serialize_hex(tx),
        ),
    )
    .await
    .expect("create deposit")
}
