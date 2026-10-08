//! End-to-end integration coverage for the v1-to-v2 Taproot transition.

use std::collections::BTreeSet;

use bitcoin::Address;
use bitcoin::AddressType;
use bitcoin::Amount;
use bitcoin::OutPoint;
use bitcoin::ScriptBuf;
use bitcoin::Sequence;
use bitcoin::Transaction;
use bitcoin::TxIn;
use bitcoin::TxOut;
use bitcoin::Witness;
use bitcoin::absolute::LockTime;
use bitcoin::transaction::Version;
use bitcoincore_rpc::RpcApi as _;
use clarity::vm::types::PrincipalData;
use emily_client::apis::deposit_api;
use sbtc::deposits::CreateDepositRequest;
use sbtc::deposits::DepositInfo;
use sbtc::deposits::DepositScriptInputsV2;
use sbtc::deposits::ReclaimScriptInputs;
use sbtc::testing::containers::TestContainersBuilder;
use sbtc::testing::emily::EmilyTables;
use sbtc::testing::regtest::Faucet;
use sbtc::testing::regtest::Recipient;
use secp256k1::Keypair;
use signer::bitcoin::poller::BitcoinChainTipPoller;
use signer::bitcoin::rpc::BitcoinCoreClient;
use signer::context::Context as _;
use signer::emily_client::EmilyClient;
use signer::keys::PublicKey;
use signer::keys::SignerScriptPubKey as _;
use signer::network::in_memory2::SignerNetwork;
use signer::network::in_memory2::WanNetwork;
use signer::stacks::api::StacksClient;
use signer::stacks::api::StacksInteract as _;
use signer::storage::DbRead as _;
use signer::storage::DbWrite as _;
use signer::storage::model;
use signer::storage::postgres::PgStore;
use signer::testing;
use stacks_common::types::chainstate::StacksAddress;

use crate::containers::BitcoinContainerExt as _;
use crate::containers::StacksContainerExt as _;
use crate::e2e::start_signers;
use crate::setup::clean_emily_setup;
use crate::setup::new_emily_setup;
use crate::stacks::wait_for_new_nonce;
use crate::transaction_coordinator::IntegrationTestContext;
use crate::transaction_coordinator::wait_for_tenure_completed;
use crate::utxo_construction::make_deposit_request;

const NUM_SIGNERS: usize = 3;
const SIGNATURES_REQUIRED: u16 = 2;
const SIGNER_UTXO_AMOUNT: u64 = 100_000;
const DEPOSITOR_FUNDS: u64 = 50_000_000;
const DEPOSIT_AMOUNT: u64 = 2_500_000;
const MIN_CHANGE_OUTPUT: u64 = 546;

/// A running signer and the resources owned by its integration harness.
type TestSigner = (
    IntegrationTestContext<StacksClient>,
    PgStore,
    Keypair,
    SignerNetwork,
);

/// Deploy the sBTC contracts, rotate to the initial v1 key, and return it.
async fn bootstrap_v1(
    signers: &[TestSigner],
    faucet: &Faucet<'_>,
    stacks_client: &StacksClient,
) -> (StacksAddress, PublicKey) {
    let deployer = signers[0].0.config().signer.deployer.clone();

    let old_nonce = stacks_client.get_account(&deployer).await.unwrap().nonce;
    let chain_tip = faucet.generate_block().into();
    wait_for_tenure_completed(signers, chain_tip).await;
    wait_for_new_nonce(stacks_client, &deployer, old_nonce).await;

    let old_nonce = stacks_client.get_account(&deployer).await.unwrap().nonce;
    let chain_tip = faucet.generate_block().into();
    wait_for_tenure_completed(signers, chain_tip).await;
    wait_for_new_nonce(stacks_client, &deployer, old_nonce).await;

    let aggregate_key = stacks_client
        .get_current_signers_aggregate_key(&deployer)
        .await
        .unwrap()
        .expect("the initial key rotation was not mined")
        .v1_public_key()
        .expect("the initial rotation should use the v1 aggregate key");

    (deployer, aggregate_key)
}

/// Mine blocks until the chain tip reaches the configured v2 activation
/// height.
///
/// Whether the signers use v2 depends only on the chain tip's height
/// compared with the configured activation height, not on the registry.
/// Crossing the activation height must not rotate the registry keys either;
/// that only happens when the configured signer set changes, and these
/// tests never change it.
async fn activate_v2(
    signers: &[TestSigner],
    faucet: &Faucet<'_>,
    stacks_client: &StacksClient,
    deployer: &StacksAddress,
) {
    let config = &signers[0].0.config().signer;
    let activation_height = *config.v2_signing_block_height();
    let registry_before = stacks_client
        .get_current_signer_set_info(deployer)
        .await
        .unwrap();

    while faucet.rpc.get_block_count().unwrap() < activation_height {
        let chain_tip = faucet.generate_block().into();
        wait_for_tenure_completed(signers, chain_tip).await;
    }
    let block_height = faucet.rpc.get_block_count().unwrap();
    assert!(config.is_v2_signing_active(block_height.into()));

    let registry_after = stacks_client
        .get_current_signer_set_info(deployer)
        .await
        .unwrap();
    assert_eq!(
        registry_after, registry_before,
        "crossing the v2 activation height rotated the registry keys"
    );
}

/// Construct a signed deposit transaction locked by a v2 signer key set.
fn make_v2_deposit<U>(
    depositor: &Recipient,
    amount: u64,
    utxo: U,
    max_fee: u64,
    key_set: &sbtc::SignerKeySet,
) -> (Transaction, DepositInfo)
where
    U: sbtc::testing::regtest::AsUtxo,
{
    let recipient = PrincipalData::from(StacksAddress::burn_address(false));
    let deposit_inputs = DepositScriptInputsV2::new(
        key_set.public_keys().clone(),
        key_set.signatures_required(),
        recipient.clone(),
        max_fee,
    )
    .unwrap();
    let reclaim_inputs = ReclaimScriptInputs::try_new(50, ScriptBuf::new()).unwrap();
    let deposit_script = deposit_inputs.deposit_script();
    let reclaim_script = reclaim_inputs.reclaim_script();
    let fee = sbtc::testing::regtest::BITCOIN_CORE_FALLBACK_FEE.to_sat();

    let mut outputs = vec![TxOut {
        value: Amount::from_sat(amount),
        script_pubkey: sbtc::deposits::to_v2_script_pubkey(
            deposit_script.clone(),
            reclaim_script.clone(),
        ),
    }];
    let change = utxo.amount() - Amount::from_sat(amount + fee);
    if change.to_sat() > MIN_CHANGE_OUTPUT {
        outputs.push(TxOut {
            value: change,
            script_pubkey: depositor.address.script_pubkey(),
        });
    }

    let mut transaction = Transaction {
        version: Version::ONE,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::new(utxo.txid(), utxo.vout()),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ZERO,
            witness: Witness::new(),
        }],
        output: outputs,
    };
    sbtc::testing::regtest::p2tr_sign_transaction(&mut transaction, 0, &[utxo], &depositor.keypair);

    let request = CreateDepositRequest {
        outpoint: OutPoint::new(transaction.compute_txid(), 0),
        deposit_script,
        reclaim_script,
        recipient: Some(recipient),
        max_fee: Some(max_fee),
    };
    let info = request.validate_tx(&transaction, false).unwrap();
    (transaction, info)
}

/// Submit a deposit transaction to Bitcoin and register it with Emily.
async fn submit_deposit(
    rpc: &bitcoincore_rpc::Client,
    emily_client: &EmilyClient,
    transaction: &Transaction,
    info: &DepositInfo,
) {
    rpc.send_raw_transaction(transaction).unwrap();
    let body = signer::testing::btc::build_emily_request(info, transaction);
    deposit_api::create_deposit(emily_client.config(), body)
        .await
        .unwrap();
}

/// Find a mempool transaction that sweeps all expected deposits.
fn find_sweep(
    rpc: &bitcoincore_rpc::Client,
    signer_script: &ScriptBuf,
    deposits: &[OutPoint],
) -> Option<Transaction> {
    rpc.get_raw_mempool().unwrap().into_iter().find_map(|txid| {
        let transaction = rpc.get_raw_transaction(&txid, None).unwrap();
        let has_signer_output = transaction
            .output
            .first()
            .is_some_and(|output| &output.script_pubkey == signer_script);
        let has_all_deposits = deposits.iter().all(|outpoint| {
            transaction
                .input
                .iter()
                .any(|input| input.previous_output == *outpoint)
        });
        (has_signer_output && has_all_deposits).then_some(transaction)
    })
}

/// Mine blocks until request decisions have propagated and a sweep is broadcast.
async fn wait_for_sweep(
    signers: &[TestSigner],
    faucet: &Faucet<'_>,
    rpc: &bitcoincore_rpc::Client,
    signer_script: &ScriptBuf,
    deposits: &[OutPoint],
) -> Transaction {
    for _ in 0..2 {
        let chain_tip = faucet.generate_block().into();
        wait_for_tenure_completed(signers, chain_tip).await;
        if let Some(transaction) = find_sweep(rpc, signer_script, deposits) {
            return transaction;
        }
    }
    panic!("the signers did not broadcast the expected sweep transaction");
}

/// Load the scriptPubKey of the output spent by a transaction input.
fn input_script_pubkey(
    rpc: &bitcoincore_rpc::Client,
    transaction: &Transaction,
    input_index: usize,
) -> ScriptBuf {
    let outpoint = transaction.input[input_index].previous_output;
    let previous_transaction = rpc.get_raw_transaction(&outpoint.txid, None).unwrap();
    previous_transaction.output[outpoint.vout as usize]
        .script_pubkey
        .clone()
}

/// Drop the signer databases and remove the per-test Emily tables.
async fn clean_up(signers: Vec<TestSigner>, emily_tables: EmilyTables) {
    for (_, database, _, _) in signers {
        testing::storage::drop_db(database).await;
    }
    clean_emily_setup(emily_tables).await;
}

/// Start three signers whose v2 activation height is controlled by the test.
async fn start_test_signers(
    bitcoin_client: &BitcoinCoreClient,
    bitcoin_chain_tip_poller: &BitcoinChainTipPoller,
    stacks_client: &StacksClient,
    emily_client: &EmilyClient,
    network: &WanNetwork,
    activation_height: u64,
) -> Vec<TestSigner> {
    start_signers(
        bitcoin_client,
        bitcoin_chain_tip_poller,
        stacks_client,
        emily_client,
        network,
        NUM_SIGNERS,
        SIGNATURES_REQUIRED,
        Some(activation_height),
        std::time::Duration::from_secs(2),
    )
    .await
}

/// The first post-activation sweep spends a v1 UTXO, along with v1 and v2
/// deposits, and creates a v2 UTXO.
#[tokio::test]
async fn signer_utxo_crosses_to_v2_at_activation_height() {
    let stack = TestContainersBuilder::start_stacks().await;
    let bitcoin = stack.bitcoin().await;
    let stacks = stack.stacks().await;
    let rpc = bitcoin.rpc();
    let faucet = bitcoin.get_faucet();
    let stacks_client = stacks.get_client();
    let (emily_client, emily_tables) = new_emily_setup().await;
    let network = WanNetwork::default();

    faucet.generate_fee_data();
    let activation_height = rpc.get_block_count().unwrap() + 3;
    let poller = bitcoin.start_chain_tip_poller().await;
    let signers = start_test_signers(
        &bitcoin.get_client(),
        &poller,
        &stacks_client,
        &emily_client,
        &network,
        activation_height,
    )
    .await;
    let (deployer, aggregate_key) = bootstrap_v1(&signers, &faucet, &stacks_client).await;

    let v1_script = aggregate_key.signers_script_pubkey();
    faucet.send_to(
        SIGNER_UTXO_AMOUNT,
        &Address::from_script(&v1_script, bitcoin::Network::Regtest).unwrap(),
    );
    let v1_depositor = Recipient::new(AddressType::P2tr);
    let v2_depositor = Recipient::new(AddressType::P2tr);
    faucet.send_to(DEPOSITOR_FUNDS, &v1_depositor.address);
    faucet.send_to(DEPOSITOR_FUNDS, &v2_depositor.address);

    activate_v2(&signers, &faucet, &stacks_client, &deployer).await;
    assert_eq!(rpc.get_block_count().unwrap(), activation_height);

    let max_fee = DEPOSIT_AMOUNT / 2;
    let v1_utxo = v1_depositor.get_utxos(rpc, None).pop().unwrap();
    let (v1_tx, _, v1_info) = make_deposit_request(
        &v1_depositor,
        DEPOSIT_AMOUNT,
        v1_utxo,
        max_fee,
        aggregate_key.into(),
    );
    submit_deposit(rpc, &emily_client, &v1_tx, &v1_info).await;

    let v2_key_set = signers[0].0.config().signer.v2_signer_key_set().unwrap();
    let v2_utxo = v2_depositor.get_utxos(rpc, None).pop().unwrap();
    let (v2_tx, v2_info) =
        make_v2_deposit(&v2_depositor, DEPOSIT_AMOUNT, v2_utxo, max_fee, &v2_key_set);
    submit_deposit(rpc, &emily_client, &v2_tx, &v2_info).await;

    let sweep = wait_for_sweep(
        &signers,
        &faucet,
        rpc,
        &v2_key_set.script_pubkey(),
        &[v1_info.outpoint, v2_info.outpoint],
    )
    .await;

    assert_eq!(input_script_pubkey(rpc, &sweep, 0), v1_script);
    assert!(
        sweep
            .input
            .iter()
            .any(|input| input.previous_output == v1_info.outpoint)
    );
    assert!(
        sweep
            .input
            .iter()
            .any(|input| input.previous_output == v2_info.outpoint)
    );
    assert_eq!(sweep.output[0].script_pubkey, v2_key_set.script_pubkey());

    clean_up(signers, emily_tables).await;
}

/// Three signers sweep v1 and v2 deposits while their UTXO is still v1.
#[tokio::test]
async fn v1_signer_utxo_sweeps_v1_and_v2_deposits() {
    let stack = TestContainersBuilder::start_stacks().await;
    let bitcoin = stack.bitcoin().await;
    let stacks = stack.stacks().await;
    let rpc = bitcoin.rpc();
    let faucet = bitcoin.get_faucet();
    let stacks_client = stacks.get_client();
    let (emily_client, emily_tables) = new_emily_setup().await;
    let network = WanNetwork::default();

    faucet.generate_fee_data();
    let poller = bitcoin.start_chain_tip_poller().await;
    let signers = start_test_signers(
        &bitcoin.get_client(),
        &poller,
        &stacks_client,
        &emily_client,
        &network,
        u64::MAX,
    )
    .await;
    let (_, aggregate_key) = bootstrap_v1(&signers, &faucet, &stacks_client).await;

    let v1_script = aggregate_key.signers_script_pubkey();
    faucet.send_to(
        SIGNER_UTXO_AMOUNT,
        &Address::from_script(&v1_script, bitcoin::Network::Regtest).unwrap(),
    );
    let v1_depositor = Recipient::new(AddressType::P2tr);
    let v2_depositor = Recipient::new(AddressType::P2tr);
    faucet.send_to(DEPOSITOR_FUNDS, &v1_depositor.address);
    faucet.send_to(DEPOSITOR_FUNDS, &v2_depositor.address);
    let chain_tip = faucet.generate_block().into();
    wait_for_tenure_completed(&signers, chain_tip).await;

    let max_fee = DEPOSIT_AMOUNT / 2;
    let v1_utxo = v1_depositor.get_utxos(rpc, None).pop().unwrap();
    let (v1_tx, _, v1_info) = make_deposit_request(
        &v1_depositor,
        DEPOSIT_AMOUNT,
        v1_utxo,
        max_fee,
        aggregate_key.into(),
    );
    submit_deposit(rpc, &emily_client, &v1_tx, &v1_info).await;

    let key_set = signers[0].0.config().signer.v2_signer_key_set().unwrap();
    let v2_utxo = v2_depositor.get_utxos(rpc, None).pop().unwrap();
    let (v2_tx, v2_info) =
        make_v2_deposit(&v2_depositor, DEPOSIT_AMOUNT, v2_utxo, max_fee, &key_set);
    submit_deposit(rpc, &emily_client, &v2_tx, &v2_info).await;

    let sweep = wait_for_sweep(
        &signers,
        &faucet,
        rpc,
        &v1_script,
        &[v1_info.outpoint, v2_info.outpoint],
    )
    .await;

    assert_eq!(input_script_pubkey(rpc, &sweep, 0), v1_script);
    assert!(
        sweep
            .input
            .iter()
            .any(|input| input.previous_output == v1_info.outpoint)
    );
    assert!(
        sweep
            .input
            .iter()
            .any(|input| input.previous_output == v2_info.outpoint)
    );
    assert_eq!(sweep.output[0].script_pubkey, v1_script);

    clean_up(signers, emily_tables).await;
}

/// Three signers sweep v1 and v2 deposits while their UTXO is v2.
#[test_log::test(tokio::test)]
async fn v2_signer_utxo_sweeps_v1_and_v2_deposits() {
    let stack = TestContainersBuilder::start_stacks().await;
    let bitcoin = stack.bitcoin().await;
    let stacks = stack.stacks().await;
    let rpc = bitcoin.rpc();
    let faucet = bitcoin.get_faucet();
    let stacks_client = stacks.get_client();
    let (emily_client, emily_tables) = new_emily_setup().await;
    let network = WanNetwork::default();

    faucet.generate_fee_data();
    let activation_height = rpc.get_block_count().unwrap() + 3;
    let poller = bitcoin.start_chain_tip_poller().await;
    let signers = start_test_signers(
        &bitcoin.get_client(),
        &poller,
        &stacks_client,
        &emily_client,
        &network,
        activation_height,
    )
    .await;
    let (deployer, aggregate_key) = bootstrap_v1(&signers, &faucet, &stacks_client).await;
    activate_v2(&signers, &faucet, &stacks_client, &deployer).await;

    let key_set = signers[0].0.config().signer.v2_signer_key_set().unwrap();
    faucet.send_to(
        SIGNER_UTXO_AMOUNT,
        &Address::from_script(&key_set.script_pubkey(), bitcoin::Network::Regtest).unwrap(),
    );
    let v1_depositor = Recipient::new(AddressType::P2tr);
    let v2_depositor = Recipient::new(AddressType::P2tr);
    faucet.send_to(DEPOSITOR_FUNDS, &v1_depositor.address);
    faucet.send_to(DEPOSITOR_FUNDS, &v2_depositor.address);
    let chain_tip = faucet.generate_block().into();
    wait_for_tenure_completed(&signers, chain_tip).await;

    let max_fee = DEPOSIT_AMOUNT / 2;
    let v1_utxo = v1_depositor.get_utxos(rpc, None).pop().unwrap();
    let (v1_tx, _, v1_info) = make_deposit_request(
        &v1_depositor,
        DEPOSIT_AMOUNT,
        v1_utxo,
        max_fee,
        aggregate_key.into(),
    );
    submit_deposit(rpc, &emily_client, &v1_tx, &v1_info).await;

    let v2_utxo = v2_depositor.get_utxos(rpc, None).pop().unwrap();
    let (v2_tx, v2_info) =
        make_v2_deposit(&v2_depositor, DEPOSIT_AMOUNT, v2_utxo, max_fee, &key_set);
    submit_deposit(rpc, &emily_client, &v2_tx, &v2_info).await;

    let sweep = wait_for_sweep(
        &signers,
        &faucet,
        rpc,
        &key_set.script_pubkey(),
        &[v1_info.outpoint, v2_info.outpoint],
    )
    .await;

    assert_eq!(input_script_pubkey(rpc, &sweep, 0), key_set.script_pubkey());
    assert!(
        sweep
            .input
            .iter()
            .any(|input| input.previous_output == v1_info.outpoint)
    );
    assert!(
        sweep
            .input
            .iter()
            .any(|input| input.previous_output == v2_info.outpoint)
    );
    assert_eq!(sweep.output[0].script_pubkey, key_set.script_pubkey());

    clean_up(signers, emily_tables).await;
}

/// Two current signers sweep a 2-of-3 deposit whose third key is an outsider.
#[test_log::test(tokio::test)]
async fn v2_deposit_for_a_different_signer_set_is_swept() {
    let stack = TestContainersBuilder::start_stacks().await;
    let bitcoin = stack.bitcoin().await;
    let stacks = stack.stacks().await;
    let rpc = bitcoin.rpc();
    let faucet = bitcoin.get_faucet();
    let stacks_client = stacks.get_client();
    let (emily_client, emily_tables) = new_emily_setup().await;
    let network = WanNetwork::default();

    faucet.generate_fee_data();
    let activation_height = rpc.get_block_count().unwrap() + 3;
    let poller = bitcoin.start_chain_tip_poller().await;
    let signers = start_test_signers(
        &bitcoin.get_client(),
        &poller,
        &stacks_client,
        &emily_client,
        &network,
        activation_height,
    )
    .await;
    let (deployer, _) = bootstrap_v1(&signers, &faucet, &stacks_client).await;
    activate_v2(&signers, &faucet, &stacks_client, &deployer).await;

    let current_key_set = signers[0].0.config().signer.v2_signer_key_set().unwrap();
    faucet.send_to(
        SIGNER_UTXO_AMOUNT,
        &Address::from_script(&current_key_set.script_pubkey(), bitcoin::Network::Regtest).unwrap(),
    );
    let depositor = Recipient::new(AddressType::P2tr);
    faucet.send_to(DEPOSITOR_FUNDS, &depositor.address);
    let chain_tip = faucet.generate_block().into();
    wait_for_tenure_completed(&signers, chain_tip).await;

    let mut alternate_keys: BTreeSet<_> = signers
        .iter()
        .take(2)
        .map(|(_, _, keypair, _)| sbtc::derive_signing_public_key(keypair.public_key()))
        .collect();
    let outsider = Keypair::new_global(&mut rand::rngs::OsRng);
    alternate_keys.insert(sbtc::derive_signing_public_key(outsider.public_key()));
    let alternate_key_set = sbtc::SignerKeySet::new(alternate_keys, SIGNATURES_REQUIRED).unwrap();
    let stored_alternate_key_set = model::SignerKeySet::from(alternate_key_set.clone());
    for (_, database, _, _) in &signers {
        database
            .write_signer_key_set(&stored_alternate_key_set)
            .await
            .unwrap();
    }

    let utxo = depositor.get_utxos(rpc, None).pop().unwrap();
    let max_fee = DEPOSIT_AMOUNT / 2;
    let (deposit_tx, deposit_info) = make_v2_deposit(
        &depositor,
        DEPOSIT_AMOUNT,
        utxo,
        max_fee,
        &alternate_key_set,
    );
    submit_deposit(rpc, &emily_client, &deposit_tx, &deposit_info).await;

    let sweep = wait_for_sweep(
        &signers,
        &faucet,
        rpc,
        &current_key_set.script_pubkey(),
        &[deposit_info.outpoint],
    )
    .await;

    assert_eq!(
        input_script_pubkey(rpc, &sweep, 0),
        current_key_set.script_pubkey()
    );
    assert!(
        sweep
            .input
            .iter()
            .any(|input| input.previous_output == deposit_info.outpoint)
    );
    assert_eq!(
        sweep.output[0].script_pubkey,
        current_key_set.script_pubkey()
    );

    let alternate_script = alternate_key_set.script_pubkey().into_bytes();
    for (_, database, _, _) in signers.iter().take(2) {
        let known_scripts = database.get_signers_script_pubkeys().await.unwrap();
        assert!(known_scripts.contains(&alternate_script));
    }

    clean_up(signers, emily_tables).await;
}
