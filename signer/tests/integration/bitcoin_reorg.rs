//! Bitcoin reorg tests: three signers with all event loops, real Postgres
//! and Emily, a per-test bitcoind, and a mocked stacks-core.

use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::sync::atomic::AtomicU8;
use std::sync::atomic::Ordering;
use std::time::Duration;

use bitcoin::Address;
use bitcoin::AddressType;
use bitcoin::Amount;
use bitcoin::BlockHash;
use bitcoin::OutPoint;
use bitcoin::ScriptBuf;
use bitcoin::Sequence;
use bitcoin::Transaction;
use bitcoin::TxIn;
use bitcoin::TxOut;
use bitcoin::Txid;
use bitcoin::Witness;
use bitcoin::absolute::LockTime;
use bitcoin::consensus::encode::serialize_hex;
use bitcoin::hashes::Hash as _;
use bitcoin::transaction::Version;
use bitcoincore_rpc::Client;
use bitcoincore_rpc::RpcApi as _;
use bitcoincore_rpc_json::Utxo;
use blockstack_lib::chainstate::stacks::StacksTransaction;
use blockstack_lib::chainstate::stacks::TransactionPayload;
use clarity::vm::Value as ClarityValue;
use clarity::vm::types::PrincipalData;
use clarity::vm::types::SequenceData;
use clarity::vm::types::StandardPrincipalData;
use emily_client::apis::deposit_api;
use lru::LruCache;
use sbtc::WITHDRAWAL_MIN_CONFIRMATIONS;
use sbtc::testing::containers::BitcoinContainer;
use sbtc::testing::containers::TestContainersBuilder;
use sbtc::testing::emily::EmilyTables;
use sbtc::testing::regtest;
use sbtc::testing::regtest::Faucet;
use sbtc::testing::regtest::Recipient;
use secp256k1::Keypair;
use serde::Deserialize;
use signer::block_observer::BlockObserver;
use signer::context::Context as _;
use signer::emily_client::EmilyClient;
use signer::keys::PublicKey;
use signer::keys::SignerScriptPubKey as _;
use signer::network::in_memory2::SignerNetwork;
use signer::network::in_memory2::WanNetwork;
use signer::request_decider::RequestDeciderEventLoop;
use signer::stacks::api::MockStacksInteract;
use signer::stacks::contracts::AcceptWithdrawalV1;
use signer::stacks::contracts::AsContractCall as _;
use signer::stacks::contracts::CompleteDepositV1;
use signer::storage::DbRead as _;
use signer::storage::DbWrite as _;
use signer::storage::model::StacksTxId;
use signer::storage::model::WithdrawalRequest;
use signer::storage::postgres::PgStore;
use signer::testing;
use signer::testing::btc::build_emily_request;
use signer::testing::btc::get_canonical_chain_tip;
use signer::testing::context::*;
use signer::testing::storage::DbReadTestExt as _;
use signer::transaction_coordinator::TxCoordinatorEventLoop;
use signer::transaction_signer::BITCOIN_SIGN_REQUEST_LRU_SIZE;
use signer::transaction_signer::STACKS_SIGN_REQUEST_LRU_SIZE;
use signer::transaction_signer::TxSignerEventLoop;
use signer::util::Sleep;
use testing_emily_client::apis::chainstate_api;
use testing_emily_client::apis::withdrawal_api;
use testing_emily_client::models::Chainstate;
use testing_emily_client::models::CreateWithdrawalRequestBody;
use testing_emily_client::models::WithdrawalParameters;
use tokio::sync::broadcast;
use tokio::sync::broadcast::error::TryRecvError;

use crate::containers::BitcoinContainerExt as _;
use crate::setup::IntoEmilyTestingConfig as _;
use crate::setup::backfill_bitcoin_blocks;
use crate::setup::clean_emily_setup;
use crate::setup::new_emily_setup;
use crate::transaction_coordinator::IntegrationTestContext;
use crate::transaction_coordinator::mock_stacks_core;
use crate::transaction_coordinator::wait_for_tenure_completed;
use crate::utxo_construction::make_deposit_request;

/// Extra blocks to wait for a sweep, since votes can arrive a tenure late.
const SWEEP_SLACK_BLOCKS: u64 = 2;

type Signer = (
    IntegrationTestContext<WrappedMock<MockStacksInteract>>,
    PgStore,
    Keypair,
    SignerNetwork,
);

/// The sweep a complete-deposit or accept-withdrawal call points at.
#[derive(Debug, PartialEq, Eq)]
struct SweepRef {
    txid: Txid,
    block_hash: BlockHash,
    block_height: u64,
}

struct Deposit {
    outpoint: OutPoint,
    /// The UTXO the deposit transaction spends.
    funding: Utxo,
}

/// Three signers that have run DKG and own a confirmed donation.
struct Harness<'a> {
    rpc: &'a Client,
    faucet: Faucet<'a>,
    emily_client: EmilyClient,
    emily_tables: EmilyTables,
    signers: Vec<Signer>,
    aggregate_key: PublicKey,
    donation: OutPoint,
    /// Funded in the donation's block.
    depositors: Vec<Recipient>,
    /// Kept alive: `mock_stacks_core` panics without a receiver.
    stacks_txs: broadcast::Receiver<StacksTransaction>,
}

impl<'a> Harness<'a> {
    async fn new(bitcoin: &'a BitcoinContainer, num_depositors: usize) -> Self {
        let (_, signer_key_pairs): (_, [Keypair; 3]) = testing::wallet::regtest_bootstrap_wallet();
        let rpc = bitcoin.rpc();
        let faucet = bitcoin.get_faucet();
        let (emily_client, emily_tables) = new_emily_setup().await;
        let network = WanNetwork::default();

        faucet.generate_fee_data();
        let chain_tip_info = get_canonical_chain_tip(rpc);

        let (stacks_tx_sender, stacks_txs) = broadcast::channel(100);
        let mut signers = Vec::new();
        for kp in signer_key_pairs.iter() {
            let db = testing::storage::new_test_database().await;
            let mut ctx = TestContext::builder()
                .with_storage(db.clone())
                .with_bitcoin_client(bitcoin.get_client())
                .with_emily_client(emily_client.clone())
                .with_mocked_stacks_client()
                .modify_settings(|settings| {
                    settings.signer.bitcoin_processing_delay = Duration::from_millis(200);
                })
                .build();

            backfill_bitcoin_blocks(&db, rpc, &chain_tip_info.hash).await;
            mock_stacks_core(
                &mut ctx,
                chain_tip_info.clone(),
                db.clone(),
                stacks_tx_sender.clone(),
            )
            .await;

            let network = network.connect(&ctx);
            signers.push((ctx, db, *kp, network));
        }

        let start_count = Arc::new(AtomicU8::new(0));
        let bitcoin_chain_tip_poller = bitcoin.start_chain_tip_poller().await;
        for (ctx, _, kp, network) in signers.iter() {
            ctx.state().set_sbtc_contracts_deployed();
            let ev = TxCoordinatorEventLoop {
                network: network.spawn(),
                context: ctx.clone(),
                context_window: 10000,
                private_key: kp.secret_key().into(),
                signing_round_max_duration: Duration::from_secs(10),
                bitcoin_presign_request_max_duration: Duration::from_secs(10),
                dkg_max_duration: Duration::from_secs(10),
                is_epoch3: true,
            };
            let counter = start_count.clone();
            tokio::spawn(async move {
                counter.fetch_add(1, Ordering::Relaxed);
                ev.run().await
            });

            let ev = TxSignerEventLoop {
                network: network.spawn(),
                context: ctx.clone(),
                context_window: 10000,
                wsts_state_machines: LruCache::new(NonZeroUsize::new(100).unwrap()),
                signer_private_key: kp.secret_key().into(),
                last_presign_block: None,
                dkg_begin_pause: None,
                dkg_verification_state_machines: LruCache::new(NonZeroUsize::new(5).unwrap()),
                stacks_sign_request: LruCache::new(STACKS_SIGN_REQUEST_LRU_SIZE),
                bitcoin_sign_request: LruCache::new(BITCOIN_SIGN_REQUEST_LRU_SIZE),
            };
            let counter = start_count.clone();
            tokio::spawn(async move {
                counter.fetch_add(1, Ordering::Relaxed);
                ev.run().await
            });

            let ev = RequestDeciderEventLoop {
                network: network.spawn(),
                context: ctx.clone(),
                context_window: 10000,
                deposit_decisions_retry_window: 1,
                withdrawal_decisions_retry_window: 1,
                blocklist_checker: Some(()),
                signer_private_key: kp.secret_key().into(),
            };
            let counter = start_count.clone();
            tokio::spawn(async move {
                counter.fetch_add(1, Ordering::Relaxed);
                ev.run().await
            });

            let block_observer = BlockObserver {
                context: ctx.clone(),
                bitcoin_block_source: bitcoin_chain_tip_poller.clone(),
            };
            let counter = start_count.clone();
            tokio::spawn(async move {
                counter.fetch_add(1, Ordering::Relaxed);
                block_observer.run().await
            });
        }

        while start_count.load(Ordering::SeqCst) < 12 {
            Sleep::for_millis(10).await;
        }

        // DKG runs on the first block.
        let chain_tip = faucet.generate_block();
        wait_for_tenure_completed(&signers, chain_tip.into()).await;

        let (_, db, _, _) = signers.first().unwrap();
        let shares = db.get_latest_encrypted_dkg_shares().await.unwrap().unwrap();
        let script_pubkey = shares.aggregate_key.signers_script_pubkey();
        let address = Address::from_script(&script_pubkey, bitcoin::Network::Regtest).unwrap();
        let donation = faucet.send_to(100_000, &address);

        let depositors: Vec<_> = std::iter::repeat_with(|| Recipient::new(AddressType::P2tr))
            .take(num_depositors)
            .collect();
        for depositor in &depositors {
            faucet.send_to(50_000_000, &depositor.address);
        }

        let harness = Self {
            rpc,
            faucet,
            emily_client,
            emily_tables,
            signers,
            aggregate_key: shares.aggregate_key,
            donation,
            depositors,
            stacks_txs,
        };
        harness.mine().await;
        harness
    }

    /// Mines a block and waits for every signer's tenure on it.
    async fn mine(&self) -> BlockHash {
        let block_hash = self.faucet.generate_block();
        self.wait_for_tenure(block_hash).await;
        block_hash
    }

    async fn wait_for_tenure(&self, block_hash: BlockHash) {
        wait_for_tenure_completed(&self.signers, block_hash.into()).await;
    }

    /// Mines a block with exactly `txs` (mempool txids or raw hex).
    fn generate_block_with(&self, txs: &[String]) -> BlockHash {
        #[derive(Deserialize)]
        struct GenerateBlock {
            hash: BlockHash,
        }
        let args = [
            self.faucet.address.to_string().into(),
            serde_json::to_value(txs).unwrap(),
        ];
        self.rpc
            .call::<GenerateBlock>("generateblock", &args)
            .unwrap()
            .hash
    }

    /// A mempool tx that keeps the next block distinct from an invalidated one.
    fn marker_tx(&self) -> String {
        self.faucet
            .send_to(1_000, &self.faucet.address)
            .txid
            .to_string()
    }

    async fn submit_deposit(&self, depositor: &Recipient) -> Deposit {
        let funding = depositor.get_utxos(self.rpc, None).pop().unwrap();
        let amount = 2_500_000;
        let (deposit_tx, deposit_request, deposit_info) = make_deposit_request(
            depositor,
            amount,
            funding.clone(),
            amount / 2,
            self.aggregate_key.into(),
        );
        self.rpc.send_raw_transaction(&deposit_tx).unwrap();

        let body = build_emily_request(&deposit_info, &deposit_tx);
        deposit_api::create_deposit(self.emily_client.config(), body)
            .await
            .unwrap();

        Deposit {
            outpoint: deposit_request.outpoint,
            funding,
        }
    }

    /// Records a withdrawal request as the stacks event observer would.
    async fn submit_withdrawal(&self, recipient: &Recipient, amount: u64) -> u64 {
        let (_, db, _, _) = self.signers.first().unwrap();
        let (bitcoin_chain_tip, stacks_chain_tip) = db.get_chain_tips().await;
        let request = WithdrawalRequest {
            request_id: 1,
            bitcoin_block_height: bitcoin_chain_tip.block_height,
            amount,
            block_hash: stacks_chain_tip,
            recipient: recipient.script_pubkey.clone().into(),
            max_fee: 10_000,
            txid: StacksTxId::from([1; 32]),
            sender_address: PrincipalData::from(StandardPrincipalData::transient()).into(),
        };
        for (_, db, _, _) in &self.signers {
            db.write_withdrawal_request(&request).await.unwrap();
        }

        let emily_config = self.emily_client.config().as_testing();
        let stacks_block_height = *db
            .get_stacks_block(&stacks_chain_tip)
            .await
            .unwrap()
            .unwrap()
            .block_height;
        let chainstate = Chainstate {
            stacks_block_hash: stacks_chain_tip.to_string(),
            stacks_block_height,
            bitcoin_block_height: Some(Some(0)),
        };
        chainstate_api::set_chainstate(&emily_config, chainstate)
            .await
            .unwrap();
        let body = CreateWithdrawalRequestBody {
            amount,
            parameters: Box::new(WithdrawalParameters { max_fee: request.max_fee }),
            recipient: request.recipient.to_string(),
            request_id: request.request_id,
            sender: request.sender_address.to_string(),
            stacks_block_hash: request.block_hash.to_string(),
            stacks_block_height,
            txid: request.txid.to_string(),
        };
        withdrawal_api::create_withdrawal(&emily_config, body)
            .await
            .unwrap();

        request.request_id
    }

    /// Mines up to `max_blocks` blocks until a mempool tx spends `outpoint`.
    async fn mine_until_spent(&self, outpoint: OutPoint, max_blocks: u64) -> Txid {
        for _ in 0..max_blocks {
            self.mine().await;
            if let Some(txid) = self.mempool_spender(outpoint) {
                return txid;
            }
        }
        panic!("no transaction spending {outpoint} reached the mempool");
    }

    fn mempool_spender(&self, outpoint: OutPoint) -> Option<Txid> {
        let (ctx, _, _, _) = self.signers.first().unwrap();
        let txids = ctx
            .bitcoin_client
            .get_tx_spending_prevout(&outpoint)
            .unwrap();
        assert!(txids.len() <= 1, "{outpoint} is spent by {txids:?}");
        txids.first().copied()
    }

    /// Asserts `expected` is unspent on the active chain and every signer's UTXO.
    async fn assert_signer_utxo(&self, chain_tip: BlockHash, expected: OutPoint) {
        assert_eq!(self.rpc.get_best_block_hash().unwrap(), chain_tip);
        let tx_out = self
            .rpc
            .get_tx_out(&expected.txid, expected.vout, Some(false))
            .unwrap();
        assert!(
            tx_out.is_some(),
            "{expected} is not unspent on the active chain"
        );

        for (_, db, _, _) in &self.signers {
            let utxo = db
                .get_signer_utxo(&chain_tip.into())
                .await
                .unwrap()
                .expect("no signer UTXO");
            assert_eq!(utxo.outpoint, expected);
        }
    }

    fn sweep_ref(&self, txid: Txid, block_hash: BlockHash) -> SweepRef {
        let header = self.rpc.get_block_header_info(&block_hash).unwrap();
        assert!(
            header.confirmations > 0,
            "{block_hash} is not on the active chain"
        );
        let block = self.rpc.get_block(&block_hash).unwrap();
        assert!(block.txdata.iter().any(|tx| tx.compute_txid() == txid));
        SweepRef {
            txid,
            block_hash,
            block_height: header.height as u64,
        }
    }

    fn assert_orphaned(&self, block_hash: &BlockHash) {
        let header = self.rpc.get_block_header_info(block_hash).unwrap();
        assert_eq!(
            header.confirmations, -1,
            "{block_hash} is still on the active chain"
        );
    }

    async fn cleanup(self) {
        for (_, db, _, _) in self.signers {
            testing::storage::drop_db(db).await;
        }
        clean_emily_setup(self.emily_tables).await;
    }
}

/// Drains submitted stacks txs into the sweeps each complete-deposit points at.
fn drain_complete_deposits(
    stacks_txs: &mut broadcast::Receiver<StacksTransaction>,
) -> HashMap<OutPoint, Vec<SweepRef>> {
    let mut sweeps: HashMap<OutPoint, Vec<SweepRef>> = HashMap::new();
    loop {
        let tx = match stacks_txs.try_recv() {
            Ok(tx) => tx,
            Err(TryRecvError::Empty) => return sweeps,
            Err(error) => panic!("missed stacks transactions: {error}"),
        };
        let TransactionPayload::ContractCall(call) = &tx.payload else {
            continue;
        };
        if call.function_name.as_str() != CompleteDepositV1::FUNCTION_NAME {
            continue;
        }
        let args = &call.function_args;
        let deposit = OutPoint::new(
            Txid::from_byte_array(le_buffer(&args[0])),
            uint(&args[1]) as u32,
        );
        sweeps.entry(deposit).or_default().push(SweepRef {
            txid: Txid::from_byte_array(le_buffer(&args[6])),
            block_hash: BlockHash::from_byte_array(le_buffer(&args[4])),
            block_height: uint(&args[5]) as u64,
        });
    }
}

/// Drains submitted stacks txs into the sweeps each accept-withdrawal points at.
fn drain_accepted_withdrawals(
    stacks_txs: &mut broadcast::Receiver<StacksTransaction>,
) -> HashMap<u64, Vec<SweepRef>> {
    let mut sweeps: HashMap<u64, Vec<SweepRef>> = HashMap::new();
    loop {
        let tx = match stacks_txs.try_recv() {
            Ok(tx) => tx,
            Err(TryRecvError::Empty) => return sweeps,
            Err(error) => panic!("missed stacks transactions: {error}"),
        };
        let TransactionPayload::ContractCall(call) = &tx.payload else {
            continue;
        };
        if call.function_name.as_str() != AcceptWithdrawalV1::FUNCTION_NAME {
            continue;
        }
        let args = &call.function_args;
        sweeps
            .entry(uint(&args[0]) as u64)
            .or_default()
            .push(SweepRef {
                txid: Txid::from_byte_array(le_buffer(&args[1])),
                block_hash: BlockHash::from_byte_array(le_buffer(&args[5])),
                block_height: uint(&args[6]) as u64,
            });
    }
}

/// Decodes a hash that contract calls carry in little-endian order.
fn le_buffer(value: &ClarityValue) -> [u8; 32] {
    let ClarityValue::Sequence(SequenceData::Buffer(buffer)) = value else {
        panic!("expected a buffer, got {value}");
    };
    let mut bytes: [u8; 32] = buffer.data.clone().try_into().unwrap();
    bytes.reverse();
    bytes
}

fn uint(value: &ClarityValue) -> u128 {
    let ClarityValue::UInt(value) = value else {
        panic!("expected a uint, got {value}");
    };
    *value
}

/// A 2-block reorg orphans a deposit and its sweep, and both are mined again.
/// The signers must mint again, only against the sweep's new block.
#[tokio::test]
async fn deposit_and_sweep_reorged_out() {
    let stack = TestContainersBuilder::start_bitcoin().await;
    let bitcoin = stack.bitcoin().await;
    let harness = Harness::new(bitcoin, 1).await;
    let mut stacks_txs = harness.stacks_txs.resubscribe();

    let deposit = harness.submit_deposit(&harness.depositors[0]).await;
    let sweep_txid = harness
        .mine_until_spent(harness.donation, 1 + SWEEP_SLACK_BLOCKS)
        .await;
    let deposit_block = harness
        .rpc
        .get_raw_transaction_info(&deposit.outpoint.txid, None)
        .unwrap()
        .blockhash
        .unwrap();
    let sweep_block = harness.mine().await;
    let sweep = OutPoint::new(sweep_txid, 0);

    harness.assert_signer_utxo(sweep_block, sweep).await;
    let minted = drain_complete_deposits(&mut stacks_txs);
    assert_eq!(
        minted[&deposit.outpoint],
        [harness.sweep_ref(sweep_txid, sweep_block)]
    );

    // Orphan the deposit's block and everything after it, then re-mine both.
    harness.rpc.invalidate_block(&deposit_block).unwrap();
    let marker = harness.marker_tx();
    harness.generate_block_with(&[deposit.outpoint.txid.to_string(), marker]);
    let new_sweep_block = harness.generate_block_with(&[sweep_txid.to_string()]);
    let chain_tip = harness.faucet.generate_block();
    harness.assert_orphaned(&sweep_block);
    harness.wait_for_tenure(chain_tip).await;

    harness.assert_signer_utxo(chain_tip, sweep).await;
    let minted = drain_complete_deposits(&mut stacks_txs);
    let sweeps = minted
        .get(&deposit.outpoint)
        .expect("the deposit was not minted again");
    let reorged = harness.sweep_ref(sweep_txid, new_sweep_block);
    assert!(sweeps.iter().all(|sweep| sweep == &reorged), "{sweeps:?}");

    harness.cleanup().await;
}

/// The latest sweep is reorged out and left in the mempool. The signers must
/// fall back to the previous sweep's output, then sweep and mint again.
#[tokio::test]
async fn latest_sweep_left_out_of_new_branch() {
    let stack = TestContainersBuilder::start_bitcoin().await;
    let bitcoin = stack.bitcoin().await;
    let harness = Harness::new(bitcoin, 2).await;
    let mut stacks_txs = harness.stacks_txs.resubscribe();

    harness.submit_deposit(&harness.depositors[0]).await;
    let first_sweep = OutPoint::new(
        harness
            .mine_until_spent(harness.donation, 1 + SWEEP_SLACK_BLOCKS)
            .await,
        0,
    );
    harness.mine().await;

    let deposit = harness.submit_deposit(&harness.depositors[1]).await;
    let second_sweep_txid = harness
        .mine_until_spent(first_sweep, 1 + SWEEP_SLACK_BLOCKS)
        .await;
    let second_sweep_block = harness.mine().await;
    harness
        .assert_signer_utxo(second_sweep_block, OutPoint::new(second_sweep_txid, 0))
        .await;
    let minted = drain_complete_deposits(&mut stacks_txs);
    let second_sweep = harness.sweep_ref(second_sweep_txid, second_sweep_block);
    assert_eq!(minted[&deposit.outpoint], [second_sweep]);

    // A longer empty branch leaves the sweep in the mempool.
    harness.rpc.invalidate_block(&second_sweep_block).unwrap();
    harness.generate_block_with(&[]);
    let chain_tip = harness.generate_block_with(&[]);
    harness.assert_orphaned(&second_sweep_block);
    harness.wait_for_tenure(chain_tip).await;

    harness.assert_signer_utxo(chain_tip, first_sweep).await;
    let minted = drain_complete_deposits(&mut stacks_txs);
    assert!(!minted.contains_key(&deposit.outpoint), "{minted:?}");
    let pending_txid = harness
        .mempool_spender(first_sweep)
        .expect("nothing spends the signers' UTXO");
    let pending = harness
        .rpc
        .get_raw_transaction(&pending_txid, None)
        .unwrap();
    assert!(
        pending
            .input
            .iter()
            .any(|tx_in| tx_in.previous_output == deposit.outpoint)
    );

    let chain_tip = harness.mine().await;
    harness
        .assert_signer_utxo(chain_tip, OutPoint::new(pending_txid, 0))
        .await;
    let minted = drain_complete_deposits(&mut stacks_txs);
    assert_eq!(
        minted[&deposit.outpoint],
        [harness.sweep_ref(pending_txid, chain_tip)]
    );

    harness.cleanup().await;
}

/// A swept deposit is double-spent on the new branch. The signers must not
/// mint it, must fall back to their previous UTXO, and keep sweeping.
#[tokio::test]
async fn swept_deposit_double_spent_on_new_branch() {
    let stack = TestContainersBuilder::start_bitcoin().await;
    let bitcoin = stack.bitcoin().await;
    let harness = Harness::new(bitcoin, 2).await;
    let mut stacks_txs = harness.stacks_txs.resubscribe();

    let deposit = harness.submit_deposit(&harness.depositors[0]).await;
    let sweep_txid = harness
        .mine_until_spent(harness.donation, 1 + SWEEP_SLACK_BLOCKS)
        .await;
    let deposit_block = harness
        .rpc
        .get_raw_transaction_info(&deposit.outpoint.txid, None)
        .unwrap()
        .blockhash
        .unwrap();
    let sweep_block = harness.mine().await;
    let minted = drain_complete_deposits(&mut stacks_txs);
    assert_eq!(
        minted[&deposit.outpoint],
        [harness.sweep_ref(sweep_txid, sweep_block)]
    );

    // The new branch spends the deposit's input elsewhere.
    harness.rpc.invalidate_block(&deposit_block).unwrap();
    let depositor = &harness.depositors[0];
    let mut double_spend = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::new(deposit.funding.txid, deposit.funding.vout),
            sequence: Sequence::ZERO,
            script_sig: ScriptBuf::new(),
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: deposit.funding.amount - Amount::from_sat(10_000),
            script_pubkey: depositor.address.script_pubkey(),
        }],
    };
    regtest::p2tr_sign_transaction(
        &mut double_spend,
        0,
        std::slice::from_ref(&deposit.funding),
        &depositor.keypair,
    );
    harness.generate_block_with(&[serialize_hex(&double_spend)]);
    let chain_tip = harness.generate_block_with(&[]);
    harness.assert_orphaned(&sweep_block);
    assert!(harness.mempool_spender(harness.donation).is_none());
    harness.wait_for_tenure(chain_tip).await;

    harness
        .assert_signer_utxo(chain_tip, harness.donation)
        .await;
    let minted = drain_complete_deposits(&mut stacks_txs);
    assert!(!minted.contains_key(&deposit.outpoint), "{minted:?}");

    // Other deposits are still swept and minted.
    let other = harness.submit_deposit(&harness.depositors[1]).await;
    let other_sweep_txid = harness
        .mine_until_spent(harness.donation, 1 + SWEEP_SLACK_BLOCKS)
        .await;
    let chain_tip = harness.mine().await;
    harness
        .assert_signer_utxo(chain_tip, OutPoint::new(other_sweep_txid, 0))
        .await;
    let minted = drain_complete_deposits(&mut stacks_txs);
    assert_eq!(
        minted[&other.outpoint],
        [harness.sweep_ref(other_sweep_txid, chain_tip)]
    );
    assert!(!minted.contains_key(&deposit.outpoint), "{minted:?}");

    harness.cleanup().await;
}

/// A withdrawal's sweep is reorged out and left in the mempool. The recipient
/// must be paid once, and accepted against the sweep's new block.
#[tokio::test]
async fn withdrawal_sweep_left_out_of_new_branch() {
    let stack = TestContainersBuilder::start_bitcoin().await;
    let bitcoin = stack.bitcoin().await;
    let harness = Harness::new(bitcoin, 0).await;
    let mut stacks_txs = harness.stacks_txs.resubscribe();

    let recipient = Recipient::new(AddressType::P2tr);
    let amount = 50_000;
    let request_id = harness.submit_withdrawal(&recipient, amount).await;
    let sweep_txid = harness
        .mine_until_spent(
            harness.donation,
            WITHDRAWAL_MIN_CONFIRMATIONS + SWEEP_SLACK_BLOCKS,
        )
        .await;
    let sweep_block = harness.mine().await;
    assert_eq!(recipient.get_balance(harness.rpc).to_sat(), amount);
    let accepted = drain_accepted_withdrawals(&mut stacks_txs);
    assert_eq!(
        accepted[&request_id],
        [harness.sweep_ref(sweep_txid, sweep_block)]
    );

    // A longer empty branch leaves the sweep in the mempool.
    harness.rpc.invalidate_block(&sweep_block).unwrap();
    harness.generate_block_with(&[]);
    let chain_tip = harness.generate_block_with(&[]);
    harness.assert_orphaned(&sweep_block);
    harness.wait_for_tenure(chain_tip).await;

    assert_eq!(recipient.get_balance(harness.rpc), Amount::ZERO);
    harness
        .assert_signer_utxo(chain_tip, harness.donation)
        .await;
    let accepted = drain_accepted_withdrawals(&mut stacks_txs);
    assert!(!accepted.contains_key(&request_id), "{accepted:?}");
    let pending_txid = harness
        .mempool_spender(harness.donation)
        .expect("nothing spends the signers' UTXO");

    let chain_tip = harness.mine().await;
    assert_eq!(recipient.get_balance(harness.rpc).to_sat(), amount);
    harness
        .assert_signer_utxo(chain_tip, OutPoint::new(pending_txid, 0))
        .await;
    let accepted = drain_accepted_withdrawals(&mut stacks_txs);
    assert_eq!(
        accepted[&request_id],
        [harness.sweep_ref(pending_txid, chain_tip)]
    );

    harness.cleanup().await;
}
