//! Integration tests for bitcoin-forking behaviours

use std::slice;

use bitcoin::Sequence;
use bitcoin::Transaction;
use bitcoin::TxIn;
use bitcoin::TxOut;
use bitcoin::Witness;
use bitcoin::absolute::LockTime;
use bitcoin::transaction::Version;
use sbtc::testing::regtest::AsUtxo as _;
use serde::Deserialize;
use serde_json::to_value;
use signer::bitcoin::BitcoinInteract as _;

use bitcoin::AddressType;
use bitcoin::Amount;
use bitcoin::ScriptBuf;
use bitcoincore_rpc::RpcApi as _;
use sbtc::testing::regtest;

use signer::context::Context as _;
use signer::testing::context::TestContext;
use signer::testing::context::*;

#[derive(Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct GenerateBlockJson {
    pub hash: bitcoin::BlockHash,
}

/// Test checking `getrawtransaction` behaviour after a fork
#[test_log::test(tokio::test)]
async fn getrawtransaction_simple_fork() {
    // We don't really need a context, we just need the bitcoin client
    let ctx = TestContext::builder()
        .with_in_memory_storage()
        .with_first_bitcoin_core_client()
        .with_mocked_stacks_client()
        .with_mocked_emily_client()
        .build();
    let bitcoin = ctx.get_bitcoin_client();

    let (rpc, faucet) = regtest::initialize_blockchain();

    // Start from a clean mempool
    faucet.generate_block();

    // Prepare the UTXO used by the tx
    let utxo_outpoint = &faucet.send_to(10_000, &faucet.address);
    faucet.generate_block();

    let utxos = faucet.get_utxos(None);
    let utxo = utxos.iter().find(|u| u.txid == utxo_outpoint.txid).unwrap();

    // Create a tx spending the UTXO
    let mut tx = Transaction {
        version: Version::ONE,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: utxo.outpoint(),
            sequence: Sequence::ZERO,
            script_sig: ScriptBuf::new(),
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(9_000),
            script_pubkey: faucet.address.script_pubkey(),
        }],
    };
    let input_index = 0;
    let keypair = &faucet.keypair;
    match faucet.address.address_type().unwrap() {
        AddressType::P2wpkh => {
            regtest::p2wpkh_sign_transaction(&mut tx, input_index, utxo, keypair)
        }
        AddressType::P2tr => {
            regtest::p2tr_sign_transaction(&mut tx, input_index, slice::from_ref(utxo), keypair)
        }
        _ => unimplemented!(),
    };
    rpc.send_raw_transaction(&tx).unwrap();
    let txid = &tx.compute_txid();

    // The tx should be in mempool
    let tx = bitcoin.get_tx(txid).await.unwrap().unwrap();
    assert!(tx.confirmations.is_none());
    assert!(tx.block_hash.is_none());

    let block_1a = faucet.generate_block();

    // And now it should be confirmed
    let tx = bitcoin.get_tx(txid).await.unwrap().unwrap();
    assert_eq!(tx.confirmations, Some(1));
    assert!(tx.block_hash.is_some());

    // Now we fork by invalidating the tip and creating a 2 blocks branch
    rpc.invalidate_block(&block_1a).unwrap();

    // As it's invalidated, the tx is back to mempool; we don't get
    // confirmations since the tx, while existing in another (forked) block, is
    // also a valid tx in the mempool.
    let tx = bitcoin.get_tx(txid).await.unwrap().unwrap();
    assert!(tx.confirmations.is_none());
    assert!(tx.block_hash.is_none());

    // Generate two blocks, with only coinbases, to get a canonical chain
    // excluding the fork.
    for _ in 0..2 {
        rpc.call::<GenerateBlockJson>(
            "generateblock",
            &[
                faucet.address.to_string().into(),
                to_value::<&[String; 0]>(&[]).unwrap(),
            ],
        )
        .unwrap();
    }

    // Even after the forked block is no longer the chain tip, as the tx is
    // valid in the mempool we get no confirmations nor mention of the forked
    // block hash.
    let tx = bitcoin.get_tx(txid).await.unwrap().unwrap();
    assert!(tx.confirmations.is_none());
    assert!(tx.block_hash.is_none());

    // And we send a new tx invalidating the previous one
    let mut tx = Transaction {
        version: Version::ONE,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: utxo.outpoint(),
            sequence: Sequence::ZERO,
            script_sig: ScriptBuf::new(),
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(8_000), // higher fee to be accepted as RBF
            script_pubkey: faucet.address.script_pubkey(),
        }],
    };
    match faucet.address.address_type().unwrap() {
        AddressType::P2wpkh => {
            regtest::p2wpkh_sign_transaction(&mut tx, input_index, utxo, keypair)
        }
        AddressType::P2tr => {
            regtest::p2tr_sign_transaction(&mut tx, input_index, slice::from_ref(utxo), keypair)
        }
        _ => unimplemented!(),
    };
    rpc.send_raw_transaction(&tx).unwrap();
    let invalidating_txid = &tx.compute_txid();

    // The invalidating tx isn't confirmed yet
    let invalidating_tx = bitcoin.get_tx(invalidating_txid).await.unwrap().unwrap();
    assert!(invalidating_tx.confirmations.is_none());

    // And the original one also is back to unconfirmed
    let tx = bitcoin.get_tx(txid).await.unwrap().unwrap();
    assert_eq!(tx.confirmations, Some(0));
    assert!(tx.block_hash.is_some());

    let block_1b = faucet.generate_block();
    assert_ne!(block_1a, block_1b);

    // The invalidating tx should be confirmed now
    let invalidating_tx = bitcoin.get_tx(invalidating_txid).await.unwrap().unwrap();
    assert_eq!(invalidating_tx.confirmations, Some(1));

    // And the original tx is still unconfirmed
    let tx = bitcoin.get_tx(txid).await.unwrap().unwrap();
    assert_eq!(tx.confirmations, Some(0));
    assert!(tx.block_hash.is_some());

    // One more block to make this the canonical one
    faucet.generate_block();

    // The invalidating tx is still very much confirmed
    let invalidating_tx = bitcoin.get_tx(invalidating_txid).await.unwrap().unwrap();
    assert_eq!(invalidating_tx.confirmations, Some(2));

    // And the original tx is still unconfirmed
    let tx = bitcoin.get_tx(txid).await.unwrap().unwrap();
    assert_eq!(tx.confirmations, Some(0));
    assert!(tx.block_hash.is_some());
}

/// Test checking `getrawtransaction` behaviour when querying for a specific tx
/// between reorgs.
#[test_log::test(tokio::test)]
async fn getrawtransaction_single_tx_regorged() {
    // We don't really need a context, we just need the bitcoin client
    let ctx = TestContext::builder()
        .with_in_memory_storage()
        .with_first_bitcoin_core_client()
        .with_mocked_stacks_client()
        .with_mocked_emily_client()
        .build();
    let bitcoin = ctx.get_bitcoin_client();

    let (rpc, faucet) = regtest::initialize_blockchain();

    // Start from a clean mempool
    faucet.generate_block();

    // Create a tx
    let txid = &faucet.send_to(10_000, &faucet.address).txid;

    // The tx should be in mempool
    let tx = bitcoin.get_tx(txid).await.unwrap().unwrap();
    assert!(tx.confirmations.is_none());
    assert!(tx.block_hash.is_none());

    let block_1a = faucet.generate_block();

    // And now it should be confirmed
    let tx = bitcoin.get_tx(txid).await.unwrap().unwrap();
    assert_eq!(tx.confirmations, Some(1));
    assert_eq!(tx.block_hash, Some(block_1a));

    faucet.generate_block();

    let tx = bitcoin.get_tx(txid).await.unwrap().unwrap();
    assert_eq!(tx.confirmations, Some(2));
    assert_eq!(tx.block_hash, Some(block_1a));

    // Now we fork
    rpc.invalidate_block(&block_1a).unwrap();

    // As it's invalidated, the tx is back to mempool; we don't get
    // confirmations since the tx, while existing in another (forked) block, is
    // also a valid tx in the mempool.
    let tx = bitcoin.get_tx(txid).await.unwrap().unwrap();
    assert!(tx.confirmations.is_none());
    assert!(tx.block_hash.is_none());

    // Generate two blocks, with only coinbases, to get a canonical chain
    // excluding the fork.
    for _ in 0..2 {
        rpc.call::<GenerateBlockJson>(
            "generateblock",
            &[
                faucet.address.to_string().into(),
                to_value::<&[String; 0]>(&[]).unwrap(),
            ],
        )
        .unwrap();
    }

    // Even after the forked block is no longer the chain tip, as the tx is
    // valid in the mempool we get no confirmations nor mention of the forked
    // block hash.
    let tx = bitcoin.get_tx(txid).await.unwrap().unwrap();
    assert!(tx.confirmations.is_none());
    assert!(tx.block_hash.is_none());

    let block_1b = faucet.generate_block();
    assert_ne!(block_1a, block_1b);

    // Now, which block are we getting? The second one (the "tallest" one), even
    // if the other had 2 confirmations, which is nice.
    let tx = bitcoin.get_tx(txid).await.unwrap().unwrap();
    assert_eq!(tx.confirmations, Some(1));
    assert_eq!(tx.block_hash, Some(block_1b));

    faucet.generate_block();

    let tx = bitcoin.get_tx(txid).await.unwrap().unwrap();
    assert_eq!(tx.confirmations, Some(2));
    assert_eq!(tx.block_hash, Some(block_1b));
}
