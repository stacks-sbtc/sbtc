use crate::error::Error;
use crate::storage::memory::MemoryStoreError;
use crate::storage::memory::store::Store;
use crate::storage::{DbRead, DbWrite, Transactable, TransactionHandle};
use crate::testing::blocks::{BitcoinChain, StacksChain};

use assert_matches::assert_matches;
use test_log::test;

#[tokio::test]
async fn test_in_memory_transaction_commit() -> Result<(), Error> {
    let shared_store = Store::new_shared();

    let bitcoin_chain = BitcoinChain::default();
    let stacks_chain = StacksChain::new_anchored(&bitcoin_chain);
    let btc_1 = bitcoin_chain.first_block();
    let stx_a = stacks_chain.first_block();
    let stx_b = stx_a.new_child().anchored_to(btc_1);
    let btc_2 = btc_1.new_child();
    let stx_c = stx_b.new_child().anchored_to(&btc_2);

    // Start transaction
    let tx = shared_store.begin_transaction().await?;

    // Write data within transaction
    tx.write_bitcoin_block(btc_1).await?;
    tx.write_stacks_block(stx_a).await?;
    tx.write_stacks_block(&stx_b).await?;

    tx.write_bitcoin_block(&btc_2).await?;
    tx.write_stacks_block(&stx_c).await?;

    // Commit transaction
    tx.commit().await?;

    // Verify data in original store
    assert_eq!(
        shared_store.get_bitcoin_block(&btc_1.block_hash).await?,
        Some(btc_1.clone())
    );
    assert_eq!(
        shared_store.get_stacks_block(&stx_a.block_hash).await?,
        Some(stx_a.clone())
    );
    assert_eq!(
        shared_store.get_stacks_block(&stx_b.block_hash).await?,
        Some(stx_b.clone())
    );

    assert_eq!(
        shared_store.get_bitcoin_block(&btc_2.block_hash).await?,
        Some(btc_2.clone())
    );
    assert_eq!(
        shared_store.get_stacks_block(&stx_c.block_hash).await?,
        Some(stx_c.clone())
    );

    // Verify one-to-many relationships in bitcoin_anchor_to_stacks_blocks
    let store_guard = shared_store.lock().await;

    let anchored_blocks1 = store_guard
        .bitcoin_anchor_to_stacks_blocks
        .get(&btc_1.block_hash)
        .expect("BTC hash 1 should have anchored Stacks blocks");
    assert_eq!(
        anchored_blocks1.len(),
        2,
        "BTC block 1 should anchor 2 Stacks blocks"
    );
    assert!(anchored_blocks1.contains(&stx_a.block_hash));
    assert!(anchored_blocks1.contains(&stx_b.block_hash));

    let anchored_blocks2 = store_guard
        .bitcoin_anchor_to_stacks_blocks
        .get(&btc_2.block_hash)
        .expect("BTC hash 2 should have anchored Stacks blocks");
    assert_eq!(
        anchored_blocks2.len(),
        1,
        "BTC block 2 should anchor 1 Stacks block"
    );
    assert!(anchored_blocks2.contains(&stx_c.block_hash));

    Ok(())
}

#[tokio::test]
async fn test_in_memory_transaction_rollback() -> Result<(), Error> {
    let shared_store = Store::new_shared();

    let bitcoin_chain = BitcoinChain::default();
    let stacks_chain = StacksChain::new_anchored(&bitcoin_chain);
    let btc_1 = bitcoin_chain.first_block();
    let stx_a = stacks_chain.first_block();

    // Start transaction
    let tx = shared_store.begin_transaction().await?;

    // Write data within transaction
    tx.write_bitcoin_block(btc_1).await?;
    tx.write_stacks_block(stx_a).await?;

    // Rollback transaction
    tx.rollback().await?;

    // Verify data is NOT in original store
    assert!(
        shared_store
            .get_bitcoin_block(&btc_1.block_hash)
            .await?
            .is_none()
    );
    assert!(
        shared_store
            .get_stacks_block(&stx_a.block_hash)
            .await?
            .is_none()
    );

    let store_guard = shared_store.lock().await;
    let anchored_stacks_blocks = store_guard
        .bitcoin_anchor_to_stacks_blocks
        .get(&btc_1.block_hash);
    assert!(
        anchored_stacks_blocks.is_none_or(|v| v.is_empty()),
        "Anchored blocks should be None or empty after rollback"
    );

    Ok(())
}

#[test(tokio::test)]
async fn test_in_memory_transaction_implicit_rollback_on_drop() -> Result<(), Error> {
    let shared_store = Store::new_shared();

    let bitcoin_chain = BitcoinChain::default();
    let stacks_chain = StacksChain::new_anchored(&bitcoin_chain);
    let btc_1 = bitcoin_chain.first_block();
    let stx_a = stacks_chain.first_block();

    // Scope for the transaction. The transaction will be dropped at the end of
    // the scope and should implicitly roll-back.
    {
        let tx = shared_store.begin_transaction().await?;
        tx.write_bitcoin_block(btc_1).await?;
        tx.write_stacks_block(stx_a).await?;
    }

    // Verify data is NOT in original store
    assert!(
        shared_store
            .get_bitcoin_block(&btc_1.block_hash)
            .await?
            .is_none()
    );
    assert!(
        shared_store
            .get_stacks_block(&stx_a.block_hash)
            .await?
            .is_none()
    );

    let store_guard = shared_store.lock().await;
    let anchored_stacks_blocks = store_guard
        .bitcoin_anchor_to_stacks_blocks
        .get(&btc_1.block_hash);
    assert!(
        anchored_stacks_blocks.is_none_or(|v| v.is_empty()),
        "Anchored blocks should be None or empty after implicit rollback"
    );

    Ok(())
}

#[tokio::test]
async fn test_in_memory_transaction_optimistic_concurrency_violation() {
    let shared_store = Store::new_shared();

    // Create some dummy block data
    let bitcoin_chain = BitcoinChain::default();
    let btc_block1 = bitcoin_chain.first_block();
    let btc_block2 = btc_block1.new_child();

    // Start transaction 1
    // Tx1 captures the initial version of shared_store (0)
    let tx1 = shared_store
        .begin_transaction()
        .await
        .expect("Failed to begin transaction 1");
    // Perform a write operation in tx1.
    tx1.write_bitcoin_block(btc_block1)
        .await
        .expect("Failed to write bitcoin block in tx1");

    // Start transaction 2
    // Tx2 also captures the initial version of shared_store (0), as tx1 hasn't committed yet.
    let tx2 = shared_store
        .begin_transaction()
        .await
        .expect("Failed to begin transaction 2");
    // Perform a write operation in tx2.
    tx2.write_bitcoin_block(&btc_block2)
        .await
        .expect("Failed to write bitcoin block in tx2");

    // Commit transaction 2
    // This should succeed as tx2 updates the version of shared_store to 1 as
    // the first to commit. Tx1 is still open and has version 0.
    tx2.commit().await.expect("Failed to commit transaction 2");

    // Attempt to commit transaction 1
    // This should fail with an optimistic concurrency error because tx1 still
    // holds the initial version of shared_store (0), while tx2 has already
    // updated it to 1.
    assert_matches!(
        tx1.commit().await,
        Err(Error::InMemoryDatabase(
            MemoryStoreError::OptimisticConcurrency { .. }
        ))
    );
}

#[tokio::test]
async fn test_in_memory_transaction_optimistic_concurrency_violation_with_direct_write() {
    let shared_store = Store::new_shared();

    // Create some dummy block data
    let bitcoin_chain = BitcoinChain::default();
    let btc_block1 = bitcoin_chain.first_block();
    let btc_block2 = btc_block1.new_child();

    // Start a transaction (tx1)
    // Tx1 captures the initial version of shared_store (e.g., version 0)
    let tx1 = shared_store
        .begin_transaction()
        .await
        .expect("Failed to begin transaction 1");

    // Perform a write operation within tx1. This modifies tx1's internal copy.
    tx1.write_bitcoin_block(btc_block1)
        .await
        .expect("Failed to write bitcoin block in tx1");

    // Simulate a concurrent write directly to the SharedStore (outside of any explicit transaction)
    // This will increment the version of the shared_store (e.g., to version 1)
    shared_store
        .write_bitcoin_block(&btc_block2)
        .await
        .expect("Failed to perform direct write on shared_store");

    // Attempt to commit transaction 1
    // This should fail with an optimistic concurrency error because tx1's captured version (0)
    // no longer matches the shared_store's current version (1).
    assert_matches!(
        tx1.commit().await,
        Err(Error::InMemoryDatabase(
            MemoryStoreError::OptimisticConcurrency { .. }
        ))
    );
}
