use bitcoin::BlockHash;
use futures::StreamExt;
use sbtc::testing::regtest;
use signer::bitcoin::BitcoinBlockHashStreamProvider as _;
use signer::bitcoin::poller::BitcoinChainTipPoller;
use signer::util::Sleep;
use test_log::test;
use tokio::sync::mpsc::error::TryRecvError;

/// This tests that our bitcoin block hash stream receives new block hashes
/// from bitcoin-core as it receives blocks. We create the stream, generate
/// bitcoin blocks, and wait for the block hashes to be received from the
/// stream. This also checks that we parse block hashes correctly, since
/// they are supposed to be little-endian formatted.
#[test(tokio::test)]
async fn chain_tip_poller_streams_chain_tips() {
    let (_, faucet) = regtest::initialize_blockchain();

    let mut block_hash_stream = BitcoinChainTipPoller::start_for_regtest()
        .await
        .get_block_hash_stream();

    // We want to have our stream always waiting for block hashes so that
    // we get them as they arise. The issue is that await points
    // essentially block progress on the current code execution path. So we
    // spawn a new task to handle the blocking part, and have the task send
    // us blocks through a channel as they arrive.
    let (sx, mut rx) = tokio::sync::mpsc::channel::<BlockHash>(100);

    // This task will "watch" for bitcoin blocks and send them to us.
    tokio::spawn(async move {
        while let Some(Ok(block_hash)) = block_hash_stream.next().await {
            if sx.is_closed() {
                break;
            }

            tracing::info!("Sending block hash {block_hash}");
            sx.send(block_hash).await.unwrap();
        }
    });

    // When the faucet generates a block it returns the block hash of the
    // generated block. We'll match this hash with the hash received from
    // our task above.
    let block_hash = faucet.generate_block();
    let received_hash = rx.recv().await.unwrap();
    assert_eq!(block_hash, received_hash);

    // We only generated one block, so we should only have one block hash.
    assert_eq!(Err(TryRecvError::Empty), rx.try_recv());

    // Now let's make sure we're actually receiving _chain tip_ block hashes by
    // generating a few more blocks. The chain tip should be the last block
    // hash we receive.
    let block_hashes = faucet.generate_blocks(5);
    let final_tip_hash = block_hashes.last().unwrap();

    // Consume all hashes sent by the poller until we get the final tip.
    // This handles the case where the poller might see intermediate blocks.
    let mut last_received_hash = None;
    for _ in 0..block_hashes.len() {
        // Use a timeout to avoid waiting forever if the poller is slow for
        // some reason.
        if let Ok(Some(received)) =
            tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv()).await
        {
            last_received_hash = Some(received);
            if last_received_hash.as_ref() == Some(final_tip_hash) {
                break;
            }
        }
    }

    // The last hash we received must be the final chain tip.
    assert_eq!(Some(*final_tip_hash), last_received_hash);

    Sleep::for_millis(250).await;
    // Ensure that no more hashes are received after the final tip.
    assert_eq!(Err(TryRecvError::Empty), rx.try_recv());
}
