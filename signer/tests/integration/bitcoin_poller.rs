use bitcoin::BlockHash;
use futures::StreamExt;
use sbtc::testing::regtest;
use signer::bitcoin::BitcoinBlockHashStreamProvider as _;
use signer::bitcoin::poller::BitcoinChainTipPoller;
use test_log::test;

/// This tests that out bitcoin block hash stream receives new block hashes
/// from bitcoin-core as it receives blocks. We create the stream, generate
/// bitcoin blocks, and wait for the block hashes to be received from the
/// stream. This also checks that we parse block hashes correctly, since
/// they are supposed to be little-endian formatted.
#[test(tokio::test)]
async fn block_hash_stream_streams_block_hashes() {
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
    let block_hashes = faucet.generate_blocks(1);
    let item = rx.recv().await;

    // We only generated one block, so we should only have one block hash.
    assert_eq!(block_hashes.len(), 1);
    assert_eq!(block_hashes[0], item.unwrap());

    // Let's try again for good measure, couldn't hurt.
    let block_hashes = faucet.generate_blocks(1);
    let item = rx.recv().await;

    assert_eq!(block_hashes.len(), 1);
    assert_eq!(block_hashes[0], item.unwrap());
}
