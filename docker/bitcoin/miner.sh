#!/bin/bash

set -e
trap "exit" INT TERM
trap "kill 0" EXIT
bitcoin-cli -rpcconnect=bitcoin -rpcwait getmininginfo
bitcoin-cli -rpcconnect=bitcoin -named createwallet wallet_name=main descriptors=false load_on_startup=true || true
bitcoin-cli -rpcconnect=bitcoin -named createwallet wallet_name=depositor descriptors=true load_on_startup=true || true
bitcoin-cli -rpcwallet=main -rpcconnect=bitcoin importaddress "${BTC_ADDR}" "" false
bitcoin-cli -rpcwallet=main -rpcconnect=bitcoin generatetoaddress "${INIT_BLOCKS}" "${BTC_ADDR}"
ADDR=$(bitcoin-cli -rpcwallet=depositor -rpcconnect=bitcoin getnewaddress label="" bech32)
bitcoin-cli -rpcwallet=depositor -rpcconnect=bitcoin generatetoaddress 101 "${ADDR}"
DEFAULT_TIMEOUT=$(($(date +%s) + 30))
while true; do
    # Attempt to get the latest transaction, defaulting to an empty string on failure.
    TX=$(bitcoin-cli -rpcwallet=main -rpcconnect=bitcoin listtransactions '*' 1 0 true 2>/dev/null || echo "")
    CONFS=$(echo "${TX}" | grep -oP '"confirmations": \K\d+' | awk '{print $1}')

    # Use a default for CONFS to prevent errors if the command fails.
    if [ "${CONFS:-999}" = "0" ] || [ "$(date +%s)" -gt $DEFAULT_TIMEOUT ]; then
        if [ "$(date +%s)" -gt $DEFAULT_TIMEOUT ]; then
            echo "Timed out waiting for a mempool tx, mining a btc block..."
        else
            echo "Detected Stacks mining mempool tx, mining btc block..."
        fi
        bitcoin-cli -rpcwallet=main -rpcconnect=bitcoin generatetoaddress 1 "${BTC_ADDR}"
        # Update the default timeout to 30 seconds from now for the next iteration.
        DEFAULT_TIMEOUT=$(($(date +%s) + 30))
    else
        echo "No Stacks mining tx detected"
    fi

    # Attempt to get the block height, defaulting to -999 on failure.
    BLOCK_HEIGHT=$(bitcoin-cli -rpcwallet=main -rpcconnect=bitcoin getblockcount 2>/dev/null || echo "-999")

    if [ "${BLOCK_HEIGHT}" -eq "-999" ]; then
        # If getting block height failed, set the sleep duration to the retry interval.
        echo "Failed to get block height, likely due to bitcoind connection issue. Retrying in ${RETRY_SLEEP_DURATION}s..."
        SLEEP_DURATION=${RETRY_SLEEP_DURATION}
    elif [ "${BLOCK_HEIGHT}" -gt $(( STACKS_30_HEIGHT + 1 )) ]; then
        # Set the sleep duration for Epoch 3.
        echo "In Epoch3, sleeping for ${MINE_INTERVAL_EPOCH3} ..."
        SLEEP_DURATION=${MINE_INTERVAL_EPOCH3}
    elif [ "${BLOCK_HEIGHT}" -gt $(( STACKS_25_HEIGHT + 1 )) ]; then
        # Set the sleep duration for Epoch 2.5.
        echo "In Epoch2.5, sleeping for ${MINE_INTERVAL_EPOCH25} ..."
        SLEEP_DURATION=${MINE_INTERVAL_EPOCH25}
    else
        # Set the default sleep duration for all other cases.
        SLEEP_DURATION=${MINE_INTERVAL}
    fi

    # Sleep for the duration determined by the logic above.
    # The `& wait` pattern allows the script to be interrupted gracefully.
    sleep "${SLEEP_DURATION}" & wait || exit 0
done
