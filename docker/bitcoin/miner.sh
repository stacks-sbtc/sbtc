#!/bin/bash

set -e
trap "exit" INT TERM
trap "kill 0" EXIT
bitcoin-cli -rpcconnect=bitcoin -rpcwait getmininginfo
bitcoin-cli -rpcconnect=bitcoin -named createwallet wallet_name=main descriptors=false || true
bitcoin-cli -rpcconnect=bitcoin -named createwallet wallet_name=depositor descriptors=true || true
bitcoin-cli -rpcwallet=main -rpcconnect=bitcoin importaddress "${BTC_ADDR}" "" false
bitcoin-cli -rpcwallet=main -rpcconnect=bitcoin generatetoaddress "${INIT_BLOCKS}" "${BTC_ADDR}"
ADDR=$(bitcoin-cli -rpcwallet=depositor -rpcconnect=bitcoin getnewaddress label="" bech32)
bitcoin-cli -rpcwallet=depositor -rpcconnect=bitcoin generatetoaddress 101 "${ADDR}"
DEFAULT_TIMEOUT=$(($(date +%s) + 30))
while true; do
    # Ensure wallets are loaded, in case bitcoind restarted.
    # The `|| true` prevents the script from exiting if the wallet is already loaded.
    bitcoin-cli -rpcconnect=bitcoin loadwallet main >/dev/null 2>&1 || true
    bitcoin-cli -rpcconnect=bitcoin loadwallet depositor >/dev/null 2>&1 || true

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

    # Attempt to get the block height, defaulting to 0 on failure.
    BLOCK_HEIGHT=$(bitcoin-cli -rpcwallet=main -rpcconnect=bitcoin getblockcount 2>/dev/null || echo "-999")

    if [ "${BLOCK_HEIGHT}" -eq "-999" ]; then
        # If getting block height failed, wait before retrying.
        echo "Failed to get block height, likely due to bitcoind connection issue. Retrying in ${RETRY_SLEEP_DURATION}s..."
        sleep "${RETRY_SLEEP_DURATION}" &
        wait || exit 0
    else
        # Otherwise, determine the correct sleep duration based on the epoch.
        SLEEP_DURATION=${MINE_INTERVAL}
        if [ "${BLOCK_HEIGHT}" -gt $(( STACKS_30_HEIGHT + 1 )) ]; then
            echo "In Epoch3, sleeping for ${MINE_INTERVAL_EPOCH3} ..."
            SLEEP_DURATION=${MINE_INTERVAL_EPOCH3}
        elif [ "${BLOCK_HEIGHT}" -gt $(( STACKS_25_HEIGHT + 1 )) ]; then
            echo "In Epoch2.5, sleeping for ${MINE_INTERVAL_EPOCH25} ..."
            SLEEP_DURATION=${MINE_INTERVAL_EPOCH25}
        fi
        sleep "${SLEEP_DURATION}" &
        wait || exit 0
    fi
done