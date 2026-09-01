#!/bin/bash
#
# Adapted from stx-labs/infrastructure cron-miner.sh:
#   https://github.com/stx-labs/infrastructure/blob/7d04fbbebbadc64c0bf146e1ba3842cf25acbc4b/terraform/deployment/stacks-api/bitcoin/regtest/kustomize/stage/scripts/cron-miner.sh
#
# Commit-aware regtest miner for the sbtc devenv. Epoch-banded intervals
# and the wait-for-block-commit grace window come from that script; k8s
# seed-relay, treasury, and jitter are omitted here (single local
# bitcoind).
#
# Nakamoto (epoch 3+) requires a stacks-miner block-commit to land in a
# specific target bitcoin block. If bitcoin mines a block before the commit
# reaches its mempool, the commit fails the modulus check ("Invalid block
# commit: missed target block") in
# stackslib/src/chainstate/burn/operations/leader_block_commit.rs; the
# sortition goes to nobody and the stacks-miner stops re-committing
# entirely, with burn advancing while the stacks tip stays flat and the
# mempool empty.
#
# Fix: at each bitcoin block, wait up to MINE_GRACE_SECS for a tx to appear
# in the local mempool before mining. Mine as soon as one arrives, or mine
# anyway once grace expires.

set -e
trap "exit" INT TERM
trap "kill 0" EXIT
bitcoin-cli -rpcconnect=bitcoin -rpcwait getmininginfo
bitcoin-cli -rpcconnect=bitcoin -named createwallet wallet_name=main descriptors=false load_on_startup=true || true
bitcoin-cli -rpcconnect=bitcoin -named createwallet wallet_name=depositor descriptors=true load_on_startup=true || true
bitcoin-cli -rpcwallet=main -rpcconnect=bitcoin importaddress "${BTC_ADDR}" "" false
bitcoin-cli -rpcwallet=main -rpcconnect=bitcoin generatetoaddress "${INIT_BLOCKS}" "${BTC_ADDR}"
# We may require to hijack the dummy address to use it as faucet, if not we use
# a random address
DUMMY_ADDR=${DUMMY_ADDR:-$(bitcoin-cli -rpcwallet=depositor -rpcconnect=bitcoin getnewaddress label="" bech32)}
bitcoin-cli -rpcwallet=depositor -rpcconnect=bitcoin generatetoaddress 101 "${DUMMY_ADDR}"

TOPUP_WALLETS=${TOPUP_WALLETS:-}

topup_wallets() {
    if [ -z "$TOPUP_WALLETS" ]; then
        return
    fi
    echo "$TOPUP_WALLETS" | tr ',' '\n' | while IFS=: read -r wallet min amt; do
        [ -z "$wallet" ] && continue
        bitcoin-cli -rpcconnect=bitcoin loadwallet "$wallet" >/dev/null 2>&1 || true
        bal=$(bitcoin-cli -rpcconnect=bitcoin -rpcwallet="$wallet" getbalance 2>/dev/null || echo "")
        if [ -z "$bal" ]; then
            echo "topup: wallet '$wallet' not present yet - skipping"
            continue
        fi
        if awk "BEGIN {exit !($bal < $min)}"; then
            waddr=$(bitcoin-cli -rpcconnect=bitcoin -rpcwallet="$wallet" getnewaddress topup)
            echo "topup: wallet '$wallet' at $bal BTC (< $min), sending $amt BTC"
            bitcoin-cli -rpcconnect=bitcoin -rpcwallet=main sendtoaddress "$waddr" "$amt" || \
                echo "WARN: topup to wallet '$wallet' failed"
        fi
    done
}

# Local mempool size. The image lacks jq, so grep the JSON.
mempool_size() {
    bitcoin-cli -rpcconnect=bitcoin getmempoolinfo 2>/dev/null | grep -oP '"size":\s*\K[0-9]+' || echo 0
}

# How long to wait for the stacks miner's block-commit before mining anyway.
# Applies in EVERY epoch band — see the loop for why. Shorter during the ramp
# only to bound the pre-genesis window, when no miner exists to commit at all.
MINE_GRACE_SECS=${MINE_GRACE_SECS:-30}

MINE_GRACE_RAMP_SECS=${MINE_GRACE_RAMP_SECS:-25}

sleep_interruptible() {
    sleep "$1" & wait || exit 0
}

while true; do
    topup_wallets

    BLOCK_HEIGHT=$(bitcoin-cli -rpcconnect=bitcoin getblockcount 2>/dev/null || echo "-999")

    if [ "${BLOCK_HEIGHT}" -eq "-999" ]; then
        echo "Failed to get block height, likely due to bitcoind connection issue. Retrying in ${RETRY_SLEEP_DURATION}s..."
        sleep_interruptible "${RETRY_SLEEP_DURATION}"
        continue
    elif [ -n "${STACKS_40_HEIGHT:-}" ] && [ "${BLOCK_HEIGHT}" -ge "${STACKS_40_HEIGHT}" ]; then
        BAND=epoch4
        SLEEP_DURATION=${MINE_INTERVAL_EPOCH4:-30}
        GRACE=${MINE_GRACE_SECS}
    elif [ "${BLOCK_HEIGHT}" -gt $(( STACKS_30_HEIGHT + 1 )) ]; then
        BAND=epoch3
        SLEEP_DURATION=${MINE_INTERVAL_EPOCH3}
        GRACE=${MINE_GRACE_SECS}
    elif [ "${BLOCK_HEIGHT}" -gt $(( STACKS_25_HEIGHT + 1 )) ]; then
        BAND=epoch2.5
        SLEEP_DURATION=${MINE_INTERVAL_EPOCH25}
        GRACE=${MINE_GRACE_RAMP_SECS}
    else
        BAND=epoch2
        SLEEP_DURATION=${MINE_INTERVAL}
        GRACE=${MINE_GRACE_RAMP_SECS}
    fi

    sleep_interruptible "${SLEEP_DURATION}"

    if [ "${GRACE}" -gt 0 ]; then
        DEADLINE=$(( $(date +%s) + GRACE ))
        while [ "$(mempool_size)" -eq 0 ] && [ "$(date +%s)" -lt "$DEADLINE" ]; do
            sleep 1
        done
        if [ "$(mempool_size)" -eq 0 ]; then
            echo "[${BAND} h=${BLOCK_HEIGHT}] no commit in mempool after ${GRACE}s, mining anyway"
        else
            echo "[${BAND} h=${BLOCK_HEIGHT}] commit in mempool (n=$(mempool_size)), mining now"
        fi
    else
        echo "[${BAND} h=${BLOCK_HEIGHT}] mining"
    fi

    bitcoin-cli -rpcconnect=bitcoin -rpcwallet=main generatetoaddress 1 "${BTC_ADDR}" >/dev/null || \
        echo "WARN: generatetoaddress failed at height ${BLOCK_HEIGHT}"
done
