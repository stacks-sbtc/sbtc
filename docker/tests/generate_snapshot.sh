#!/bin/bash

set -e

cd "$(dirname "$0")"

TARGET_BLOCK=237
DOCKER_COMPOSE="docker compose -f docker-compose.stacks.build.yml"

$DOCKER_COMPOSE down -v -t 0
rm -rf snapshot || true

$DOCKER_COMPOSE up -d --build

while true; do
    BITCOIN_HEIGHT=$(curl -s http://localhost:20443/v2/info | jq .burn_block_height 2> /dev/null)
    BITCOIN_HEIGHT=${BITCOIN_HEIGHT:--1}

    if [ "${BITCOIN_HEIGHT}" -gt $TARGET_BLOCK ]; then
        break
    fi

    echo "At block $BITCOIN_HEIGHT/$TARGET_BLOCK, still waiting"
    sleep 1s & wait || exit 0
done

$DOCKER_COMPOSE stop tx-broadcaster bitcoin-miner
$DOCKER_COMPOSE down -v

rm snapshot/bitcoin/mempool.dat || true
tar -czf snapshot.tgz snapshot
rm -rf snapshot
