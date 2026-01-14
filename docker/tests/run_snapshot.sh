#!/bin/bash

set -e

cd "$(dirname "$0")"/../../

DOCKER_COMPOSE="docker compose -f docker/tests/docker-compose.stacks.yml"

$DOCKER_COMPOSE down -v -t 0
$DOCKER_COMPOSE up --build -d

STACKS_RPC_PORT=$(docker compose -f docker/tests/docker-compose.stacks.yml port stacks-node 20443 | sed 's/.*://')
while true; do
    BITCOIN_HEIGHT=$(curl -s http://localhost:$STACKS_RPC_PORT/v2/info | jq .burn_block_height 2> /dev/null)
    BITCOIN_HEIGHT=${BITCOIN_HEIGHT:--1}

    echo "At block $BITCOIN_HEIGHT"

    $DOCKER_COMPOSE exec bitcoin bash -c 'bitcoin-cli -rpcwallet=depositor -rpcconnect=bitcoin generatetoaddress 1 "$(bitcoin-cli -rpcwallet=depositor -rpcconnect=bitcoin getnewaddress label="" bech32)"'
    sleep 3s & wait || exit 0
done
