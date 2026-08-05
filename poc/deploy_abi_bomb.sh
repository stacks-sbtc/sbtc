#!/usr/bin/env bash
# Deploy the ABI-bomb contract from Immunefi report 86722 against the
# local devenv. One publish is enough — the /new_block webhook for the
# block that includes it is already large enough to be rejected by the
# signer's 256 MiB `NEW_BLOCK_BODY_LIMIT`.
#
# Requires a locally-built `stacks-cli` binary (from a sibling checkout
# of `stacks-network/stacks-core`) — the sBTC repo does not vendor one.

set -euo pipefail

CLI=${CLI:?set CLI to a stacks-cli binary, e.g. /path/to/stacks-core/target/debug/stacks-cli}
RPC=${RPC:-http://127.0.0.1:20443}
DEPLOYER_ADDR=${DEPLOYER_ADDR:-ST2SBXRBJJTH7GV5J93HJ62W2NRRQ46XYBK92Y039}
DEPLOYER_KEY=${DEPLOYER_KEY:-27e27a9c242bcf79784bb8b19c8d875e23aaf65c132d54a47c84e1a5a67bc62601}
CONTRACT_NAME=${CONTRACT_NAME:-abi-bomb}
FEE=${FEE:-1000000}

HERE=$(cd "$(dirname "$0")" && pwd)
SRC="${HERE}/${CONTRACT_NAME}.clar"

python3 "${HERE}/gen_abi_bomb.py" > "${SRC}"

get_nonce() {
  curl -s "${RPC}/v2/accounts/$1?proof=0" \
    | python3 -c "import sys,json; print(json.load(sys.stdin)['nonce'])"
}

nonce=$(get_nonce "${DEPLOYER_ADDR}")
echo "[deploy] publishing ${CONTRACT_NAME} from ${DEPLOYER_ADDR} at nonce ${nonce}"

"${CLI}" --testnet publish "${DEPLOYER_KEY}" "${FEE}" "${nonce}" \
  "${CONTRACT_NAME}" "${SRC}" \
  | xxd -r -p \
  | curl -s -o /dev/null -w '[deploy] http=%{http_code}\n' \
      -X POST -H 'Content-Type: application/octet-stream' \
      --data-binary @- "${RPC}/v2/transactions"

echo "[deploy] waiting for confirmation..."
until curl -sf "${RPC}/v2/contracts/interface/${DEPLOYER_ADDR}/${CONTRACT_NAME}" \
      -o /dev/null; do
  sleep 2
done
echo "[deploy] confirmed. watch signer/examples/poc_observer.rs logs for the 413."
