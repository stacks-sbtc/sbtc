import os
import time
import requests
import subprocess

STACKS_API = "http://localhost:3999"
MEMPOOL_API = "http://localhost:8999"

# From stacks config
NAKAMOTO_START_HEIGHT = 232

# From demo_cli.rs
DEPLOYER_ADDRESS = "SN3R84XZYA63QS28932XQF3G1J8R9PC3W76P9CSQS"
DEMO_STACKS_ADDR = "ST3497E9JFQ7KB9VEHAZRWYKF3296WQZEXBPXG193"
DEMO_BITCOIN_ADDR = "bcrt1qezfmjvnaeu66wm52h7885mccjfh9lmh2v4kf8n"

DEPOSIT_AMOUNT = 2000000
WITHDRAWAL_AMOUNT = 1000000
MAX_FEE = 20000

# Extra slack to account for txs submitted close to the new block being mined or
# similar delaying scenarios
BLOCKS_SLACK = 3

root = os.path.dirname(os.path.realpath(__file__)) + "/../../"


def cmd(cmd):
    subprocess.check_call(cmd, shell=True, cwd=root)


def get_bitcoin_height():
    return requests.get(f"{MEMPOOL_API}/api/v1/blocks/tip/height").json()


def wait_next_block(delta=1):
    print(f"Waiting for {delta} blocks")
    start = get_bitcoin_height()
    while get_bitcoin_height() < start + delta:
        time.sleep(5)


def get_btc_balance(address):
    account = requests.get(f"{MEMPOOL_API}/api/v1/address/{address}").json()
    return (
        account["chain_stats"]["funded_txo_sum"]
        - account["chain_stats"]["spent_txo_sum"]
    )


def get_sbtc_balance(address):
    balances = requests.get(
        f"{STACKS_API}/extended/v1/address/{address}/balances?unanchored=true"
    ).json()
    return int(
        balances["fungible_tokens"]
        .get(f"{DEPLOYER_ADDRESS}.sbtc-token::sbtc-token", {})
        .get("balance", 0)
    )


cmd("make devenv-down")
cmd("docker compose --verbose -f docker/docker-compose.yml -f devenv/tests/docker-compose.override.yml --profile default --profile bitcoin-mempool --profile sbtc-signer up --detach --quiet-pull")
print("devenv started")

# Wait for nakamoto
while True:
    try:
        bitcoin_height = requests.get(f"{STACKS_API}/v2/pox").json()[
            "current_burnchain_block_height"
        ]
        if bitcoin_height > NAKAMOTO_START_HEIGHT:
            break
    except:
        bitcoin_height = "?"
    time.sleep(5)
    print(f"waiting for Nakamoto ({bitcoin_height}/{NAKAMOTO_START_HEIGHT})")
print("reached Nakamoto")

# Wait for registry deployment
while True:
    maybe_source = requests.get(
        f"{STACKS_API}/v2/contracts/source/{DEPLOYER_ADDRESS}/sbtc-registry"
    )
    if maybe_source.status_code == 200 and maybe_source.json().get("source"):
        break
    time.sleep(5)
    print("waiting for .sbtc-registry")
print(".sbtc-registry deployed")

# Wait for key rotation
while True:
    aggregate_key = requests.post(
        f"{STACKS_API}/v2/contracts/call-read/{DEPLOYER_ADDRESS}/sbtc-registry/get-current-aggregate-pubkey",
        json={"arguments": [], "sender": DEPLOYER_ADDRESS},
    ).json()
    if aggregate_key["result"] != "0x020000000100":
        break
    time.sleep(5)
    print("waiting for rotate key")
print(f"key rotation submitted: {aggregate_key}")


# Fund signers UTXO
cmd("cargo run -p signer --bin demo-cli donation --amount 10000")
wait_next_block(1 + BLOCKS_SLACK)


initial_btc = get_btc_balance(DEMO_BITCOIN_ADDR)
initial_sbtc = get_sbtc_balance(DEMO_STACKS_ADDR)
print(f"Demo account initial balances: {initial_btc} BTC, {initial_sbtc} sBTC")

# == Deposit test ==

cmd(
    f"cargo run -p signer --bin demo-cli deposit --amount {DEPOSIT_AMOUNT} --max-fee {MAX_FEE}"
)
wait_next_block(2 + BLOCKS_SLACK)

sbtc = get_sbtc_balance(DEMO_STACKS_ADDR) - initial_sbtc
if sbtc < DEPOSIT_AMOUNT - MAX_FEE:
    print(
        f"Expected demo account to have at least {DEPOSIT_AMOUNT - MAX_FEE} sBTC, got {sbtc}"
    )
    exit(1)

print("Deposit OK")

# == Withdrawal test ==

cmd(
    f"cargo run -p signer --bin demo-cli withdraw --amount {WITHDRAWAL_AMOUNT} --max-fee {MAX_FEE}"
)
wait_next_block(7 + BLOCKS_SLACK)

sbtc_new = get_sbtc_balance(DEMO_STACKS_ADDR) - initial_sbtc
if not sbtc - WITHDRAWAL_AMOUNT - MAX_FEE <= sbtc_new <= sbtc - WITHDRAWAL_AMOUNT:
    print(
        f"Expected demo account to have between {sbtc - WITHDRAWAL_AMOUNT - MAX_FEE} and {sbtc - WITHDRAWAL_AMOUNT} sBTC, got {sbtc_new}"
    )
    exit(1)

btc = get_btc_balance(DEMO_BITCOIN_ADDR)
if btc - initial_btc != WITHDRAWAL_AMOUNT:
    print(f"Expected demo account to have {WITHDRAWAL_AMOUNT} BTC, got {btc}")
    exit(1)

print("Withdrawal OK")

cmd("make devenv-down")
