# PoC: contract-interface expansion wedges the signer `/new_block` webhook

Stacks Core attaches a `contract_interface` to every contract-publish receipt in the `/new_block` webhook. The interface is built from *inferred* return types, so a 302 KB Clarity source that defines one 1,000-field tuple constant and returns it from 8,200 private functions expands to ~270 MB of interface JSON — 2 MB over the signer's 256 MiB `NEW_BLOCK_BODY_LIMIT`. Axum rejects with 413 before the handler runs, stacks-core retries the same payload forever, and block delivery to every signer stops until operators patch and drop the poison payload from `event_observers.sqlite`.

## Two PoCs

### 1. Self-contained unit reproduction (no devenv)

[signer/tests/abi_webhook_expansion_poc.rs](signer/tests/abi_webhook_expansion_poc.rs)
plus [signer/tests/abi_webhook_expansion_stacks_core_3_4_0_0_1.patch](signer/tests/abi_webhook_expansion_stacks_core_3_4_0_0_1.patch).
Runs the Clarity analyzer + `build_contract_interface` in-process and
posts the interface through the production signer router.

```bash
cargo test -p signer --test abi_webhook_expansion_poc \
  inferred_return_types_amplify_contract_interface -- --exact --nocapture

# Full 256 MiB reproduction (~2.5 GiB peak memory, tens of seconds):
cargo test -p signer --test abi_webhook_expansion_poc \
  full_payload_is_accepted_by_cost_tracked_clarity \
  -- --ignored --exact --nocapture
```

### 2. Live devenv reproduction

Build the malicious contract, publish it through a real stacks-node, and
watch the signer's `/new_block` handler 413 the resulting block.

Prerequisites: sBTC devenv running (`make devenv-up`), plus a
locally-built `stacks-cli` from a sibling `stacks-network/stacks-core`
checkout.

```bash
# Terminal 1 — dual observer: real signer router on :8804, permissive peek on :8811.
cargo run -p signer --example poc_observer --features testing

# In docker/stacks/stacks-regtest-miner.toml, point one of the sbtc-signer
# event_observer entries at host.docker.internal:8804 (real router) and
# one at host.docker.internal:8811 (peek), both keeping the existing
# `sbtc-registry::print` filter. Restart the stacks-node container.

# Terminal 2 — generate abi-bomb.clar, publish it, wait for confirmation.
CLI=/Users/dan/repos/stacks-core/personal/target/debug/stacks-cli \
  ./poc/deploy_abi_bomb.sh
```

The observer on :8804 logs `413 PAYLOAD_TOO_LARGE` for the block that
contains the publish; the peek on :8811 dumps the same block body to
`/tmp/poc_block_*.raw.json` so its size can be measured directly.

## Files

- [poc/gen_abi_bomb.py](poc/gen_abi_bomb.py) — contract generator
- [poc/deploy_abi_bomb.sh](poc/deploy_abi_bomb.sh) — devenv deployer
- [signer/examples/poc_observer.rs](signer/examples/poc_observer.rs) — real + peek observer
- [signer/tests/abi_webhook_expansion_poc.rs](signer/tests/abi_webhook_expansion_poc.rs) — unit PoC
- [signer/tests/abi_webhook_expansion_stacks_core_3_4_0_0_1.patch](signer/tests/abi_webhook_expansion_stacks_core_3_4_0_0_1.patch) — companion patch for the deployed Stacks Core tag
