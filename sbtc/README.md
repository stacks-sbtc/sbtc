# lib-sbtc

A library for creating Bitcoin deposit transactions that can be handled by the sBTC signers.

## CLI

The `sbtc` binary computes a Bitcoin address for an sBTC deposit. From the root
of this repository, build it with the `cli` feature enabled:

```console
$ cargo build --release -p sbtc --features cli
```

Display the available commands, or detailed help for `compute-deposit-address`,
with:

```console
$ ./target/release/sbtc --help
$ ./target/release/sbtc compute-deposit-address --help
```

By default, the binary fetches the current signer aggregate key from the mainnet sBTC registry smart contract through the Hiro API. Run it from the repository root with:

```console
$ ./target/release/sbtc compute-deposit-address <STACKS_RECIPIENT> \
  --reclaim-pubkey <PUBLIC_KEY>
```

For example, the following uses the sBTC mainnet deployer as the recipient and a well-known test public key as the reclaim key:

```console
$ ./target/release/sbtc compute-deposit-address \
  SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4 \
  --reclaim-pubkey 0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
```

> [!WARNING]
> The example reclaim key above corresponds to the publicly known private key `1`. Never send real Bitcoin to the resulting address. Use a reclaim public key controlled by the depositor in production.

The reclaim public key may be either a 32-byte x-only or a 33-byte compressed public key, encoded as hex. The CLI converts a compressed key to its x-only form automatically.

When `--reclaim-pubkey` is used, the CLI constructs the complete reclaim script as `<lock-time> OP_CSV OP_DROP <x-only-public-key> OP_CHECKSIG`. `OP_CSV` leaves the lock time on the stack, so the generated `OP_DROP` removes it before signature verification.

For a custom reclaim condition, pass the complete hex-encoded reclaim script, including its lock-time prefix. This is an advanced option: the CLI validates the script but does not insert `OP_DROP` or otherwise modify its semantics. Its lock time is read from the script. Note that `--lock-time` and `--reclaim-pubkey` cannot be used with `--reclaim-script`.

```console
$ ./target/release/sbtc compute-deposit-address <STACKS_RECIPIENT> \
  --reclaim-script <SCRIPT_HEX>
```

The default maximum signer fee is 80,000 satoshis and the default relative reclaim lock time is 950 Bitcoin blocks, matching the sBTC bridge at [sbtc.stacks.co](https://sbtc.stacks.co). Use `--help` to see overrides for these values, the aggregate key, the Stacks API, the registry deployer, and the Bitcoin network.
