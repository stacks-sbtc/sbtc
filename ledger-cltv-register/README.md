# Ledger CLTV + Covenant test (Option 2)

Manual test harness for the **Option 2** locking script template from the
[Persisting staker data](https://www.notion.so/Persisting-staker-data-367f95826435801b8c9ddaa18886c065)
design doc, run end-to-end against testnet4 with a Ledger device.

The miniscript template is:

```
wsh(
  and_v(
    v:pk(@staker/**),
    or_i(
      after(N),
      and_v(
        v:sha256(H),
        pk(@covenant/**)
      )
    )
  )
)
```

with `N = 1000` (already in the past on testnet4) and `H = sha256(preimage)`
for a hardcoded 32-byte preimage. The `sha256(H)` check sits inside the
covenant arm of the `or_i`: the staker can spend through the timelock
without ever revealing the preimage, and only the covenant unstake path
requires it. `H` is still committed on-chain via the witness-script hash,
so the Stacks-principal binding is preserved.

> **Why Option 2 and not Option 3?** We tried Option 3 first. Both
> `@bitcoinerlab/descriptors` and the Ledger Bitcoin Test app rejected the
> policy with the same complaint: the inner `or_i(sha256(H), 1)` makes the H
> reveal optional, which the satisfier flags as a redundant commitment. The
> Ledger error was `0x6a82` ("wallet policy not accepted"). Option 2 keeps
> the H commitment but makes the preimage reveal **mandatory** at spend
> time, which is sane miniscript and accepted by Ledger.
>
> The cost is the one called out in the design doc: losing the preimage is
> as severe as losing the HMAC. Both must be persisted server-side (keyed by
> Stacks address) and treated as critical state.

## Prerequisites

1. Ledger device connected via USB and unlocked.
2. **Bitcoin Test** app (≥ 2.1.0) open on the device.
3. Node.js ≥ 18 (Node 24 works after a `node-hid` rebuild — see below).
4. `pnpm install`.

If `node index.js --generate` errors with `Could not locate the bindings
file` (node-hid prebuilds don't cover Node ≥ 22), rebuild the native module:

```bash
cd ../node_modules/.pnpm/node-hid@2.1.2/node_modules/node-hid
npx --yes node-gyp rebuild
```

## 1. Generate the locking address

```bash
node index.js --generate
```

This:

1. Reads the master fingerprint and the staker xpub at `m/48'/1'/0'/2'`
   from the Ledger.
2. Builds the Option 2 wallet policy with the deterministic covenant xpub,
   CLTV `1000`, and `H = sha256(preimage)`.
3. Computes the P2WSH address locally so you always have it, even if the
   device rejects the policy.
4. Calls `app.registerWallet(...)`. Confirm each screen on the device.
5. Asks the device to display the address for `(change, index) = (0, 0)` and
   compares it to the locally computed one.
6. Writes the descriptor, policy HMAC, witness script, and preimage to
   `cltv-wallet.json`.

Fund the printed `tb1q…` address from any testnet4 wallet.

## 2. Spend the locked UTXO

```bash
node index.js --spend \
  --txid   <funding-txid>          \
  --vout   <output-index>          \
  --amount <amount-in-sats>        \
  --to     <destination-tb1-addr>  \
  --fee    <fee-in-sats>           \
  [--branch timelock|covenant]
```

`--branch` defaults to `timelock`. Both branches:

1. Rebuild the witness script from `cltv-wallet.json`.
2. Fetch the funding tx hex from mempool.space testnet4 (pass `--txhex <hex>`
   to skip the HTTP call).
3. Build a PSBT with witnessUtxo, witnessScript, and bip32Derivation for
   both keys.
4. Call `app.signPsbt(...)` and prompt the Ledger to sign with the staker
   key.

The two branches differ only at the end:

**`--branch timelock`** — sets `nLockTime = 1000`, `nSequence = 0xfffffffe`,
and assembles the witness as
```
[ 0x01, <staker-sig>, <witnessScript> ]
```
The preimage is not needed in this path.

**`--branch covenant`** — leaves locktime/sequence at their defaults, locally
computes the BIP-143 sighash, signs it with the deterministic covenant key,
and assembles
```
[ <covenant-sig>, <preimage>, <empty>, <staker-sig>, <witnessScript> ]
```
The empty selector sits above the covenant sig and preimage so OP_IF pops it
(empty is the canonical "false" under MINIMALIF); the ELSE arm then consumes
the preimage and the covenant sig.

Then either way, the raw transaction is broadcast through mempool.space
testnet4.

Note that the same Ledger signature works for both branches, because
`pk(@staker)` is checked above the `OP_IF` and the device commits to the
spending tx, not the chosen path.

## State file

`cltv-wallet.json` is the only off-chain state the spend needs:

- master fingerprint + staker xpub
- covenant xpub + fingerprint (deterministic, recomputable from the seed)
- policy template + key roots + policy HMAC
- witness script and scriptPubKey
- chosen change/index and address
- **the preimage** (mandatory at spend time for Option 2)

Losing the HMAC or the preimage means losing the ability to spend via
Ledger. Back it up if you actually fund the address.
