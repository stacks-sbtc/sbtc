# Ledger CLTV + Covenant test (Option 3)

Manual test harness for the **Option 3** locking script template from the
[Persisting staker data](https://www.notion.so/Persisting-staker-data-367f95826435801b8c9ddaa18886c065)
design doc, run end-to-end against testnet4 with a Ledger device.

The miniscript template under test is:

```
wsh(
  and_v(
    v:pk(@staker/**),
    and_v(
      v:or_i(
        and_v(v:sha256(H), 1),
        1
      ),
      or_i(
        after(N),
        pk(@covenant/**)
      )
    )
  )
)
```

with `N = 1000` (already in the past on testnet4) and `H` derived from a
hardcoded 32-byte preimage. The covenant xpub is derived deterministically
from a fixed seed inside `index.js`, so re-running the script produces the
same address.

> **Note.** This miniscript is **not "sane"** by the standard miniscript rules
> (the inner `or_i(sha256(H), 1)` makes the H reveal optional, which the
> satisfier considers a redundant commitment). `@bitcoinerlab/descriptors`
> refuses to operate on it, so this harness drives the Ledger SDK directly,
> compiles the script via `@bitcoinerlab/miniscript` (which produces the ASM
> regardless of sanity), and builds the spend witness by hand. The whole point
> of the test is to find out whether the **Ledger Bitcoin Test app** also
> rejects the policy, or accepts it and signs.

## Prerequisites

1. Ledger device connected via USB and unlocked.
2. **Bitcoin Test** app (≥ 2.1.0) open on the device.
3. Node.js ≥ 18.
4. `pnpm install` (or `npm install`).

## 1. Generate the locking address

```bash
node index.js --generate
```

This:

1. Reads the master fingerprint and the staker xpub at `m/48'/1'/0'/2'` from
   the Ledger.
2. Builds the Option 3 wallet policy with the deterministic covenant xpub,
   CLTV `1000`, and `H = sha256(preimage)`.
3. Computes the P2WSH address locally so you always have it, even if the
   device rejects the policy in the next step.
4. Calls `app.registerWallet(...)`. The Ledger UI walks you through the
   template, the two key fingerprints/paths, and `H` — confirm each one.
   - If the device **rejects** the registration, the script reports the
     error and exits. The local address is still saved to `cltv-wallet.json`.
   - If it **accepts**, the device returns a policy id + HMAC.
5. Asks the device to display the address for `(change, index) = (0, 0)` and
   compares it to the locally computed one.
6. Writes everything needed to spend (descriptor, HMAC, witness script,
   scriptPubKey, derivation info) to `cltv-wallet.json`.

Fund the printed `tb1q…` address from any testnet4 wallet.

## 2. Spend the locked UTXO

```bash
node index.js --spend \
  --txid   <funding-txid>          \
  --vout   <output-index>          \
  --amount <amount-in-sats>        \
  --to     <destination-tb1-addr>  \
  --fee    <fee-in-sats>
```

This:

1. Rebuilds the witness script from `cltv-wallet.json`.
2. Fetches the funding tx hex from `https://mempool.space/testnet4/api`
   (pass `--txhex <hex>` to skip the HTTP call).
3. Builds a PSBT spending the staked UTXO with `nLockTime = 1000` and
   `nSequence = 0xfffffffe`, populating witnessUtxo, witnessScript, and
   bip32Derivation for both keys.
4. Calls `app.signPsbt(...)`. Confirm the spend on the device.
5. Extracts the staker signature from the Ledger response and builds the
   final witness for the **timelock branch**, skipping the H reveal:
   ```
   [ 0x01, <empty>, <staker-sig||sighash>, <witnessScript> ]
   ```
6. Extracts the raw transaction and POSTs it to mempool.space testnet4.

## State file

Everything off-chain lives in `cltv-wallet.json`:

- master fingerprint + staker xpub
- covenant xpub + fingerprint (deterministic, recomputable from the seed)
- policy template + key roots + policy HMAC
- witness script and scriptPubKey
- chosen change/index and address

Losing the HMAC means losing the ability to spend via Ledger, so back it up
if you actually fund the address.
