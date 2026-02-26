# Ledger CLTV Wallet Policy Registration

This tool registers a wallet policy on a Ledger Nano S device with the following miniscript template:

```
wsh(and_v(v:after(360),pkh(key)))
```

This creates a **P2WSH** (Pay-to-Witness-Script-Hash) address with:
- A **relative timelock** of 360 blocks (CLTV - Check Lock Time Verify)
- A **public key hash** requirement

This uses the official [@ledgerhq/ledger-bitcoin](https://www.npmjs.com/package/@ledgerhq/ledger-bitcoin) SDK.

## Prerequisites

1. **Ledger Nano S** device connected via USB
2. **Bitcoin app** installed and open on the device
3. **Node.js** version 18 or higher
4. Device must be **unlocked**

## Installation

```bash
cd ledger-cltv-register
pnpm install
```

Or if using npm:

```bash
npm install
```

## Usage

1. Connect your Ledger Nano S via USB
2. Unlock the device
3. Open the Bitcoin app on the device
4. Run the registration script:

```bash
pnpm run register
```

Or:

```bash
node index.js
```

## What Happens

1. The script connects to your Ledger device
2. Retrieves the master key fingerprint
3. Gets the extended public key for the derivation path (default: `m/44'/1'/0'` for testnet)
4. Creates a wallet policy with the miniscript template
5. Registers the policy on the device (you'll need to confirm on the device)
6. Returns the Policy ID and Policy HMAC
7. Derives and displays an address for the registered wallet

## Configuration

Default is **testnet/regtest** (`m/44'/1'/0'`). Open the **Bitcoin Testnet** app on the device.

- **Testnet/regtest** (default): Open the Bitcoin Testnet app, run `pnpm run register`.
- **Mainnet**: Open the **Bitcoin** app, then run `USE_MAINNET=1 pnpm run register`.

If you get `0x6a82`, the app and path don’t match—use Bitcoin Testnet for default, or Bitcoin app with `USE_MAINNET=1`.

When using the default (testnet/regtest), the script prints both the Ledger address (tb1...) and the **regtest address** (bcrt1...). The regtest form is computed by re-encoding the Ledger address with the regtest bech32 prefix (`bcrt`) using the [bech32](https://github.com/bitcoinjs/bech32) package. Use the bcrt1 address with Bitcoin Core in `-regtest` mode; it is the same key, only the address prefix differs.

## Important Notes

- **Store the Policy HMAC securely** - you'll need it for future operations
- The relative timelock of 360 blocks means funds can only be spent after 360 blocks have passed since the transaction was confirmed
- The policy uses a single key (`@0/**`) - modify the template if you need multiple keys
- The device will prompt you to confirm the registration on-screen

## Miniscript Explanation

The miniscript `wsh(and_v(v:after(360),pkh(key)))` breaks down as:

- `wsh(...)` - Wrapped Script Hash (P2WSH output type)
- `and_v(...)` - AND operator (both conditions must be satisfied)
- `v:after(360)` - Relative timelock: can only spend after 360 blocks
- `pkh(key)` - Public key hash: standard P2PKH requirement

## Troubleshooting

**"No device found" error:**
- Ensure the Ledger is connected via USB
- Make sure the device is unlocked
- Verify the Bitcoin app is open on the device

**Connection issues:**
- Try disconnecting and reconnecting the device
- Restart the Bitcoin app on the device
- On Linux, you may need to configure udev rules for USB device access
