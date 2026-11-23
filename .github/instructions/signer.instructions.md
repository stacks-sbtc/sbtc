---
applyTo: "signer/src/**/*.rs,sbtc/src/**/*.rs,wsts/src/**/*.rs"
---

# Signer review guidance

## Decisions and validation

- Each signer must validate what the coordinator proposes (sweep
  transactions, fees, Stacks contract calls, DKG rounds) against its own
  view of the chain. Flag validation that trusts the coordinator or a peer
  instead of checking.
- Emily data is a hint, never a source of truth. Anything from Emily that
  affects a signer decision must be checked against chain data.
- Check that threshold checks use the right source for the current signer
  set and threshold, and that the comparison is correct (`>=` vs `>`):
  - Bitcoin signing (`BitcoinSignerSet::load`): before the v2 signing
    activation height, the latest verified DKG shares; from that height
    on, the registry.
  - The Stacks multisig wallet (`SignerWallet::load`): the registry,
    falling back to the bootstrap config only when the registry is empty.
  - The `bootstrap_signing_set` and `bootstrap_signatures_required` config
    is the target signer set, used for DKG, key rotation and the P2P
    allowlist. Flag code that uses it as the current threshold or signer
    set while the registry has one.
- Check that requests are not processed twice and that decisions are
  persisted before they are relied on.
- When a change tightens what signers accept from the coordinator, such
  as a lower limit or a new check, coordinators running the previous
  release may still send what is now rejected. The coordinator-side change
  should ship in an earlier release. Otherwise the PR should say that
  operators need to upgrade together.
- Check that contract-call arguments match the deployed contracts in
  `contracts/contracts/`.

## Messages and state

- Messages from peers must be authenticated and tied to the right chain
  tip. Check how stale, duplicated, replayed or out-of-order messages are
  handled.
- Check WSTS and DKG state transitions when a round fails or a signer drops
  out partway through.

## Storage

- When a change stops writing rows, writes fewer rows, or changes what a
  column means, check every query that reads that table.
- A new or changed query in `signer/src/storage/postgres/` usually needs a
  matching change in the in-memory store (`signer/src/storage/memory/`),
  which tests use.
- Changes to `signer/src/config/` must keep existing config files working,
  and must update `signer/src/config/default.toml` when defaults change.
