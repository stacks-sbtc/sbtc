---
applyTo: "contracts/contracts/**/*.clar"
---

# Clarity contract review guidance

- Check authorization on every public function: `is-protocol-caller` roles
  in `sbtc-registry`, `contract-caller` vs `tx-sender`, and calls made
  through other contracts.
- Check how sBTC is minted, burned, locked and transferred, including
  boundary amounts. Comments must match the amounts that actually move.
- Check input validation, such as recipient address versions and hash
  lengths, amounts and fees, and how replayed or duplicate requests are
  handled.
- Contracts are deployed and called by the signer. Flag changes to function
  signatures, error codes, print events or data maps that the signer or
  Emily rely on, and check that the matching signer code
  (`signer/src/stacks/contracts.rs`) is updated.
