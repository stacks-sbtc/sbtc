---
applyTo: "contracts/tests/**/*.ts"
---

# Contract test review guidance

- Check that callers and senders are set up so the test actually exercises
  the `contract-caller` or `tx-sender` path it claims to.
- `contracts/tests/clarigen-types.ts` is generated. Report problems in it
  against the contract it was generated from.
