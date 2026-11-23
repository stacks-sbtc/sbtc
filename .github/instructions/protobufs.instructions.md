---
applyTo: "protobufs/**/*.proto,signer/src/proto/**"
---

# Protobuf review guidance

- These messages are exchanged between signers that may run different
  versions. Flag renumbered fields, reused field numbers, changed field
  types and removed fields that are not reserved.
- Check that the generated code in `signer/src/proto/generated/` is
  regenerated in the same PR when a `.proto` file changes. Do not review
  the generated code itself.
- Check that conversions in `signer/src/proto/convert.rs` handle new fields
  in both directions and reject malformed input instead of panicking.
