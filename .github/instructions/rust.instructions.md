---
applyTo: "**/*.rs"
---

# Rust review guidance

- Flag `unwrap`, `expect`, indexing or `panic!` that untrusted input can
  reach: peer messages, Bitcoin or Stacks node responses, Emily responses,
  or database rows written from those.
- Check integer conversions and arithmetic on amounts, fees, heights and
  counts. Look for silent truncation, overflow, or `as` casts that change
  values.
- Check that logging does not expose private keys, DKG shares or other
  secrets.
