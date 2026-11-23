---
applyTo: "signer/migrations/**"
---

# Database migration review guidance

- Flag edits to a migration that has already been released. Changes must go
  in a new migration with the next sequence number.
- Check that the migration is safe on a database with existing production
  data: backfills, `NOT NULL` columns without defaults, changed primary keys
  and dropped columns.
- Check that new queries have suitable indexes, and that new constraints
  match what the code writes.
- Check that the Rust models and queries in `signer/src/storage/` match the
  new schema. When a column is dropped or its meaning changes, check every
  query that reads it.
