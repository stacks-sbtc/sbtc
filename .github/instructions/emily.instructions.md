---
applyTo: "emily/**,emily_sidecar/**,emily_cron/**"
---

# Emily review guidance

- Emily's API is used by signers, wallets and other clients through the
  generated clients in `.generated-sources/`. Flag changes to routes,
  request or response models, status codes and validation that existing
  clients would break on. When the handler's API or models change, check
  that the committed specs in `emily/openapi-gen/generated-specs/` and the
  clients in `.generated-sources/emily/` are regenerated in the same PR. Do
  not review the generated code itself.
- Check status transitions for deposits and withdrawals, and who may make
  them. Endpoints that only signers or internal services should call must
  stay protected.
- Check that updates to existing entries go through the versioned write
  path (`put_entry_with_version`, `VersionedEntryTrait`), so concurrent
  writers cannot overwrite each other.

## DynamoDB indexes

- A single CloudFormation update can create or delete only one global
  secondary index (GSI) per table. Check that a change adding or removing
  several GSIs on one table says how the rollout is staged.
- A new GSI backfills after the deploy finishes. The handler must not query
  a new index until it is `ACTIVE`, so check that the switch to a new index
  ships after the index exists, not in the same deploy.
- Changing a GSI's keys or projection needs a new index. Check that every
  field of the index's `*Entry` struct that has no `#[serde(default)]` is
  projected by that index, or reads through it fail.
