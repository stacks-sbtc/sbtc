# PR review guidance for sBTC

## Scope

These are criteria for reviewing pull requests, not rules for writing code.
Raise optional rewrites, style changes or unrelated cleanup only when they
address a concrete risk.

sBTC holds BTC in a threshold-signed wallet and mints sBTC on Stacks. A
set of signers must independently reach the same decisions from the same
chain data. Review correctness, the safety of funds, agreement between
signers, security and compatibility ahead of maintainability and style.

## Review priorities

- **Safety of funds.** Check how deposits, withdrawals and sweeps are
  validated and built: amounts, fees and `max_fee`, UTXO selection, change,
  locktimes, scripts and signature hashes. Check boundary amounts, overflow
  and dust.
- **Agreement between signers.** A decision that signers make independently
  must depend only on data every signer has (chain data, the database,
  config), not on timing, `HashMap` iteration order, randomness or local
  clocks. Some inputs differ between signers by design, such as blocklist
  results and each signer's own request votes. Check what happens when
  signers disagree on them.
- **Reorgs and chain views.** Queries and decisions must use the canonical
  Bitcoin chain and the right Stacks tip. Check data keyed by block hash,
  and work done for one tip that is reused for another.
- **Rolling upgrades.** Each operator upgrades their own signer on their
  own schedule, so old and new versions run side by side after every
  release. Check that changes to P2P messages, protobufs, config and
  decision logic still work in a mixed set. Behavior that every signer must
  switch at the same moment should be gated on a Bitcoin activation height,
  as v2 signing is with `MAINNET_V2_SIGNING_BLOCK_HEIGHT`. Flag changes
  that need coordinated operator action, and check that the PR says so
  (the `breaking-protocol` or `breaking-local` label feeds the release
  notes).
- **Downgrades.** These are not supported. There are no down migrations,
  and the release instructions have operators back up their database before
  upgrading. Do not flag problems that only occur when an older signer runs
  against a database migrated by a newer one.
- **Compatibility-sensitive surfaces.** These include the deployed Clarity
  contracts and how the signer calls them, the Emily API and its generated
  clients, protobuf wire formats, database migrations, signer config keys
  and defaults, and the blocklist client API.
- **Blocklist screening.** Note whether a change makes screening fail
  closed or fail open, and whether that is intended.
- **Error handling.** Check whether an error is retried, skipped or fatal.
  A deterministic failure must not be retried forever. A transient failure
  must not cause a permanent decision. Errors must not be silently dropped.
- **Review guidance.** If the PR changes behavior, names, paths or Make
  targets that this file, `.github/instructions/` or
  `.agents/skills/code-review/SKILL.md` describe, flag that the
  guidance needs updating in the same PR.

## Review comment threshold

- Prefer fewer comments with high confidence. Each comment should name a
  concrete trigger and its impact, and suggest a fix or a way to validate it.
- Read the callers and tests before commenting. If a concern depends on an
  invariant you could not confirm, say so.
- Do not comment on what `rustfmt`, `clippy`, the compiler or CI already
  catch.
- Do not ask for architectural changes, refactors or style changes without
  a concrete defect.
- Do not ask for tests for mechanical or behavior-preserving changes.
- Raise each root cause once.

## Test code

- Tests should exercise the invariant the change relies on, not only the
  happy path.
- Scripts, commitments and addresses that wallets or other tools build
  must be pinned by fixed test vectors, not only round-tripped through our
  own code. Ask for them even though the comment threshold otherwise
  limits requests for tests.
- `unwrap`, `expect` and `panic!` are fine in tests and on constants.
- Check that each wait or signal really means the work being asserted on
  has finished, that receivers subscribe before the event can fire, and
  that fixed `sleep`s are not used to synchronize. When a flaky test is
  fixed, check whether sibling tests need the same fix.
