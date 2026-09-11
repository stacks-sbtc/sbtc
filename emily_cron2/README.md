# Emily cron2

Rust deposit reconciliation service, independent of the Python `emily_cron`.
Emily requests and wire types come from the generated `private-emily-client` crate.
It reads pending and accepted deposits from the private Emily endpoint and updates
`/deposit_private` for expired unspent deposits, depositor reclaims, confirmed RBF
replacements, and old pending transactions that have disappeared from the mempool.

```sh
# Preview a single cycle using the endpoint environment variables below.
cargo run -p emily-cron2 -- --once --dry-run

# Run once under an external scheduler (nonzero exit on incomplete/failed work).
cargo run -p emily-cron2 -- --once

# Run immediately, then wait 10 minutes after each cycle completes.
cargo run -p emily-cron2

# Build and start only the new service and its dependencies in the local stack.
docker compose -f docker/docker-compose.yml \
  --profile default --profile bitcoin-mempool --profile observability \
  up -d --build emily-cron2
```

The Compose service is opt-in via the `emily-cron2` profile (also activated by
explicitly targeting the service); existing default services are unchanged. The
other profiles in the command enable the existing dependency graph. When switching
reconciliation to Rust in an existing stack, stop the Python worker first:

```sh
docker compose -f docker/docker-compose.yml \
  --profile default --profile bitcoin-mempool --profile observability \
  stop emily-cron
```

Running both writers against the same Emily instance is unnecessary.
The devenv image uses a debug build. The container runs as an unprivileged user and handles SIGHUP/SIGINT/SIGTERM. It logs to
stdout and retries failed cycles at the next interval without overlapping runs.

| Environment variable | Default |
| --- | --- |
| `PRIVATE_EMILY_ENDPOINT` | `http://emily-server:3031` |
| `EMILY_API_KEY` | empty |
| `MEMPOOL_API_URL` | `http://mempool-api:8999/api` |
| `ELECTRS_API_URL` | `http://electrs:3002` |
| `HIRO_API_URL` | `https://api.hiro.so` |
| `MIN_BLOCK_CONFIRMATIONS` | `6` |
| `MAX_UNCONFIRMED_TIME` | `86400` seconds |
| `POLL_INTERVAL_SECONDS` | `600` seconds, must be positive |
| `RUST_LOG` | `info` |

Each setting except `RUST_LOG` also has a corresponding CLI option; see `--help`.
Like the Python processor, reads use `PRIVATE_EMILY_ENDPOINT`. `EMILY_ENDPOINT`
and `DEPLOYER_ADDRESS` are not needed by this job. Requests time out after 30
seconds. Hosted mempool.space transaction requests use `/tx/{txid}`; local
mempool backend requests use `/v1/tx/{txid}`. Electrs outspend requests use the
separate Electrs URL.

## Behavior and intentional fixes

The expiry threshold remains `confirmed_height + lock_time + MIN_BLOCK_CONFIRMATIONS`,
and RBF replacements require `tip >= replacement_height + MIN_BLOCK_CONFIRMATIONS`.
Only missing **pending** transactions older than `MAX_UNCONFIRMED_TIME` are failed
for age. Accepted deposits remain eligible for expiry/reclaim checks. An expired
output spent by signers is left alone.

Compared with Python:

- Follow Emily pages until complete or a 10s pagination timeout, and send at most
  one update per deposit outpoint.
- Fetch RBF replacement transactions even when they are absent from Emily or the
  original has disappeared. RBF takes precedence over the pending-age rule.
- Treat only transaction HTTP 404 as missing. Transport errors, other HTTP errors,
  malformed responses, and failed outspend lookups do not establish deposit failure.
  Skip affected deposits, process independent deposits, and report an unsuccessful cycle.
- Require a whole reclaim-script witness element instead of a substring match.
- Use `sbtc::deposits::ReclaimScriptInputs` to parse and validate reclaim scripts,
  including the CSV block delay and user-script restrictions.

The service remains a periodic reconciliation job: it does not make upstream reads
atomic or prevent concurrent updates by other services. `--dry-run` makes all the
same reads and logs the proposed JSON updates without writing them.

## Crate layout

The package provides the `emily_cron2` library and the `emily-cron2` binary.
The library exposes configuration, errors, logging, API models, and the deposit
processor. The binary handles startup, scheduling, and shutdown signals. Unit
tests live in the library's `tests` module.

## Tests

```sh
cargo test -p emily-cron2
cargo clippy -p emily-cron2 --all-targets --no-deps -- -D warnings
```

Tests use mock HTTP APIs and reuse the Python RBF fixtures. They cover expiry
boundaries, reclaim versus signer spending, replacement confirmation depth, pending
age, pagination, dry runs, and upstream/batch failures.
