# Emily cron2

Rust deposit reconciliation service, independent of the Python `emily_cron`. It reads pending deposits from the private Emily endpoint and updates `/deposit_private` for expired unspent deposits, depositor reclaims, confirmed RBF replacements, and old pending transactions that are not currently in the mempool.

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

## Behavior and intentional fixes

This service will only change the status of a deposit if RBF is such that the current bitcoin chain tip height is at least `replacement_height + MIN_BLOCK_CONFIRMATIONS`. Only missing pending transactions older than `MAX_UNCONFIRMED_TIME` are marked as failed.

The service remains a periodic reconciliation job: it does not make upstream reads
atomic or prevent concurrent updates by other services. `--dry-run` makes all the
same reads and logs the proposed JSON updates without writing them.
