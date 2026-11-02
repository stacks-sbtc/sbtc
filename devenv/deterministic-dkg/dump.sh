#!/usr/bin/env bash
# Script to dump the DKG shares from devenv

set -e
cd "$(dirname "$0")"

# Pinned to match the devenv version to avoid unrecognized directives in the dump
PG_IMAGE="postgres:16.6-bookworm@sha256:c965017e1d29eb03e18a11abc25f5e3cd78cb5ac799d495922264b8489d5a3a1"

dump_dkg_shares() {
  docker run --rm -e PGPASSWORD=postgres "${PG_IMAGE}" \
    pg_dump -h host.docker.internal -p "$1" -U postgres -d signer \
    --table=sbtc_signer.dkg_shares \
    --data-only --column-inserts --no-owner --no-privileges \
    > "$2"
}

dump_dkg_shares 5432 "signer-1.sql"
dump_dkg_shares 5433 "signer-2.sql"
dump_dkg_shares 5434 "signer-3.sql"
