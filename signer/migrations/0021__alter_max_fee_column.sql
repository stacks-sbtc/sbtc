-- Add new bytea column for max_fee on deposit_requests, backfill from
-- BIGINT, then replace the existing max_fee column with the new version.

ALTER TABLE sbtc_signer.deposit_requests
    ADD COLUMN max_fee_bytes BYTEA;

-- Convert existing max_fee (BIGINT) to an 8-byte big-endian bytea.
UPDATE sbtc_signer.deposit_requests
SET max_fee_bytes = decode(lpad(to_hex(max_fee), 16, '0'), 'hex');

ALTER TABLE sbtc_signer.deposit_requests
    ALTER COLUMN max_fee_bytes SET NOT NULL;

ALTER TABLE sbtc_signer.deposit_requests
    DROP COLUMN max_fee;

ALTER TABLE sbtc_signer.deposit_requests
    RENAME COLUMN max_fee_bytes TO max_fee;
