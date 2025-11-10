-- This table's schema must mirror the `sbtc_signer.stacks_blocks` table.
CREATE TABLE sbtc_signer.stacks_blocks_temp (
    block_hash BYTEA PRIMARY KEY,
    block_height BIGINT NOT NULL,
    parent_hash BYTEA NOT NULL,
    bitcoin_anchor BYTEA NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL
);
