-- Add is_canonical column to bitcoin_blocks table to track which blocks
-- are on the canonical Bitcoin blockchain.

ALTER TABLE sbtc_signer.bitcoin_blocks
ADD COLUMN is_canonical BOOLEAN;

-- Create an index on is_canonical for efficient queries filtering
-- canonical vs non-canonical blocks.
CREATE INDEX ix_bitcoin_blocks_is_canonical ON sbtc_signer.bitcoin_blocks(is_canonical);
