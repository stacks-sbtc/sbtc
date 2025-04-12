ALTER TABLE sbtc_signer.rotate_keys_transactions
ADD COLUMN block_hash BYTEA;

-- At the time that this query was executed, all rotate keys transaction
-- events are associated with one stacks blocks.
WITH block_hashes AS (
    SELECT st.block_hash
    FROM sbtc_signer.rotate_keys_transactions AS rkt
    JOIN sbtc_signer.stacks_transactions AS st ON st.txid = rkt.txid
)
UPDATE sbtc_signer.rotate_keys_transactions
SET block_hash = block_hashes.block_hash
FROM block_hashes

-- Make the new column `NOT NULL` now that they should all have a value.
ALTER TABLE sbtc_signer.rotate_keys_transactions
    ALTER COLUMN block_hash SET NOT NULL;
