ALTER TABLE sbtc_signer.rotate_keys_transactions
    ADD COLUMN block_hash BYTEA;

-- At the time that this query was executed, all rotate keys transaction
-- events are associated with one stacks blocks.
WITH block_hashes_txids AS (
    SELECT 
        st.block_hash
      , st.txid
    FROM sbtc_signer.rotate_keys_transactions AS rkt
    JOIN sbtc_signer.stacks_transactions AS st 
      ON st.txid = rkt.txid
)
UPDATE sbtc_signer.rotate_keys_transactions
SET block_hash = bht.block_hash
FROM block_hashes_txids AS bht
WHERE sbtc_signer.rotate_keys_transactions.txid = bht.txid;

-- Make the new column `NOT NULL` now that they should all have a value.
ALTER TABLE sbtc_signer.rotate_keys_transactions
    ALTER COLUMN block_hash SET NOT NULL;

 -- The existing primary key is on txid, but now the block hash needs to be
 -- part of the primary key.
ALTER TABLE sbtc_signer.rotate_keys_transactions
  DROP CONSTRAINT rotate_keys_transactions_pkey;

-- Add the new composite primary key
ALTER TABLE sbtc_signer.rotate_keys_transactions
  ADD PRIMARY KEY (txid, block_hash);
