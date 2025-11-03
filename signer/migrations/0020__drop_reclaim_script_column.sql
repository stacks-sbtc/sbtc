-- We want to add a NOT NULL constraint on the deposit_request.reclaim_scipt_hash 
-- column and drop the deposit_request.reclaim_script column. In order to do so,
-- we need to delete all rows where the reclaim_script_hash column IS NULL, as
-- well as all rows from other tables with FOREIGN KEY pointers to the
-- deposit_request table where reclaim_script_hash column IS NULL.


-- Since deposit_signers references deposit requests with ON DELETE CASCADE
-- this should delete nothing, just added for consistency.
DELETE FROM sbtc_signer.deposit_signers ds
USING sbtc_signer.deposit_requests dr
WHERE ds.txid = dr.txid
  AND ds.output_index = dr.output_index
  AND dr.reclaim_script_hash IS NULL;

DELETE FROM sbtc_signer.deposit_requests
WHERE reclaim_script_hash IS NULL;

ALTER TABLE sbtc_signer.deposit_requests
ALTER COLUMN reclaim_script_hash SET NOT NULL;

ALTER TABLE sbtc_signer.deposit_requests
DROP COLUMN reclaim_script;
