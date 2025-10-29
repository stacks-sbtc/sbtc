BEGIN;
-- We want to set reclaim_scipt_hash to NOT NULL, since we dropping
-- reclaim_script and reclaim_script_hash now will replace the reclaim_script
-- functionality. In order to do so, we need to delete all rows where 
-- reclaim_script_hash IS NULL, and rows from another tables pointing via
-- FOREIGHN KEY to rows where reclaim_script_hash IS NULL.


-- Since deposit_signers references deposit requests with ON DELETE CASCADE
-- this should delete nothing, just added for consistency.
DELETE FROM sbtc_signer.deposit_signers ds
USING sbtc_signer.deposit_requests dr
WHERE ds.deposit_request_txid = dr.txid
  AND ds.deposit_request_output_index = dr.output_index
  AND dr.reclaim_script_hash IS NULL;


DELETE FROM sbtc_signer.swept_deposits sd
USING sbtc_signer.deposit_requests dr
WHERE sd.deposit_request_txid = dr.txid
  AND sd.deposit_request_output_index = dr.output_index
  AND dr.reclaim_script_hash IS NULL;

DELETE FROM sbtc_signer.deposit_requests
WHERE reclaim_script_hash IS NULL;

ALTER TABLE sbtc_signer.deposit_requests
ALTER COLUMN reclaim_script_hash SET NOT NULL;

ALTER TABLE sbtc_signer.deposit_requests
DROP COLUMN reclaim_script;

COMMIT;
