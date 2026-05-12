-- We now only persist sighashes and withdrawal outputs for transactions
-- that this signer will sign. All non-fee validation failures cause the
-- presign step to bail before any rows are written, and rows with a
-- failing fee check are filtered out. Under that invariant
-- `validation_result` is always `'ok'`, `is_valid_tx` is always `true`,
-- and `will_sign` is always `true` for persisted rows — so the columns
-- carry no information and can be dropped.

ALTER TABLE sbtc_signer.bitcoin_tx_sighashes
    DROP COLUMN validation_result,
    DROP COLUMN is_valid_tx,
    DROP COLUMN will_sign;

ALTER TABLE sbtc_signer.bitcoin_withdrawals_outputs
    DROP COLUMN validation_result,
    DROP COLUMN is_valid_tx;
