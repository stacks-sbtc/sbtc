DROP TABLE sbtc_signer.stacks_transactions;

-- This is the foreign key in `bitcoin_transactions` references the txid
-- column in the `transactions` table
ALTER TABLE sbtc_signer.bitcoin_transactions
  DROP CONSTRAINT bitcoin_transactions_txid_fkey;

DROP TABLE sbtc_signer.transactions;
DROP TYPE sbtc_signer.transaction_type;
