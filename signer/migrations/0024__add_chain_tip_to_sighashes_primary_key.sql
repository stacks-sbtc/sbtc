-- Signers only sign a sighash during the tenure of the bitcoin block in
-- which they approved it, so a sighash may be approved again under a new
-- chain tip. Include the chain tip in the primary key so that each
-- approval is stored.

ALTER TABLE sbtc_signer.bitcoin_tx_sighashes
DROP CONSTRAINT bitcoin_tx_sighashes_pkey;

ALTER TABLE sbtc_signer.bitcoin_tx_sighashes
ADD PRIMARY KEY (sighash, chain_tip);
