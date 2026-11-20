CREATE TYPE sbtc_signer.script_version AS ENUM ('v1', 'v2');

-- A key_set_id determines its key set's version. A v1 key set is
-- identified by its 32-byte x-only aggregate public key, and a v2 key set
-- by the byte 0xFF followed by the 32-byte hash of its threshold and
-- signing keys. The key_set_id columns in deposit_requests and
-- bitcoin_tx_sighashes use the same encoding.
--
-- The signer_public_keys column always holds x-only public keys, but what
-- they represent depends on the version. For v1 they are the x-only form
-- of each signer's identity public key, and for v2 they are each signer's
-- derived Bitcoin signing public key.
CREATE TABLE sbtc_signer.signer_key_sets (
    key_set_id          BYTEA PRIMARY KEY,
    script_version      sbtc_signer.script_version NOT NULL,
    script_pubkey       BYTEA NOT NULL,
    signer_public_keys  BYTEA[] NOT NULL,
    signatures_required INTEGER NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- A v1 key set is identified by its x-only aggregate public key. The
-- dkg_shares table holds compressed public keys, so we lop off the first
-- byte of each key to get its x-only form.
INSERT INTO sbtc_signer.signer_key_sets (
    key_set_id,
    script_version,
    script_pubkey,
    signer_public_keys,
    signatures_required,
    created_at
)
SELECT substring(ds.aggregate_key FROM 2)
     , 'v1'
     , ds.script_pubkey
     , ARRAY(
           SELECT substring(signer_public_key FROM 2)
           FROM UNNEST(ds.signer_set_public_keys) AS signer_public_key
       )
     , ds.signature_share_threshold
     , ds.created_at
FROM sbtc_signer.dkg_shares AS ds
WHERE ds.dkg_shares_status = 'verified';

-- Existing rows in these tables are v1, so their x-only public keys are
-- already v1 key-set identifiers.
ALTER TABLE sbtc_signer.deposit_requests
    RENAME COLUMN signers_public_key TO key_set_id;

ALTER TABLE sbtc_signer.bitcoin_tx_sighashes
    RENAME COLUMN x_only_public_key TO key_set_id;
