-- Stores information about known libp2p peers.
CREATE TABLE p2p_peers (
    -- The public key of the peer
    public_key BYTEA PRIMARY KEY,
    -- The libp2p PeerId of the peer (base58 encoded multihash).
    peer_id TEXT NOT NULL,
    -- The last known reachable multiaddress for this peer.
    address TEXT NOT NULL,
    -- Timestamp of when this peer was first added.
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- Timestamp of the last update to this peer's record (e.g. a successful
    -- dial).
    last_dialed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Index to ensure that a peer_id is unique across all public keys (peer id's
-- are derived from their public key, so the rows in this table should be 1:1
-- public_key:peer_id).
CREATE UNIQUE INDEX uk_p2p_peers_public_key_peer_id ON p2p_peers (peer_id);
