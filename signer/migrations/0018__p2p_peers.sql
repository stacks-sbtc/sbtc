-- Stores information about known libp2p peers.
CREATE TABLE p2p_peers (
    -- The libp2p PeerId of the peer (base58 encoded multihash).
    peer_id TEXT NOT NULL,
    -- The public key of the peer
    public_key BYTEA NOT NULL,
    -- The last known reachable multiaddress for this peer.
    address TEXT NOT NULL,
    -- Timestamp of when this peer was first added.
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- Timestamp of the last update to this peer's record (e.g. a successful
    -- dial).
    last_dialed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- The peer_id is derived from the public_key, so these values should always
    -- be "connected". We log them both here to make it easier for potential
    -- monitoring and future queries/joins which only have the public key.
    PRIMARY KEY (peer_id, public_key)
);

