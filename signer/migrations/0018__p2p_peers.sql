-- Stores information about known libp2p peers.
CREATE TABLE p2p_peers (
    -- The libp2p PeerId of the peer (base58 encoded multihash).
    peer_id TEXT,
    -- The public key of the peer
    public_key BYTEA NOT NULL,
    -- The last known reachable multiaddress for this peer.
    address TEXT NOT NULL,
    -- Timestamp of when this peer was first added.
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- Timestamp of the last update to this peer''s record (e.g. a successful
    -- dial).
    last_dialed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- The peer_id is derived from the public_key, so these values should always
    -- be "connected". We log them both here to make it easier for potential
    -- monitoring and future queries/joins which only have the public key.
    PRIMARY KEY (peer_id, public_key)
);

CREATE OR REPLACE FUNCTION update_last_dialed_at_column()
RETURNS TRIGGER AS $$
BEGIN
   NEW.last_dialed_at = NOW();
   RETURN NEW;
END;
$$ language 'plpgsql';

-- Trigger for `p2p_peers` table which sets the `last_updated_at` column
-- to the current time whenever a row is updated.
CREATE TRIGGER update_p2p_peers_last_updated_at
BEFORE UPDATE ON p2p_peers
FOR EACH ROW
EXECUTE FUNCTION update_last_dialed_at_column();
