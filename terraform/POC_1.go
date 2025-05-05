package main

import (
        "context"
        "encoding/hex"
        "log"
        "sync"
        "time"

        libp2p "github.com/libp2p/go-libp2p"
        peer "github.com/libp2p/go-libp2p/core/peer"
        crypto "github.com/libp2p/go-libp2p/core/crypto"
        ma "github.com/multiformats/go-multiaddr"
)

const (
        numInstances = 1000000
)

var (
        semaphore = make(chan struct{}, 12000) // limit concurrency
)

// const privKeyBase64 = "CAESQEFjR2LYnfoJEzpKjpwTeNAWHSnNCpQztR8ePTKUenPcdvQTOHqdfS+qNZIdtYWRnO+40WPoaFpld743Q3XVhpU="

// func getIdentity() (crypto.PrivKey, error) {
//         keyBytes, err := base64.StdEncoding.DecodeString(privKeyBase64)
//         if err != nil {
//                 return nil, err
//         }
//         return crypto.UnmarshalPrivateKey(keyBytes)
// }

func nonPeerIdentity() (crypto.PrivKey, error) {
        raw, err := hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000001")
        if err != nil {
                log.Fatal(err)
        }

        // 2. Unmarshal into a libp2p PrivKey
        return crypto.UnmarshalSecp256k1PrivateKey(raw)
}

func connectAndClose(targetAddr ma.Multiaddr, instanceID int, wg *sync.WaitGroup) {
        defer wg.Done()
        semaphore <- struct{}{}        // acquire
        defer func() { <-semaphore }() // release

        ctx := context.Background()

        privKey, err := nonPeerIdentity()
        if err != nil {
                log.Printf("[Instance %d] Failed to get identity: %s", instanceID, err)
                return
        }

        h, err := libp2p.New(libp2p.Identity(privKey))
        if err != nil {
                log.Printf("[Instance %d] Failed to create host: %s", instanceID, err)
                return
        }
        defer h.Close()

        // Extract peer info without expecting peer ID
        peerInfo, err := peer.AddrInfoFromP2pAddr(targetAddr)
        if err != nil {
                log.Printf("[Instance %d] Failed to parse peer info: %s", instanceID, err)
                return
        }

        // Remove any hardcoded peer ID to allow libp2p to validate the actual peer

        if err := h.Connect(ctx, *peerInfo); err != nil {
                log.Printf("[Instance %d] Connection failed: %s", instanceID, err)
                return
        }

        log.Printf("[Instance %d] Connected to peer %s", instanceID, peerInfo.ID)

        time.Sleep(5 * time.Second)
}

func main() {
        target := "/ip4/10.0.3.92/tcp/4123/p2p/16Uiu2HAmERfbmUTgXfvR6xafvuuGZHiRDDP2938nJWqsJGqYot5D"

        maddr, err := ma.NewMultiaddr(target)
        if err != nil {
                log.Fatalf("Invalid multiaddress: %s", err)
        }

        log.Printf("Starting connection test with %d instances...", numInstances)

        var wg sync.WaitGroup
        for i := 0; i < numInstances; i++ {
                wg.Add(1)
                go connectAndClose(maddr, i, &wg)
        }
        wg.Wait()
        log.Println("All connections completed.")
}
