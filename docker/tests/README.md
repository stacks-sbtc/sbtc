# Chainstate snapshot

To test Stacks interactions in integration tests we use snapshotted chainstates (for both Stacks and Bitcoin)
to get the chains up and running as soon as possible. 

The `docker-compose.stacks.yml` compose stack is used in such tests; it mounts chainstates contained in `snapshot.tar.xz`.

To regenerate a snapshot run:
```bash
# It uses xz to compress the archive, ensure you have it installed to generate a new snapshot
./generate_snapshot.sh
```

It will spin up a docker compose stack (`docker-compose.stacks.build.yml`), let it progress up to a certain height,
stop it and zip the volumes content (for bitcoin and stacks node).
