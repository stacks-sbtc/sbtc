# Chainstate snapshot

To test Stacks interactions in integration tests we use snapshotted chainstates (for both Stacks and Bitcoin)
to make the chains up and running as soon as possible. 

The `docker-compose.stacks.yml` compose stack is used in such tests; it mounts chainstates contained in `snapshot.tgz`.

To regenerate a snapshot run:
```bash
./generate_snapshot.sh
```

It will spin up a docker compose stack (`docker-compose.stacks.build.yml`), let it progress up to a certain height,
stop it and zip the volumes content (for bitcoin and stacks node).
