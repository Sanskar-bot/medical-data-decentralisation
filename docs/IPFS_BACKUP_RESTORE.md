# Private IPFS backup and restore

MedVault stores encrypted registration records and per-share ciphertext in the named Docker volumes `ipfs_data` and `ipfs_replica_data`. The matching PostgreSQL rows contain their CIDs, SHA-256 digests, sizes and access metadata. Back up the database and both Kubo volumes from the same quiesced maintenance window.

## Backup

1. Stop API writers and the maintenance worker: `docker compose stop backend ipfs_maintenance patient_portal doctor_portal landing`.
2. Dump PostgreSQL using its container environment: `docker compose exec -T postgres sh -c 'pg_dump -U "$POSTGRES_USER" "$POSTGRES_DB"' > medvault.sql`.
3. Find the actual volume names with `docker volume ls` (Compose prefixes them with the project name). Archive each volume without changing its contents:

   ```sh
   docker run --rm -v PROJECT_ipfs_data:/data:ro -v "$PWD/backups:/backup" busybox \
     tar -czf /backup/ipfs-primary.tgz -C /data .
   docker run --rm -v PROJECT_ipfs_replica_data:/data:ro -v "$PWD/backups:/backup" busybox \
     tar -czf /backup/ipfs-replica.tgz -C /data .
   ```

4. Store the SQL dump and both volume archives together as one backup set. Protect them as clinical data: ciphertext and metadata remain sensitive, and old backups may retain records after application-level deletion.
5. Restart the services with `docker compose start`.

## Restore

1. Stop API writers and the maintenance worker. Restore both Kubo archives into their matching named volumes and restore the SQL dump into PostgreSQL from the same backup set.
2. Start the Kubo nodes and wait for `/health` on the backend to report both IPFS targets as healthy.
3. Start the maintenance worker and backend. Pin repair verifies each CID and SHA-256 and restores missing private replicas. Check the worker logs and test representative registration/share fetches before reopening traffic.
4. Do not run `ipfs repo gc` against a partially restored or mismatched volume/database set; it can discard unpinned blocks needed for recovery.

Unpinning and repository GC only remove this deployment's live references. They do not erase someone else's fetched copy, offline backups, snapshots or copies held by other operators.

## Migration rollback

Before enabling the legacy-ciphertext migration worker, create and verify a coordinated PostgreSQL dump and archives of both Kubo volumes using the backup steps above. The migration is resumable: each row keeps its inline ciphertext until upload, re-fetch, CID, SHA-256 and size verification succeed and the pointer update commits. If migration or post-migration reads fail, stop API writers and the maintenance worker, then restore the PostgreSQL dump and both Kubo volumes from the same pre-migration backup set. Do not restore only the database or only one Kubo volume; that can leave rows pointing at missing blocks. There is no in-place down migration after inline ciphertext has been cleared.
