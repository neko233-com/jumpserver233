# Encrypted full-site standalone backup and recovery

> [中文](./BACKUP.md) | English

Native `jms backup` exports, verifies and restores standalone data without an external database or extra backup program. Stop the service before creating or restoring backups; archive verification does not require stopping it. This batch passed Go/Testify, Linux race, real SSH, Docker volume restoration and complete production-browser verification. A general updater and PostgreSQL cluster backup remain pending.

## Quick start

Successfully start this version once in the existing deployment mode, then stop it normally. Startup records the authoritative storage mode and the accepted Vault key fingerprint. Older binaries do not honor this lock and must be stopped first. Preserve the deployment's `JMS_DATA_DIR` and `JMS_VAULT_KEY` settings. Interactive input hides the passphrase and confirms it twice when creating a backup.

```sh
jms backup create --data-dir /srv/jumpserver233/data --file /srv/backups/jms233.jmsbackup
jms backup verify --file /srv/backups/jms233.jmsbackup
jms backup restore --data-dir /srv/jumpserver233/data --file /srv/backups/jms233.jmsbackup --replace
```

`--data-dir` defaults to `JMS_DATA_DIR`, then `JumpServer233` under the user's config directory, matching the server. Archive output must be outside that directory with an existing parent. Creation never replaces an existing file. Restoring into an empty directory needs no `--replace`; replacing existing data requires it explicitly. JSON results contain backup ID, source version, time, file count, bytes and archive SHA-256, with no credentials or per-file inventory.

Automation supplies the passphrase through protected stdin using `--passphrase-file -`, or a private 0600 file. Never place it in command arguments, Git, logs or pipeline parameters. Passphrases require 12–1024 bytes and separate safekeeping. On Windows, protect passphrase files, data/control directories and archives through user-controlled ACLs; Go's Unix mode bits do not verify Windows ACLs. A lost passphrase cannot decrypt the archive.

## Coverage and format

Export ordinary files under `JMS_DATA_DIR`: identities, organizations, inventory, credentials, policies, schedules, audit, recordings and other runtime data, including `vault.key`. With `JMS_VAULT_KEY`, first match the fingerprint recorded after a successful server load, then wrap that same key into the encrypted archive without changing the source directory. Recovery may use the local key or the same configured external value. Results never expose the key.

Do not recursively export `.jms233-maintenance/` locks, stages or previous snapshots, or restore receipts. Keep external startup settings, reverse-proxy certificates, `runtime.json` and application programs through the deployment's own process. This tool cannot capture PostgreSQL cluster state from stale local import files. Storage markers or `JMS_CLUSTER_MODE=true` reject that use. Older deployments must start this version in their existing cluster mode to write the marker; clearing cluster settings is not a standalone migration.

`JMS233BK1` uses scrypt, AES-256-GCM authenticated chunks, gzip/tar and an encrypted versioned per-file SHA-256 manifest. Sequence numbers, lengths and the header are authenticated; a terminal frame plus physical EOF reject truncation, reordering, replay and append. Processing uses 1 MiB chunks. Limits: 64 GiB logical data, 200000 file/directory entries, 64 MiB manifest. Reject traversal, unsafe cross-platform names, case collisions, archive symlinks/hard links and special files; source symlinks are also rejected.

## Recovery, idempotency and interruption

Decrypt and validate everything in a private 0700 directory on the data volume before switching business data. Restore files as 0600; directories and previously executable files as 0700. Do not restore old host UID/GID or group/public access. Unix flushes files and directories. Windows flushes files and relies on journaled same-volume renames; equivalent power-loss directory-sync guarantees are not claimed.

Restore replaces snapshots without merging inventory or duplicating IDs. Reimporting the same backup ID and manifest returns `unchanged=true`, preserving changes made after the first import. The same ID with a different manifest is rejected. Explicit replacement retains all old data in the returned `previous_data_dir` under the maintenance directory. Apply retention after business checks; it is not deleted automatically.

Restoring a local snapshot does not roll back remote machines. Reconcile passwords or keys rotated after the snapshot. Restoration does not automatically disable saved schedules; startup follows existing scheduling and uncertain-operation recovery rules. Use a controlled maintenance window to check credentials and automatic tasks. Archive integrity does not prove recovery of external machine state.

The data root and lock stay in place while top-level entries move. This supports a direct Docker `/data` volume with a read-only container root. Startup reconciles a pending journal before opening any inventory or authentication store. Uncertain or corrupt state blocks startup instead of initializing empty data. While stopped, explicitly run:

```sh
jms backup recover --data-dir /srv/jumpserver233/data
jms backup recover --data-dir /srv/jumpserver233/data --rollback
```

The first resumes a verified switch; the second restores old data and retains partially installed data in a private `failed-data` directory. Rollback has persistent phases and can itself resume after interruption. Cross-version application schema compatibility still needs target-version startup and real business verification; container integrity is not application compatibility acceptance.

## Acceptance

Full Go/Testify: 1,523 passed (42 skipped); Linux race: 745 passed (nine skipped); complete production browser: 85/85; Docker feature checks: 7/7. Suites overlap. Coverage includes process exclusion/crash release, wrong keys/tampering/path attacks, interrupted restore/rollback, repeat imports and real HTTP/SSH. See [TESTING.en.md](./TESTING.en.md). Update checks and automatic upgrades follow the [stable SSH scope](./SSH-FIRST.en.md).
