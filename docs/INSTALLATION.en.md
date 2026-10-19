# Controlled standalone installation transactions

> [中文](./INSTALLATION.md) | English

The native CLI binds a staged version to a fixed data directory, creates/verifies an encrypted checkpoint and runs the target binary's offline data preflight before atomically selecting it. Failure restores the checkpoint and previous selection. Interrupted transactions retain journals and block startup. Use `jms update run` for normal service operation. This is an offline upgrade mechanism; automatic download/installation scheduling, rollback after live health failure and cross-version business migration acceptance remain pending.

## Prerequisites

- Standalone local persistence requires no external database. PostgreSQL clusters are unsupported; disabling cluster configuration must not expose stale local files to this workflow.
- Deploy an upgrade-guard-aware baseline, start it successfully once, then stop it completely and pause external supervisor restarts. Older programs do not obey the new guard. Missing upgrade-protocol/key-fingerprint markers refuse installation. Source data must already be initialized; this does not initialize an empty site.
- Follow [candidate staging](./UPDATES.en.md#controlled-candidate-staging) for a reviewed official stable package. The target manifest must declare `preflight_protocol=1` and match the current OS/architecture. Legacy packages can still be verified/staged but cannot enter installation transactions.
- Managed root/data directories must not contain each other. Keep the same `JMS_VAULT_KEY` when using an external key. Other environment configuration and proxy certificates remain deployment responsibilities.
- Keep checkpoint passphrases separately, outside arguments, Git, logs and pipeline parameters. Interactive input is hidden and confirmed. Automation uses protected stdin with `--passphrase-file -`, or a private regular file. Passphrase rules match [full-site backup](./BACKUP.en.md).

## Commands

```sh
jms update install-status --root /srv/jumpserver233-releases
jms update install --root /srv/jumpserver233-releases --data-dir /srv/jumpserver233/data --sha256 VERIFIED_PACKAGE_SHA256 --revision 0 --request-id upgrade-unique-001
jms update run --root /srv/jumpserver233-releases
```

The initial revision is `0`; successful selections increment it. Subsequent operations use the current status revision. Initial adoption can record a baseline with `--source-version`; existing managed installations use their actually selected source version. `install` never starts production service automatically. Configure normal startup as `jms update run --root …`: it rechecks candidate contents and starts the server with bound data/web paths and its built-in version, retaining listener/public-origin/auth/Vault configuration and enforcing standalone mode.

The same request ID, target SHA, original revision and data path returns its original receipt without repeating checkpoint/preflight/restore. Changed request contents conflict. Stale revisions conflict for new requests. The current identical package is unchanged; another package with the same version, downgrades and changed data bindings refuse installation. Private local metadata retains the latest 100 request receipts.

## Transaction and guard

1. Validate ownership, version, data binding and revision; acquire the OS data lock, refusing active services or unfinished restores.
2. Persist the journal/data guard and create an independently verified, consistent encrypted checkpoint at `backups/TRANSACTION_ID.jmsbackup`. It excludes control locks, guards and application programs.
3. Persist the checking phase, release the data lock temporarily and execute the pinned target binary with `--check-data --upgrade-id ID`, bounded to two minutes. Preflight uses normal default/active-organization store loading, all organizations' credentials and static-web validation. It starts no listener, collection/scheduling/notification loop or remote shared-password recovery. Normal local startup migrations/interruption records may be written, hence the checkpoint requirement.
4. Reacquire the lock. Failure validates the recorded archive SHA/passphrase and restores the previous data, retaining failed content at `previous_data_dir`. Success atomically persists the selection, changes the guard to the active binary, then removes the journal.

The data-volume guard is `.jms233-maintenance/upgrade.json` and is excluded from backups. Pending transactions admit only offline preflight matching the transaction ID and executable SHA-256. Completed transactions admit normal startup only for the selected binary digest, preventing a racing old launch from opening newly migrated data after lock release. Transaction IDs are local identifiers, not authentication credentials. File ownership/ACLs are the trust boundary; arbitrary same-privilege local modification is not isolated.

`run` forwards termination signals and waits; it kills a child that has not exited within 12 seconds. Windows does not guarantee console interrupt forwarding and may take the termination path. This does not establish graceful shutdown acceptance for every platform. Drain SSH/jobs and verify shutdown using the platform's deployment procedure.

## Interruption recovery

```sh
jms update install-recover --root /srv/jumpserver233-releases
```

Recovery first obtains the same data lock. A live preflight/business process holding it refuses recovery; observation timeouts do not establish process death. Before the durable selection, recovery restores the old checkpoint/version. After the durable selection, it completes commit without rolling new business writes back to an older checkpoint. Recorded rollback receipts also only finish cleanup. Repeated recovery with no pending transaction returns `unchanged=true`.

When checkpoint verification is required, wrong passphrases/digests retain state and refuse recovery. Unknown revisions/journals, changed root ownership and changed data paths also refuse recovery. Preparation before target execution only cancels preparation. Published checkpoints, old versions, failed data and unproven crash remnants are retained for an explicit post-verification policy. QA runners separately remove their owned test resources.

Checkpoints restore local data without reversing passwords/commands already changed on remote machines. Offline preflight performs no such remote actions; normal startup resumes existing recovery/scheduling behavior. Passing preflight does not establish listener/proxy availability, authentication/authorization, actual SSH or complete application migration compatibility. Verify those after deployment. The complete updater and Enterprise objective remain active; see [SSH-first scope](./SSH-FIRST.en.md).
