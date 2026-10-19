# Controlled standalone installation transactions

> [中文](./INSTALLATION.md) | English

The native CLI binds a staged version to fixed data, verifies an encrypted checkpoint, runs offline preflight and awaits first-start acceptance. Business traffic and remote work stay gated until acceptance. Failure restores old data/selection and resumes an existing managed version. After release, new data is preserved and failures require forward repair. [Scheduled standalone installation](./INSTALLATION-SCHEDULE.en.md) connects fixed verified candidates to scheduling, drain, shutdown and startup. Automatic download policies and historical-version migration acceptance remain pending.

## Prerequisites

- Standalone local persistence requires no external database. PostgreSQL clusters are unsupported; disabling cluster configuration must not expose stale local files to this workflow.
- Deploy an upgrade-guard-aware baseline, start it successfully once, then stop it completely and pause external supervisor restarts. Older programs do not obey the new guard. Missing upgrade-protocol/key-fingerprint markers refuse installation. Source data must already be initialized; this does not initialize an empty site.
- Follow [candidate staging](./UPDATES.en.md#controlled-candidate-staging) for a reviewed official stable package. The target declares `preflight_protocol=1` and `activation_protocol=1`, matching the host OS/architecture. Legacy packages remain verifiable/stageable but cannot enter new installation transactions.
- Managed root/data directories must not contain each other. Keep the same `JMS_VAULT_KEY` when using an external key. Other environment configuration and proxy certificates remain deployment responsibilities.
- Keep checkpoint passphrases separately, outside arguments, Git, logs and pipeline parameters. Interactive input is hidden and confirmed. Automation uses protected stdin with `--passphrase-file -`, or a private regular file. Passphrase rules match [full-site backup](./BACKUP.en.md).

## Commands

```sh
jms update install-status --root /srv/jumpserver233-releases
jms update install --root /srv/jumpserver233-releases --data-dir /srv/jumpserver233/data --sha256 VERIFIED_PACKAGE_SHA256 --revision 0 --request-id upgrade-unique-001
jms update run --root /srv/jumpserver233-releases --passphrase-file /run/secrets/jms-update-passphrase
```

The initial revision is `0`; successful selections increment it. Later operations use current status. Initial adoption can record a baseline using `--source-version`; managed installations use their actual source selection. `install` leaves `awaiting_start` without launching service. First `run` needs the same checkpoint passphrase through hidden input, protected stdin or a private file; accepted-version restarts no longer read it. Configure startup as `jms update run --root …`; it verifies contents, binds data/web paths and the built-in version, retains listener/public-origin/auth/Vault configuration and enforces standalone mode.

The same request ID, target SHA, original revision and data path returns its original receipt without repeating checkpoint/preflight/restore. Changed request contents conflict. Stale revisions conflict for new requests. The current identical package is unchanged. Existing managed versions refuse same-version rebuilds, downgrades and changed data bindings. Initial adoption checks format through target preflight without inferring migration compatibility from a `--source-version` declaration. Private local metadata retains the latest 100 request receipts.

## Transaction and guard

1. Validate ownership, version, data binding and revision; acquire the OS data lock, refusing active services or unfinished restores.
2. Persist the journal/data guard and create an independently verified, consistent encrypted checkpoint at `backups/TRANSACTION_ID.jmsbackup`. It excludes control locks, guards and application programs.
3. Persist the checking phase, release the data lock temporarily and execute the pinned target binary with `--check-data --upgrade-id ID`, bounded to two minutes. Preflight uses normal default/active-organization store loading, all organizations' credentials and static-web validation. It starts no listener, collection/scheduling/notification loop or remote shared-password recovery. Normal local startup migrations/interruption records may be written, hence the checkpoint requirement.
4. Reacquire the lock. Failure verifies the checkpoint and restores old data, retaining failed content at `previous_data_dir`. Success persists the selection and `selected` guard, retaining an `awaiting_start` journal. Pending acceptance blocks other installations while allowing the original receipt to replay.
5. First `run` verifies checkpoint key/digest, writes a fresh attempt and `trial` guard and launches the candidate PID. Only health/root GET are allowed; other API, WS and page requests return 503. Remote work remains stopped.
6. The parent matches private readiness root/transaction/attempt, PID, executable digest, version and actual listener. It directly checks health, index digest and API/WS gates without proxies or redirects, then writes a local release file. There is no HTTP release endpoint.
7. The child persists the `active` guard before resuming organization/global tasks, publishing active readiness and opening traffic. The parent verifies active health and removes the journal. Preflight and first-start acceptance are each bounded to two minutes.

The data-volume guard is `.jms233-maintenance/upgrade.json`, outside backups. Pending transactions admit matching ID/digest preflight or attempt-bound controlled startup. Completed transactions admit normal startup only for the active executable digest, preventing old launches from opening upgraded data. Transaction/attempt IDs are local lifecycle identifiers, not login credentials. File ownership/ACLs define the trust boundary; arbitrary same-privilege local modification is not isolated.

Preparation failure, unavailable data locks or failed recovery verification leave the transaction pending, retaining its journal and blocking service startup. `install` still exits nonzero after successfully rolling a failed target back. `install-recover` exits successfully after completing recovery, identifying `rolled_back`, `aborted` or `selected` in JSON.

`run` forwards termination signals and waits; it kills a child that has not exited within 12 seconds. Windows does not guarantee console interrupt forwarding and may take the termination path. This does not establish graceful shutdown acceptance for every platform. Drain SSH/jobs and verify shutdown using the platform's deployment procedure.

## Interruption recovery

```sh
jms update install-recover --root /srv/jumpserver233-releases
```

Recovery first obtains the same data lock, refusing live owners; observation timeouts never establish process death. Before `active` release it restores old data/selection. The parent confirms candidate exit first, automatically resuming an existing managed version; initial adoption restores data and exits. Rollback after selection publication also increments revision, for example `N → N+1 → N+2`, preventing stale requests from acquiring new meaning. `active` is irreversible: even exit before active health is observed preserves new data/version for forward repair, avoiding loss of possible business writes/remote actions. Legacy schema 1 journals retain historical commit semantics. Recorded rollback receipts only finalize cleanup. With no transaction, repeated recovery returns `unchanged=true`.

When checkpoint verification is required, wrong passphrases/digests retain state and refuse recovery. Unknown revisions/journals, changed root ownership and changed data paths also refuse recovery. Preparation before target execution only cancels preparation. Published checkpoints, old versions, failed data and unproven crash remnants are retained for an explicit post-verification policy. QA runners separately remove their owned test resources.

Checkpoints restore local data without reversing passwords/commands already changed on remote machines. Offline preflight performs no such remote actions; normal startup resumes existing recovery/scheduling behavior. Passing preflight does not establish listener/proxy availability, authentication/authorization, actual SSH or complete application migration compatibility. Verify those after deployment. The complete updater and Enterprise objective remain active; see [SSH-first scope](./SSH-FIRST.en.md).
