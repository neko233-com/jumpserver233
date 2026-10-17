# Automatic SSH Password Rotation

> [中文](./PASSWORD-ROTATION.md) | English

Primary and named SSH accounts on one host have independent enablement, seven-day policies and encrypted credentials. Shared passwords still synchronize to disabled copies: [Managed SSH accounts](./MANAGED-ACCOUNTS.en.md).

SSH key installation, verified rotation, opt-in seven-day scheduling and persistent staged recovery are described in [SSH key rotation](./SSH-KEY-ROTATION.en.md).

Targets and gateways support imported SSH private keys with write-only input, vault encryption, public fingerprints and verified history restore. Password rotation remains password-specific. See [SSH private keys](./SSHKEYS.en.md).

SSH gateway routing supports up to three pinned hops across monitoring, Web SSH, CLI, SFTP, jobs and password rotation. Configuration and encrypted credentials support standalone and PostgreSQL single-active HA; see [SSH gateways](./GATEWAYS.en.md). Full Enterprise parity remains in progress.

Delegate manual rotation with `assets.rotate`, backup/restore with `assets.backups`, and asset/credential editing with `assets.manage`. See [RBAC.en.md](./RBAC.en.md). APIs still never return plaintext credentials.

## Current behavior

Managed Linux SSH account passwords rotate automatically every 7 days by default. An administrator can also start a rotation from the asset page. The interval starts at asset creation or the most recent successfully verified password change. Operators cannot see rotation timing or trigger a rotation.

The scheduler runs with the asset-monitor service and processes at most four hosts concurrently per process. The last attempt time and result of a failed rotation are stored with the asset, so the one-hour retry backoff for ordinary rotations survives service restarts and single-active HA failover. If an encrypted pending credential exists, the service checks both credentials at startup; unresolved recovery is retried at least one hour later. In cluster mode, only the active node holding the PostgreSQL election lock loads the asset service and runs the scheduler. Asset inventory and encrypted credentials live in shared PostgreSQL documents; every node must receive the same Vault key through `JMS_VAULT_KEY`. Rotation logs remain under the shared `JMS_DATA_DIR` mounted by every node. Cluster mode is single-active hot standby; see [CLUSTER-HA.en.md](./CLUSTER-HA.en.md).

## Multiple managed copies of one account

The active server coordinates password assets with the same normalized host address, port, pinned host-key fingerprint and SSH username, including copies within one organization. Current passwords must match. Creating or editing a conflicting credential returns `409 shared_credential_conflict`; it neither borrows another organization's credentials nor changes the remote password. The inventory's “Coordinated account rotation” indicator is visible only with asset management, rotation or vault management permissions and reveals no other organization or asset names.

The coordinator first persists its decision and AES-GCM encrypted old/new credentials in root `shared-passwords.json` or the PostgreSQL `shared-passwords` document. Encryption binds the operation ID and purpose. It then stages an encrypted pending password in every vault before changing the remote password once. After verification it persists a commit decision before promoting each vault. Copies retain their own history, revision, seven-day schedule and local audit; a common operation ID links events without copying foreign asset metadata.

Interrupted preparation aborts pending changes. Ambiguous remote outcomes retain both credentials and retry verification hourly. A verified commit decision resumes local promotion after restart or single-active HA takeover without changing the remote password again. An unresolved operation blocks editing, deletion and new rotation only for the affected account. Disabled and archived organizations receive verified passwords for matching accounts without starting monitoring or jobs.

DNS aliases versus IP addresses and different SSH ports are not automatically merged; use a consistent managed address. Do not clone host keys between machines, since their identities could no longer be distinguished reliably. Copies of an identical private key also promote all vaults before retiring the old key; see [key rotation](./SSH-KEY-ROTATION.en.md). Different private keys retain independent authorization lifecycles. Each organization retains four automatic rotation workers; the active node serializes remote credential mutations.

## Host password-change privileges

- The target must run Linux and allow the managed account to authenticate over SSH with its pinned SHA256 host key.
- The `root` account is changed through `chpasswd`; a non-root account needs non-interactive `sudo -n chpasswd` permission.
- The account name and host password policy must accept the generated URL-safe password. No remote agent is required.

If the host is unreachable, its host key does not match, authentication fails, or the account cannot run the password-change command, rotation fails and retains the currently active credential. An administrator can fix the cause and retry manually. When the state is “recovery required,” the service retries checking both credentials hourly; do not change the asset password until recovery resolves.

## Credentials and recovery

The new password is generated with a cryptographically secure random source and sent to `chpasswd` only through stdin on an SSH connection with a verified host key. It is never placed in command arguments, environment variables, browser responses, or audit records. The Vault stores both the active credential and any pending credential encrypted with AES-GCM.

If the remote result is ambiguous, the service tries authentication with both the new and old credentials. It commits the new credential when that succeeds, discards the pending credential when the old credential succeeds, and retains the encrypted pending credential with a “recovery required” state if neither can be verified. The service retries recovery hourly and after restart.

## Credential backup and restore

Administrators can create, list, delete, or restore an encrypted version from **More → Credential history** on an asset. Backup passwords use AES-GCM with the Vault key. The API and page return only a backup ID and creation time; they never display the password. The store keeps at most 10 versions. Manual backup creation fails at the limit until an older version is deleted. Automatic password replacements and successful rotations first snapshot the current password, pruning the oldest version when necessary.

Restore does not immediately make a historical password active. The service first stores it as an encrypted pending credential, then uses the current credential over SSH with the pinned SHA256 host key to change the remote password and reconnect with the selected backup to verify it. Only a successful verification promotes it to the active Vault credential. An ambiguous result retains the active credential and encrypted pending value for the hourly recovery process. Audit records contain the operator, backup ID, result, and time, never the password. Backup management and restore APIs are administrator-only and disable response caching.

Rotation events are written to `${JMS_DATA_DIR}/credential-rotations/index.jsonl`. Records include the asset, account, trigger, time, and stable error code, but never the password. The `POST /api/v1/assets/{assetID}/password-rotation` endpoint is administrator-only, disables response caching, and never returns the password.

## Acceptance boundary

Standalone mode implements automatic scheduling, SSH password changes, host-key verification, credential confirmation, failure recovery, audit records, and the administrator UI. In cluster mode, only the active node runs the scheduler. Unexpired login sessions can continue after failover because only their token digests are shared; active SSH sessions do not migrate. See [CLUSTER-HA.en.md](./CLUSTER-HA.en.md) for cluster acceptance scope and limitations.
