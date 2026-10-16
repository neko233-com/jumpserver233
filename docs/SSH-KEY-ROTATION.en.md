# SSH key installation and rotation

> English | [中文](./SSH-KEY-ROTATION.md)

Administrators can install a new Ed25519 key, rotate a managed account's current key and explicitly enable seven-day rotation. Web SSH, CLI, monitoring and SFTP use the new credential after vault promotion; private keys are never returned to clients. The backend remains a Go service with standalone and PostgreSQL single-active HA state. The competitor's account-change feature supports passwords and SSH keys; see its [official documentation](https://docs.fit2cloud.com/jumpserver/v3/guide/admin/account/account_change_secret/). Full Enterprise scope remains in [PLAN](./PLAN.en.md).

## Managed copies of the same private key

Assets with the same normalized host address, port, pinned host key, SSH username and private-key fingerprint coordinate candidate installation and old-key retirement, including copies within one organization and in disabled or archived organizations. Different private keys retain independent authorization lifecycles. Address aliases and different ports are not automatically merged.

An encrypted global participant list is persisted before staging the candidate under each organization's vault key. The server verifies the new key and promotes each vault, then removes the old public key only after all vaults commit. Failures retain both authorizations and stage records; recovery reuses the same candidate and operation ID. Editing/deleting participants and creating conflicting copies are blocked during pending work. A signature proves possession of the same private key rather than comparing PEM bytes containing randomized serialization data.

The participant list, stages and revisions are encrypted together with AES-GCM in root `shared-keys.json` or PostgreSQL `shared-keys`. Private keys remain in each organization's encrypted records. Restart and single-active takeover load all vaults, including disabled and archived organizations. Existing pending changes without a global list also discover shared copies before retiring the old key.

Before the promotion decision is persisted, any prepared copy can cancel the shared operation. Cancellation removes only its candidate and preserves the old key and individual schedules. Once promotion begins, the operation must resume and the UI disables cancellation. A verified finalization decision completes remaining local records after takeover without another remote mutation. Each organization audits only its own asset, linked by the operation ID. Credential-management views show “Coordinated key rotation” without listing foreign organizations or returning private keys.

## Individual asset operations

- For password assets, “More → Install SSH key” generates a key and switches vault authentication. The remote password retains its value. Password rotation ends for that key credential; key rotation can be enabled separately.
- For key assets, “More → Rotate SSH key” replaces ordinary authorization entries for the current public key, preserving restrictions, other keys and comments. New keys use Ed25519.
- Editing a key asset can enable seven-day rotation, calculated from the credential's last change. Overdue plans run at the next scheduler pass. Policy changes require both asset-management and rotation permission, enforced on the server; inventory-management permission alone cannot change the plan.
- Pending operations offer “Resume SSH key change.” Before vault promotion they can be cancelled: the original credential is verified before the candidate is removed. After promotion, resume old-key cleanup. Cancellation retains automatic policy; failed/cancelled automatic work backs off for one hour. Edit the asset to disable its plan.

## Commit and recovery sequence

1. Read and validate SSH/SFTP capabilities and the standard authorization file. Failed checks create no pending journal or remote lock.
2. Persist an encrypted journal containing both credentials and operation identity, then acquire the account-directory cooperative lock.
3. Capture old entries and restrictions, encrypt the plan, then add the candidate public key with its operation marker.
4. Verify the pinned host key and new authentication on an independent SSH connection.
5. Atomically promote the vault credential, management revision, old-credential backup and pending-cleanup phase.
6. Revoke the captured ordinary old-key entries, verify the new key again, release the lock and finish the journal.

Old-key revocation follows durable vault promotion. Restart or takeover can continue the same operation with the encrypted old/new credentials, without generating another candidate. Changed records, remote edits, network errors and uncertain writes retain recovery state and are not reported as completion. Installation and cleanup can be retried idempotently.

`POST /api/v1/assets/{id}/ssh-key-rotation` requires `request_id` and `expected_revision`, using the asset's `credential_revision`. A completed duplicate returns current state; new requests using a stale revision are rejected. The `/cancel` suffix requires the current `operation_id`. Cancellation also increments the management revision, preventing old requests from becoming active again. Credential audit records operations, retries, cancellation and outcomes with server-recorded identity and operation ID.

## Host requirements and file protection

Linux/OpenSSH, SFTP, `posix-rename@openssh.com` and `fsync@openssh.com` are required. The canonical login home and `.ssh/authorized_keys` are used. Home, `.ssh` and authorization files must be account-owned, without group/other write access; symlinks are rejected. Limits are 1 MiB per file, 8192 bytes per entry and 64 restriction variants for the current key.

Updates use an exclusive account-directory lock, a 0600 temporary file, file sync, conflict recheck, atomic replacement and directory sync. A complete token file is installed as the lock; recovery accepts only its own operation token and never steals an unknown lock. Existing `from`, `command`, `restrict` and forwarding options are copied unchanged. Cleanup removes only captured old entries. Rotation rejects a current key also used as a CA; separate CA management remains open. Other keys' CA entries are retained.

The cooperative lock coordinates platform writers. Coordinate edits from other tools: observed restriction/candidate changes are rejected, and unrelated additions are retained by the merge. Custom `AuthorizedKeysFile`, `AuthorizedKeysCommand`, root-owned managed files, SSH CAs/certificates, central directories, hardware signers and multi-active distributed key scheduling remain open. Established SSH connections continue; revocation affects subsequent authentication.

## Verification

Testify covers restriction preservation, conflicts, CA rejection, encrypted journals, idempotent requests, stale revisions, cancellation and staged recovery. A real Linux OpenSSH fixture covers installation, rejection of old-key login, new-key forwarding restrictions, SFTP filesystem behavior, restart after vault promotion and unsafe-permission/symlink rejection. Two-node HA prepares pending cleanup in shared storage, continues old-key revocation on takeover and executes a real command using the recovered credential.

Playwright exercises installation, rotation, public-key-file inspection, automatic policy, CLI, Web SSH, Chinese/English rendering and view-only operator denial through real OpenSSH and the SSH gateway. Docker supplies the test host with IPv4-loopback published ports. Public synthetic accounts must never be used in production. See [TESTING](./TESTING.en.md) for the unified entry point, ports and integration environment. Production hosts and production HA failure drills require separate acceptance.
