# Native SSH / SFTP entry

> [中文](./NATIVE-SSH.md) | English

## Scope and status

The user explicitly added ordinary SSH client access. Keep Web on 8180 and embed SSH/SFTP on 2222 in the Go process, without system sshd or an external proxy. Implementation, cases and deployment changes are authored together. Unified verification and the single official release have not run. The accepted v0.2.2 remains a historical baseline, not acceptance of this batch.

| Acceptance item | Current state |
|---|---|
| root/root platform login, TOTP and denial policies | Authored; unified verification pending |
| Case insensitive title, desc and IP search, multiple terms and pagination | Authored; unified verification pending |
| Native PTY, resizing, returning to the menu and reconnecting | Authored; unified verification pending |
| Shared command blocking, approval, one-use consumption, directory proof, replay and actor audit | Authored; unified verification pending |
| Authorized account directories, atomic upload, direct download, rename and deletion | Authored; unified verification pending |
| Revocation, changed connection bindings, traversal and symlink denial | Authored; unified verification pending |
| Data retention, stable host fingerprints and maintenance draining | Authored; unified verification pending |
| Docker, native and intranet acceptance, single publication and idempotent cleanup | Authored; unified verification pending |

## Usage

For direct standalone execution, explicitly set `JMS_SSH_ADDR=0.0.0.0:2222`. Development and concurrent test instances leave SSH disabled by default to avoid port conflicts. An external SSH listener follows the existing non-loopback configuration rules and needs the server's existing `JMS_ADMIN_TOKEN`; that token is never sent to SSH clients. Docker and `Jenkinsfile_mac_single` enable 2222. HTTP and SSH use separate ports without protocol sniffing.

```sh
ssh -p 2222 root@192.168.110.42
sftp -P 2222 root@192.168.110.42
```

The initial platform identity is root/root. Existing accounts and passwords survive startup and upgrades without reset. This username is not a macOS system account. TOTP uses keyboard-interactive; select it with `ssh -o PreferredAuthentications=keyboard-interactive -p 2222 ...`. Identities requiring initial MFA enrollment, SMS/RADIUS or platform login review continue using the Web flow for those steps; native login cannot bypass them.

The menu displays Chinese and English together. Enter a query or `/query`; space separated terms must all match. Title maps to existing `name`, desc to `remark`, and IP to `host`; accounts are searchable too. Select a numbered entry, `r` to refresh, `n/p` for pages, or `q` to quit. Exiting the target shell returns to the menu. `ssh ... connect <account-id>` selects an authorized account directly without executing arbitrary bastion system commands.

SFTP `/` lists `server-title--account@stable-account-ID`; stable `/<account-id>/...` paths also work and survive title changes. Standard `ls/cd/get/put/mkdir/rename/rm/rmdir` need no additional port. Existing workspace authorization and the remote SFTP home remain boundaries. Cross-account moves, traversal and symlink following are denied. Complete create/overwrite uploads are supported; append, partial in-place modification, file attribute changes and arbitrary TCP/Agent forwarding are unsupported.

Append `%<organization-UUID>` to the SSH username to select an existing organization. Membership and resource isolation still apply. Ordinary standalone users need no organization configuration.

## Security, performance and cleanup

Login, search and session creation use process-local HTTP pipes and the full existing identity, source IP, rate limit, organization, RBAC, grant, login review and session policy chain. The native entry has no superuser API token. Terminal bytes pass through the existing WebSocket gateway, preserving command reviews, blocking, directory proofs and encrypted replay. SFTP uses a process-local callback that HTTP clients cannot forge to enter the same file authorization middleware. Every read/write packet rechecks access and the connection binding; target credentials stay server-side.

Downloads read directly from remote SFTP handles without whole-file disk caching. Uploads stage in 0600 files inside an owned 0700 directory, with at most two files of 1 GiB each. Incomplete sparse uploads are rejected. Successful commits use the existing remote temporary-file and atomic-rename service. Disconnect, cancellation and failure remove staging without replacing the old file. Normal shutdown removes its temporary directory. Crash recovery only removes explicitly marked, unlocked directories for the same Vault identity. They live in the system temporary directory outside business backups.

The Ed25519 host key is derived from the existing Vault key with a dedicated domain identifier. Restart, upgrade and restore retain the fingerprint with that same Vault key; replacing the Vault key changes it. Limits are 64 clients, four channels per client and a 30-second handshake. Active native clients count as maintenance work. Close SSH/SFTP clients before release rather than interrupting existing operations. Failed publication is not retried automatically.

The acceptance helper is `server/testsupport/nativecheck`. Configuration arrives only on stdin. Output contains booleans, counts and hashes, without passwords, real target IPs or raw terminal output. Owned temporary test data is cleaned and compact reports stay in ignored `.cache/qa-reports/`.
