# Native SSH / SFTP entry

> [中文](./NATIVE-SSH.md) | English

## Scope and status

Web remains on 8180, with SSH/SFTP embedded on 2222 in the Go process and no system sshd or external proxy. Unified verification followed the complete implementation. Official v0.3.0 was released and upgraded once on the intranet. [BuildWorld #7 (1014)](http://192.168.110.42:8080/builds/1014) passed 6/6 stages in 4m43s. New acceptance: **8/8**; existing mini checklist: **12/12**.

| Acceptance item | Current state |
|---|---|
| root/root platform login, TOTP and denial policies | Integration passed; live Web/SSH login passed before and after restart |
| Case insensitive title, desc and IP search, multiple terms and pagination | Automated checks and live searches across all three fields passed |
| Native PTY, resizing, returning to the menu and reconnecting | Integration and real Linux relay/menu return passed |
| Shared command blocking, approval, one-use consumption, directory proof, replay and actor audit | Real OpenSSH integration, race and existing policy regressions passed |
| Authorized account directories, atomic upload, direct download, rename and deletion | Live 55,296-byte round trip matched SHA-256; repeat and cleanup passed |
| Revocation, changed connection bindings, traversal and symlink denial | Integration and real OpenSSH fixtures passed |
| Data retention, stable host fingerprints and maintenance draining | Real macOS upgrade, graceful restart and reconnect passed |
| Docker, native and intranet acceptance, single publication and idempotent cleanup | Docker, six archives, native Mac 34/34, one release and cleanup passed |

## Evidence and boundaries

The running artifact uses release commit `0f4582783e2cae2e48c7a2b841fc0a4634099d30`; deployment configuration is `d0c30aa856a76a0ff539b31535f18bbb7a955ae8`. The official arm64 archive is 28,064,206 bytes, SHA-256 `b437731e9f4971d9b2f38354d1f0db656f8a3166479216f86e862283f8b844a1`. Both ends verified it before installation, without rebuilding or patching the artifact on the node.

Backend, race, external integrations and Docker passed in [full CI](https://github.com/neko233-com/jumpserver233/actions/runs/39629822885). The new browser case initially used a monitor-only fixture; replacing it with the existing pinned OpenSSH fixture passed [repair CI](https://github.com/neko233-com/jumpserver233/actions/runs/39632479703). The production browser baseline passed 69 cases; the repaired case passed 1/1 separately. The historical failing run remains recorded as failed. The full Windows Go baseline had 2078 passed, one failure and 134 skips. After repairing the normal listener-close result, 42 affected cases passed repeatedly and the complete backend CI passed. Vet, builds, bilingual content, 53 cleanup-tool tests, six platform archives and isolated Docker browser checks passed.

Live default Web/SSH login, real Web SSH, native search/SSH/SFTP, Linux CPU/memory/disk/network metrics and restart retention passed. Existing assets, all previous audit IDs, stored credentials and the Vault key survived; the SSH host fingerprint stayed unchanged. The acceptance helper now normalizes real-shell CSI/CRLF output with six matching cases; this changes QA tooling only. Sanitized reports and essential screenshots remain, while owned test data and temporary artifacts are removed. Business audit records remain as required evidence.

TOTP, revocation, approvals, replay rejection and directory denial are supported by automation and real OpenSSH fixtures; production accounts and policies were not modified for acceptance. All six archives were built; actual execution evidence covers Windows, Linux fixtures and macOS arm64, without claiming device acceptance on every platform.

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
