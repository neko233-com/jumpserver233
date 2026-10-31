# Native SSH / SFTP entry

> [中文](./NATIVE-SSH.md) | English

`deployment-host.invalid` in commands is a placeholder; obtain the actual address from the organization's private configuration.

## XTerminal compatibility and terminal UI maintenance

**v0.3.2 is published and upgraded once; the table workbench passed 6/6 gates.** BuildWorld #9 (1041) passed six stages and 34/34 native Mac cases in 2m51s. [Full CI](https://github.com/neko233-com/jumpserver233/actions/runs/39746482439) passed six jobs and 70/70 production browser cases. Default login, real Web/native SSH, search across all three fields, return to menu, a 55,296-byte SFTP round trip and removal passed. Three CPU/memory/disk/network samples passed both before and after the graceful restart; the host fingerprint remained stable. The original asset, 14 pre-upgrade audit IDs, 16 pre-restart audit IDs, Vault key and stored credentials survived.

Running source: `6e717232c607a6b2661ae4a189cd3272e5469a1d`; deployment pin: `222cc8f79599551801bd01c0f84fdff70a21e1d9`. The official Mac ARM archive is 28,138,076 bytes, SHA-256 `cbed946bf190743058594d9fb2536e77fce9b6d83deddf731c03099aae8d77b6`. Compact receipts and the successful-build capture are ignored under `.cache/qa-reports/native-workbench-live-20261022/`; implementation and visual evidence are in neighboring `native-workbench-20261022/`. Browser acceptance used the authorized in-app browser; XTerminal was not driven through native application UI automation.

### Previous v0.3.1

v0.3.1 is published and upgraded once: BuildWorld #8 (1022) passed six stages and 34/34 native Mac cases. [Full CI](https://github.com/neko233-com/jumpserver233/actions/runs/39735942366) passed six jobs and 70/70 production browser cases. Local Linux race, isolated Docker and three samples from the actual XTerminal scripts passed. Live root/root, Web/native SSH, a 55,296-byte file round trip and repeated post-restart acceptance passed. The original asset, all 11 pre-upgrade audit IDs and 13 pre-restart audit IDs, credentials, Vault key and host fingerprint survived.

The running source is `d4a2fb7eec694ba453285bb12c0151bb9baee874`; deployment is pinned to `8108be93a8f58cda8191fe1098233dd9c16ec99f`. The official Mac ARM archive is 28,104,267 bytes, SHA-256 `6f4ed63129ee76e9251b1d5affe0ba43f8a77face176d9c2425fbcb5867d8734`. The target's existing `.xterminal` differs from the local copy. Acceptance preserved that installation and collected three samples before and after restart without replacing files. The user's screenshot confirms file browsing and monitoring, but rejects menu contrast and interaction and requests a selectable table.

### v0.3.2 table workbench: implementation and intranet acceptance 6/6

Six gates cover table contrast, keyboard selection/live search, asynchronous feedback/cancellation, responsive dimensions, bilingual/paste behavior, and shared authorization/audit regression. A native Go state model and incremental row rendering add no dependencies. Use arrows/Tab to select, Enter to connect, Home/End/PgUp/PgDn to navigate, `/` to search title/desc/IP, and Esc to leave search or clear. `r` refreshes, `m` probes the selected row, `i` shows pinned connection details, `l` changes language, and `q` exits. Number entry and the `TERM=dumb` line interface remain available.

Search filters the authorized inventory locally without API requests per key. Connection still reauthorizes. Loading/refreshing provides feedback and disconnects cancel requests. Resizing immediately rearranges the table; narrow panes move address/account into selected details. Explicit RGB colors keep help readable when clients map ANSI dark gray almost to black. Remote shells use the normal screen; exiting restores the table and selection. Mouse behavior, colors and font settings remain under the SSH client's control.

| Gate | Established evidence |
|---|---|
| Table contrast and selection hierarchy | Text, help and separators meet 4.5:1; actual Go ANSI wide/narrow captures, English rendering and independent visual review passed |
| Keyboard selection, search and return | Go/Testify covers arrows, Tab, paging, numbers, UTF-8 search and preserved selection after exit; real OpenSSH selection/return passed three runs |
| Asynchronous feedback and cancellation | Loading/refresh states, no inventory request per key, disconnect cancellation and shutdown passed; Linux race passed twice |
| Responsive dimensions | 8 widths × 7 heights × two languages: 112 dimension cases; actual SSH window changes passed |
| Languages and safe paste | Language changes, fragmented UTF-8/keys, pasted newlines without connection, and visibility of every shortcut passed |
| Authority, command policy, audit, files and monitoring | File-only access cannot open SSH; review/denial/one-time consumption/revocation regressions passed; real Linux relay, monitoring probe and SFTP passed three runs |

The full backend passed 100 packages, with 2,240 passed and 124 skipped test events including subtests. External database, unrelated protocol and platform skips do not count toward these gates. Go vet/build, frontend lint/build, bilingual checks, and isolated Docker browser/native-entry/restart idempotence passed. English help initially exceeded the shared label limit; earlier wrapping and regression assertions repair it. Narrow-pane expectations and a test password were also corrected. Ignored reports live in `.cache/qa-reports/native-workbench-20261022/`. Captures render actual Go frames; they do not substitute for native XTerminal GUI operation.

The native menu adapts to terminal dimensions and defaults to Chinese. Use `l` in the table, or `en`/`zh` in plain input. Stable IDs and repeated instructions move behind `i`. Selected details show cached CPU/memory/disk/network metrics; sufficiently wide tables also include CPU/memory columns. `m` refreshes the selected host through existing monitor authorization without periodically scanning all assets. `TERM=dumb` retains plain input.

Client exec runs on the selected host through `/api/v1/ops/jobs`, preserving grants, source, pinned connections, directory controls, command denial/review and encrypted history. It never executes bastion OS commands. A single available host binds automatically. For multiple hosts use `platform-user#account-id` (optional `%organization-UUID` suffix) or select through the menu first. Active file/monitor/terminal channels prevent retargeting; open another connection for another host.

Bound SFTP opens the account's authorized root and retains `/<account-id>/...` paths. Absolute home paths map to that same authorized root without expanding workspace boundaries. XTerminal can upload `.xterminal` scripts into its authorized home and invoke them through controlled exec, requiring both upload and command permissions. Custom workspaces must include the home actually used by the client's scripts; otherwise existing boundaries reject access. Unbound multi-host SFTP retains asset-directory browsing. SFTP binds its target when the channel opens. If a multi-host client opens its file pool before menu selection, reconnect as `platform-user#account-id` to align its file and monitor channels.

Connections allow 16 session channels. Unstarted channels expire after ten seconds and invalid startup requests close immediately. Auxiliary exec queues serially per connection to respect backend job capacity. Each execution is audited; the existing 64 KiB output limit remains. Disconnects cancel jobs and revocation prevents further file access or jobs. Raw TCP/Agent forwarding stays denied.

## Historical v0.3.0 scope and status

Web remains on 8180, with SSH/SFTP embedded on 2222 in the Go process and no system sshd or external proxy. Unified verification followed the complete implementation. Official v0.3.0 was released and upgraded once on the intranet. BuildWorld #7 (1014) passed 6/6 stages in 4m43s. New acceptance: **8/8**; existing mini checklist: **12/12**.

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
ssh -p 2222 root@deployment-host.invalid
sftp -P 2222 root@deployment-host.invalid
```

The initial platform identity is root/root. Existing accounts and passwords survive startup and upgrades without reset. This username is not a macOS system account. TOTP uses keyboard-interactive; select it with `ssh -o PreferredAuthentications=keyboard-interactive -p 2222 ...`. Identities requiring initial MFA enrollment, SMS/RADIUS or platform login review continue using the Web flow for those steps; native login cannot bypass them.

The menu defaults to Chinese; `en` selects English. Enter a query or `/query`; space separated terms must all match. Title maps to existing `name`, desc to `remark`, and IP to `host`; accounts are searchable too. Select a numbered entry, `r` to refresh, `m` to refresh the selected host's metrics, `n/p` for pages, `i` for pinned-account connection details, or `q` to quit. Exiting the target shell returns to the menu. `ssh ... connect <account-id>` selects an authorized account directly. Ordinary remote commands use audited jobs on the bound target.

Single-account or bound SFTP opens the remote authorized root. Only unbound multi-host sessions list `server-title--account@stable-account-ID`. Both accept stable `/<account-id>/...` paths that survive title changes. Standard `ls/cd/get/put/mkdir/rename/rm/rmdir` need no additional port. Existing workspace authorization and the remote SFTP home remain boundaries. Cross-account moves, traversal and symlink following are denied. Complete create/overwrite uploads are supported; append, partial in-place modification, file attribute changes and arbitrary TCP/Agent forwarding are unsupported.

Append `%<organization-UUID>` to the SSH username to select an existing organization. Membership and resource isolation still apply. Ordinary standalone users need no organization configuration.

### Sync to local OpenSSH

The asset page offers “Import local SSH config” in an HTTPS secure context on browsers with File System Access. Select the existing `~/.ssh/config` to update its managed block. On intranet HTTP pages where browsers cannot access local files, the page presents the client workflow below and does not claim an import happened.

With the installed `jms` client and an existing platform identity, run `jms ssh-config sync --host <bastion-host> --port 2222`. Set `JMS_SERVER_URL` to the management API and use `JMS_TOKEN_FILE`, `JMS_TOKEN`, or the existing AccessKey authentication; `JMS_ORG_ID` is optional. Add `--preview` to display aliases without writing. Sync reads active SSH accounts with `connect` permission and creates stable aliases in a dedicated managed block in local `~/.ssh/config`. It stores no target passwords and preserves existing configuration. Conflicts or concurrent changes fail closed. Run again to sync changes; an empty inventory never deletes existing aliases.

Connections still require platform SSH authentication and the existing grants, review, and audit. Verify the bastion host key through the normal OpenSSH first-connection flow. Interactive SSH using `platform-user#account-id` enters that account's terminal directly; remote commands and SFTP continue to use the same target.

## Security, performance and cleanup

Login, search and session creation use process-local HTTP pipes and the full existing identity, source IP, rate limit, organization, RBAC, grant, login review and session policy chain. The native entry has no superuser API token. Terminal bytes pass through the existing WebSocket gateway, preserving command reviews, blocking, directory proofs and encrypted replay. SFTP uses a process-local callback that HTTP clients cannot forge to enter the same file authorization middleware. Every read/write packet rechecks access and the connection binding; target credentials stay server-side.

Downloads read directly from remote SFTP handles without whole-file disk caching. Uploads stage in 0600 files inside an owned 0700 directory, with at most two files of 1 GiB each. Incomplete sparse uploads are rejected. Successful commits use the existing remote temporary-file and atomic-rename service. Disconnect, cancellation and failure remove staging without replacing the old file. Normal shutdown removes its temporary directory. Crash recovery only removes explicitly marked, unlocked directories for the same Vault identity. They live in the system temporary directory outside business backups.

The Ed25519 host key is derived from the existing Vault key with a dedicated domain identifier. Restart, upgrade and restore retain the fingerprint with that same Vault key; replacing the Vault key changes it. Limits are 64 clients, 16 channels per client and a 30-second handshake. Active native clients count as maintenance work. Close SSH/SFTP clients before release rather than interrupting existing operations. Failed publication is not retried automatically.

The acceptance helper is `server/testsupport/nativecheck`. Configuration arrives only on stdin. Output contains booleans, counts and hashes, without passwords, real target IPs or raw terminal output. Owned temporary test data is cleaned and compact reports stay in ignored `.cache/qa-reports/`.
