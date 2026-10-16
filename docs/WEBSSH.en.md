# Web SSH and Agent CLI

> [中文](./WEBSSH.md) | English

SSH key installation, verified rotation, opt-in seven-day scheduling and persistent staged recovery are described in [SSH key rotation](./SSH-KEY-ROTATION.en.md).

Targets and gateways support imported SSH private keys with write-only input, vault encryption, public fingerprints and verified history restore. Password rotation remains password-specific. See [SSH private keys](./SSHKEYS.en.md).

SSH gateway routing supports up to three pinned hops across monitoring, Web SSH, CLI, SFTP, jobs and password rotation. Configuration and encrypted credentials support standalone and PostgreSQL single-active HA; see [SSH gateways](./GATEWAYS.en.md). Full Enterprise parity remains in progress.

Sessions remain owner-scoped by default. Global session, replay, command-audit, and termination access use separate [RBAC permissions](./RBAC.en.md); reading audits does not grant connection or termination.

This document describes the SSH bastion slice delivered so far in Phase 4. The competitor remains JumpServer Enterprise. This slice prioritizes standalone deployment and does not claim full Enterprise parity.

## Current capabilities

- Noninteractive Agents can use `jms exec` or Workbench for single commands with stdout/stderr, exit codes, review, timeouts, cancellation, and encrypted audits. See [JOBS.en.md](./JOBS.en.md). PTY parsing limitations below apply to interactive SSH sessions.

- The asset list's **Connect** action asks the server to read the encrypted asset credential and open an SSH PTY. The remote password is never returned to the browser.
- Assets with login review enabled wait for administrator approval before the SSH PTY opens; Web SSH continues automatically after approval. See [ACCESS-REVIEWS.en.md](./ACCESS-REVIEWS.en.md) for the CLI flow and limits.
- The asset list's **Files** action uses a server-side SSH/SFTP channel with the pinned host key to browse the remote account's home directory, create folders, upload, download, and delete files. Credentials stay on the server. Paths stay below the initial SFTP directory, symbolic links are not followed, and each transfer is limited to 1 GiB.
- File operations append to `JMS_DATA_DIR/file-transfers/index.jsonl`. Administrators can query all records; operators can query only their own. Cluster nodes must share this audit directory.
- The browser and server exchange terminal binary frames and resize messages at `/ws/api/v1/sessions/{sessionID}/terminal`. The browser uses a single-use ticket that expires after 30 seconds; the ticket is sent as a WebSocket subprotocol, never in the URL.
- The agent CLI uses the same session API and WebSocket route. It needs only an asset ID and accepts no remote SSH password argument.
- The SSH host key must match the asset's pinned SHA256 fingerprint.
- The SSH inventory also shows host latency, CPU, memory, root disk, and network throughput. See [SSHMONITOR.en.md](./SSHMONITOR.en.md) for collection details and limits.
- Session start and end events append to `JMS_DATA_DIR/sessions/index.jsonl`. Asciinema v2 gzip recordings are stored as `.json.gz.enc` files encrypted with the local vault key.
- A session in the Audit page can open its **Commands** view. `GET /api/v1/sessions/{sessionID}/commands?limit=50&offset=0` is readable only by administrators or the session owner. Records are AES-GCM encrypted with a per-session key derived from the vault key and stored in `JMS_DATA_DIR/sessions/commands.jsonl`; cluster nodes must share this directory. Input is forwarded to the remote SSH PTY only after its audit record is written and synced successfully.
- Capture recognizes single-line input submitted with Enter at common shell prompts. Input at recognized password/passphrase prompts is omitted; common `--password` arguments, credential environment assignments, `sshpass -p`, database `-p...`, and URL user credentials are redacted. Custom prompts, interactive applications, multiline/pasted input, and arrow-key editing may not be captured; unrecognized secret formats may pass through. A record means a command line was recognized as submitted, not that the remote command succeeded, what it returned, or that command control is complete.
- Administrators can create allow/deny/review rules in Settings → Command Filters and scope them by user or group, asset or node, SSH account, and time window. Match types are exact command, contains text, and regular expression. Lower priority numbers run first; the first matching rule decides, while unmatched commands are allowed. For a review rule, command text may appear in the remote terminal, but the gateway withholds Enter until an administrator approves it in Settings → Command Review. Denial or a five-minute timeout sends Ctrl+C to clear the pending line; further input is discarded while the request is pending. Request and resolution events are written separately to the encrypted command audit.
- Filtering parses PTY input lines rather than a shell AST. Custom prompts, nested shells, terminal applications, shell functions/aliases, compound-command semantics, and every terminal key encoding are not fully covered. Do not treat it as a general control over direct connections outside the bastion. Review only controls submission of a recognized single-line command; it does not provide command results or exit codes. Disconnect cancels a pending review. The queue is in-memory and is not restored after restart; orphaned pending audit entries are presented as cancelled when read.
- The Audit page lists sessions newest first and refreshes every 10 seconds. Administrators can view all sessions; operators can view only their own. An operator or administrator can stop an active session or replay its completed recording.
- After local sign-in, the server resolves the operator from the validated Bearer session and records the user ID/name with session start/end events. Clients cannot forge this identity in the session creation request.
- `GET /api/v1/sessions?limit=50&offset=0` lists sessions (all for administrators, owned sessions for operators), `DELETE /api/v1/sessions/{sessionID}` stops an active session (owner or administrator only), and `GET /api/v1/sessions/{sessionID}/replay` returns a decrypted asciinema v2 gzip stream (owner or administrator only).
- Playback renders remote output only; it never injects recorded input into a terminal. The browser limits a recording to 64 MiB compressed and 128 MiB expanded, with play/pause, restart, and 0.5×–4× speed controls.

## Run locally

Start the server in one terminal:

```powershell
cd server
$env:JMS_ADDR = '127.0.0.1:8080'
go run ./cmd/server
```

Start the frontend in another terminal:

```powershell
cd web
$env:VITE_API_TARGET = 'http://127.0.0.1:8080'
pnpm dev
```

Add an SSH host in the inventory and choose **Connect**. The CLI requires an interactive terminal:

```powershell
cd server
$env:JMS_SERVER_URL = 'http://127.0.0.1:8080'
go run ./cmd/jms ssh <asset-id>
```

For remote deployments, use an HTTPS entry point and provide `JMS_ACCESS_KEY_ID` and `JMS_ACCESS_KEY_SECRET` (or the existing `JMS_TOKEN`) through a secret manager; do not put credentials in command-line arguments. AccessKey signs the session API with HTTP Message Signatures; the WebSocket then receives only a short-lived, single-use session ticket. When the server listens on a non-loopback address, `JMS_ADMIN_TOKEN` must be at least 32 bytes and protects the asset and session-management APIs.

## Authorization and remaining work

Administrators can manage assets, grants, and all sessions with a local account session or `JMS_ADMIN_TOKEN`. Operators need an active `connect` grant assigned directly or through a group for the asset's configured SSH account to create a session; grants can target one asset directly or a node and inherit to descendant assets. `view` grants allow access to inventory and monitoring only. Operators can view, stop, and replay only their own sessions. Administrators can create users, groups, and asset nodes and maintain grants in Settings → Access Control.

Recording files are authenticated and encrypted at rest; the replay API and Audit page are available. The audit index records both the SSH asset account and validated operator identity. Sessions without an end event are marked interrupted after a process restart and cannot be replayed. File transfers and recognizable command lines have separate audit indexes; command audit shows allow/deny/review decisions and the matched rule. Filtering remains limited by PTY line parsing; command results/exit codes and full shell semantics remain outstanding. See [AUTH.en.md](./AUTH.en.md), [SFTP.en.md](./SFTP.en.md), [COMMAND-FILTERS.en.md](./COMMAND-FILTERS.en.md), and [SSHMONITOR.en.md](./SSHMONITOR.en.md).
