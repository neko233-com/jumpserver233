# Controlled SSH Execution Directories and Command Rules

> [中文](./EXECUTION-DIRECTORIES.md) | English

Single-command Web workbench jobs and `jms exec` can select a starting directory inside a configured SSH workspace. Rules support exact paths, directory subtrees and full-path RE2 expressions; approvals bind real directory objects and the current command policy. Implementation is connected; consult [testing](./TESTING.en.md) for unified acceptance results. The competitor remains JumpServer Enterprise, with full parity still in progress.

## Configuration and use

Configure a Linux asset's [SSH workspace](./SSH-WORKSPACES.en.md), for example `/srv/work`, and create `/srv/work/deploy` on that host. Every directory component must exist without symlinks. Select the asset in the Web workbench and optionally enter an execution directory; empty uses the workspace root.

```sh
jms exec ASSET_ID --directory /srv/work/deploy --timeout 60 --json -- pwd
```

`POST /api/v1/ops/jobs` accepts optional `working_directory`, a canonical Linux absolute path inside the workspace. Jobs retain that request parameter; `execution_directory` identifies the directory actually verified by remote preflight. Assets without a workspace cannot use the parameter. There is no fallback that concatenates a `cd` command. Batch schedules, Playbooks and fixed management operations do not yet expose this parameter.

Command-filter forms add an execution-directory scope through these optional fields:

| directory_match | directory_pattern | Meaning |
|---|---|---|
| Empty | Empty | Preserve existing command-rule behavior |
| `exact` | `/srv/work/deploy` | Match this starting directory only |
| `tree` | `/srv/work/deploy` | Match this directory and slash-delimited descendants, excluding `deploy-other` |
| `regex` | `/srv/work/releases/[0-9]+` | Match the entire starting path with Go RE2 |

Directory patterns are limited to 256 bytes. Exact/subtree patterns require canonical absolute paths. Command matching, user/group, asset/node, account, priority and active windows still determine the first matching rule. Explicit higher-priority allow rules remain effective. Standalone files and PostgreSQL state documents store the same fields.

## Actual directories and approvals

The server prepares a SHA-256-verified native helper through the pinned-host-key management channel. The helper opens a child relative to the held workspace-root FD with `openat2` and `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS`. Terminal prompts, client `PWD` and inferred `cd` history are not authorities. See the [Linux openat2 manual](https://man7.org/linux/man-pages/man2/openat2.2.html) for path-resolution semantics.

Root and starting directories separately bind boot ID, filesystem device, inode and `statx` birth time. Ordinary file writes preserve proofs; directory replacement, unavailable identity capabilities and host restart invalidate old proofs. Execution reopens and checks the FDs, uses that same cwd object for `fchdir`, then starts the confined command. The workspace root still defines Landlock rights for its whole subtree; see the [kernel documentation](https://docs.kernel.org/userspace-api/landlock.html).

New jobs use an internal `cx2-` context containing connection/gateway snapshots, root identity, starting-directory identity and an active command-policy digest. Deleting and recreating a same-name rule changes that digest. Login permits are consumed once for the full context. Command approval retains its submitted context and rechecks current authorization, policy and the remote directory before approval. Authorization is checked again after SSH/helper setup and before sending the operator command. Mismatches refuse execution without an unrestricted fallback.

Authenticated encrypted envelope v6 stores directory fields and proofs; v1–v5 remain readable. Existing `cx1-` SSH/SFTP approvals remain compatible. Legacy ordinary jobs still awaiting command review must be cancelled and resubmitted to bind the current policy. SSH and SFTP approvals remain independent.

The same user's repeated `request_id` with identical parameters returns the original job; a changed execution directory returns `409`. Receipt retries do not reconnect, consume a second login permit or execute another command. Use a new `request_id` when a changed configuration/directory requires a new request. Unverifiable preflight returns `412`, a changed bound object returns `428`, and current permission/policy rejection during approval returns `403`.

## Terminals and limits

Raw PTYs cannot prove each command's cwd. Commands matching directory rules conservatively fail when cwd is unverified, with a notice directing operators to Web jobs or `jms exec --directory`. Human approval cannot turn an unknown directory into a verified one. Unsupported input continues to fail when an applicable rule exists. Shared terminals and Agent CLI receive the same notice.

Rules match the **execution starting directory**, not a file-path access ACL. Commands retain access to the configured workspace; full semantics of shells, scripts, aliases, descendants and later `cd` operations do not gain per-command proof. Authorization follows held objects and does not promise immutable namespace paths during execution. Configure separate workspaces and restricted host accounts for smaller file-access boundaries. Complete interactive cwd proofs, arbitrary shell semantics and resource quotas remain outstanding.
