# SSH execution workspaces

> [中文](./SSH-WORKSPACES.md) | English

The optional asset `ssh_workspace` confines file access for Web SSH, `jms ssh`, `jms exec`, ordinary SSH jobs and Web SFTP. It provides a directory tree for restricted operators or agents. Empty remains the ordinary SSH default. JumpServer Enterprise remains the competitor; this does not complete directory-specific command policies.

## Configuration and use

An administrator first creates an existing Linux directory with ordinary remote-account permissions, then enters its absolute path under Assets → Edit → SSH execution workspace, for example `/srv/workspace`. Every path component must be free of symlinks. No directory creation or privilege elevation occurs automatically. Kernel interfaces, system/runtime trees cannot be workspaces.

The workspace must also be disjoint from the remote account's `~/.jumpserver233` helper cache. It cannot contain or live inside that cache; granting the entire home is refused. The helper itself must stay outside the writable tree, preventing confined execution from modifying future startup programs.

Asset creation/update accepts a `ssh_workspace` string. Omission during update preserves the policy; empty disables it. Asset management permission is required. Managed accounts inherit the host workspace. Access-ticket and SSH-session bindings include it, invalidating old bindings after changes. SFTP login permits authorize a user, asset and account; each new channel enforces the current workspace policy. A permit does not attest a remote directory inode or directory-specific approval. Existing grants and command filtering/review still apply.

```sh
jms exec ASSET_ID -- pwd
jms exec ASSET_ID -- 'printf hello > result.txt; cat result.txt'
jms ssh ASSET_ID
```

Operators need no remote password and cannot override the workspace in execution requests. The server installs its embedded digest-pinned native helper through host-key-verified SSH, caches it by content SHA and verifies reuse. It opens no new host port, downloads no remote program and requires no permanent daemon.

## Enforcement

- The helper uses `openat2` to reject path aliases, holds the directory FD and uses the same object for real cwd and Landlock grants. Its subtree permits read/write/execute; fixed OS programs/libraries stay read-only, with only loader cache, timezone and tty/null devices added. Whole `/etc`, other homes, `/proc` and `/sys` are not exposed.
- Landlock ABI 3+ is required for truncation and cross-directory link/move control. Seccomp blocks network sockets, process injection/external signals, namespaces/mounts, io_uring, shared IPC and dangerous device ioctls. Shells, aliases, scripts and descendants inherit restrictions. Symlinks cannot grant outside target access; creating cross-boundary hard links/moves is denied.
- The environment is replaced with fixed PATH/language/terminal/workspace values. FDs beyond 0/1/2 are closed, capabilities cleared and `no_new_privs` set. Root cannot regain implicit capabilities across exec. Unsupported platforms/kernels or verification failures refuse execution without an ordinary-shell fallback.
- SFTP uses an embedded Go protocol service after kernel confinement and self-exec, so all Go threads inherit that boundary. A sealed memfd briefly carries PID/cwd device/inode metadata and is closed after validation. Invalid startup chains refuse service without falling back to ordinary host SFTP. SSH/discovery gateway use remains disabled.

## Confined file management

Existing `sftp` grants, login reviews, transfer limits and audit still apply. The file manager's `/` represents the configured workspace rather than the host root; its actual path is shown. Protocol handlers additionally use [Go `os.Root`](https://go.dev/doc/go1.24) for file and metadata confinement, without exposing shell runtime-library exceptions to SFTP.

Supported operations include paged listing, download/upload, directory creation, deletion, append and offset reads/writes. Ordinary rename atomically refuses replacement; explicit overwrite uploads use POSIX atomic rename. Link creation, link-target reads and mode/owner/time changes are refused. Web requests still reject traversal/symlinks. Files are created under existing account permissions without elevation, new ports or a separately installed host `sftp-server`.

This confines file content access without hiding all path metadata. It is not a full container or CPU/memory/process-count quota. `cd` may traverse other directories without gaining content permissions. OS programs/libraries are explicit read-only exceptions and must not contain business secrets that need isolation. The policy grants an entire subtree without excluding individual descendants.

Existing hard links and content mounted into the workspace are part of its granted scope. Use a dedicated directory without sensitive aliases or mounts. See the [official Linux Landlock documentation](https://kernel.org/doc/html/v6.6/userspace-api/landlock.html) for kernel path-access semantics.

Ownership, mode, timestamp and xattr changes not mediated by Landlock are globally denied by seccomp, including inside the workspace. Tools requiring these operations may fail; enforcement is never silently weakened. External process resource changes are also refused.

Fixed password rotation, monitoring, plugin and remote-account administration use separately authorized management channels and may need outside access; they do not expose arbitrary scripts to ordinary execution requests. Host administrators and direct SSH access outside the bastion are outside this boundary. Use dedicated remote accounts and restrict other login paths.

## Remaining scope

Kernel restrictions apply when the helper starts and cannot retrofit running unconfined processes. Drain old sessions/jobs and stop residual processes under host policy before enabling confinement; configuration edits cannot confine old processes retroactively.

Exact/regex directory command policies, trusted-directory approval binding and resource quotas remain pending. Command-text regexes are not filesystem permissions, and workspaces do not establish complete Enterprise acceptance. See [testing](./TESTING.en.md) for evidence and [command filters](./COMMAND-FILTERS.en.md) for existing rules.
