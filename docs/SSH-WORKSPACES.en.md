# SSH execution workspaces

> [中文](./SSH-WORKSPACES.md) | English

The optional asset `ssh_workspace` confines file access for Web SSH, `jms ssh`, `jms exec` and ordinary SSH jobs. It provides a dedicated directory tree for restricted operators or agents. Empty remains the default for ordinary SSH. JumpServer Enterprise remains the competitor; this does not complete directory-specific command policies.

## Configuration and use

An administrator first creates an existing Linux directory with ordinary remote-account permissions, then enters its absolute path under Assets → Edit → SSH execution workspace, for example `/srv/workspace`. Every path component must be free of symlinks. No directory creation or privilege elevation occurs automatically. Kernel interfaces, system/runtime trees cannot be workspaces.

Asset creation/update accepts a `ssh_workspace` string. Omission during update preserves the policy; empty disables it. Asset management permission is required. Managed accounts inherit the host workspace. Approval/connection bindings include it, invalidating old bindings after changes. Existing grants and command filtering/review still apply.

```sh
jms exec ASSET_ID -- pwd
jms exec ASSET_ID -- 'printf hello > result.txt; cat result.txt'
jms ssh ASSET_ID
```

Operators need no remote password and cannot override the workspace in execution requests. The server installs its embedded digest-pinned native helper through host-key-verified SSH, caches it by content SHA and verifies reuse. It opens no new host port, downloads no remote program and requires no permanent daemon.

## Enforcement

- The helper uses `openat2` to reject path aliases, holds the directory FD and uses the same object for real cwd and Landlock grants. Its subtree permits read/write/execute; fixed OS programs/libraries stay read-only, with only loader cache, timezone and tty/null devices added. Whole `/etc`, other homes, `/proc` and `/sys` are not exposed.
- Landlock ABI 3+ is required for truncation and cross-directory link/move control. Seccomp blocks network sockets, process injection/external signals, namespaces/mounts, io_uring, shared IPC and dangerous device ioctls. Shells, aliases, scripts and descendants inherit restrictions; links inside the tree cannot grant outside content access.
- The environment is replaced with fixed PATH/language/terminal/workspace values. FDs beyond 0/1/2 are closed, capabilities cleared and `no_new_privs` set. Root cannot regain implicit capabilities across exec. Unsupported platforms/kernels or verification failures refuse execution without an ordinary-shell fallback.
- SFTP currently lacks the same remote kernel boundary and is explicitly disabled. Workspace assets cannot serve as SSH/discovery gateways, preventing forwarding/file-channel bypasses.

This confines file content access without hiding all path metadata. It is not a full container or CPU/memory/process-count quota. `cd` may traverse other directories without gaining content permissions. OS programs/libraries are explicit read-only exceptions and must not contain business secrets that need isolation. The policy grants an entire subtree without excluding individual descendants.

Ownership, mode, timestamp and xattr changes not mediated by Landlock are globally denied by seccomp, including inside the workspace. Tools requiring these operations may fail; enforcement is never silently weakened. External process resource changes are also refused.

Fixed password rotation, monitoring, plugin and remote-account administration use separately authorized management channels and may need outside access; they do not expose arbitrary scripts to ordinary execution requests. Host administrators and direct SSH access outside the bastion are outside this boundary. Use dedicated remote accounts and restrict other login paths.

## Remaining scope

Kernel restrictions apply when the helper starts and cannot retrofit running unconfined processes. Drain old sessions/jobs and stop residual processes under host policy before enabling confinement; configuration edits cannot confine old processes retroactively.

Exact/regex directory command policies, trusted-directory approval binding, confined SFTP and resource quotas remain pending. Command-text regexes are not filesystem permissions, and workspaces do not establish complete Enterprise acceptance. See [testing](./TESTING.en.md) for evidence and [command filters](./COMMAND-FILTERS.en.md) for existing rules.
