# Trusted submission directories for interactive SSH

> [中文](./INTERACTIVE-DIRECTORIES.md) | English

With a Linux [SSH workspace](./SSH-WORKSPACES.en.md), Web SSH, `jms ssh` and shared controllers use the same native helper to obtain a kernel-confirmed cwd for recognized single-line submissions. Exact, subtree and RE2 directory rules and approval checks reuse existing command policy. Code, Testify cases and native browser entrypoints are authored; **unified verification has not run**.

## Native channel

The server reuses the host-key-pinned, digest-verified, content-cached `jms-agent` and starts `workspace-terminal`. The SSH channel has no outer PTY. The helper creates an inner PTY; its child enters the existing Landlock/seccomp workspace before executing `/bin/sh`. No daemon, listener, remote package dependency or public WebSocket message type is added.

A dedicated supervisor wraps PTY output in data frames and exchanges requests, proofs, commits and aborts in private control frames. Printed prompts, `PWD` and frame-shaped output cannot generate proof. Browser and CLI requests cannot supply proof fields. Public authentication, `X-JMS-ORG`, terminal frames and replay formats retain their contracts.

## Measurement and commit

For input containing Enter, the server requests a one-use lease. Only the original single-threaded shell can supply proof: it must own the foreground PTY process group, retain the expected stdin device and be interrupted in a restartable `read(0)`. The supervisor thread uses its own ptrace relationship to stop the child and checks registers plus an empty input queue, preventing an earlier queued `cd` from lending its old directory. See Linux [`ptrace`](https://man7.org/linux/man-pages/man2/ptrace.2.html), [`proc_pid_syscall`](https://man7.org/linux/man-pages/man5/proc_pid_syscall.5.html) and [`waitid`](https://man7.org/linux/man-pages/man2/waitid.2.html).

While stopped, the helper opens the actual `/proc/PID/cwd` object and verifies the canonical path, root and directory identities through root-relative `openat2`/`statx`. Proof must match the pinned asset workspace. The confined shell cannot access supervisor procfs, use ptrace, create a separate process sharing cwd, call `setsid` or inject terminal input to replace this boundary.

The server evaluates policy, commits encrypted audit and rechecks session/controller authorization while the shell remains stopped. Before writing, the helper rechecks the directory object, foreground group and queue, then resumes the shell after writing. Repeating an identical commit returns its receipt without writing again. Changed payloads, protocol errors, unknown receipts and leases exceeding five seconds close the terminal instead of replaying uncertain execution.

Only one recognized submission, at most 2048 bytes, receives proof from an input packet. Multiline paste, foreground applications, replaced executables, multithreaded shells, unmeasurable directories and unsupported targets remain unverified; applicable directory rules deny conservatively. Existing priority and explicit-rule ordering remain. A shell's password-looking prompt neither records secrets nor bypasses applicable policy.

## Approvals, sharing and audit

Approval retains its existing five-minute deadline without freezing the shell for that duration. Initial submission holds Enter while preserving pending text, then releases the short lease. Approval acquires new proof and rechecks the original object, current rules and authority before Enter. Replacement, rename, policy changes, revocation or lost control deny approval. Replaying an approval retains existing one-time refusal semantics.

Shared controllers use the same input path and both owner and controller policies. Normal submission and approval recheck access before writing. Encrypted command audit stores proof; authorized command lists additionally expose `working_directory` and `directory_verified`. The bilingual UI labels this a kernel-verified submission directory. Historical records lack these optional fields and remain readable.

## Supported boundary

Interactive proof describes the **original shell's cwd at input submission**. Controlled exec proof describes the **command's starting cwd**. Neither interprets command text as file-access ACLs nor proves later directory changes inside functions, aliases, scripts, signal handlers or descendants. Workspace and host-account permissions retain the file-access boundary; resource quotas require separate configuration.

Native targets are Linux amd64/arm64, requiring existing Landlock ABI 3, `openat2`, birth-time directory identity, PTY, procfs, pidfd and own-child ptrace support. LSM/container refusal does not automatically change sysctls or elevate capabilities. Unverified submissions retain conservative directory-policy handling. SSH without a configured workspace retains its ordinary path and cannot claim trusted cwd.

## Authored unified verification entrypoints

- Testify: private framing, short/truncated writes, proof validation, one-use receipts, no resend after lost acknowledgement, forged output and timeout teardown.
- Native Linux: real cwd, forged PWD, queued `cd`, same-name replacement, foreground-program refusal, stopped-child shutdown and repeated cleanup; syscall fixtures cover shared cwd/FD and `setsid` refusal.
- Gateway/API: single-line audit, multiline refusal, secret-looking prompts, replacement/approval replay, shared-controller current policy and public JSON proof refusal.
- `scripts/interactive-directories-qa.mjs` reuses the native-package SSH/API/artifact fixture for exact/subtree/regex decisions, real approvals, replacement and audit. Existing bilingual browser entrypoints check trusted-directory refusal without another stack or additional screenshots.

Run these entrypoints with full verification only after all 42 groups are authored. Cleanup repeats session/rule/strictly scoped temporary-path removal and retains existing container ownership checks and report retention. This source batch adds no passing, performance or size claim.
