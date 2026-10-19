# SSH Command Filters

> [中文](./COMMAND-FILTERS.md) | English

Policy administration, terminal review, and SSH-job review use `command_filters.manage`, `reviews.command.manage`, and `jobs.review` separately. Command policy still applies to global connection roles. See [RBAC.en.md](./RBAC.en.md).

This document describes current command-filter ACL rules, matching order, and PTY parsing limits. The competitor is JumpServer Enterprise; this feature is one part of the project's phased parity work.

## Rule configuration

Administrators manage rules in **Settings → Command Filters**. Each rule has a name, user or group scope, asset or node scope, SSH account, match type, command pattern, allow/deny/review action, priority, and active time window.

- User, group, asset, and node scopes may be left empty to mean any. A rule cannot specify both a user and a group or both an asset and a node.
- A node rule applies to the node and descendant assets. Account `*` matches the SSH account configured on the asset; any other value is an exact account match.
- Match types are exact command, contains text, and Go RE2 regular expression. Patterns are limited to 256 bytes.
- Optional `directory_match` and `directory_pattern` scope commands to a remotely verified starting directory. Unverified terminals conservatively deny matching directory-scoped commands. Priority and first-match semantics remain unchanged.
- Priority ranges from 0 to 9999. Lower numbers run first; ties use creation time and ID for stable ordering. The first matching rule decides. Unmatched commands are allowed.
- Active time windows are inclusive at the start and exclusive at the end. No start means immediately; no end means no expiry.
- The `review` action holds command submission for an administrator decision in **Settings → Command Review**. Approval submits Enter to the remote PTY; denial sends Ctrl+C to clear the pending line. Unresolved requests are denied after five minutes.
- Active rules apply to matching user/group, asset/node, and account scopes. Unknown terminal input is denied when any active rule applies, because the gateway cannot prove that the input does not match a rule.

The REST management API is `GET /api/v1/command-filters`, `POST /api/v1/command-filters`, and `DELETE /api/v1/command-filters/{filterID}`. Only administrators can use it. Standalone mode stores rules in `command-filters.json`; cluster mode uses the shared PostgreSQL state document.

## PTY enforcement and audit

Web SSH and `jms ssh` use the same server-side SSH gateway. At session creation, the server builds the rule scope from the authenticated identity, user groups, asset-node ancestors, and SSH account. The gateway checks recognized input when Enter is submitted. For a denial, it inserts Ctrl+C before Enter to clear the pending command line in the remote PTY and sends the matched rule name to the WebSocket client. For review, command text may appear in the remote terminal, but Enter is withheld and subsequent input is discarded while the request is pending. Approval submits Enter; denial or timeout sends Ctrl+C. The encrypted command audit stores separate request and resolution events, correlated by review ID and including the reviewer. An allow or approval decision does not prove remote execution succeeded.

The administrator queue is `GET /api/v1/command-reviews`; resolution uses `POST /api/v1/command-reviews/{reviewID}/approve` or `/deny`. These routes are administrator-only and list only in-memory requests for active sessions. Disconnect cancels a request. Pending requests are not restored after a process restart; when command audit is read, orphaned pending records for inactive sessions are presented as cancelled.

## Current limits

Current regex rules match command input text, not directory permissions. [Controlled execution directories](./EXECUTION-DIRECTORIES.en.md) are connected to single-command Web jobs and `jms exec`, including exact/subtree/full-path RE2 rules and approval binding. Complete interactive cwd proofs remain outstanding. Trusted working directories and resolved paths need a remote Agent or controlled execution channel together with account permissions. A terminal prompt, `PWD` value or inferred `cd` history cannot be the sole security authority.

Optional [SSH execution workspaces](./SSH-WORKSPACES.en.md) use a native helper and Linux kernel confinement for whole-tree content access. They compose with command filters without replacing exact/regex directory command rules.

Filters operate on interactive PTY input bytes and recognize common shell prompts and input lines. They do not parse a shell AST or prove command execution semantics. Custom prompts, terminal applications, nested shells, compound commands, aliases/functions, multiline paste, and nonstandard key sequences can cause conservative denials or incomplete recognition. Rules do not constrain direct SSH connections that bypass the bastion. Command results/exit codes and full shell semantics are not implemented.
