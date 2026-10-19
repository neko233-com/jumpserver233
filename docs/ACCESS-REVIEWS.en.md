# SSH/SFTP Login Review

> [中文](./ACCESS-REVIEWS.md) | English

Login-review management can be delegated with `reviews.login.manage`. Global connection permissions still require review unless `login_review.bypass` is assigned. See [RBAC.en.md](./RBAC.en.md).

Login review is an enterprise-parity slice. It adds a second check on top of existing asset grants: an operator must have the `connect` or `sftp` grant required by the requested access method, and an administrator must approve access when review is enabled on the asset.

## Configuration and flow

- An administrator enables **Require administrator review for SSH and SFTP login** in the SSH asset editor. Administrators bypass the review queue.
- An operator starts access from Web SSH, `jms ssh <asset-id>`, or the SFTP file manager. The server checks the matching grant first. Configured workspaces prepare/check a helper and directory identity through a pinned management connection; no operator PTY, user command or file access starts while approval is pending.
- An administrator reviews the requester, asset, account, workspace path, request time and expiry in **System Settings → Login review**, then approves or denies it.
- After SSH approval, the operator client reads its review state and retries automatically. The one-time permit is bound to the operator, asset, and SSH account and can be consumed once within 60 seconds. A failed connection cannot reuse it.
- After SFTP approval, the file manager consumes the one-time permit through `POST /api/v1/assets/{assetID}/files/session` and receives a 30-minute browser session token. The token is bound to the operator, asset, and SSH account; only its digest is stored server-side, and closing the file manager revokes it. Every SFTP file endpoint validates this token.
- Requests expire after five minutes. Denied or expired requests do not create sessions. Repeated requests for the same operator, asset, and account reuse the current pending request.

## Connection and directory binding

New SSH/SFTP reviews also bind the asset/account configuration, credential revision, complete gateway chain and workspace policy snapshot. A changed configuration or credential revision creates a new request; old approvals cannot authorize the new target. Workspace reviews additionally bind a digest of the remote boot ID, filesystem device, inode and creation time. Ordinary file changes preserve root identity; directory replacement or host restart requires approval again.

Ordinary SSH jobs, including `jms exec`, batches and Playbook SSH steps, also retain the connection snapshot. Login/command-reviewed workspace jobs pin root identity at submission and persist the proof encrypted. Execution and manual approval recheck current grants/configuration; real execution starts with the retained proof. Repeated request IDs return the original job without executing again, and missing context binders fail closed. Fixed plugin/account-discovery/account-management operations retain their separate authorization. See [SSH jobs](./JOBS.en.md).

The 30-minute SFTP token retains the same configuration binding and directory proof. Every file API checks current grants/configuration; the real channel starts with the retained proof. A mismatch returns `428`; reopen the file manager. The native helper holds a directory FD opened without symlinks, checks identity before confinement, and uses that same object for cwd and the Landlock grant.

The internal canonical `request_scope` and displayed `workspace` path are not credentials. Legacy unscoped records remain readable; new SSH/SFTP requests do not consume unscoped permits. Tokens remain digest-only and process-local. Directory proofs require a trusted remote kernel and filesystem birth-time support through `statx`; missing capabilities fail closed. This authorizes the workspace root object. Ordinary exec adds a `cx2-` context binding the verified starting-directory object and current command policy. Complete interactive cwd proof remains open. See [controlled execution directories](./EXECUTION-DIRECTORIES.en.md).

## API and storage

- `POST /api/v1/sessions` returns `202 Accepted` with a `review_id` when approval is required; no SSH session exists yet.
- The SFTP file manager first calls `POST /api/v1/assets/{assetID}/files/session`. Pending approval returns `202 Accepted` with a `review_id`; retry after approval returns `201 Created` with a short-lived `session_token`. When review is disabled, the endpoint returns `200 OK` and existing `sftp` grant checks remain in effect.
- Reviewed SFTP file requests must include `X-JMS-SFTP-Session`. The token is kept in process memory and expires on service restart or HA takeover; operators must reopen the file manager and request approval again.
- Administrators can list pending requests with `GET /api/v1/access-reviews` and resolve them with `POST /api/v1/access-reviews/{reviewID}/approve` or `/deny`.
- The requester can read their own state with `GET /api/v1/access-reviews/{reviewID}`. Other operators receive `404` for that ID.
- Standalone mode writes `JMS_DATA_DIR/access-reviews.json` with file permissions `0600`; cluster mode writes the PostgreSQL `access-reviews` JSONB document. Pending requests and reviewer identity survive process restart or active-node failover.
- Resolved records are retained for seven days. Records contain requester, asset, SSH account, request and review times, and reviewer identity. They contain no passwords, terminal tickets, or SSH credentials.

## Current limits

- Review protects Web SSH, Agent CLI, and SFTP file-manager access. The SFTP token is a short-lived browser-session authorization and never returns the SSH password to the browser.
- Login review is an additional check after a `connect` or `sftp` grant; it does not grant access to an otherwise unauthorized user.
- The permit is consumed before the server opens the SSH session. If SSH connection setup fails, the operator must request and receive approval again.
- Standalone is the default deployment. Cluster mode relies on shared PostgreSQL documents and the existing single-active election; in-memory SFTP browser tokens expire on failover and must be reissued. Production failover drills remain outstanding.
