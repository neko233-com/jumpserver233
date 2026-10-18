# SSH Jobs and Noninteractive Agent CLI

> [中文](./JOBS.md) | English

Go native Playbooks provide revisioned workspaces, organization publication, source snapshots, sequential SSH modules, conditions/loops/retries, durable recovery and Web/CLI/SDK. See [Native Playbooks](./PLAYBOOKS.en.md). Full Ansible and Enterprise parity remain in progress.

Host plugins expose structured `jms plugin` operations through the same idempotent jobs, review, owner audit and encrypted output. Authorization is checked during execution. See [host tools and agents](./HOST-PLUGINS.en.md).

Source, weekly-hour and execution-channel restrictions support standalone and single-active HA. See [Access policies](./ACCESS-POLICIES.en.md). Full Enterprise parity remains in progress.

Global job reading, cancellation, review, and plan reading/management support separate [RBAC permissions](./RBAC.en.md). Dispatch checks current roles; personal templates stay private. Administrative operations described below can also be delegated with their specific permissions.

Workbench at `/workbench` submits single and batch SSH commands, manages personal templates and one-time or recurring plans, displays stdout/stderr and exit codes, cancels execution, and reviews commands. The Agent CLI uses the same single-command server path without a TTY. It never accepts or retrieves the remote SSH password.

```powershell
# JMS_TOKEN is a platform short-lived Bearer token; existing AccessKey variables also work.
$env:JMS_SERVER_URL = 'http://127.0.0.1:8080'
go run ./cmd/jms exec <asset-id> --timeout 60 --json -- 'uname -a'
```

By default the CLI writes remote stdout/stderr to the corresponding local streams and the job ID to stderr. `--json` emits the complete result. The compiled CLI preserves remote exit codes 1–255; `go run` wraps child failures, so automation should use a compiled `jms` binary. Timeouts, denials, and transport errors return nonzero status.

## Authorization and audit

- Submission requires `connect` permission for the asset account, including group membership, ancestor nodes, and grant time windows. `view` does not permit execution. Administrators retain existing asset-management access.
- Assets requiring login review use the existing one-use SSH approval. The CLI waits for approval; the browser asks the user to resubmit after approval.
- Command filters apply before execution. Deny records an audit without connecting. Review creates a pending job that an administrator must approve or reject within five minutes. Approval rechecks the original owner's current grant, asset account, and command policy.
- When scoped filters apply, shell composition, substitution, redirection, and similar operators are conservatively rejected. Rules match the submitted string; they do not parse a remote shell AST or prove alias/script behavior.
- Commands and results are AES-GCM encrypted with the Vault key in `ssh-jobs.json`, or in the PostgreSQL `ssh-jobs` document in cluster mode. The initial audit must persist before execution. Only the owner and administrators can read results. Command output can contain sensitive business data; arbitrary output is not automatically redacted.
- Clients generate a `request_id`. Repeating the same request for the same user returns the existing job; different parameters with the same ID return 409. Remote commands are never retried automatically.

## Resources and failure behavior

- Default execution timeout is 60 seconds, configurable from 1 to 300. Combined stdout/stderr capture is limited to 64 KiB; additional output is drained and discarded.
- At most eight jobs run globally and two per user. Each user can have 20 pending reviews. The store holds 1000 audit records; new jobs are refused at capacity, without silently deleting old audits.
- Cancellation, timeout, or node shutdown closes the SSH transport. Detached remote descendants may continue; verify them separately when needed.
- Restart or HA takeover marks unfinished jobs interrupted without replay. A node that loses its election lock stops writing job documents. Failure to persist the final audit reports `audit_unavailable`; verify the remote outcome before retrying.
- Current coverage includes SSH jobs, batch dispatch, templates, and interval schedules. Full Ansible and other ticket types remain open; cron/calendar scheduling is described in [Calendar schedules](./SCHEDULING.en.md); access tickets and external notifications are covered in [Access tickets](./ACCESS-TICKETS.en.md) and [Notifications](./NOTIFICATIONS.en.md).

## Batches, templates, and schedules

Expand “Batch commands and schedules” in the workbench, select 1–50 authorized hosts, and create an immediate batch, future one-time plan, or recurring interval plan. Intervals range from 60 seconds to 31 days. The page accepts browser-local time and converts it to UTC. Templates belong to their creator and require the current `revision` for updates/deletion. Plans snapshot the command, timeout, and template revision; editing or deleting a template never changes an existing plan.

- Each host creates an independent encrypted job using the same current identity, `connect` grants, login review, command policy, capacity, and audit checks. Authorization is checked both at creation and actual dispatch. Revoked hosts are not connected. Administrators can inspect all plans and runs; operators only see their own. Personal templates remain private even from other administrators.
- Only definite capacity rejection and pending login review are retried. Login approval resumes dispatch; denial/expiry terminates that target. Command review uses existing job details. Duplicate requests and capacity rejection do not consume additional login permits.
- Recurrence uses dispatch time plus the interval. Missed occurrences coalesce into one; an active run or review causes the next occurrence to be skipped. Pause affects future occurrences. Cancel stops undispatched targets and requests cancellation of existing child jobs.
- A target claim must persist before dispatch. After restart/HA takeover, claimed targets only link an existing job with the same request ID. Ambiguous dispatches become interrupted and are never replayed. Unclaimed targets continue after current authorization checks.
- Templates, plans, and run indexes are encrypted with Vault-key AES-GCM in local `operations.json` or the PostgreSQL `operations` document for single-active HA. A former leader stops dispatch and writes. Limits are 500 templates, 1000 plans, and 1000 runs. Full history pauses due plans without removing audits. Child jobs also have a separate 1000-record audit limit.

## API

`POST /api/v1/ops/jobs` accepts `{asset_id, command, timeout_seconds, request_id}`. List with `GET /api/v1/ops/jobs?limit=50&offset=0`, inspect with `GET /api/v1/ops/jobs/{id}`, and cancel with `DELETE /api/v1/ops/jobs/{id}`. Administrators review through `POST /api/v1/ops/jobs/{id}/review` with `{approve: true|false}`. Pending login approval returns 202 with `review_id`; job creation returns 201.

Templates: `GET/POST /api/v1/ops/templates`, `PUT /api/v1/ops/templates/{id}`, and `DELETE /api/v1/ops/templates/{id}?revision=N`. Create/update fields are `{name, command, timeout_seconds, revision}`.

Plans: `GET/POST /api/v1/ops/plans`. Create fields are `{name, asset_ids, command, timeout_seconds, kind, request_id}`. With `template_id`, omit `command`. Kind is `batch`, `once` (requires future `run_at`), `interval` (requires `interval_seconds`, optional future `run_at`), or `cron` (five-field `cron_expression` and explicit `timezone`). `PUT /api/v1/ops/plans/{id}` with `{enabled: true|false, revision: N}` pauses/resumes unfinished plans.

Runs: `GET /api/v1/ops/runs?limit=50&offset=0`, `GET /api/v1/ops/runs/{id}`, and `POST /api/v1/ops/runs/{id}/cancel`. Each target exposes `state`, `job_id`, `review_id`, or `error_code`. Job details contain actual output.

## Automated verification

Testify cases cover template ownership/revisions/snapshots, encryption, local and PostgreSQL recovery, capacity queuing, batch cancellation, missed occurrences, overlap prevention, claim recovery without replay, grant revocation, both reviews, and former-leader write rejection. Set `JMS_TEST_DATABASE_URL` and run `go test ./...`; Linux CI runs the complete `go test -race ./...` suite. `pnpm test:e2e` uses isolated temporary data and a real synthetic SSH server to cover two-host batches, scheduled template snapshots, recurring pause/resume, bilingual UI, and view-only denial. HA integration verifies retained login sessions, templates, and future plans after takeover.
