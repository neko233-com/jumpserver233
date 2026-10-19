# Scheduled standalone installation

> [中文](./INSTALLATION-SCHEDULE.md) | English

A managed native installation can schedule one fixed staged digest, installation revision and time. A foreground supervisor drains work, stops the service, checkpoints encrypted data, runs offline preflight and accepts first startup. Scheduling is opt-in and never changes its target when another release appears. Automatic checks still read published stable Releases; existing commands download and stage packages. Unattended download policies, historical data migrations and cluster updates remain outstanding.

## Start the supervisor

First adopt a native baseline using [controlled installation](./INSTALLATION.en.md). Normal `jms update run` remains available. To execute schedules, use this foreground service-manager command:

```sh
jms update supervise --root /srv/jumpserver233-releases --passphrase-file /run/secrets/jms-update-passphrase
```

- Use an absolute managed root and its bound data directory. The checkpoint passphrase must be in a private regular file; stdin and command-line passphrases are unsupported. Validate the file at supervisor startup, read it again for installation/acceptance and clear buffers afterward.
- Set `JMS_SERVER_URL` to the child's HTTP/HTTPS loopback IP origin, such as `http://127.0.0.1:8080`. Remote addresses, proxies, URL credentials, prefixes and redirects are refused. Existing TLS trust configuration still applies.
- Use a protected `jms auth` identity file or existing platform credential configuration. Every maintenance request requires current global `security.manage`. The supervisor never receives a remote SSH password; revoking its platform identity blocks subsequent control. Keep credentials and checkpoint passphrases out of Git, logs and reports.
- An OS lock permits one supervisor per root and releases on exit. Only its own confirmed child PID is managed; arbitrary PIDs returned by HTTP are never signalled.
- Managed startup binds `JMS_RELEASE_ROOT`. Plain native `run` can display and queue plans, but execution requires `supervise`. The UI shows last reported time without claiming a historical timestamp/PID proves current liveness.
- This flow supports standalone native installation. Docker images and PostgreSQL HA retain their deployment workflows.

## Web and CLI

Settings → Security → Software updates → Scheduled installation. Expand the form, explicitly refresh verified candidates, select a version/digest, local time and maximum drain wait. A candidate must be newer, match the native platform, and declare preflight/activation protocols. Candidate refresh verifies file bytes; status polling does not repeatedly hash executables.

```sh
jms update schedule-status --root /srv/jumpserver233-releases
jms update schedule --root /srv/jumpserver233-releases --sha256 VERIFIED_SHA256 --revision 1 --installation-revision 2 --request-id install-20261020 --at 2026-10-21T02:00:00+08:00 --drain-timeout 60s
jms update schedule-cancel --root /srv/jumpserver233-releases --revision 2 --request-id cancel-20261020 --plan-id PLAN_ID
```

Time may be within the preceding minute or up to 366 days ahead; drain wait is 5–86400 seconds. CLI duration must represent whole seconds. Local scheduling relies on OS file permissions; Web scheduling requires global platform permission. Organization administrators and operators cannot manage global installation.

`/api/v1/settings/security/updates/installation` supports `GET` status, `GET /candidates` explicit verification, `POST` scheduling and `POST /cancel`. Inputs contain `revision`, `request_id`, `installation_revision`, `archive_sha256`, RFC3339 `not_before` and `drain_timeout_seconds`; cancellation contains revision, request ID and `plan_id`. Responses contain no passphrase or platform credentials.

Private `.jms233-schedule.json` stores the plan and latest 100 events/receipts separately from installation transactions. An identical request ID, full original input and actor returns current status. Replaying after cancellation or success never installs again. Changed input/actor, stale new requests, non-new targets and changed installation revisions conflict.

## Execution and failures

1. Recheck the passphrase file, installation revision, staged bytes, platform permission and own child PID. Existing maintenance owned by another operator is not adopted.
2. Persist `draining` and start admission drain using the current instance/revision. Existing SSH and admitted work finish; new sessions/jobs are refused. A `scheduled` or `draining` plan can be cancelled.
3. Timeout/cancellation reopens admission only when the original instance/revision still belongs to this plan. Another operator's decision is preserved. Failure to reopen is recorded for inspection.
4. After readiness, compare revisions and commit `stopping`. Global `POST /api/v1/settings/security/maintenance/stop` requires the same instance/revision, unique request ID and `draining=true`. Unready work, stale revisions and another actor's replay are refused. Persist audit, seal cancellation, flush the response and gracefully stop; receipt replay never repeats the shutdown callback.
5. The supervisor requires confirmed shutdown and waits up to 30 seconds for its own child to exit. Without both, installation does not proceed. The [installation transaction](./INSTALLATION.en.md) then takes the data OS lock, checkpoints, preflights, selects and starts the gated candidate. Accepted activation records `succeeded`.
6. Preflight/pre-activation failures restore old data and the old managed service and record failure. After irreversible activation, retain the new version/data and require forward repair. A new process resets process-local draining.

Restart never repeats completed/cancelled plans. Interrupted running plans do not silently retry installation. If a target transaction already exists, installation/activation guards determine recovery/acceptance and retain the result. Uncertain journal/lock state stops progress; inspect `install-status` / `install-recover`. Normal supervisor shutdown follows existing signal forwarding and the 12-second termination fallback; a scheduled drain timeout does not trigger termination.

See [verification records](./TESTING.en.md) for acceptance boundaries. Same-source injected versions do not prove historical migration compatibility; source versions must honor upgrade guards. UI success proves managed first-start acceptance; deployment-specific proxies, business behavior and production recovery require corresponding evidence.
