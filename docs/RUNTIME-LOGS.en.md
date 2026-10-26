# Runtime logs and convenient operations

> [中文](./RUNTIME-LOGS.md) | English

This batch adds standalone operational log management and private-IP HTTP compatibility. Implementation and cases are authored; unified verification, official artifacts and one intranet upgrade remain. Historical mini acceptance stays 12/12; this batch is counted separately.

## Acceptance gates

| Item | Implementation | Acceptance |
|---|---|---|
| Native Go size/UTC-day rotation and quiet expiry | Ready | Pending unified verification |
| Disk usage, archive/day limits and private file safety | Ready | Pending unified verification |
| Admin status, manual rotation, conflicts and idempotent retries | Ready | Pending unified verification |
| IP HTTP operation request IDs without randomUUID | Ready | Pending unified verification |
| macOS legacy log adoption, CI and official artifacts | Ready | Pending unified verification |
| One upgrade, real login/SSH/files/monitoring/data retention/cleanup | Pending release | Pending live acceptance |

## Works with defaults

The Go service writes `JMS_DATA_DIR/logs/server.log` without system logrotate, cron or another resident process. It rotates before exceeding 10 MiB and on the first write or hourly maintenance after a UTC date change. At most five archives and 14 days are retained, whichever limit is reached first. New files stay within the configured size; oversized individual records are shortened and counted. Existing oversized legacy logs are archived intact and expire under retention, preserving historical content. This limit does not bound business audit storage.

Expiry runs at startup and hourly, even without new requests. Only precisely named regular archives are removed; unknown files and symlink targets are preserved. Directories use 0700 and files 0600. A process directory lock prevents two writers sharing the same log directory. Recordings, command/file audits, business data and credentials follow their own policies. Do not add copytruncate or move the active file externally.

| Environment variable | Default | Range |
|---|---|---|
| `JMS_LOG_DIR` | `JMS_DATA_DIR/logs` | Log directory; `-` selects console only |
| `JMS_LOG_MAX_MB` | `10` | 1–100 MiB |
| `JMS_LOG_BACKUPS` | `5` | 1–30 archives |
| `JMS_LOG_DAYS` | `14` | 1–365 days |
| `JMS_LOG_CONSOLE` | `true` | Mirror console output; its supervisor must bound console logs |

Cluster mode defaults to console only; explicitly enabled local logs require a different directory per node. macOS deployment adopts the existing deployment-root `logs/server.log`, disables console duplication and connects launchd stdout/stderr to `/dev/null`, avoiding another growing output file. Pre-logging argument failures surface through artifact preflight and health checks; Fatal Go output follows the current log across rotations; OS crash output is not business audit. A fatal record can temporarily exceed the per-file threshold and is archived on the next startup. Configuration changes require restart.

## View and operate

Open Settings → Security → Runtime logs for disk usage, archives, policy, last rotation and storage errors. Refresh or rotate immediately. Rotating an empty file creates no archive. The existing compact settings style is reused without a new design system or motion.

Global-admin endpoints are `GET /api/v1/settings/security/runtime-logs` and `POST .../rotate`. They expose no log content or absolute disk paths. Input includes process `instance`, `revision` and `request_id`; restarted/stale processes return 409. Replaying a request within the most recent 128 entries does not rotate again. Disk errors return generic codes; resolve disk space/permissions and retry. Reading status does not clean files.

Operation buttons use `crypto.getRandomValues` to generate UUID v4 request IDs on private HTTP origins. They do not use Math.random or weaken credentials/review enforcement. SSH, file and approval contracts remain intact.

Evidence belongs in ignored `.cache/qa-reports/`. Actual CI, BuildWorld, retention, rotation and cleanup results will be recorded after publication.

Unified CI found long permission codes expanding the roles page at 375px. Fieldset shrinking, permission wrapping and narrow-screen cases address it. For a frontend-only repair, the manual `frontend_only` CI entry still runs the entire production browser suite. Unchanged backend, race, integrations and Docker reuse their passed source evidence; skipped jobs are not counted as passes.
