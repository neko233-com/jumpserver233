# Runtime logs and convenient operations

> [中文](./RUNTIME-LOGS.md) | English

This batch is released as v0.5.0 and upgraded once on the intranet: implemented 6/6, accepted 6/6, no remaining batch gate. Historical mini acceptance stays 12/12 and is counted separately.

## Acceptance gates

| Item | Implementation | Acceptance |
|---|---|---|
| Native Go size/UTC-day rotation and quiet expiry | Ready | Passed |
| Disk usage, archive/day limits and private file safety | Ready | Passed |
| Admin status, manual rotation, conflicts and idempotent retries | Ready | Passed |
| IP HTTP operation request IDs without randomUUID | Ready | Passed |
| macOS legacy log adoption, CI and official artifacts | Ready | Passed |
| One upgrade, real login/SSH/files/monitoring/data retention/cleanup | Published | Passed |

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

Actual CI, BuildWorld, retention, rotation and cleanup results follow; compact evidence is retained in ignored `.cache/qa-reports/`.

Unified CI found long permission codes expanding the roles page at 375px. Fieldset shrinking, permission wrapping and narrow-screen cases address it. For a frontend-only repair, the manual `frontend_only` CI entry still runs the entire production browser suite. Unchanged backend, race, integrations and Docker reuse their passed source evidence; skipped jobs are not counted as passes.

## Formal delivery — 2026-10-26

- Version `v0.5.0`, tag/artifact source `f9220160b9ad8ff49610d517332b6af5d8398988`; the [release workflow](https://github.com/neko233-com/jumpserver233/actions/runs/40342469844) passed with 12 immutable archives/checksums for six platforms. Only release metadata differs from frontend-verified source `8efd03f`.
- [Full CI](https://github.com/neko233-com/jumpserver233/actions/runs/40332577507) passed backend, Linux race, three external integration groups and Docker. Its browser run found a 12px roles-page overflow. After repair, [complete frontend verification](https://github.com/neko233-com/jumpserver233/actions/runs/40338533455) passed **73/73**. Skipped backend jobs reuse passing evidence against identical Go sources; they are not new passes.
- Local Go: 2249 passed, 137 skipped. Repaired package/browser cases passed three consecutive runs. macOS deployment: 34/34, zero skips. Content, vet, lint and builds passed, retaining five existing lint warnings. Initial JS: 498349 bytes, gzip 160815; total JS 1651195. Budgets remain unchanged.
- Dedicated deployment lock commit `cacaa0f`, root `Jenkinsfile_mac_single`; BuildWorld 1127 / #11 submitted and activated once, **6/6 stages in 83.35 seconds**. The subsequent ordered restart verifies retention.
- root/root login worked across upgrade/restart. Real Web/native SSH returned Linux/root; Web command audit and asciinema replay contain this batch's markers. Native SFTP transferred 65280 bytes and browser upload/actual download 8640 bytes, with byte/SHA-256 equality. Owned remote files were removed and checked again; repeated Web deletion returned 204 then 404.
- Three real monitoring samples passed. The original asset, 25 old session audits, Vault key, saved credentials and target/entry host fingerprints survived. Retention restart preserved 26 audits; final count is 29. Acceptance audit records remain.
- The original 10476522-byte operational-log prefix matches SHA-256 and remains archived intact. The current file is below 10 MiB with 3/5 archives. Real manual rotation and request replay passed; permissions are 0700/0600 and launchd duplication is disabled. Date/14-day expiry uses clock-controlled cases; this is not a 14-day soak or native XTerminal UI automation. HTTP authentication sessions require sign-in after restart; accounts and business data survive.
- Owned temporary services, files, archive copies, containers/volumes and QA caches were cleaned. The old v0.4.0 download cache was removed. Keep the current verified cache, previous installed release, two stopped-data snapshots and compact reports, with only two essential screenshots. Evidence: `.cache/qa-reports/runtime-logs-20261026/`.

Access: HTTP workspace, SSH/SFTP 2222 on the same intranet host. Logs: Settings → Security → Runtime logs.
