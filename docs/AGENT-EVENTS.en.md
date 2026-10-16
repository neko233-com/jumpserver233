# Agent events and centralized audit

[中文](./AGENT-EVENTS.md) | [Documentation index](./README.en.md)

Native `jms-agent` version 2 and later record recovery events on managed Linux hosts. The platform collects bounded pages over the verified SSH route. Hosts need no new listening port or platform credentials.

## Records and limits

- Persist `repair_started` before recovery and append a completed or failed result. The next repair explicitly records a previously interrupted attempt.
- Each event includes host time, trigger, configuration SHA-256, active ban count, attempt ID, sequence and previous hash. Supervisor recovery and platform lifecycle operations have separate triggers.
- Hosts retain 1024 events; each read returns at most 64. Reads never acknowledge, delete or initialize a journal. Gaps, missing journals and stream resets become separate audit records. Rollbacks and inconsistent chains are rejected.
- These are host-reported facts. Host root can alter them; the hash chain does not guarantee protection against root. The platform independently records collection jobs, authenticated collector identity and receipt time.

## Use

1. In an asset's Tools & agents → Diagnostics & details, select Update native component. Old components and launchers are never executed. Replacement preserves unknown regular files and refuses symlinks and special files. Existing native versions require this migration step.
2. Select Sync events and expand Agent event audit. Repeated collection does not duplicate imported events.
3. Managers can enable a collection interval from 60 seconds to one day. The UI offers 60/300/900/3600 seconds. The centralized page is `/console/agent-audit`.
4. Stopping collection disables the plan. Cancel started jobs in Operations if needed. Disabling does not delete remote journals or platform history.

The CLI uses existing platform identity authentication:

```sh
jms plugin ASSET banhack233 agent_update
jms plugin ASSET banhack233 events
jms agent-events ASSET --before 0
jms agent-events all
jms agent-events ASSET collection --enable --interval 300
jms agent-events ASSET collection --disable
```

A zero `next_before` ends the current history. Source `more_events=true` means retained events remain: sync again or wait for the next collection run.

## Authorization, persistence and HA

- Asset history requires current `connect` access to the target account and one of `plugins.inspect/manage/protect`. A `view` grant alone does not expose events or collection settings.
- Global audit requires `audit.agents.view_all`. Managing collection and updating components require `plugins.manage`. Every remote execution still checks SSH grants, source/time access policies and login/command reviews.
- Collection uses internal typed Operations/Jobs, without a client-provided shell. Each dispatch resolves current credentials and gateway bindings, so rotation does not retain old secrets. Revocation denies subsequent execution.
- Terminal collection receipts are encrypted and archived before leaving hot job/run history. Ordinary jobs keep their capacity rules. Latest archived receipts remain available by job/run ID; older receipts are paged through Agent history.
- Local files and PostgreSQL documents use organization-key AES-GCM encryption. Segments are written before atomically publishing the index and source cursor. Failures do not advance cursors. Separate paths, document scopes and derived keys preserve organization isolation.
- Existing single-active HA ownership applies. Losing the lease or closing an organization rejects late writes. This does not establish multi-active writes or production HA acceptance.

## API

- `GET /api/v1/assets/{id}/agent-events?before=0&limit=30`
- `GET /api/v1/audit/agent-events?before=0&limit=30`
- `GET/POST /api/v1/assets/{id}/agent-events/collection`
- Explicit plugin actions `events` / `agent_update`; `events_collect` is reserved for internal plans.

The page defaults to host events. Collection receipts and all records are separate views, so empty polls do not bury repairs. First use of PostgreSQL imports the same organization's local encrypted index, segments and cursor.

![Agent event audit, local isolated environment on 2026-10-16](./images/agent-events.en.png)
