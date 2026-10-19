# Drain before a standalone upgrade

[中文](./SERVICE-MAINTENANCE.md) | [Documentation](./README.en.md)

System settings → Security → Software updates → Prepare for an upgrade starts, inspects and cancels draining. Global `security.manage` is required; organization administration grants no platform control. Only standalone mode supports this control. Coordinate cluster maintenance separately.

Draining rejects new API writes, WebSockets and SSH connections, and pauses operation-plan and inventory-monitor cycles. Existing terminals remain usable. Admitted requests, jobs, credential changes and monitor cycles may complete their later steps, including post-change credential verification. Their permits expire when work finishes. Job cancellation, session interruption, platform login and drain control remain available. Remote processes started through an existing SSH channel are not automatically killed.

Status aggregates SSH transports, requests/sockets, terminal sessions and pending tickets, desktops, SSH jobs, database queries, monitor cycles, credential operations and plan dispatch across every loaded organization. Multiple counters can describe the same operation; these are not unique host counts. Awaiting-review jobs, undispatched plans and platform memory state are distinct from executing remote work. Draining does not freeze every local scheduled write.

## API, CLI and retries

`GET /api/v1/settings/security/maintenance` returns `supported`, `instance`, `pid`, `revision`, `draining`, `ready` and `activity`. `PUT` requires the current `instance` / `revision`, an 8–80 character `request_id` and `draining`. Request IDs accept letters, digits, underscores and hyphens.

```sh
jms update drain-status
jms update drain-start --instance INSTANCE --revision 1 --request-id upgrade-20261020 --wait 60s
jms update drain-cancel --instance INSTANCE --revision 2 --request-id cancel-20261020
```

The CLI uses platform identity without remote passwords. `--wait` follows one instance and revision; cancellation, process replacement or timeout exits nonzero. A timeout does not reopen admission. Update audit is persisted before changing admission; audit failure leaves state unchanged. The last 100 in-memory receipts bind the actor and complete input. Replaying a start after cancellation returns current status and its original applied revision without restarting draining. Stale revisions, changed input under one ID, another actor and previous process instances are rejected.

Drain state and receipts are process-local. Restart restores admission and creates a new instance ID; update audit persists. This status grants no installation permission across restart.

## Finish the upgrade

`ready=true` only indicates that tracked active work has ended. Stop the service normally, then use [encrypted full-site backup](./BACKUP.en.md) and the [controlled installation transaction](./INSTALLATION.en.md). The exclusive data OS lock remains responsible for stopped-service consistency. A single ready response never authorizes online copying or replacement of data. Automatic installation scheduling, process-stop control and historical-release format migration are outside this batch.
