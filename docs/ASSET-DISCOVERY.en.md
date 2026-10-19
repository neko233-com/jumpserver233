# LAN asset discovery and synchronization

> English | [中文](./ASSET-DISCOVERY.md)

The competitor is [JumpServer Enterprise](https://www.jumpserver.org/enterprise.html). Source and synchronization workflows follow its [official asset documentation](https://docs.fit2cloud.com/jumpserver/manual/admin/console/assets/assets_list/). This module implements LAN sources. Cloud vendor APIs and other enterprise features remain on the PLAN roadmap.

## Workflow

1. Open Asset discovery, add a source and enter literal IPs, CIDRs or inclusive ranges, exclusions and ports. Select a protocol template and optional SSH gateway.
2. Scan first. SSH observes the host key before authentication. Other protocols only receive a TCP reachability check, which does not establish successful login. Scans do not use import credentials.
3. Configure credentials for new assets, save the source and scan again. Credentials are write-only and encrypted; reads, audit and exports do not return them.
4. Create a policy, confirm the source revision and set name prefix, node, group and CIDR filters. Automatic import and trust of new SSH keys require separate explicit choices.
5. Select hosts, preview and verify fingerprints before import. Previews last five minutes and are consumed once. Retrying the same request returns its original receipt.

Source changes pause referencing policies. Scan again and save each policy to confirm the new source revision. Credentials initialize new assets only; existing passwords, keys and rotation results remain intact. Seven-day rotation follows the existing credential policy.

## Synchronization and bounds

- Asset IDs derive from source and endpoint; retries and process restarts do not duplicate them.
- Manual assets and other sources' assets are not adopted. One existing endpoint is reported as existing; ambiguous matches conflict.
- Policies update name, node, group and remark. Manual edits or different policy ownership conflict by default. Explicit overwrite can reclaim metadata but cannot replace endpoints, usernames, credentials or existing SSH pins.
- Missing hosts remain by default. A source can disable its own assets after 1–10 consecutive misses. Only endpoints actually scanned are counted; removing ranges retains earlier assets. Returning hosts disabled by sync are re-enabled, while manual edits remain protected.
- Limits: 1,024 addresses, 16 ports, 8,192 endpoints, 1–32 workers and 100–5,000 ms timeouts. One active run per source, four per organization.
- Up to 500 assets are staged and persisted together. Findings are written in batches.
- DNS names are not targets. Gateways reuse the existing pinned SSH route, at most three hops and one connection per scan. Login reviews bind to the run and current route; old approvals cannot be replayed.

## Schedules, permissions and recovery

One-time, interval and five-field cron schedules with IANA timezones share native misfire and daylight-saving fold rules. Overlapping occurrences are skipped. Execution rechecks user state, organization membership, permissions, access policies and gateway grants. Schedules retain their actor and trusted source IP; revocation removes their execution authority.

Metadata edits preserve the next occurrence, skipped count and DST watermark. Renaming or re-enabling an executed one-time schedule does not replay it.

Access requires `assets.view_all` plus the corresponding organization-scoped `assets.discovery.view/manage/execute/import/trust/export` permission. Import also requires `assets.manage`.

Standalone mode uses a dedicated encrypted file. HA uses PostgreSQL shared documents and organization keys. On takeover, scanning, syncing and pending-review runs become interrupted; uncertain network actions are not replayed automatically. Claimed receipts and deterministic asset IDs allow the same import request to resume. Uncertain acknowledgements require authoritative reload before further writes.

Retention: 32 sources, 128 policies, 16,384 findings, 200 runs, 128 previews, 200 receipts and 1,000 audit events. Previews, receipts and audit also have byte limits. Only preview-token HMACs are stored.

## API / CLI

Prefix `/api/v1/asset-discovery`: sources and policies support list/create/detail/update and revision-checked deletion. Runs support create/list/detail and `/{id}/cancel`. Findings and findings.csv require source_id. Import-preview/import use a one-use capability and stable request_id. Audit returns sanitized snapshots; schedules/preview calculates execution instants. Lists use offset/limit.

Use `jms discover sources|policies|runs|findings|audit` to read data; `source save [ID] --file CONFIG.json` and `policy save [ID] --file CONFIG.json` to save; `run start --file RUN.json` to scan; `source|policy delete ID --revision N` to delete configuration; `run show|cancel ID` to query/cancel; `preview|import --file INPUT.json` to import; `export --source ID` to export. `--file -` reads stdin. Existing authentication and `JMS_ORG_ID` apply. Keep request_id unchanged across retries.

SDK: `server/internal/sessionclient/asset_discovery.go`. Templates reject inline secrets. Omit credential to preserve it; an empty object clears it. Updates require revision; policies require source_revision.

## Acceptance

2026-10-19: final Go/Testify 1324 passed/48 skipped; Linux race 559 passed/8 skipped; full production browser suite 83/83 passed. The schedule metadata correction also passed final full Go/race and a real Docker scheduling check. Narrow-screen styling was checked in the actual Docker browser; final local and Docker CSS digests match. All eight final Docker functional checks passed, including credential/receipt recovery after API restart and no replay after renaming an executed one-time schedule.

See [verification](./TESTING.en.md) for stages, cleanup and local report locations. This batch excludes intranet deployment and a formal Release. Publish once after overall acceptance.
