# Asset discovery and synchronization

> English | [中文](./ASSET-DISCOVERY.md)

The competitor is [JumpServer Enterprise](https://www.jumpserver.org/enterprise.html). Source and synchronization workflows follow its [official asset documentation](https://docs.fit2cloud.com/jumpserver/manual/admin/console/assets/assets_list/). This module implements LAN discovery and native AWS international/China, Alibaba Cloud ECS and Tencent Cloud CVM inventory. Other cloud vendor APIs and enterprise features remain on the PLAN roadmap.

## Alibaba Cloud ECS and Tencent Cloud CVM

Choose `aliyun` with the Alibaba Cloud account UID, or `tencentcloud` with the root account UIN. These are provider account identifiers, not a RAM user ID, Tencent AppID or a subaccount UIN. Provider and account are immutable on an existing source. Regions are explicit; address selection, optional pinned SSH gateways, one-use import, policies, scheduling, source revisions, audit and metadata ownership use the same flow as AWS/LAN. Cloud credentials are separate from SSH import credentials.

The shared write-only `cloud_credential` fields map to Alibaba Cloud AccessKey ID/secret and optional STS token, or Tencent Cloud SecretId/SecretKey and optional STS token. Temporary Tencent IDs and secrets accept up to 1024 bytes; its token accepts up to 4096. No key is stored in a request URL, returned by source reads, audit, CSV or CLI, or substituted for an existing native asset credential. Switching provider in a new source form clears entered cloud keys. Provider state is preserved alongside normalized power state; unknown/new states stay visible without probing or counting as missing.

- Alibaba Cloud verifies [STS GetCallerIdentity](https://www.alibabacloud.com/help/en/ram/developer-reference/api-sts-2015-04-01-getcalleridentity), then calls regional [ECS DescribeInstances](https://www.alibabacloud.com/help/en/ecs/developer-reference/api-ecs-2014-05-26-describeinstances) with `MaxResults=100` and `NextToken`. Requests use the documented [RPC signature](https://www.alibabacloud.com/help/en/sdk/product-overview/rpc-mechanism), independent random nonces and HTTPS POST form bodies. A `DryRun=true` request must return `DryRunOperation` before and after each region's enumeration. Missing permission can otherwise appear as an empty list; a denied or ambiguous preflight aborts the entire run and preserves prior findings.
- Tencent Cloud verifies STS `GetCallerIdentity` against the configured root UIN, then uses [CVM DescribeInstances](https://cloud.tencent.com/document/product/213/15728) with `Limit=100`, offsets and [TC3-HMAC-SHA256](https://www.tencentcloud.com/document/product/1176/55147). Every page must contain an explicit total count and instance array. Count changes, duplicate IDs, a premature empty page, provider errors or partial-region failures abort the complete run. Credential scope uses UTC dates.

Both adapters use fixed provider HTTPS endpoints, reject redirects, bound response/instance/metadata sizes and retry throttling or transient server responses at most twice with cancellation. They normalize private/public IPv4, IPv6, names, zones and tags without introducing a vendor SDK dependency. IPv6 is a stable selected address; Alibaba EIP takes precedence over ordinary public IPv4. No cloud mutation API is invoked.

Grant full inventory visibility in all selected regions before enabling automatic missing-asset handling. API identity/preflight checks do not prove that a production RAM/CAM resource policy exposes every asset; resource-scoped visibility changes and cloud eventual consistency require operational review and conservative missing thresholds. Signed protocol fixtures, encrypted restart, API/CLI and browser verification are distinct from real cloud-account acceptance. Real Alibaba/Tencent accounts, private-cloud variants and other cloud vendors remain unverified or unimplemented as listed in PLAN.

## AWS international and China

Choose `aws` or `aws_cn`, a fixed 12-digit AWS account ID, explicit regions and private IPv4, public IPv4 or IPv6. Cloud credentials are separate from new assets' SSH credentials. Access key ID, secret access key and optional STS session token are write-only and encrypted in the organization store; source reads, audit, CSV and CLI output do not return them. Editing a source preserves the cloud credential unless explicitly replaced. Provider and account cannot change on an existing source; create another source for another account. Key rotation within that account is supported.

The connector uses canonical regional HTTPS endpoints, verifies STS `GetCallerIdentity`, signs POST Query requests with SigV4 and paginates EC2 `DescribeInstances`. No redirects, custom endpoints, insecure TLS or cloud mutation APIs are available. A read-only identity needs `ec2:DescribeInstances`; STS identity follows [AWS's permission contract](https://docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html). Region opt-in and account access remain the operator's responsibility. AWS GovCloud and isolated partitions are outside these two adapters.

Inventory is published only after all selected regions/pages succeed. Failures, malformed results, repeated page tokens or wrong account/owner IDs leave findings unchanged and cannot count assets as missing. Up to 32 regions, 500 pages per region, 8 MiB per response, 4 MiB of normalized cloud metadata and 8,192 observed instances/endpoints are accepted. The metadata budget includes every selected port and missing-resource record before probing or publishing, preventing tag/port fanout from amplifying memory use. Throttled requests retry at most twice; cancellation and the existing 15-minute run bound apply.

Findings include stable provider/account/region/instance identity, name, state, addresses and tags. Running instances with the selected address receive the existing credential-free SSH key observation or TCP probe, optionally through the pinned SSH gateway. Stopped instances and instances without the selected address remain visible and do not count as missing. Only a complete successful inventory increments misses for absent instances in the currently selected regions/ports. Removing a region retains its earlier assets. The existing threshold/disable policy and one-use preview/import flow apply.

Instance identity keeps the same finding/asset ID across IP changes. This batch deliberately reports existing endpoint or SSH pin changes as conflicts and preserves native credentials and trust; automatic IP migration and multi-node mapping remain open. Resolve such moves explicitly in inventory and reconfirm the source/policy. Instance name updates use the existing metadata ownership protection. No real AWS account acceptance is claimed without a real cloud account; signed connector fixtures and API/browser contracts are separate evidence.

Web, SDK and `jms discover source save --file -` use the same `provider`, `cloud` (`account_id`, `regions`, `address_mode`) and write-only `cloud_credential` (`access_key_id`, `secret_access_key`, `session_token`) fields. Supply credentials through protected standard input, never shell arguments or a committed config. `jms discover source show` returns only public settings and credential-configured flags.

## Workflow

1. Open Asset discovery, add a source and enter literal IPs, CIDRs or inclusive ranges, exclusions and ports. Select a protocol template and optional SSH gateway.
2. Scan first. SSH observes the host key before authentication. Other protocols only receive a TCP reachability check, which does not establish successful login. Scans do not use import credentials.
3. Configure credentials for new assets, save the source and scan again. Credentials are write-only and encrypted; reads, audit and exports do not return them.
4. Create a policy, confirm the source revision and set name prefix, node, group and CIDR filters. Automatic import and trust of new SSH keys require separate explicit choices.
5. Select hosts, preview and verify fingerprints before import. Previews last five minutes and are consumed once. Retrying the same request returns its original receipt.

Source changes pause referencing policies. Scan again and save each policy to confirm the new source revision. Credentials initialize new assets only; existing passwords, keys and rotation results remain intact. Seven-day rotation follows the existing credential policy.

## Synchronization and bounds

- LAN asset IDs derive from source and endpoint. Cloud asset IDs derive from source, provider/account/region/instance, protocol and port. Retries and process restarts do not duplicate them.
- Manual assets and other sources' assets are not adopted. One existing endpoint is reported as existing; ambiguous matches conflict.
- Policies update name, node, group and remark. Manual edits or different policy ownership conflict by default. Explicit overwrite can reclaim metadata but cannot replace endpoints, usernames, credentials or existing SSH pins.
- Missing hosts remain by default. A source can disable its own assets after 1–10 consecutive misses. Only endpoints actually scanned are counted; removing ranges retains earlier assets. Returning hosts disabled by sync are re-enabled, while manual edits remain protected.
- LAN limits: 1,024 addresses, 16 ports and 8,192 endpoints. All probes use 1–32 workers and 100–5,000 ms timeouts. One active run per source, four per organization.
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
