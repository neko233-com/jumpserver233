# Sign-in and asset access policies

> English | [中文](./ACCESS-POLICIES.md)

Organizations isolate resources, roles and operational audit through `X-JMS-ORG`, browser switching and Agent CLI selection. Standalone storage and PostgreSQL single-active HA are supported. See [Organizations](./ORGANIZATIONS.en.md). Full Enterprise parity remains in progress.

The console provides user sign-in, asset access and connection-channel rules. The competitor also controls source addresses, weekly hours and connection methods; see [JumpServer documentation](https://docs.fit2cloud.com/jumpserver/manual/admin/console/access_control/acls/). Policies add restrictions to identity, asset grants and approvals. An allow rule never grants asset access. Standalone mode uses a local file; PostgreSQL single-active HA shares policy configuration, changes and denied decisions.

## Matching

- Subjects: all users, one user or a user group. Asset rules can also select an asset, a node and its descendants, and an SSH account.
- Sources: IPv4/IPv6 addresses, CIDRs or inclusive ranges. Any listed source matches. Empty or `*` matches all sources.
- Hours: an IANA timezone and weekly day/minute windows. Starts are inclusive and ends exclusive. Empty means all times. Split overnight periods into two windows. Daylight-saving conversion applies, including both occurrences of repeated local times.
- Actions: allow or deny; sign-in also supports review and notify. See [Platform sign-in reviews](./PLATFORM-LOGIN-REVIEWS.en.md). Each category selects its first matching rule in ascending priority order. Deny wins equal-priority ties, followed by ID order. Categories are checked independently; any denial stops the request. No match continues normal authorization.
- Revisions: editing, toggling and deletion check the current revision. Changes that immediately deny the current administrator’s sign-in are rejected. Future windows still apply; create appropriate higher-priority administrator-source exceptions before a broad time restriction.

## Server execution channels

| Channel | Enforcement |
|---|---|
| Interactive SSH | Shared Web SSH/Agent CLI session creation, WebSocket attachment and terminal input; live sessions are also checked every ten seconds |
| SFTP access | Review-session issuance and every file request |
| Command execution | Immediate workbench/CLI commands and batches |
| Scheduled execution | Actual dispatch of one-time and recurring plans |
| Upload/download/delete/create directory | Corresponding HTTP operations, after the SFTP channel check |

The server execution entry point selects the channel. Web SSH and interactive CLI share `ssh`; workbench and CLI commands share `exec`. Clients cannot select another channel to evade policy. Administrators also follow policies; the existing review-bypass permission only affects login reviews.

Jobs and plans retain their API-derived source. Review and actual execution recheck current users, groups, nodes and rules. Schedules use their creation source and dispatch-time hours. Older jobs/plans without a source retain an unknown value and fail an applicable source restriction; recreate them when needed. Policy rejection opens no SSH connection and touches no remote file.

New sign-ins are checked before returning cookies/tokens. Existing cookie, Bearer, permanent-token and AccessKey requests also pass sign-in deny rules. Approval/notification applies at fresh sign-in only. Sign-out remains available. Denied live SSH sessions close with `access_policy_denied`; an individual file transfer follows its request-start decision.

## Reverse proxies

The default source is the HTTP peer. Set `JMS_TRUSTED_PROXIES` to up to 32 proxy CIDRs, for example `10.20.0.0/24,2001:db8:1::/48`. Only a trusted immediate peer enables `X-Forwarded-For`; the resolver walks right to left to the first untrusted hop. Proxies must correctly replace/append client addresses. Missing, malformed, oversized or more-than-32-hop trusted headers produce an unknown source, which fails an applicable source restriction. Other forwarding headers do not change policy identity.

The Vite development proxy normally appears as loopback to the API. The page displays the API-observed source. Production proxies and both HA nodes need consistent trust configuration.

## Administration, audit and verification

Management requires `access_policies.manage`, included for built-in administrators. `/api/v1/access-policies` supports list/create/revisioned update/delete; `/context` returns the observed source, and `/audit?limit=25&offset=0` pages audit records. Denials expose stable error codes without revealing matching scopes. Limits are 500 rules and the latest 5,000 configuration/denial events. Identical user/rule/source/channel denials are combined for one minute. Audit-write failure prevents the restricted operation.

Testify covers address syntax, proxy chains, lockout protection, revision conflicts, group/node scope, ordering, DST, failed-write rollback, retention, review sources, plan recovery and live SSH revocation. PostgreSQL/two-node cases check policies and plan sources after takeover. Playwright covers bilingual management, toggle/edit/delete, sign-in, Web SSH, CLI and denied file actions. See [TESTING](./TESTING.en.md) for the combined entry points.

Attribute filters, organization policies, RDP clipboard controls and database result masking remain in the full Enterprise goal. Back up the policy file/shared document with other configuration. If a future-window mistake removes access, stop the relevant nodes and restore a valid configuration backup.
