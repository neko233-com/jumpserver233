# Global organization overview

> [中文](./GLOBAL-ORGANIZATIONS.md) | English

E08 cross-organization summaries, bilingual Web, CLI/SDK and cases are authored, **unverified**. Existing [organization isolation](./ORGANIZATIONS.en.md) and new [directory organization mappings](./IDENTITY-SOURCES.en.md) complete the implementation scope together. Production multi-organization failure drills still require unified acceptance and actual-environment evidence.

## Permission and entrypoints

The independently delegated global read permission is `organizations.overview`, included for administrators. Organization role catalogs exclude it. Local administrators/auditors and organization-management/report-export permissions do not independently grant this overview. Existing role revision, audit and revocation behavior remains. Delegation exposes every organization's name, enabled/archive state, active memberships and aggregate resource counts without granting asset operations.

Web route: `/console/organization-overview`. API: `GET /api/v1/organizations/overview?include_archived=false`. SDK: `OrganizationOverview(ctx, includeArchived)`. CLI: `jms reports organizations [--include-archived]`. Repeated reads create no background jobs, business records or outbound messages. Responses are `private, no-store`. Before returning, the server authenticates the credential again and rechecks global authority, rejecting revoked permissions or identity-generation changes.

This is a platform route; a valid `X-JMS-ORG` does not limit the overview. Invalid/duplicate headers still fail under existing rules; GLOBAL/SYSTEM virtual organizations are unsupported. Existing resource isolation, four REST authentication methods, WebSocket frames and replay format remain.

## Definitions and performance

Per-organization counts cover primary assets, SSH assets, protocols, cached online/offline/unknown monitoring, nodes, groups, active terminal/desktop tickets and running jobs. Subaccounts are excluded from asset totals. Monitoring is not refreshed during collection; states other than online/offline count as unknown. Session totals include unattached/closing tickets and are not a count of currently connected people. SFTP access capabilities and database queries are excluded.

Memberships count currently usable platform identities separately for every organization. Default implicit membership retains explicit `none` exclusions. Manual entries override directory-managed entries. Disabled/archived organizations can expose membership metadata but have null resource counts excluded from totals. Membership and resource totals therefore cover different sets.

Collection reads initialized runtimes and existing probe caches without probing SSH, decrypting remote credentials, opening disabled stores or starting newly created organizations. Enabled but uninitialized/closed/unreadable organizations are unavailable/null with `partial=true`; totals include only collected organizations and report collected/enabled counts. Membership, inventory and activity are observations during a request, not an atomic cross-store snapshot or historical warehouse.

The existing maximum is 100 organizations. Each instance permits four concurrent overview requests with a 15-second context budget. Native inventory statistics copy primary IDs/protocols before reading status counts, avoiding complete inventory/rotation/credential responses. No aggregate replica or new dependency is persisted. Web uses manual refresh, local name filtering over at most 100 rows and horizontal table scrolling. Revocation/refresh failure clears stale results; there is no polling loop.

## Authored cases, not executed

- Testify: default exclusions, manual/directory precedence, no collection for disabled/archived stores, missing counts, repeatable reads, counter validation, cancellation, copy isolation, four-request concurrency, global delegation/revocation and SDK/CLI arguments.
- Native service: inventory/disabled assertions extend existing organization-isolation cases. Existing PostgreSQL active/standby cases compare organization/protocol/membership counts before and after takeover, without another Docker stack.
- Playwright: existing OpenSSH fixtures probe a synthetic asset, independent delegation/revocation, enabled/disabled organizations, bilingual views and 390px layout. Retain two screenshots without secrets. Remove owned assets, bindings, roles and synthetic users, archive temporary organizations, and repeat cleanup twice.

Run these after all 42 implementation groups are ready. Historical SSH/organization passes do not cover this source. The overview provides no global resource mutation, organization-data migration, production partition fencing or multi-active guarantee; those boundaries remain governed by actual requirements and E39.
