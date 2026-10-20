# Organizations and resource isolation

> English | [中文](./ORGANIZATIONS.md)

[Global organization overview](./GLOBAL-ORGANIZATIONS.en.md) authors independent global read authority, cross-organization inventory/cached health/activity counts, bilingual Web, CLI/SDK and revocation/concurrency/reopen/existing-standby cases. E08 awaits verification after all 42 implementation groups are ready.

New [multiple identity-source and directory synchronization](./IDENTITY-SOURCES.en.md) source keeps named sources separate from default endpoints. Complete LDAP synchronization and owned group/organization mapping preserve manual precedence. This batch is unverified; historical default-provider acceptance below does not cover new source.

Each organization holds separate assets/encrypted credentials, nodes, user groups, grants, command filters, asset/channel policies, SSH/SFTP reviews, live terminals, recordings, file audits, jobs, templates and schedules. Platform users, login sessions, identity providers, Passkeys, MFA, platform sign-in policies/reviews and system roles are shared. The competitor is [JumpServer Enterprise](https://www.jumpserver.org/enterprise.html); overall parity remains in progress.

## Default organization and request selection

The default ID is `00000000-0000-0000-0000-000000000002`, matching [JumpServer source](https://github.com/jumpserver/jumpserver/blob/dev/apps/orgs/models.py). Existing files, encryption key and PostgreSQL documents remain default-organization data without relocation. Existing and new platform users have implicit default membership; explicit removal persists an exclusion. The default organization cannot be disabled or archived.

REST selects a canonical lowercase UUID with `X-JMS-ORG`, defaulting to the default organization when omitted. Duplicate/invalid headers and GLOBAL/SYSTEM virtual IDs never fall back. Unknown, disabled and archived organizations return 404; nonmembers receive 403. Missing asset, gateway, job and session IDs are never looked up elsewhere. REST rejects the `org` query parameter. WebSockets use the server-returned non-secret `?org=<uuid>`; tickets retain the existing subprotocol transport. Conflicting query/header scopes are rejected.

The browser switcher reloads the console, closes that page's terminals and clears old page state. Other tabs in the same browser reload on the storage event. Selection is saved as `jms233.org`. After membership loss, the switcher provides an explicit selection entry. Shared authentication and sign-out do not require membership in the selected organization.

Agent CLI supports `JMS_ORG_ID` with Bearer and AccessKey authentication. Library clients use `WithOrganization(id)`. Clients never read remote account passwords, private keys or import passphrases.

## System and organization roles

System administrators, including compatible admin accounts and the global system-administrator role, can access every enabled organization. Other system roles require membership; their resource permissions apply in organizations they can access.

Membership roles are member, organization auditor and organization administrator. Auditors read that organization's assets/audits; organization administrators manage its resources, members and roles. Ordinary members require asset grants. Organization roles cannot create platform administrators, change providers/MFA, manage platform sign-in reviews or acquire system organization management. An organization-scoped builtin named system-administrator also contains only organization permissions.

The UI separates system and organization roles. Existing global `/api/v1/rbac` management routes stay compatible. Explicit system routes use `/api/v1/system/rbac`; organization roles use `/api/v1/organization-rbac`. `/api/v1/rbac/me` returns the current organization/system permission union plus separate `organization_permissions`, `system_permissions` and `organization_id`. Endpoints enforce their server-side scope.

Groups are organization-local. Legacy default groups may already be bound to system roles; organization administrators cannot edit their membership or delete them without system management permission. User subjects in resource grants and filters must remain organization members.

## Administration, revocation and audit

`/api/v1/organizations` provides list/create/revisioned update. `/{id}/members` reads or revision-updates membership, accepting a shared user ID or exact username for existing users. Organization administration requires system `organizations.manage`; membership administration requires scoped `organizations.members.manage`. `/{id}/audit` provides paged change events. Limits are 100 organizations including default/archived entries, 10,000 explicit memberships per organization and the latest 10,000 audit events.

Role `none` removes membership, including implicit default membership. Subsequent resource requests and schedule dispatch check current membership; SSH input and periodic checks reject removed members. Existing grants, groups and role configuration remain and participate again after rejoining; review them before re-adding a user.

Disabling blocks new resource access and stops the organization's monitoring, schedules, jobs and terminals. Operations/transfers already entered on a remote host may finish under their request-start decision. DELETE `/{id}?revision=N` archives while retaining data. POST `/{id}/restore?revision=N` restores in disabled state and requires explicit re-enabling. Archive does not erase credentials or audit history.

Platform sign-in rules use `/api/v1/platform-access-policies` in the UI. Asset/channel policies use the selected organization's `/api/v1/access-policies`. Organization administrators cannot alter platform sign-in rules, and their policy audit excludes platform sign-in events.

## Standalone and single-active HA

New organizations use separate files, audit directories and services under `JMS_DATA_DIR/organizations/<uuid>/`. Encryption keys are derived from the master Vault key and UUID with HMAC-SHA256; the default retains its original key. Backups must retain the master key, organization metadata, corresponding directories and shared documents. The active server coordinates password assets with the same host address, port, pinned host key and username, synchronizing their vaults even in disabled or archived organizations. Conflicting credentials block rotation. Copies of an identical private key promote every vault before old-key retirement; address aliases are not automatically merged. See [password rotation](./PASSWORD-ROTATION.en.md) and [key rotation](./SSH-KEY-ROTATION.en.md).

PostgreSQL uses `<uuid>:<document-key>` within the cluster namespace and reuses the active node's pool. Existing default documents keep their keys; new organization roles have a separate scope. Takeover restores scoped resources, memberships, roles, templates and schedules. Live SSH/SFTP sessions do not migrate. See [CLUSTER-HA](./CLUSTER-HA.en.md) for shared-file and election requirements.

Testify cases cover revisions, archive/restore, encrypted/document scopes, membership/system authority, foreign IDs, actual SSH/monitoring/SFTP/CLI/WebSocket, live removal and HA takeover. Playwright covers create/membership/switching/roles, monitoring, terminals, CLI, archive and bilingual UI. See [TESTING](./TESTING.en.md). Global aggregation and automatic directory organization mapping are authored pending verification. Organization migration tooling and production multi-organization failure drills remain outstanding.
