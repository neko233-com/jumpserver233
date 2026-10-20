# System Roles and Permissions

> [中文](./RBAC.md) | English

[SSH connectivity checks](./ACCOUNT-CHECKS.en.md) use `accounts.rotation.check` alongside `accounts.rotation.view`, `assets.view_all` and `assets.probe`. Checks and check retries require no rotation execution, fixed-password or privileged-rotation rights.

Fixed plans additionally require `accounts.rotation.fixed_password` for configuration, execution and recovery alongside existing rotation rights. It provides no password read endpoint. Viewers see source mode only; see [fixed-password plans](./FIXED-PASSWORDS.en.md).

Organization [generated SSH password policies](./SSH-PASSWORD-POLICY.en.md) use independent `accounts.password_policy.view` / `accounts.password_policy.manage`; neither grants credential access or rotation execution. Role controls have bilingual labels, and policy-only users can access the configuration card.

Host plugins add `plugins.inspect` and `plugins.manage`, with target-account connect authorization still required in the current organization. Revocation closes a running task SSH transport; detached agents require explicit stopping. See [host tools and agents](./HOST-PLUGINS.en.md).

Database metadata audit and cancellation across operators use `database.audit.view_all` and `database.cancel_all`; review uses `reviews.command.manage`. Result rows remain limited to the owner with current authorization. See [PostgreSQL](./POSTGRESQL.en.md).

Organizations isolate resources, roles and operational audit through `X-JMS-ORG`, browser switching and Agent CLI selection. Standalone storage and PostgreSQL single-active HA are supported. See [Organizations](./ORGANIZATIONS.en.md). Full Enterprise parity remains in progress.

Role management at `/console/roles` supports custom system roles, user/group bindings, and permission-change audits. Existing `admin/operator` identities stay compatible: administrators retain all capabilities, while operators can add system roles alongside asset-account grants. System and current-organization roles are managed separately; organization roles and grants apply to that organization’s resources.

After administrator initialization, anonymous local requests require authentication too. An absent `JMS_ADMIN_TOKEN` cannot fall back to administrator authority, and plans created under the earlier anonymous identity no longer gain execution permission.

## Permission semantics

- Direct and current group roles combine as a union. Missing permissions deny access; wildcards and unknown permissions are rejected. Every HTTP request or scheduled dispatch resolves current bindings/membership instead of storing permissions in login tokens. Revocation does not automatically terminate an established SSH session.
- Asset management, global inventory, SSH execution, SFTP, probing, rotation, and credential backups are separate capabilities. `assets.manage` edits all assets and credentials and includes inventory visibility, without granting SSH/SFTP execution or backup restore. Global SSH/SFTP permissions include required inventory visibility. Existing user/group, asset/node, account, action, and time grants still authorize scoped host access.
- Session visibility, recordings, commands, file audit, and session termination are independent. Reading all jobs and cancelling them are separate, as are reading and managing others' plans. Personal command templates always remain private to their creator.
- A user manager can create operators by default. Creating a compatible administrator also requires `roles.manage`. That permission can assign the system-administrator role and therefore represents full permission-management authority.
- Login review still applies to global SSH/SFTP access unless `login_review.bypass` is assigned. Command policies still apply to global connection roles.
- With global MFA policy `admins`, accounts holding any system-role permission also require MFA at their next login. Setup challenges only authorize enrollment and cannot act as normal tokens. Existing sessions retain the current policy activation timing.

## Built-in roles

| Role | Capabilities |
|---|---|
| System administrator | All registered system permissions, compatible with the existing `admin` identity |
| Auditor | Global inventory/monitoring, session/recording/command/file audits, job and plan reading; no connection, rotation, termination, or cancellation |
| Asset manager | Asset/credential editing, nodes, inventory, probing; no connection, rotation, or backup restore |
| Access reviewer | Login reviews, terminal-command reviews, SSH job review, and job-result reading |

Built-in roles cannot be changed/deleted. Role bindings cannot revoke the original `admin` identity, preventing accidental removal of the final compatible administrator. `GET /api/v1/rbac/permissions` returns the catalog; the page displays bilingual descriptions and permission IDs.

## Persistence, revisions, and audit

Role updates/deletion and binding updates require the current `revision`; stale writes return 409. Bound roles cannot be deleted. Empty `role_ids` revokes that subject's binding. Users/groups must exist. Every successful change commits together with an audit containing before/after snapshots, authenticated actor, and time. Failure leaves effective authorization unchanged. Returned slices cannot mutate stored permissions.

Standalone uses mode-0600 `rbac.json`; single-active HA uses the PostgreSQL `rbac` document, without another remote service. Metadata and audits contain no SSH passwords, tokens, or secrets. Limits are 100 custom roles, 2000 subject bindings, and 10000 changes. Capacity rejects further changes without deleting history. Audit archiving/retention remains outstanding.

## API

| Endpoint | Purpose |
|---|---|
| `GET /api/v1/rbac/me` | Current identity, role IDs, and effective permissions, available to authenticated accounts |
| `GET /api/v1/rbac/permissions` | Registered permission catalog |
| `GET/POST /api/v1/rbac/roles` | List/create roles with `{name, description, permissions}` |
| `PUT /api/v1/rbac/roles/{id}` | Update with `revision` |
| `DELETE /api/v1/rbac/roles/{id}?revision=N` | Delete an unbound custom role |
| `GET/PUT /api/v1/rbac/bindings` | List/save `{subject_type: user|group, subject_id, role_ids, revision}` |
| `GET /api/v1/rbac/audit?limit=50&offset=0` | Changes, at most 100 per page |

All except `me` require `roles.manage`. Every identity entry point (Cookie, Bearer, permanent token, HTTP Signature) resolves permissions on the server. Supplying a role field or changing hidden controls cannot bypass enforcement.

## Verification

Testify covers permission unions, group revocation, revision conflicts, immutable built-ins, administrator-creation rejection, auditor termination/cancellation denial, persistence rollback, slice isolation, concurrent updates, and PostgreSQL reload. Two-node HA checks retained roles after takeover. Playwright creates and binds a role through the management page, verifies the isolated synthetic account only has user management, rejects forged administrator creation, and verifies revocation for an existing session. See [TESTING.en.md](./TESTING.en.md) for the unified entry point.
