# Platform user lifecycle

> [中文](./USERS.md) | English

`/console/users` manages global identities: display names, comments, roles, enabled status, expiry, archive, restore, credential revocation and atomic batches of up to 100 changes. Creation uses existing system settings. The competitor baseline is [JumpServer Enterprise](https://www.jumpserver.org/enterprise.html); overall parity remains in progress.

## Permissions and recovery

Global `users.manage` is required. Managing administrators or promoting a role also requires `roles.manage`. External identities remain operators. Administrative security changes to oneself are rejected. One enabled local administrator without expiry must remain.

Archive preserves the user ID, reserved username/external subject, enrolled MFA, grants, groups, role bindings and history. Restore leaves the user disabled. Review existing authorization before enabling; retained grants then apply. Existing plans recheck the current identity before execution and may resume after enabling. Archive does not erase data permanently.

## Credentials and sessions

Actual role/status/expiry changes, archive, restore and revocation increment `auth_generation`, remove permanent tokens, AccessKeys and pending MFA setup, and revoke login sessions. Passwords and enrolled MFA/Passkeys remain; fresh authentication can issue a new session. Display name/comment changes preserve sessions.

Local/external login, four REST authentication methods, RADIUS factors, platform login reviews and pending Passkey/SSO flows check current validity or identity generation. Active SSH, monitors, collaboration, RDP, Telnet and Kubernetes authorization retains the initial generation. A quick disable/enable cycle cannot preserve an old connection. Expiry is checked during authentication, requests and recurring authorization, rather than by an exact millisecond timer. SSO/Passkey generation binding covers pending tickets after identity verification and before platform session issuance; upstream provider sessions remain provider-managed.

## API / Go SDK / CLI

Read `GET /api/v1/users/management?scope=current|archived|all&q=…&offset=0&limit=25` and `GET /api/v1/users/{id}`. Maximum page size is 100. The existing `/api/v1/users` array interface excludes archived users.

`PUT /api/v1/users/{id}` requires the current `revision`, with optional `name`, `comment`, `role`, `is_active`, RFC3339 `date_expired`, or `clear_date_expired: true`. `DELETE …/{id}?revision=N` archives. `POST …/{id}/restore` and `/revoke` accept `{"revision":N}`.

`POST /api/v1/users/actions` accepts `{"changes":[{"id":"user-…","action":"update","revision":1,"is_active":false}]}`. Actions are update/archive/restore/revoke; duplicate IDs are rejected. Revision conflicts, permission failures or recovery guard failures abort the whole batch. Requests reject unknown fields and are limited to 64 KiB. `GET /api/v1/users/audit` supports pagination and `user_id` filtering.

Go SDK: `ManagedUsers`, `ManagedUser`, `UpdateUser`, `ChangeUsers`, `UserAction`, `UserAudit`. CLI: `jms user list|show|update|archive|restore|revoke|batch|audit` using existing platform authentication. Update/batch read JSON via `--file` or standard input with `--file -`. Archive/restore/revoke require `--revision N`. Use protected authentication files for credentials; do not place them in JSON or command arguments.

## Persistence and boundaries

Standalone first, with PostgreSQL single-active HA. User state, credential revocation and lifecycle audit commit atomically in a v3 user document. Legacy arrays and v2 documents are read and migrated on the next write. Old binaries cannot read v2: back up before upgrade and deploy compatible binaries to every takeover node. Multiple active writers are unsupported.

If session-document cleanup fails, the committed user generation still fences old sessions on takeover. Cleanup is best effort. New administrative changes prune audit older than six months, with at most 5,000 events retained; there is no scheduled erasure. Records contain actions, field names, actors, identity IDs, states and revisions. It excludes name/comment values and credentials. The lifecycle list also records personal password changes and administrative password/TOTP recovery. Creation and personal MFA enrollment changes are excluded.

Administrative password/TOTP recovery is covered in [Password security](./PASSWORD-SECURITY.en.md). Permanent erasure, bulk user import, directory state writeback and complete Enterprise identity governance remain outstanding. See [Testing](./TESTING.en.md) for verification evidence.
