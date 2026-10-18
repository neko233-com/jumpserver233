# Platform password security and credential recovery

> [中文](./PASSWORD-SECURITY.md) | English

Local platform passwords support role-specific minimum length, character classes, history and age. Administrators can separately reset passwords or local TOTP. Web, Go SDK and CLI share native Go logic. Default administrator creation keeps its startup rules; policy changes never reset an existing password. Remote SSH credentials retain separate [weekly rotation plans](./ROTATION-PLANS.en.md).

Policy fields reference the [official JumpServer definitions](https://raw.githubusercontent.com/jumpserver/jumpserver/dev/apps/settings/serializers/security.py), reviewed on 2026-10-18. The competitor remains [JumpServer Enterprise](https://www.jumpserver.org/enterprise.html); overall parity remains in progress.

## Policy and scope

Settings → Security → Password security requires global `security.manage`. Operators and administrators have separate minimums of 12–128 bytes and maximum ages of 0–36500 days. Passwords are capped at 256 UTF-8 bytes with no control characters. Uppercase, lowercase, digits and symbols can be required separately. Zero disables age enforcement. Length/classes apply to new passwords; age also applies to existing local passwords. Legacy records use creation time until the first password change.

History is 0–24 recorded passwords. Disabling history does not retrospectively record old passwords from subsequent changes. Known passwords use user-scoped HMAC-SHA256 fingerprints derived from the Vault key. The unknown current password of a legacy record can retain one original scrypt salt/hash for history checks. No plaintext is stored; records are bounded and ordinary history checks use fingerprints. Enabling history or age requires the Vault key. A store marker checks key consistency between nodes.

Changed, revisioned policies atomically save configuration, audit and new generations for all local identities. Local sessions, permanent tokens, AccessKeys and pending sign-ins are revoked, including the actor's session. The UI returns to sign-in. Identical settings with the current revision return the existing policy without audit or revocation; stale revisions conflict. The UI disables unchanged submissions. External providers retain control over external passwords and accounts.

## Expired or mandatory password changes

Valid password/Passkey → local MFA/mandatory enrollment → required RADIUS factor → restricted password change → fresh sign-in → login review and session. The restricted step cannot operate assets and preserves access policy, MFA and factor checks.

Each user has at most one capability bound to identity generation, verified login proof, policy revision, source IP and a five-minute lifetime. Only its digest and encrypted proof persist. Browsers receive an HttpOnly, SameSite=Lax, path-limited cookie with no token in the response. CLI capabilities use a POSIX 0600 or Windows protected-DACL state file (current user and SYSTEM); stdout contains only next steps and metadata. Refresh can resume; cancellation or success prevents replay. Restart and PostgreSQL single-active takeover preserve it, while provider, RADIUS, MFA, credential, source and policy checks remain current.

Completion clears mandatory change status and revokes prior sessions/API credentials. Sign in with the new password. Ordinary profile password changes preserve the current login session and existing API keys/permanent tokens, while revoking other login sessions. Generations fence stale session documents even when cleanup writes fail. Cleanup is best effort; the retained session may also require sign-in after takeover. Expiry is checked during authentication, requests and continuous authorization; no exact-time erasure timer is configured.

## Administrative recovery

Platform users provides Reset password and Reset TOTP. Both require `users.manage` plus independent `users.credentials.manage`; administrator targets additionally require `roles.manage`. Self-recovery through administrative endpoints is rejected. Revision conflicts abort changes. Restore archived identities first; disabled identities remain disabled. Grants and groups remain configured.

Password reset is local-only and defaults to requiring a change on next sign-in, with an explicit opt-out. The new password must satisfy current policy/history and is never returned in responses, audit or stdout. TOTP reset clears local TOTP secrets, consumed steps and recovery codes. Enrolled Passkeys remain and use their own revocation controls. Global MFA requirements remain effective and can require enrollment again.

## API / SDK / CLI

- `GET|PUT /api/v1/settings/security/passwords`: policy/revision. `GET …/audit?offset=0&limit=25`: audit, maximum page size 100.
- `GET /api/v1/authentication/password-policy`: public requirements without credentials or audit.
- `POST /api/v1/users/{id}/password/reset`: `revision`, `new_password`, optional `force_change` (default true). `POST …/{id}/mfa/reset`: `revision`.
- Login returns HTTP 202 and `password_change_required`. SDK callers also receive `change_token`; browsers use the scoped cookie. `GET …/authentication/password-change/pending` resumes browsers; POST accepts the CLI `change_token`.
- `POST …/password-change/complete`: `new_password` and optional CLI `change_token`. `POST …/cancel`: optional `change_token`. Completion returns `password_changed: true`, without a platform token.
- SDK: `PasswordPolicy`, `SavePasswordPolicy`, `PasswordPolicyAudit`, `ResetPassword`, `ResetMFA`, `ChangePassword`; `Authentication` adds password-status/complete/cancel.
- CLI: `jms auth password-settings|password-save|password-audit`; `jms user reset-password <id> --file -`, `reset-mfa <id> --revision N`, `password --file -`. Restricted authentication uses `jms auth login|status|continue --state-file PATH` and JSON on stdin. Completion returns the next step login.

## Persistence and audit

Standalone first, with PostgreSQL single-active support. Writes use a v3 user document and read legacy arrays/v2. Older writers cannot use v3. Back up and upgrade every takeover node. Active SSH/RDP/monitors retain their initial identity generation and close at recurring authorization checks; online connections do not migrate.

User audit adds password_change/password_reset/mfa_reset with field names and identity metadata only. Policy audit stores before/after configuration and affected counts. Neither contains passwords, MFA secrets, recovery codes or capabilities. New changes prune entries older than six months, capped at 5,000 user events and 1,000 policy events. No scheduled erasure is configured.

Expiry reminder mail, breached-password lists, email password reset, directory writeback, idle-account disablement, configurable account/IP locks, bulk user import and production HA drills remain outstanding. This feature does not establish complete Enterprise parity.
