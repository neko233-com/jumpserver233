# Windows and database account PAM

> English | [中文](./ACCOUNT-PAM.md)

## Current boundary

E18 code, cases and bilingual UI have been authored. **Verification has not run.** The user's gate requires all 42 capability groups to be implementation ready before unified verification. This document describes the candidate implementation and provides no native Windows, database or production acceptance evidence.

Use `/console/pam`, `jms pam` or Go `sessionclient`. PAM reuses the asset Vault, managed accounts, enrollment receipts, rotation plans, seven-day scheduling, audit and credential recovery. Single-node deployment adds no resident service, database, Agent or port. Linux SSH lifecycle operations remain in [remote account management](./REMOTE-ACCOUNTS.en.md).

| Target | Transport and pinned identity | Collection and reset scope |
|---|---|---|
| Windows local accounts | Existing OpenSSH with pinned host key; local SAM SID | Built-in PowerShell `Get-LocalUser` / `Set-LocalUser`; collector needs local account management rights |
| PostgreSQL | Verified TLS; cluster role OID | Login roles; writes a SCRAM-SHA-256 verifier rather than placing the plaintext password in DDL |
| MySQL | Verified TLS; exact `user@host` and authentication plugin | `mysql_native_password`, `caching_sha2_password`, `sha256_password`; refuses accounts with a secondary password |
| MariaDB 10.4+ | Verified TLS; exact `user@host` and authentication plugin | Single native `mysql_native_password` accounts in `mysql.global_priv` / `mysql.user`; excludes roles, external authentication and multiple-authentication chains |
| SQL Server | Verified TLS; instance SQL login SID | Enabled SQL logins; fixed parameterized batch, system identifier quoting and a reset transaction |

Windows domain accounts remain at their directory identity source; PAM does not modify AD. Oracle, DB2 and Dameng remain E26 protocol gaps. MySQL has no equivalent of PostgreSQL's role OID: its pin identifies the logical `user@host` and plugin, and cannot detect deletion/recreation preserving both.

## Workflow

1. Configure the asset and collector credential. For Windows, use SSH and select Windows local-account mode on the PAM page. Disable SSH key rotation first; an existing directory-constrained configuration cannot enter this mode. Databases require the corresponding protocol and valid TLS CA/server name.
2. Collect accounts. Collection reads identity metadata only, never remote passwords or password hashes. It installs nothing and changes no password. Inventory is bounded to 1,000 principals; larger inventories fail explicitly.
3. Select an account, preview and confirm enrollment. New records need a known initial password; existing password records may retain their saved credential. Preview rereads native identities and binds the actor, request, input and asset/account revision. Confirmation stores metadata and encrypted credentials only.
4. Open [rotation plans](./ROTATION-PLANS.en.md), select a target and a privileged collector on the same pinned host or database instance. Use batch/manual/periodic operations, checks, explicit retries and recovery. Database resets use database privileges; collectors are not interchangeable across protocols.

New PAM enrollment disables seven-day automatic rotation by default. Opting in uses the existing asset scheduler as the target account itself, which must be able to connect and reset its own password. Windows accounts without SSH logon and database accounts without self-reset privileges should keep this option off and use a 168-hour plan with a privileged collector. Saving an enabled periodic plan may execute immediately; existing confirmation text applies.

Windows checks use the collector to call the system credential API and verify the SID, so the target local account does not need SSH logon rights. Ordinary SSH checks authenticate over SSH only. Database checks authenticate and verify the actual OID, `CURRENT_USER()` or SID. MySQL authenticates through `information_schema` without granting application database access. Windows monitoring currently reports SSH reachability and latency; it neither executes Linux `/proc` probes nor fabricates CPU/memory data.

## Permissions, idempotence and recovery

- Every PAM endpoint requires current organization `assets.view_all` and access policy approval. Collection additionally requires `accounts.discover`. Mode changes require `accounts.manage` + `assets.rotate`; preview/confirmation also require `accounts.import` + `accounts.discover`.
- Generic managed-account updates and imports carrying PAM metadata also require independent `assets.rotate`. Rotation, fixed passwords, privileged collectors and checks retain their respective `accounts.rotation.*` permissions. Windows checks additionally authorize the chosen privileged collector and its access policy.
- Passwords are write only. API, CLI output and audit expose identities, revisions and states. Windows sends base64 UTF-8 JSON through encrypted SSH stdin; the command contains a fixed PowerShell script, with no password in arguments, environment or interpolated script text.
- Before reset, old/new credentials and request metadata are durably encrypted. Native mutation checks identity and current authorization. An unknown result authenticates staged/old candidates before commit/abort; an unconfirmed result stays pending. Recovery does not send another password reset.
- Replaying an enrollment or plan request returns its original receipt. Changed input under the same request, another actor's confirmation, expired previews and revision conflicts are refused. Browser retries after a lost response preserve the original request ID and payload.
- Copies of the same pinned remote identity across organizations use the existing shared credential transaction: one reset updates their independent encrypted Vault records without granting access to another organization. Different MySQL Host values are separate identities.
- Asset envelope **5** preserves PAM metadata. Old arrays/v2/v3/v4 retain their original supported contents and reject injected PAM/recovery fields. Older binaries must not ignore v5. Downgrades require the complete pre-upgrade snapshot; see [upgrade compatibility](./UPGRADE-COMPATIBILITY.en.md).

Database audit, SQL events/replication and administrator logging have independent controls. The application keeps plaintext credentials out of its own output, errors and audit; it cannot promise that an external database never records sensitive DDL. PostgreSQL uses a pregenerated SCRAM verifier, which remains sensitive authentication material. MySQL preserves the pinned plugin explicitly and refuses a secondary password so a still-valid old password cannot be mistaken for successful revocation.

## REST and CLI

| Method | Path under `/api/v1/assets/{assetID}` | Purpose |
|---|---|---|
| GET | `/pam/principals` | Current native identity metadata |
| PUT | `/pam/platform` | Save `platform`, `version`, `request_id` |
| POST | `/pam/import-preview` | Bind native identity and enrollment input |
| POST | `/pam/import-commit` | Same input plus `preview_token`; save/replay receipt |

Enrollment input contains `principal`, `version`, `update`, optional `name`/write-only `password`, `automatic` and `request_id`; confirmation adds `preview_token`. `version` is the current existing-account version or the physical asset version for a new account. Do not put passwords, platform tokens or signing secrets in tracked files or command arguments.

```text
jms pam discover ASSET_ID
jms pam platform ASSET_ID --file -
jms pam preview ASSET_ID --file -
jms pam commit ASSET_ID --file -
```

Pass structured JSON through stdin. Existing CLI platform identity, organization header and signing configuration apply. Use the existing `jms account rotation` interfaces for batch execution. SDK methods are `PAMPrincipals`, `ConfigurePAMPlatform`, `PreviewPAMImport` and `CommitPAMImport`. Enrollment writes a credential; normal SSH/Agent operations continue to use the server Vault without exposing the target password to the caller.

## Cases awaiting the unified run

- Testify: input/capacity/cancellation, independently salted SCRAM keys, fixed Windows script/Unicode stdin/incorrect host key/output bounds, MySQL plugin/Host and SQL Server SID/UTF-16 limits.
- Application/API/SDK/CLI: independent authority, forged principals, stale revision, another actor, receipt replay, old-format refusal, Vault reopen, one cross-organization mutation, uncertain-result recovery and changed collector credentials.
- Real PostgreSQL/MySQL/MariaDB/SQL Server: reuse existing TLS fixtures; dedicated `pam_admin` creates unique `pamqa_` accounts. Authenticate the new credential, reject the old one and incorrect identity. Delete only owned accounts, repeating deletion twice.
- `web/e2e/pam.spec.ts`: four actual databases, collection, English/Chinese and narrow layouts, enrollment preview/confirmation, receipt replay, planned rotation/authentication and cleanup. No second database stack is added.
- Optional native Windows: `TestRealWindowsPAMLocalSAMAndCollectorCredentialProof` requires `JMS_TEST_WINDOWS_PAM_DISPOSABLE=true` and local environment `JMS_TEST_WINDOWS_PAM_HOST/PORT/USER/PASSWORD/FINGERPRINT`. It creates one unique local `pamqa_` account on the explicitly disposable OpenSSH fixture, pins its SID for cleanup and repeats deletion. Missing fixtures skip; that skip cannot be reported as native Windows acceptance.

No fixture or verification resource was started in this batch. The final run retains compact reports and essential sanitized screenshots. Existing isolated runners remove owned containers, data, volumes and attributable caches without pruning other projects.

## Native references

PostgreSQL accepts pregenerated authentication verifiers and warns about password DDL logging: [CREATE ROLE](https://www.postgresql.org/docs/current/sql-createrole.html). MySQL plugin and secondary-password semantics: [ALTER USER](https://dev.mysql.com/doc/refman/8.4/en/alter-user.html). SQL Server reset interface: [ALTER LOGIN](https://learn.microsoft.com/en-us/sql/t-sql/statements/alter-login-transact-sql). Windows local reset and credential validation: [Set-LocalUser](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.localaccounts/set-localuser), [PrincipalContext.ValidateCredentials](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.accountmanagement.principalcontext.validatecredentials).

MariaDB's `ALTER USER ... IDENTIFIED VIA` removes authentication methods not listed in the statement. This implementation refuses `auth_or` chains to preserve existing login methods: [MariaDB ALTER USER](https://mariadb.com/docs/server/reference/sql-statements/account-management-sql-statements/alter-user).
