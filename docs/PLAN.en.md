# jumpserver233 Master Plan

> [中文](./PLAN.md) | English

[AI assistant and conversation audit](./AI-ASSISTANT.en.md): organization provider settings/write-only keys, platform authority, native HTTPS, receipts/revisions, revocation, encrypted history/archive, bilingual Web, CLI/SDK and cases are authored. E34 awaits unified verification after all 42 groups are ready.

[Trusted interactive SSH submission directories](./INTERACTIVE-DIRECTORIES.en.md) authors native private framing, kernel cwd/input-queue proof, one-use leases, approval remeasurement, shared controllers and encrypted audit. Together with batch/template/schedule/Playbook propagation this forms E14. Code, Testify and existing native/bilingual browser entrypoints are authored and unrun; unified verification waits for all 42 groups.

[Global organization overview](./GLOBAL-ORGANIZATIONS.en.md) authors independent global read authority, cross-organization inventory/cached health/activity counts, bilingual Web, CLI/SDK and revocation/concurrency/reopen/existing-standby cases. E08 awaits verification after all 42 implementation groups are ready.

[Sign-in SMS MFA](./SMS-MFA.en.md) authors native platform transport, initial/personal binding, enforcement, one-time capabilities, limits/encryption, TOTP/RADIUS/review, bilingual Web, CLI/SDK and cases. E06 awaits verification; no tests, builds, browser or Docker runs before all 42 groups are implementation-ready.

[Native cloud SMS and enterprise bots](./NATIVE-NOTIFICATIONS.en.md) authors three cloud SMS providers, CMPP 2.0, four bots, settings receipts/secret isolation, bilingual Web, CLI/SDK, protocol/permission/reopen and browser cases. E22 awaits verification. Cases reuse the TLS/CONNECT fixture and a temporary organization, with essential screenshots and repeated cleanup. No validation has run; E06 has separate SMS MFA documentation.

[Enterprise QR sign-in](./ENTERPRISE-LOGIN.en.md) authors native WeCom, DingTalk and Feishu/Lark authorization, tenant/internal membership checks, isolated sources, MFA/review/audit, bilingual Web, CLI/SDK and cases. E05 awaits verification. No tests, builds, browser or Docker runs; actual tenants and mobile scanning await unified acceptance.

[Multiple identity sources and directory synchronization](./IDENTITY-SOURCES.en.md) authors named LDAP/OIDC/CAS/SAML, separate encryption/callbacks/credential revocation, complete LDAP collection, group/organization mappings, schedules/retry/abort, bilingual Web, CLI/SDK and cases. E04 is implementation-ready and unverified.

[Fixed acceptance checklist and overall progress](./PROGRESS.en.md) separately counts stable SSH and the full baseline, recording closed/partial/undelivered items, batch delta and closing gates. Progress follows this checklist and named acceptance, rather than test or phase counts.

The user's 2026-10-20 workflow instruction requires all checklist features, cases and bilingual docs before tests, builds, browser or Docker verification. SSH remains the development priority; prior SSH-only acceptance batches no longer apply. [Platform announcement](./ANNOUNCEMENTS.en.md) and [organization label](./LABELS.en.md) source, cases and bilingual docs are authored. E41 is implementation-ready, awaiting verification with no accepted credit.

E36 [SSH user certificates](./SSH-CERTIFICATES.en.md) author built-in CA/OpenBao signing, short-lived account/gateway authentication, two-phase CA rotation, Web/CLI/SDK, cases and bilingual docs. They await unified verification after full implementation.

E35 [external replay storage](./REPLAY-STORAGE.en.md) authors S3/OSS/COS/OBS/SFTP/PostgreSQL objects, encrypted archives/retries, lifecycle/drain integration, authorized replay, controlled local removal, cache/backups, bilingual Web, CLI/SDK and cases. It is implementation-ready awaiting verification. Actual SSH/SFTP, Web SSH output, one restart, receipts and bilingual narrow-screen cases join existing unified entrypoints without executing early.

Phase 7 adds [SSH account connectivity checks](./ACCOUNT-CHECKS.en.md): password/key authentication for default and named accounts, independent scheduling, results/failure notifications, explicit retries and no automatic replay after interruption. Full Enterprise parity remains in progress.

Phase 7 adds [individual/bulk SSH rotation retries](./ROTATION-RETRIES.en.md): select unsuccessful items from terminal runs, exclude successes, combine aliases, bind current plan revision, claim each source once and retain Web/CLI/SDK, linked audit and takeover. Full Enterprise parity remains active.

Added [fixed-password plans and idempotent saves](./FIXED-PASSWORDS.en.md): specified/random sources, independent permissions, write-only input, save receipts, immutable snapshots, organization constraints and recovery. Default seven-day rotation continues random generation; the full Enterprise objective remains active.


Added [generated SSH password policy](./SSH-PASSWORD-POLICY.en.md): organization rules, shared seven-day/manual/planned generation, merged shared-account constraints, independent permissions, Web/CLI, encrypted receipts and backup retention. Per-plan additional constraints and immutable run snapshots are connected; full Enterprise parity remains in progress.

## Current priority: stable SSH release (user change, 2026-10-19)

Added [controlled SSH execution directories](./EXECUTION-DIRECTORIES.en.md): single-command Web/CLI selects a real workspace starting directory; approvals bind root/cwd objects and command policy for exact/subtree/full-path RE2 rules. Go/Testify 1598, Linux race 171, complete production regression 86/86, six native platforms and current bilingual desktop/mobile layout acceptance passed. Clean Docker source builds and browser smoke also passed; see [testing](./TESTING.en.md). Existing [SSH/SFTP login review](./ACCESS-REVIEWS.en.md) still binds connection/gateway and workspace-root objects. Complete interactive cwd, arbitrary shell semantics and full Enterprise parity remain in progress.

Added [published-release checks and native artifacts](./UPDATES.en.md): Web/CLI/SDK checks, optional automatic checks, revisions/idempotent receipts, archive verification, six-platform packaging and staging. [Standalone installation transactions](./INSTALLATION.en.md) add encrypted checkpoints, offline preflight, first-start health/traffic gates, rollback before release and old-service resumption. After release, new data is preserved. [Scheduled standalone installation](./INSTALLATION-SCHEDULE.en.md) connects fixed candidates, drain, shutdown, checkpoints and first startup. [Automatic preparation/window installation](./AUTOMATIC-UPDATES.en.md) adds default-off policy, official digest binding, revisions and one-attempt receipts. Pinned historical-source data-retention rehearsal passed; official historical-release and earlier-format migration remain pending; [pre-upgrade draining](./SERVICE-MAINTENANCE.en.md) adds standalone Web/CLI, cross-organization activity and process-instance binding; the general updater is incomplete.

This batch's [encrypted standalone backup/recovery](./BACKUP.en.md) passed unified verification: native `jms backup`, process exclusion, external-key fingerprint checks, format/path/integrity preflight, Docker mount-point recovery and idempotent restore/rollback journals. Go/Testify: 1,523 passed; Linux race: 745 passed; production browser: 85/85; Docker: 7/7. See [verification](./TESTING.en.md).

Deliver a [practical, stable SSH bastion with few dependencies](./SSH-FIRST.en.md) first: standalone local persistence, Web/CLI SSH, update checks and data-preserving upgrades, full export/import, sensitive command audit/review and trusted directory rules. Overall Enterprise parity remains a long-term reference. Other protocols, cloud providers and complex integrations follow actual need and do not gate this release. Offline standalone backup is delivered. A general updater, strong directory restrictions, cluster backup and live backup remain pending; macOS recovery or command regex cannot substitute for those acceptance requirements.

This batch's [cloud SSH IP migration](./ASSET-DISCOVERY.en.md) passed unified verification: stable instance identity and existing host-key trust, preserved parent/child credentials, pending-operation isolation, invalidated old SSH connection bindings, migration receipts and bilingual Web/CLI/SDK. Real OpenSSH/gateway, full Go, Linux race, 85 production-browser cases and Docker restart evidence appear in [verification](./TESTING.en.md). No intranet deployment or formal Release.

Phase 7 delivers [LAN asset discovery and sync](./ASSET-DISCOVERY.en.md): sources/policies, bounded scans, pinned SSH gateways, one-use import, metadata sync, missing-host handling, native scheduling, organization permissions and bilingual Web/CLI/SDK. See [verification stages](./TESTING.en.md). AWS international/China, Alibaba Cloud ECS and Tencent Cloud CVM inventory adapters passed signed-fixture, Go/race, isolated Docker and complete production-browser verification. Real cloud-account acceptance, other clouds, multi-node mapping and other Enterprise features follow actual need. Intranet deployment was cancelled; publish once after stable SSH acceptance.

Phase 7 adds [branding](./BRANDING.en.md): bilingual site/sign-in titles, five themes, four image slots, registration footers, global permission/audit, CLI/SDK and PostgreSQL single-active takeover. See [unified verification](./TESTING.en.md). Overall Enterprise parity remains in progress.

Phase 3/5 adds [SSH monitoring history](./MONITOR-HISTORY.en.md): encrypted hourly segments, seven-day minute records, missing/offline distinctions, current binding and asset-view authorization, native Web charts and CLI/SDK, with PostgreSQL single-active takeover reads. Overall Enterprise parity remains in progress.

Added the BuildWorld intranet `builtin` macOS deployment entry and default `Jenkinsfile_mac_single`, with persistent data, same-port frontend, idempotent activation and recovery. See [deployment](./BUILDWORLD.en.md) for acceptance boundaries. Enterprise parity and production HA continue through the phased roadmap.

Local password policy, history/expiry, restricted password changes and independently authorized password/TOTP recovery support Web/CLI/SDK and v3 user-document takeover. See [Password security](./PASSWORD-SECURITY.en.md). Overall Enterprise parity remains in progress.

Platform identity editing, expiry, archive/restore, credential revocation, atomic batches and metadata audit are available in Web/CLI/SDK. See [User lifecycle](./USERS.en.md). Overall Enterprise parity remains in progress.

Native PAP RADIUS primary sign-in, mutual TLS, multiple challenges and a shared additional factor support Web/CLI/SDK, preserving local MFA and platform approvals. See [RADIUS authentication](./RADIUS.en.md). Overall Enterprise parity remains in progress.

Go native Playbooks provide revisioned workspaces, organization publication, source snapshots, sequential SSH modules, conditions/loops/retries, durable recovery and Web/CLI/SDK. See [Native Playbooks](./PLAYBOOKS.en.md). Full Ansible and Enterprise parity remain in progress.

SSH command plans support five-field cron, explicit timezones, DST, missed-run policies, previews, revisioned editing and change audit, with a complete Ops CLI. See [Calendar schedules](./SCHEDULING.en.md).

Phase 5 adds [operations reports](./REPORTS.en.md): 12 organization sources, explicit global identity statistics, UTC daily trends, native permissions, partial-source labels, audited CSV before download, Web/CLI/SDK and PostgreSQL scoped receipt takeover. Scheduled reports, PDF, a full historical warehouse and Enterprise parity remain in progress.

Phase 5 adds [platform sign-in audit and independent platform notifications](./LOGIN-AUDIT.en.md): global authentication steps, MFA, commit before session delivery, native review cursors, permission filtering, CSV, Web/CLI/SDK and PostgreSQL single-active takeover. Native cloud SMS, IM and full Enterprise parity remain open.

Phase 3/5 adds [native SSH monitoring alerts](./MONITOR-ALERTS.en.md): eight conditions, host/node scopes, sample counts and duration, recovery thresholds, maintenance mute, acknowledgement, notifications and Web/CLI/SDK. Organization encryption and PostgreSQL single-active recovery are integrated. Escalation policies and production HA acceptance remain open.

Phase 5 adds the [notification center](./NOTIFICATIONS.en.md): in-app unread messages, personal subscriptions/contact verification, TLS SMTP, signed HTTPS Webhooks, custom SMS gateway, ticket/SSH job/rotation results, delivery receipts and explicit retries, with organization encryption and PostgreSQL single-active recovery. Security messages now cover native asset/command reviews, blocked SSH input, risk scans, host monitoring and Agent repair reports, with current-permission inline review details. Platform sign-in aggregation now uses independent global notifications; native cloud SMS and instant messaging remain open.

Phase 5/7 adds [access request tickets](./ACCESS-TICKETS.en.md): published asset/node and account scopes, one to five distinct reviewers, user/group/role selectors, copied discussion, amendment reset, time-limited native grants, revocation and recovery across Web/CLI/SDK with organization encryption. External delivery is in the notification center; production multi-active, the phase and full Enterprise goal remain in progress.

Phase 7 adds [SSH credential rotation plans](./ROTATION-PLANS.en.md): multi-host passwords/keys, optional privileged accounts, manual/once/weekly scheduling, per-account results, cancellation/recovery and Web/CLI/SDK, with organization encryption and PostgreSQL single-active takeover. Windows/database rotation, automatic risk remediation and production HA acceptance remain open.

Phase 7 adds [SSH account risks](./ACCOUNT-RISKS.en.md): seven local checks, human review, metadata CSV, periodic policies and Web/CLI/SDK, with organization encryption, live permissions and PostgreSQL single-active takeover. Usage uses retained platform audit. Remote OS expiry/login history, automatic bulk remediation and complete Enterprise acceptance remain open.

Native creation, disabling, restoration, retained home deletion and explicit recovery for regular Linux users are covered in [Remote account lifecycle](./REMOTE-ACCOUNTS.en.md).

Phase 7 adds managed SSH accounts: independent encrypted credentials, account grants/enablement/rotation, discovery association, named gateways, Web SSH/SFTP/workbench and platform CLI, with standalone and PostgreSQL active/standby takeover. CSV/XLSX bulk credential import now supports multi-host create/update, preview, atomic commits and idempotent receipts; see [Account import](./ACCOUNT-IMPORT.en.md). Other protocol account management remains open. See [Managed SSH accounts](./MANAGED-ACCOUNTS.en.md). Overall Enterprise parity remains in progress.

Local Linux discovery supports native Go collection, pinned gateways, both approvals, ongoing authorization, complete-page publication, encrypted present/missing findings, human review and Web/CLI. Interval plans add per-run approval isolation, pause cancellation, credential revision refresh and independent run archives, with standalone and PostgreSQL active/standby takeover. See [Scheduled account discovery](./SCHEDULED-ACCOUNT-DISCOVERY.en.md). Other platforms and retention policies remain open.

Phase 6/7 adds read-only live RDP monitoring: independent `audit.desktops.monitor_all`, durable viewer audit, source/membership/current-permission checks, Web/CLI capture and bounded frame decoding. Historical replay permission cannot read another user's active screen. Standalone comes first; live state does not migrate. See [Live RDP monitoring](./RDP-LIVE-MONITOR.en.md). Overall phases remain in progress.

Phase 4/7 adds terminal collaboration: named platform users, expiring codes, read-only/single-writer control, removal/revocation, continuous authorization, dual-identity command review and collaboration audit, with Web/CLI and bilingual UI. It defaults off with independent `sessions.share` permission. Live state does not migrate; RDP sharing remains open. See [Session collaboration](./SESSION-SHARING.en.md). Overall phases remain in progress.

Agent lifecycle supports account-scoped boot startup, one-minute crash recovery, disabling supervision and data-preserving uninstall, with pinned upgrade/rollback, interrupted checkpoints and separately authorized SSH protection policies. A native Go companion now passes isolated Linux checks for actual cron, container reboot and ban restoration after table loss. It uses existing cron without automatic privilege elevation. Centralized repair events and scheduled collection are covered in [AGENT-EVENTS.en.md](./AGENT-EVENTS.en.md). See [host tools and agents](./HOST-PLUGINS.en.md) for builds and other remaining scope.

SSH host tools and native agent operations are part of the current goal: detection, installation, status and lifecycle start with banhack233 and node_exporter, sharing platform identity, organizations, review and job audit. This Linux installation/lifecycle/API/CLI/UI batch passed Go/race and full browser acceptance. See [host tools and agents](./HOST-PLUGINS.en.md).

RDP adds native Go desktops, Web mouse/keyboard and Unicode text, platform-identity CLI capture, independent review, method policies, encrypted graphical replay and explicit text clipboard. Actual Windows NLA and complete Enterprise high-definition parity remain unverified; see [RDP](./RDP.en.md).

Telnet adds native Web/CLI terminals, device prompt patterns, NVT negotiation/window sizes, verified TLS/pinned gateways, independent login review, command/recording audit and single-active takeover. Device MFA, scripted login and Telnet rotation remain open; see [Telnet](./TELNET.en.md).

Kubernetes adds cluster assets, namespace/Pod/container selection, Web/CLI terminals, verified TLS/pinned gateways, independent login reviews, command/recording audit and single-active takeover. File transfer, container jobs, resource management and cloud-token refresh remain open. See [Kubernetes](./KUBERNETES.en.md).

Redis/MongoDB add native protocols, JSON command consoles, key/collection browsing, verified TLS/gateways, CLI, review/redacted audit and active/standby takeover. MongoDB supports authentication databases, cursor batches and distinct NULL/missing fields. Automatic node discovery and native TCP client proxying remain open. See [NoSQL](./NOSQL.en.md).

ClickHouse adds official HTTPS SQL access: verified TLS, typed parameters, pinned SSH gateways, UI/CLI, server read-only mode, cancellation cleanup, reviews and redacted audit. Configuration/indexes support existing active/standby HA; native TCP proxying and full Enterprise database parity remain open. See [ClickHouse](./CLICKHOUSE.en.md).

Enterprise database access adds SQL Server: official Go TDS driver, verified TLS, @p1 parameters, batches/multiple result sets, pinned SSH gateways, UI/CLI, reviews and redacted audit. Read-only mode combines restricted SELECT/CTE reads with rollback; writes preserve server transaction semantics and uncertain outcomes. Configuration/audit use the existing active/standby store. Integrated Windows identity, procedure output parameters and native TCP client proxying remain open. See [SQL Server](./SQLSERVER.en.md).

Phase 3 database progress adds native MySQL/MariaDB: verified TLS/read-only defaults, bound queries, gateways, browser/CLI, review/audit and active/standby takeover. Writes use auto-commit; cancellation cannot undo completed changes, and procedures report server-managed transactions. Other protocols and persistent transactions remain open. See [MySQL/MariaDB](./MYSQL.en.md).

Phase 3 database progress: native PostgreSQL with verified TLS/read-only defaults, browser SQL console and jms db, bound parameters, cancellation/timeouts, bounded results, login/SQL reviews and encrypted redacted audit. Indexes support single-node and PostgreSQL active/standby storage. Other database protocols, persistent transactions and database password rotation remain open. [PostgreSQL](./POSTGRESQL.en.md).

Managed copies of an identical SSH private key coordinate vault promotion and old-key retirement within/across organizations, including archived ones. See [key rotation](./SSH-KEY-ROTATION.en.md).

Managed copies of the same SSH password account support coordinated remote rotation, encrypted decision recovery and vault synchronization across organizations, including disabled/archived ones. See [password rotation](./PASSWORD-ROTATION.en.md).

Organizations isolate resources, roles and operational audit through `X-JMS-ORG`, browser switching and Agent CLI selection. Standalone storage and PostgreSQL single-active HA are supported. See [Organizations](./ORGANIZATIONS.en.md). Full Enterprise parity remains in progress.

Platform sign-in approval and console notifications use verified identities, original-source one-use completion, encrypted persistence and PostgreSQL single-active HA. See [Platform sign-in reviews](./PLATFORM-LOGIN-REVIEWS.en.md). Full Enterprise parity remains in progress.

Source, weekly-hour and execution-channel restrictions support standalone and single-active HA. See [Access policies](./ACCESS-POLICIES.en.md). Full Enterprise parity remains in progress.

SSH key installation, verified rotation, opt-in seven-day scheduling and persistent staged recovery are described in [SSH key rotation](./SSH-KEY-ROTATION.en.md).

Targets and gateways support imported SSH private keys with write-only input, vault encryption, public fingerprints and verified history restore. Password rotation remains password-specific. See [SSH private keys](./SSHKEYS.en.md).

SSH gateway routing supports up to three pinned hops across monitoring, Web SSH, CLI, SFTP, jobs and password rotation. Configuration and encrypted credentials support standalone and PostgreSQL single-active HA; see [SSH gateways](./GATEWAYS.en.md). Full Enterprise parity remains in progress.

Passkey registration, device-verified sign-in, local MFA, revocation, and HA recovery: [Passkey](./PASSKEY.en.md).

SAML signed assertions, browser binding, local MFA, encrypted SP identity, and configuration audits: [SAML](./SAML.en.md). Remaining profiles and production IdP integration are open.

Align all JumpServer Enterprise software features on Go + React, with Community features as the implementation foundation. This document is the requirement baseline and phase roadmap; scope disputes are resolved against this document.

## 1. Scope

Interactive session security adds configurable global idle limits, maximum duration and creation-time identity watermarks for Web / CLI terminals and RDP. RDP markers are rendered server-side; terminal recordings preserve compatible metadata. See [interactive session security](./SESSION-SECURITY.en.md).

Active SSH / Telnet / Kubernetes terminals support read-only live monitoring, separate monitoring permission and viewer audit. SSH continuously rechecks current authorization and connection revisions. See [live terminal monitoring](./LIVE-SESSIONS.en.md). Terminal collaboration and read-only RDP monitoring are delivered separately; RDP sharing, collaborative control and full Enterprise parity remain in progress.

### 1.1 Target and competitor

- **Competitor = JumpServer Enterprise** (https://www.jumpserver.org/enterprise.html). The end goal is feature parity with Enterprise (the X-Pack add-on plus app-store capabilities).
- Deliver JumpServer Enterprise features in phases. **Standalone remains the default and prioritized deployment; cluster high availability is also required and will continue to improve.**
- Cluster roadmap: PostgreSQL-coordinated single-active hot standby is implemented. Active/active load balancing, Kubernetes distributed deployment, and production failover drills remain future work. We do not inherit the Enterprise "flagship-only" restriction. Vendor support services (non-software) are out of scope.

Baseline sources: official JumpServer docs (v5), lina frontend routes, the jumpserver backend `apps/` layout, jumpserver.org Enterprise and comparison pages. See [BASELINE.en.md](./BASELINE.en.md).

### 1.2 Enterprise (X-Pack) features — alignment target for Phase 7+

Deferred during the Community phases (1–6), implemented item by item from Phase 7 (per enterprise.html and the comparison page):

- QR-code login (WeCom/DingTalk/Feishu), SMS MFA, RADIUS second-factor, login review
- RBAC role management pages, multi-org management, global org (the org-switch API stays; no admin page yet)
- Two-level approval for access tickets, login/asset-login ACL, data masking, clipboard ACL, connection-method ACL
- Account collection / bulk password rotation / account backup, Vault credential storage
- Cloud asset sync, virtual apps, UI personalization (theme/LOGO)
- Oracle/SQLServer/PostgreSQL/ClickHouse/DB2/DM database protocols, high-definition RDP, reports
- Components: Magnus, Razor, Nec, Panda, JDMC, Video Worker
- Script-based credential filling for web assets, advanced remote apps from the app store, automatic SSH account password rotation every 7 days
- Asset cap ≤ 5000 (Community limit; Enterprise flagship is unlimited; this project sets no hard cap)
- Facial recognition (Enterprise-only per enterprise.html)
- Hot-standby / distributed HA deployment (Enterprise flagship capability, Phase 7+)

### 1.3 Community core that must work

- SSH / Telnet / K8s / SFTP; RDP (web); databases: MySQL, MariaDB, Redis, MongoDB (web GUI)
- Asset tree (node inheritance) + zone/gateway multi-level proxying; platform and account management
- Grouped SSH inventory and monitoring: reachability, latency, CPU/cores, memory, network throughput, disk capacity and usage
- Web SSH and a generic agent CLI operate through the server-side bastion; remote SSH passwords are never returned to the browser or CLI, and commands/sessions are audited
- Grant rules (user/group × asset/node × account × action × time)
- Command-filter ACL; labels; session sharing; watermarking
- Audit: sessions (live/recording/monitor/terminate), commands, file transfers, logins, operations, password changes, jobs, tickets
- Auth: local, LDAP, CAS, OAuth2, OIDC, SAML2, SSO, Passkey; MFA (OTP)
- Notifications: email, SMS (basic), in-app; job center (quick commands, Adhoc/Playbook); tickets with 1–5 approval levels
- Profile: passwords/SSH keys, AccessKey, temporary tokens, MFA binding
- Full REST API (/api/v1, Swagger)
- AI assistant (ChatAI, OpenAI-compatible backend)

## 2. Tech stack (confirmed)

| Layer | Choice | Version |
|---|---|---|
| Backend | Go (monolithic Core + connector boundary layering) | 1.27 |
| Frontend build | Vite | 8.x |
| Frontend framework | React + TypeScript | 19.x |
| Toolchain | vite+ (Void's official toolchain, lint/format) | 1.x |
| UI motion | reactbits (source-installed via shadcn CLI) | latest |
| Visuals | WebGL shaders (decorative backgrounds/transitions) | — |
| Terminal | @xterm/xterm | 6.x |
| i18n | i18next + react-i18next (zh-CN / en, auto-detect) | 26.x / 17.x |

## 3. Architecture

Upstream is a Django monolith (Core) + polyglot connectors (koko/chen/lion). The Go counterpart:

```
server/                 Go module
  cmd/server/           entry: Core API + WebSocket gateway
  internal/core/        users/groups/orgs/auth/RBAC/assets/grants/audit/settings (Django apps equivalent)
    assets/             groups, inventory, encrypted credentials, and monitor status
  internal/gateway/     session WebSocket gateway (xterm ↔ connector)
  internal/connector/   protocol connectors
    sshclient/          host-key-pinned SSH + SFTP (golang.org/x/crypto/ssh)
    postgresclient/     Native PostgreSQL queries, verified TLS, SSH gateways and transactions
    mysqlclient/        Native MySQL/MariaDB, verified TLS, SSH gateways and auto-commit outcomes
    sqlserverclient/    Native TDS, verified TLS, SSH gateways, batches and multiple result sets
    clickhouseclient/   Official HTTPS SQL interface, verified TLS and typed parameters
    redisclient/        Bounded native RESP commands, verified TLS and SSH gateways
    mongodbclient/      Official BSON driver, verified TLS, fixed destinations and cursors
    kubeclient/         Kubernetes TLS API, WebSocket v5/SPDY and pinned SSH gateways
    telnetclient/       NVT, device login prompts, verified TLS/pinned gateways and window sizes
    databasewire/       Fixed-destination dialing and verified TLS
    sqlclient/          Shared database request/result limits and dialect-specific audit redaction
  cmd/jms/              agent CLI: uses server-authorized sessions without reading remote passwords
  internal/recorder/    recording (asciinema-compatible replay.json.gz) and replay
  api/v1/               REST routes in JumpServer resource-path style
web/                    Vite 8 + React 19 frontend
docs/                   PLAN/BASELINE/AGENTS docs (bilingual)
```

### 3.1 External compatibility surfaces (do not change casually)

1. REST auth compatibility target: session cookie, one-shot Bearer token (POST /api/v1/authentication/auth/), permanent token, and AccessKey/Secret HTTP signature (hmac-sha256). All four auth methods are implemented. Browser sessions use an HttpOnly `jms_sessionid` cookie; users create and revoke permanent tokens, and the server stores only their digests.
2. Multi-tenant header `X-JMS-ORG`
3. Session WebSocket (binary frames for terminal I/O + resize/clipboard/file-transfer messages)
4. Recording format asciinema-compatible `replay.json.gz`
5. MFA flow: password → OTP verification → validity window without repeat checks

### 3.2 Protocol implementation strategy (confirmed)

- SSH + SFTP: real implementation (Phase 4)
- PostgreSQL, MySQL, MariaDB and SQL Server use real drivers; ClickHouse uses the official HTTPS interface. Redis uses bounded native RESP and MongoDB uses the official BSON driver. All support verified TLS and SSH gateways. Each protocol's documentation defines its read-only and transaction boundaries. Kubernetes supports real container terminals, and RDP supports native graphical access. Other databases and advanced desktop parity remain open.
- Telnet: native terminals and server-side account login, sharing grants, review, audit and gateways; other protocols attach through the connector interface in their phases

## 4. Roadmap

| Phase | Content | Status |
|---|---|---|
| Phase 1 | Skeleton: Go backend, Vite/React frontend, AGENTS.md docs, lint/build/test baseline, i18n, release/changelog workflow | Done |
| Phase 2 | Users/user groups/local auth/MFA OTP/token auth/permissions/basic settings API | In progress |
| Phase 3 | Assets/platforms/node tree/zones & gateways/accounts/grant rules/command filters/labels/SSH host monitoring | In progress |
| Phase 4 | Real SSH+SFTP, Web SSH, agent CLI bastion, session/command/file records, replay | In progress |
| Phase 5 | Full audit, notifications, job center, tickets, dashboards | In progress |
| Phase 6 | LDAP/OIDC/CAS auth backends, RDP/K8s/DB mock→real, web assets, AI assistant | In progress |
| Phase 7 | Enterprise parity (competitor): RBAC, multi-org, access control/review, asset sync, enterprise DB protocols, account collection/rotation/backup, 7-day SSH account password rotation, app store, facial recognition, UI personalization, hot-standby/distributed | In progress |

Definition of done per phase: tests/lint/build pass (commands in AGENTS.md §4; the Makefile wraps them as `make test/lint/build`, and Windows users can run the raw commands), features work end-to-end in the UI, and this document's status is updated.

Phase 2 slice delivered so far: local administrator bootstrap, password sign-in, 12-hour in-memory Bearer sessions, sign-out revocation, administrator/operator roles, and user list/create APIs. Passwords are stored as scrypt-derived hashes and failed sign-ins are rate-limited by source IP. Users can change their sign-in password from Profile after verifying the current password; the server derives a fresh hash, keeps the current session, and revokes the account's other active sessions. Profile supports up to 10 AccessKeys, encrypts secrets with the vault key using AES-GCM, and returns each secret only at creation. REST requests accept HMAC-SHA256 HTTP Message Signatures covering `(request-target)` and `date`; `jms ssh` can use `JMS_ACCESS_KEY_ID` and `JMS_ACCESS_KEY_SECRET` for the authorized session API. Optional TOTP enrollment, confirmation, disablement, and password-plus-second-factor sign-in are available. TOTP secrets use AES-GCM with the vault key, and accepted time steps cannot be replayed. Users can generate 10 one-time recovery codes after password plus fresh second-factor verification; only SHA-256 digests are persisted, login consumes a code once, regeneration invalidates the previous set, and disabling MFA clears the remaining codes. Administrators can enforce MFA for `admins` or `all` users in Settings; unenrolled accounts complete setup through a short-lived challenge, and in-scope users cannot disable MFA. Administrators can create user groups, manage operator membership, and maintain grants by user or group, asset or node, SSH account, action, and active time. Inventory, SSH session creation, and SFTP resolve direct grants, current group membership, and ancestor-node grants. Phase 3 slice: the asset-node tree supports CRUD, asset assignment, and inherited grants across descendants. Linux SSH host monitoring uses a pinned SHA256 host key to collect latency, CPU, memory, root disk, and network rates; collection defaults to once per minute while the inventory page refreshes every 15 seconds. Each host row groups CPU/memory and network/disk metrics in two columns to match the reference inventory layout. See [AUTH.en.md](./AUTH.en.md) and [SSHMONITOR.en.md](./SSHMONITOR.en.md). Phase 4 slice delivered so far: inventory rows can start a server-side SSH PTY; the WebSocket uses a short-lived single-use ticket for terminal I/O and resize; `jms ssh <asset-id>` uses the same authorized session path; session start/end events and authenticated operator identity are indexed for audit, and asciinema v2 gzip recordings are encrypted at rest with the local vault key. The Audit page lists sessions, stops active sessions, and replays completed recordings. The inventory's file manager provides authorized SFTP browsing, folder creation, upload/download/delete, and a separate transfer audit index with an Audit-page tab. Paths stay under the SFTP starting directory and do not follow symbolic links; each file is limited to 1 GiB. Command audit recognizes command lines submitted with Enter at common shell prompts, encrypts records per session, and forwards terminal input only after the audit append succeeds. Administrators and the session owner can read the records. Password-prompt input is omitted and common credential arguments are redacted. Administrators can configure allow/deny rules by user/group, asset/node, SSH account, match type, priority, and active time; Web SSH and Agent CLI enforce them at the shared gateway, and denials enter the encrypted command audit. Filters parse PTY input lines and deny unrecognized input when an applicable rule exists. Administrators can approve or deny command reviews in Settings; unresolved requests are denied after five minutes, and Web SSH and Agent CLI share the queue and encrypted audit flow. Full shell semantics and command results/exit codes remain outstanding. See [SFTP.en.md](./SFTP.en.md), [WEBSSH.en.md](./WEBSSH.en.md), and [COMMAND-FILTERS.en.md](./COMMAND-FILTERS.en.md).

**Competitor = the JumpServer Enterprise features at [https://www.jumpserver.org/enterprise.html](https://www.jumpserver.org/enterprise.html)** (including X-Pack). External positioning and feature gaps are checked against that page and BASELINE.md section 5.

Phase 7 credential-backup slice: credential history uses AES-GCM encryption and password edits or rotations retain up to 10 recent versions. Restore changes the remote account through SSH with its pinned host key and verifies the remote credential before updating the Vault. Backup management is administrator-only; neither the API nor page returns plaintext credentials. See [PASSWORD-ROTATION.en.md](./PASSWORD-ROTATION.en.md).

Phase 7 slice in progress: managed Linux SSH accounts support automatic password rotation every 7 days, administrator-triggered rotation, verified credential promotion, failure recovery, and audit. Failed-rotation backoff state survives service restarts and single-active HA failover. Administrators can enable SSH/SFTP login review per asset; operators must first pass the matching `connect` or `sftp` grant check. SSH permits are bound to user, asset, and account and consumed once; Web SSH and Agent CLI share this flow. SFTP approvals issue a 30-minute browser-session token whose digest alone is held server-side; every file operation validates it. Review requests and reviewer identity persist to the local file or PostgreSQL document. SFTP tokens are process-local and expire on service restart or HA takeover. PostgreSQL election lock coordinates single-active hot standby. Assets, asset nodes, users, user groups, grants, access reviews, and login-token digests are stored in shared PostgreSQL JSONB documents, with legacy JSON files imported on first startup; audit indexes, recordings, and rotation logs still require shared read/write file storage. The active node alone serves APIs, monitoring, and rotation scheduling. Login sessions continue after failover; live SSH sessions and in-memory monitoring snapshots do not migrate. Active/active operation, Kubernetes, and production failover drills remain outstanding; see [ACCESS-REVIEWS.en.md](./ACCESS-REVIEWS.en.md), [PASSWORD-ROTATION.en.md](./PASSWORD-ROTATION.en.md), and [CLUSTER-HA.en.md](./CLUSTER-HA.en.md).

Phase 5 now includes SSH command jobs from Workbench and non-TTY `jms exec`, with stdout/stderr, exit codes, timeout/cancel, request deduplication, command review, and encrypted execution audits. Workbench also supports batches of up to 50 hosts, revisioned personal command templates, saved command snapshots, one-time and interval plans, pause/resume, and per-host results. Actual dispatch rechecks grants, login reviews, and command policy. Recurring plans coalesce missed occurrences and avoid overlap. Standalone comes first; plans and run indexes also support PostgreSQL single-active HA. Ambiguous claimed dispatches are never replayed. Full Ansible and other ticket types remain open; cron/calendar scheduling is covered in [Calendar schedules](./SCHEDULING.en.md); access tickets and external notifications are covered in [Access tickets](./ACCESS-TICKETS.en.md) and [Notifications](./NOTIFICATIONS.en.md). See [JOBS.en.md](./JOBS.en.md).

Phase 7 RBAC now includes global system-role management, custom permission combinations, user/group bindings, optimistic revisions, and change audits. The server resolves current permissions for every request/scheduled dispatch. Management, connections, credentials, global audit reading, and termination/cancellation are separate capabilities. Compatible administrators retain full access, and delegated user management cannot create administrators alone. The `admins` MFA policy includes system-role holders. Standalone files and PostgreSQL single-active HA are supported; cross-organization aggregation and automatic organization mapping remain outstanding. See [RBAC.en.md](./RBAC.en.md).

Phase 6 OIDC capabilities: single-provider Authorization Code + PKCE, server-side ID-token/JWKS validation, controlled provisioning by exact issuer/subject, HttpOnly browser tickets, enforced local MFA/recovery codes, encrypted secrets, and configuration audits. External claims cannot link to local administrators or elevate permissions; disabling the provider blocks its platform identity entry points. Configuration, identity mappings, and completed shared sessions support single-active HA; incomplete flows must restart after process restart/takeover. Multiple providers, organization/group claim mapping, and federated logout remain incomplete. See [OIDC.en.md](./OIDC.en.md).

Phase 6 LDAP capabilities: single-directory LDAPS/mandatory StartTLS, encrypted write-only search credentials, stable-ID controlled provisioning, user binds, local MFA/recovery, HttpOnly platform sessions, and provider disablement. Standalone comes first; configuration, mappings, and completed sessions support PostgreSQL single-active HA. Incomplete flows restart after takeover. Directory synchronization, automatic groups, multiple directories, and production AD/OpenLDAP integration remain outstanding. See [LDAP.en.md](./LDAP.en.md).

Phase 6 CAS capabilities: one CAS 2/3 provider, exact service/browser proof binding, enforced renew, local MFA/recovery, controlled provisioning, versioned/audited configuration, and disablement. Standalone comes first; configuration, mappings, and completed sessions support PostgreSQL single-active HA. Incomplete flows restart after takeover. Federated logout, multiple providers, attribute mapping, and production CAS integration remain outstanding. See [CAS.en.md](./CAS.en.md).

## 5. Agent documentation conventions

- Root `AGENTS.md`: instructions for AI agents, organized like deepseek-harness's AGENTS.md (layered everything-is-a-plugin docs with a docs/ index) — see [../AGENTS.md](../AGENTS.md)
- Wording follows the GPT-6 "Using GPT-6" spec (developers.openai.com/api/docs/guides/latest-model/gpt-6-astra.md): user instructions outrank skills/guidelines, avoid vague phrasing, state behavioral boundaries and acceptance criteria explicitly

## 6. Internationalization and releases

- Frontend: i18next Chinese/English, first-load browser-language detection, and a manual override persisted as `jms233.lang`. Static user-facing text uses translation keys.
- Documentation: Chinese/English pairs (`X.md` / `X.en.md`) with reciprocal links at the top.
- Commits: Conventional Commits (`feat:`, `fix:`, `chore:`, and others).
- Changelog: generated/updated only during a release by release-please, together with the GitHub Release. Do not maintain `CHANGELOG.md` between releases.

Current Agent slice: native component version 2 adds bounded repair journals and hash chaining. The server imports pages, detects gaps/resets and encrypts history per organization. Typed collection plans reuse authorization/reviews, refresh credential bindings before dispatch and archive terminal receipts before freeing hot history. Bilingual UI, CLI and explicit upgrades of older components are included. See [AGENT-EVENTS.en.md](./AGENT-EVENTS.en.md). This does not complete Phase 4/7 or Enterprise parity; multi-active operation, production HA, remaining protocols and enterprise extensions stay on the roadmap.

Agent version 3 adds a resident Go supervisor and systemd service management for root and ordinary accounts, while retaining explicit cron compatibility. Lifecycle actions share platform authorization and audit. Upgrades and policy changes pause the service and revalidate the pinned launcher. See [native systemd supervision](./AGENT-SYSTEMD.en.md) for the verification scope.
