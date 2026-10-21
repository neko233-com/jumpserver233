# docs — index

> [中文](./README.md) | English

[Current maintenance batch](./MAINTENANCE.en.md): native IP HTTP, accurate login failures, cookie verification, manifest integrity and upgrade persistence. Unified verification passed; v0.2.1 publication and intranet upgrade are the remaining gates.

[Mini release acceptance](./MINI-ACCEPTANCE.en.md): 12/12 accepted, verified source, results, reports and limits. The Enterprise entries below retain historical design notes; their old 42-group gate is superseded.

[Current product scope](./PRODUCT-SCOPE.en.md): a standalone mini SSH bastion for small and medium businesses, with few dependencies, usability, security and efficiency. Finish S01–S12. Enterprise entries below describe existing work/historical research rather than automatic requirements; the user's correction supersedes the former 42-group gate.

[Project UI skill and design direction](./UI-DESIGN.en.md): project-local oil-ui, pinned provenance, compact operational navigation and bilingual/narrow-screen cases; awaiting unified verification.

This batch's unverified PDF/email reports, report scheduling and permanent statistics warehouse have been withdrawn. Preserve existing statistics/CSV without adding mini runtime/maintenance burden. Retain [encrypted job/operation history](./EXECUTION-HISTORY.en.md), with standalone upgrade preflight and backup/recovery coverage.

[Windows/database account PAM](./ACCOUNT-PAM.en.md): local Windows accounts, four native databases, enrollment, batch/periodic reset and recovery, bilingual Web, CLI/SDK and unified cases. E18 is implementation ready; verification has not run.

[AI assistant and conversation audit](./AI-ASSISTANT.en.md): organization provider settings/write-only keys, platform authority, native HTTPS, receipts/revisions, revocation, encrypted history/archive, bilingual Web, CLI/SDK and cases are authored. E34 awaits unified verification only if this historical Enterprise extension is explicitly requested.

[Trusted interactive SSH submission directories](./INTERACTIVE-DIRECTORIES.en.md) authors native private framing, kernel cwd/input-queue proof, one-use leases, approval remeasurement, shared controllers and encrypted audit. Together with batch/template/schedule/Playbook propagation this forms E14. Code, Testify and existing native/bilingual browser entrypoints are authored and unrun; the historical 42-group gate is superseded by the mini release checklist.

[Global organization overview](./GLOBAL-ORGANIZATIONS.en.md) authors independent global read authority, cross-organization inventory/cached health/activity counts, bilingual Web, CLI/SDK and revocation/concurrency/reopen/existing-standby cases. E08 awaits verification only if this historical Enterprise extension is explicitly requested.

[Sign-in SMS MFA](./SMS-MFA.en.md) authors native platform transport, initial/personal binding, enforcement, one-time capabilities, limits/encryption, TOTP/RADIUS/review, bilingual Web, CLI/SDK and cases. E06 awaits verification; the historical 42-group gate is superseded by the mini release checklist.

[Native cloud SMS and enterprise bots](./NATIVE-NOTIFICATIONS.en.md) authors three cloud SMS providers, CMPP 2.0, four bots, settings receipts/secret isolation, bilingual Web, CLI/SDK, protocol/permission/reopen and browser cases. E22 awaits verification. Cases reuse the TLS/CONNECT fixture and a temporary organization, with essential screenshots and repeated cleanup. No validation has run; E06 has separate SMS MFA documentation.

[Enterprise QR sign-in](./ENTERPRISE-LOGIN.en.md): native WeCom, DingTalk and Feishu/Lark protocols, tenant/membership checks, MFA/review/audit, bilingual administration and CLI/SDK. Code and cases are authored; E05 awaits verification, including actual tenants and mobile scanning.

[Multiple identity sources and directory synchronization](./IDENTITY-SOURCES.en.md) authors named LDAP/OIDC/CAS/SAML, separate encryption/callbacks/credential revocation, complete LDAP collection, group/organization mappings, schedules/retry/abort, bilingual Web, CLI/SDK and cases. E04 is implementation-ready and unverified.

[External replay storage](./REPLAY-STORAGE.en.md): authored object backends, lifecycle/drain integration, archives/retries, authorized replay, local removal, cache/backups, bilingual Web, CLI/SDK and cases. E35 is implementation-ready and unverified.

[Delivery progress and fixed acceptance checklist](./PROGRESS.en.md): separate stable-SSH and full-baseline counts, batch delta, unverified changes, remaining gaps and the unified acceptance gate.

[Platform announcements](./ANNOUNCEMENTS.en.md): bilingual plain text, drafts/publication windows, pinning, per-revision reading receipts, system management permission, encryption and Web/CLI/SDK. Source/cases are authored and await verification after all features are implemented.

[Organization labels](./LABELS.en.md): shared catalog, asset/node inheritance, filtering, organization permissions/audit, encryption and Web/CLI/SDK. Source/cases await unified verification.

[SSH user certificates](./SSH-CERTIFICATES.en.md): built-in CA/OpenBao, short-lived account/gateway authentication, two-phase CA rotation, permissions, audit and Web/CLI/SDK. Source/cases await unified verification.

[SSH account connectivity checks](./ACCOUNT-CHECKS.en.md): manual and independently scheduled authentication of stored passwords/keys, per-account results, explicit retries, security notifications and backup persistence.

[SSH execution workspaces](./SSH-WORKSPACES.en.md): native Linux subtree confinement for Web/CLI. Added [controlled execution directories](./EXECUTION-DIRECTORIES.en.md): single-command verified starting directories, exact/subtree/regex rules and approval binding; complete interactive cwd remains outstanding.

[Software updates and native artifacts](./UPDATES.en.md): published stable checks, automatic policy, system permissions/revisions/receipts, download/archive verification and six-platform release packaging.

[Drain before upgrading](./SERVICE-MAINTENANCE.en.md): standalone Web/CLI control, cross-organization activity, admission gates, admitted-work completion, cancellation and process-instance binding.

[Controlled standalone installation](./INSTALLATION.en.md): encrypted checkpoints, offline preflight, first-start health/traffic gates, rollback before release and old-service resumption. New data is preserved after release. [Scheduled standalone installation](./INSTALLATION-SCHEDULE.en.md) adds controlled shutdown. [Automatic preparation/window installation](./AUTOMATIC-UPDATES.en.md) is added; historical-version migration acceptance remains pending.

[Encrypted standalone backups](./BACKUP.en.md): native CLI, stopped-state exclusion, wrapped Vault key, integrity preflight, idempotent import, retained old data and interrupted-switch recovery. Unified verification passed.

[Stable SSH release scope](./SSH-FIRST.en.md): standalone deployment, few dependencies, SSH first, data-preserving updates, full backup/recovery, sensitive command review and directory restrictions. Distinguishes existing capabilities from acceptance gaps; complex extensions follow actual need.

[Asset discovery and sync](./ASSET-DISCOVERY.en.md): LAN, AWS international/China, Alibaba Cloud ECS and Tencent Cloud CVM inventory, write-only cloud credentials, sync policies, SSH fingerprint preview/import, scheduling and organization permissions. See the document for basic HA and remaining cloud boundaries.

[Branding](./BRANDING.en.md): bilingual titles, themes, logos/icons/sign-in illustrations, footers, global permission/audit, CLI and HA persistence.

[SSH monitoring history](./MONITOR-HISTORY.en.md): encrypted hourly segments, seven-day minute records, current bindings/permissions, Web charts and native CLI.

[BuildWorld intranet macOS deployment](./BUILDWORLD.en.md): default `Jenkinsfile_mac_single`, same-port frontend, launchd, health checks and recovery.

Local password policy, history/expiry, restricted password changes and independently authorized password/TOTP recovery support Web/CLI/SDK and v3 user-document takeover. See [Password security](./PASSWORD-SECURITY.en.md). Enterprise extensions are historical scope; see [current product scope](./PRODUCT-SCOPE.en.md).

Platform identity editing, expiry, archive/restore, credential revocation, atomic batches and metadata audit are available in Web/CLI/SDK. See [User lifecycle](./USERS.en.md). Enterprise extensions are historical scope; see [current product scope](./PRODUCT-SCOPE.en.md).

Native PAP RADIUS primary sign-in, mutual TLS, multiple challenges and a shared additional factor support Web/CLI/SDK, preserving local MFA and platform approvals. See [RADIUS authentication](./RADIUS.en.md). Enterprise extensions are historical scope; see [current product scope](./PRODUCT-SCOPE.en.md).

Go native Playbooks provide revisioned workspaces, organization publication, source snapshots, sequential SSH modules, conditions/loops/retries, durable recovery and Web/CLI/SDK. See [Native Playbooks](./PLAYBOOKS.en.md). Full Ansible and Enterprise parity remain in progress.

SSH command plans support five-field cron, explicit timezones, DST, missed-run policies, previews, revisioned editing and change audit, with a complete Ops CLI. See [Calendar schedules](./SCHEDULING.en.md).

Inventory, audit sources, UTC daily trends, current permissions and CSV digest receipts are covered in [Operations reports](./REPORTS.en.md).

Global authentication, MFA, session grants, native reviews, CSV and independent platform notifications: [Platform sign-in audit](./LOGIN-AUDIT.en.md).

Threshold/offline/missing-data rules, maintenance mute, acknowledgement, recovery and delivery from real SSH probes: [Monitoring alerts](./MONITOR-ALERTS.en.md).

In-app messages, email, Webhooks, custom SMS, contact verification and delivery recovery: [Notification center](./NOTIFICATIONS.en.md).

Published scopes, one to five approval stages, amendment reset, temporary grants, revocation and Web/CLI are covered in [Access request tickets](./ACCESS-TICKETS.en.md).

Multi-host SSH password/key rotation, weekly scheduling, privileged accounts, per-account results and recovery: [Credential rotation plans](./ROTATION-PLANS.en.md).

[Fixed-password plans and idempotent saves](./FIXED-PASSWORDS.en.md): independent permissions, write-only input, deduplicated saves, snapshots and recovery.

[Individual and bulk SSH rotation retries](./ROTATION-RETRIES.en.md): skip successful items, combine aliases, claim sources once, confirm current revision and retain linked audit.

[Generated SSH password policy](./SSH-PASSWORD-POLICY.en.md): organization lengths/categories/exclusions, merged shared-account constraints, Web/CLI, replay receipts and encrypted persistence.

Weak/reused SSH credentials, age/usage risks, human review and periodic scanning: [Account risks](./ACCOUNT-RISKS.en.md).

Multi-host CSV/XLSX create/update, atomic commits, idempotent receipts and Web/CLI are covered in [Account credential import](./ACCOUNT-IMPORT.en.md).

Native creation, disabling, restoration, retained home deletion and explicit recovery for regular Linux users are covered in [Remote account lifecycle](./REMOTE-ACCOUNTS.en.md).

See [Managed SSH accounts](./MANAGED-ACCOUNTS.en.md) for independently encrypted named credentials, discovery association, grants and seven-day rotation.

See [Account discovery](./ACCOUNT-DISCOVERY.en.md) for native Linux collection, approvals, human review, metadata protection and CLI.

See [Scheduled account discovery](./SCHEDULED-ACCOUNT-DISCOVERY.en.md) for interval plans, per-run approval isolation, pause cancellation, credential rotation support and encrypted run archives.

See [Live RDP monitoring](./RDP-LIVE-MONITOR.en.md) for independently authorized read-only viewing, viewer audit, CLI capture and permission boundaries.

Named-user read-only sharing, input control, removal and collaboration audit are documented in [Terminal collaboration](./SESSION-SHARING.en.md).

See [interactive session security](./SESSION-SECURITY.en.md) for shared terminal/RDP idle limits, maximum duration, watermarks, permissions and persistence.

[Clean Docker verification and parallel debugging](./DOCKER-QA.en.md) · [Performance and packaging](./PERFORMANCE.en.md)

See [live terminal monitoring](./LIVE-SESSIONS.en.md) for read-only SSH / Telnet / Kubernetes views, separate permissions, audit and continuous authorization.

See [host tools](./HOST-PLUGINS.en.md) for SSH tool detection, installation, agent operations and current integration status.

See [native host recovery](./HOST-AGENT.en.md) for Go component builds, persisted-ban restoration, kernel health and status limits.

RDP adds native Go desktops, Web mouse/keyboard and Unicode text, platform-identity CLI capture, independent review, method policies, encrypted graphical replay and explicit text clipboard. Actual Windows NLA and complete Enterprise high-definition parity remain unverified; see [RDP](./RDP.en.md).

See [Telnet](./TELNET.en.md) for native terminals, login prompts, TLS/gateways, authorization/review and protocol boundaries.

See [Kubernetes](./KUBERNETES.en.md) for cluster assets, Pod/container terminals, platform-authenticated CLI, TLS/gateways, reviews and recordings.

See [NoSQL](./NOSQL.en.md) for native Redis/MongoDB protocols, JSON commands, TLS, read-only policy and audit limits.

See [ClickHouse](./CLICKHOUSE.en.md) for HTTPS, typed parameters, server-side read-only mode, cancellation and uncertain write outcomes.

See [SQL Server](./SQLSERVER.en.md) for native TDS, bound parameters, multiple result sets, read-only restrictions and server transaction boundaries.

See [MySQL/MariaDB](./MYSQL.en.md) for native access, TLS, bound queries, auto-commit and reviewed auditing.

Native PostgreSQL access, bound queries, SQL review and audit are available. [PostgreSQL](./POSTGRESQL.en.md).

Organizations isolate resources, roles and operational audit through `X-JMS-ORG`, browser switching and Agent CLI selection. Standalone storage and PostgreSQL single-active HA are supported. See [Organizations](./ORGANIZATIONS.en.md). Enterprise extensions are historical scope; see [current product scope](./PRODUCT-SCOPE.en.md).

Platform sign-in approval and console notifications use verified identities, original-source one-use completion, encrypted persistence and PostgreSQL single-active HA. See [Platform sign-in reviews](./PLATFORM-LOGIN-REVIEWS.en.md). Enterprise extensions are historical scope; see [current product scope](./PRODUCT-SCOPE.en.md).

Source, weekly-hour and execution-channel restrictions support standalone and single-active HA. See [Access policies](./ACCESS-POLICIES.en.md). Enterprise extensions are historical scope; see [current product scope](./PRODUCT-SCOPE.en.md).

SSH key installation, verified rotation, opt-in seven-day scheduling and persistent staged recovery are described in [SSH key rotation](./SSH-KEY-ROTATION.en.md).

Targets and gateways support imported SSH private keys with write-only input, vault encryption, public fingerprints and verified history restore. Password rotation remains password-specific. See [SSH private keys](./SSHKEYS.en.md).

SSH gateway routing supports up to three pinned hops across monitoring, Web SSH, CLI, SFTP, jobs and password rotation. Configuration and encrypted credentials support standalone and PostgreSQL single-active HA; see [SSH gateways](./GATEWAYS.en.md). Enterprise extensions are historical scope; see [current product scope](./PRODUCT-SCOPE.en.md).

Passkey registration, device-verified sign-in, local MFA, revocation, and HA recovery: [Passkey](./PASSKEY.en.md).

SAML signed assertions, browser binding, local MFA, encrypted SP identity, and configuration audits: [SAML](./SAML.en.md). Remaining profiles and production IdP integration are open.

## English

| Doc | Purpose |
|---|---|
| [PLAN.en.md](./PLAN.en.md) | Master plan: scope, competitor statement, stack, architecture, roadmap (authoritative for scope) |
| [BASELINE.en.md](./BASELINE.en.md) | Research snapshot of the JumpServer Community feature baseline (requirement source) |
| [WEBSSH.en.md](./WEBSSH.en.md) | Current Web SSH, agent CLI, recording, and security boundaries |
| [ACCESS-REVIEWS.en.md](./ACCESS-REVIEWS.en.md) | SSH login review policy, one-time permits, API, and limits |
| [COMMAND-FILTERS.en.md](./COMMAND-FILTERS.en.md) | SSH command-filter rules, priority, PTY enforcement, and parser limits |
| [SFTP.en.md](./SFTP.en.md) | SSH file manager, transfer API, grants, and audit boundaries |
| [AUTH.en.md](./AUTH.en.md) | Local user authentication, bootstrap, and current authorization boundary |
| [RBAC.en.md](./RBAC.en.md) | System roles, delegated permissions, user/group bindings, and change audit |
| [OIDC.en.md](./OIDC.en.md) | OIDC SSO, controlled provisioning, local MFA, and provider disablement |
| [LDAP.en.md](./LDAP.en.md) | LDAP/AD directory login, controlled provisioning, MFA, and disablement |
| [CAS.en.md](./CAS.en.md) | CAS 2/3 tickets, browser binding, local MFA, and audits |
| [SSHMONITOR.en.md](./SSHMONITOR.en.md) | SSH host metrics, collection, and access boundaries |
| [JOBS.en.md](./JOBS.en.md) | SSH jobs, batches/templates/schedules, Agent exec, reviews, and audits |
| [EXECUTION-HISTORY.en.md](./EXECUTION-HISTORY.en.md) | Embedded SQLite / PostgreSQL encrypted job and Playbook history and durable deduplication |
| [TESTING.en.md](./TESTING.en.md) | Unified Testify, PostgreSQL/HA, race, and browser verification |
| [PASSWORD-ROTATION.en.md](./PASSWORD-ROTATION.en.md) | Seven-day SSH password rotation, credential protection, and standalone acceptance boundary |
| [CLUSTER-HA.en.md](./CLUSTER-HA.en.md) | PostgreSQL active/standby, shared storage, health probes, and acceptance boundary |

## 中文

| 文档 | 说明 |
|---|---|
| [PLAN.md](./PLAN.md) | 总体规划：范围、竞品口径、技术栈、架构、阶段路线（范围争议以它为准） |
| [BASELINE.md](./BASELINE.md) | JumpServer 社区版功能基线调研快照（需求来源） |
| [WEBSSH.md](./WEBSSH.md) | Web SSH、Agent CLI 与会话录像当前能力和安全边界 |
| [ACCESS-REVIEWS.md](./ACCESS-REVIEWS.md) | SSH 登录复核配置、一次性许可、API 与边界 |
| [COMMAND-FILTERS.md](./COMMAND-FILTERS.md) | SSH 命令过滤规则、优先级、PTY 执行和解析边界 |
| [SFTP.md](./SFTP.md) | SSH 文件管理器、传输接口、授权与审计边界 |
| [AUTH.md](./AUTH.md) | 本地用户认证、初始化与当前授权边界 |
| [RBAC.md](./RBAC.md) | 系统角色、权限委派、用户/组绑定及变更审计 |
| [OIDC.md](./OIDC.md) | OIDC 统一登录、受控建号、本地 MFA 与身份源停用 |
| [LDAP.md](./LDAP.md) | LDAP/AD 安全目录登录、受控建号、MFA 与身份源停用 |
| [CAS.md](./CAS.md) | CAS 2/3 服务票据、浏览器绑定、本地 MFA 和配置审计 |
| [SSHMONITOR.md](./SSHMONITOR.md) | SSH 主机监控指标、采集方式与权限边界 |
| [JOBS.md](./JOBS.md) | SSH 作业、批量/模板/定时计划、Agent exec、命令复核与审计 |
| [EXECUTION-HISTORY.md](./EXECUTION-HISTORY.md) | 内置 SQLite / PostgreSQL 加密作业与 Playbook 历史、持久化重试去重 |
| [TESTING.md](./TESTING.md) | Testify、PostgreSQL/HA、race 与浏览器端到端统一验证 |
| [PASSWORD-ROTATION.md](./PASSWORD-ROTATION.md) | SSH 账号每 7 天密码轮换、凭据保护与单机验收边界 |
| [CLUSTER-HA.md](./CLUSTER-HA.md) | PostgreSQL 单活热备、共享存储配置、健康探针与验收边界 |

Repository root also has `AGENTS.md` / `AGENTS.zh.md` (AI agent working agreement) and `README.md` / `README.en.md` (quick start).

[Agent events and centralized audit](./AGENT-EVENTS.en.md)

[Native Agent supervision with systemd](./AGENT-SYSTEMD.en.md)
