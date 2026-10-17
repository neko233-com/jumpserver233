# docs — index

> [中文](./README.md) | English

See [Managed SSH accounts](./MANAGED-ACCOUNTS.en.md) for independently encrypted named credentials, discovery association, grants and seven-day rotation.

See [Account discovery](./ACCOUNT-DISCOVERY.en.md) for native Linux collection, approvals, human review, metadata protection and CLI.

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

Organizations isolate resources, roles and operational audit through `X-JMS-ORG`, browser switching and Agent CLI selection. Standalone storage and PostgreSQL single-active HA are supported. See [Organizations](./ORGANIZATIONS.en.md). Full Enterprise parity remains in progress.

Platform sign-in approval and console notifications use verified identities, original-source one-use completion, encrypted persistence and PostgreSQL single-active HA. See [Platform sign-in reviews](./PLATFORM-LOGIN-REVIEWS.en.md). Full Enterprise parity remains in progress.

Source, weekly-hour and execution-channel restrictions support standalone and single-active HA. See [Access policies](./ACCESS-POLICIES.en.md). Full Enterprise parity remains in progress.

SSH key installation, verified rotation, opt-in seven-day scheduling and persistent staged recovery are described in [SSH key rotation](./SSH-KEY-ROTATION.en.md).

Targets and gateways support imported SSH private keys with write-only input, vault encryption, public fingerprints and verified history restore. Password rotation remains password-specific. See [SSH private keys](./SSHKEYS.en.md).

SSH gateway routing supports up to three pinned hops across monitoring, Web SSH, CLI, SFTP, jobs and password rotation. Configuration and encrypted credentials support standalone and PostgreSQL single-active HA; see [SSH gateways](./GATEWAYS.en.md). Full Enterprise parity remains in progress.

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
| [TESTING.md](./TESTING.md) | Testify、PostgreSQL/HA、race 与浏览器端到端统一验证 |
| [PASSWORD-ROTATION.md](./PASSWORD-ROTATION.md) | SSH 账号每 7 天密码轮换、凭据保护与单机验收边界 |
| [CLUSTER-HA.md](./CLUSTER-HA.md) | PostgreSQL 单活热备、共享存储配置、健康探针与验收边界 |

Repository root also has `AGENTS.md` / `AGENTS.zh.md` (AI agent working agreement) and `README.md` / `README.en.md` (quick start).

[Agent events and centralized audit](./AGENT-EVENTS.en.md)

[Native Agent supervision with systemd](./AGENT-SYSTEMD.en.md)
