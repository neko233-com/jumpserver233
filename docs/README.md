# docs — 文档索引 / index

> 中文 | [English](./README.en.md)

发布申请范围、1–5 级审批、调整重审、限时授权、撤销和 Web/CLI 见[访问授权工单](./ACCESS-TICKETS.md)。

多主机 SSH 密码/密钥轮换、每周计划、特权账号、逐项结果及恢复见[账号改密计划](./ROTATION-PLANS.md)。

SSH 弱密码、凭据复用、超期与使用风险、处置和周期检测见[账号风险](./ACCOUNT-RISKS.md)。

CSV/XLSX 多主机新增/更新、原子提交、幂等回执与 Web/CLI 见[账号凭据导入](./ACCOUNT-IMPORT.md)。

远端 Linux 普通账号的原生创建、停用、恢复、保留目录删除及显式恢复见 [远端账号生命周期](./REMOTE-ACCOUNTS.md)。

独立加密的具名 SSH 凭据、发现记录关联、授权和七天轮换见 [SSH 多账号托管](./MANAGED-ACCOUNTS.md)。

原生 Linux 账号收集、审批、确认状态、元数据保护与 CLI 见 [账号收集](./ACCOUNT-DISCOVERY.md)。

间隔计划、逐轮审批隔离、暂停取消、凭据轮换兼容及加密运行归档见[计划账号收集](./SCHEDULED-ACCOUNT-DISCOVERY.md)。

独立 RDP 实时只读监看、观看者审计、CLI 截图和权限边界见 [RDP 实时监看](./RDP-LIVE-MONITOR.md)。

指定平台用户的只读分享、输入接管、踢出和协作审计见 [终端会话协作](./SESSION-SHARING.md)。

终端与 RDP 的统一空闲/最大时长、水印、权限及持久化见 [交互会话安全](./SESSION-SECURITY.md)。

[Docker 纯净验证与并行调试](./DOCKER-QA.md) · [性能与打包基线](./PERFORMANCE.md)

活动 SSH / Telnet / Kubernetes 终端的只读监看、独立权限、审计与持续授权见 [在线终端监看](./LIVE-SESSIONS.md)。

SSH 远程工具检测、安装与 Agent 运维的范围和接入状态见 [远程工具](./HOST-PLUGINS.md)。

原生 Go 组件的构建、封禁持久恢复、内核健康和状态边界见 [原生主机恢复](./HOST-AGENT.md)。

RDP 新增 Go 原生桌面连接、Web 键鼠与 Unicode 文字、平台身份 CLI 截图、独立复核、通道策略、加密图形回放和显式文本剪贴板。实际 Windows NLA 与完整企业高清桌面仍待验收，见 [RDP](./RDP.md)。

Telnet 原生终端、登录提示、TLS/网关、授权复核及协议边界见 [Telnet](./TELNET.md)。

Kubernetes 资产、Pod/容器终端、平台身份 CLI、TLS/网关、授权复核和录像见 [Kubernetes](./KUBERNETES.md)。

Redis/MongoDB 的原生协议、JSON 命令、TLS、只读与审计边界见 [NoSQL](./NOSQL.md)。

ClickHouse HTTPS、类型参数、服务端只读、取消及不确定写入边界见 [ClickHouse](./CLICKHOUSE.md)。

SQL Server 的原生 TDS、参数绑定、多结果集、只读限制及服务端事务边界见 [SQL Server](./SQLSERVER.md)。

MySQL 与 MariaDB 原生访问、TLS、参数查询、自动提交及复核审计见 [MySQL/MariaDB](./MYSQL.md)。

PostgreSQL 原生数据库访问、参数查询、SQL 复核和审计已接入。 [PostgreSQL](./POSTGRESQL.md).

组织通过 `X-JMS-ORG`、浏览器切换和 Agent CLI 选择隔离资源、角色与运维审计，支持单机存储和 PostgreSQL 单活 HA。详见 [组织隔离](./ORGANIZATIONS.md)；完整企业版目标仍在进行。

平台登录审批与站内通知已接入：认证后等待、原来源一次性兑换、加密持久化及 PostgreSQL 单活 HA。详见 [平台登录复核](./PLATFORM-LOGIN-REVIEWS.md)；完整企业版目标仍在进行。

来源、每周时段及执行通道限制支持单机和单活 HA，详见 [访问策略](./ACCESS-POLICIES.md)；完整企业版对齐仍在推进。

SSH 密钥安装、验证后轮换、显式启用的七天计划及持久化阶段恢复见 [SSH 密钥轮换](./SSH-KEY-ROTATION.md)。

目标资产与网关现支持导入 SSH 私钥：输入只写、保管库加密、公钥指纹及验证后恢复历史版本。密码轮换仍按密码凭据调度，详见 [SSH 私钥](./SSHKEYS.md)。

SSH 网关现支持最多三跳，监控、Web SSH、CLI、SFTP、任务和改密共用逐跳指纹校验连接。配置与加密凭据支持单机及 PostgreSQL 单活 HA，详见 [SSH 网关](./GATEWAYS.md)。完整企业版对齐仍在推进。

Passkey 注册、设备验证登录、本地 MFA、撤销与 HA 恢复见 [Passkey](./PASSKEY.md)。

SAML 签名断言、浏览器绑定、本地 MFA、SP 身份加密和配置审计见 [SAML](./SAML.md)；其余协议配置及生产 IdP 对接仍待完成。

## 中文

| 文档 | 说明 |
|---|---|
| [PLAN.md](./PLAN.md) | 总体规划：范围、竞品口径、技术栈、架构、阶段路线（范围争议以它为准） |
| [BASELINE.md](./BASELINE.md) | JumpServer 社区版功能基线调研快照（需求来源） |
| [WEBSSH.md](./WEBSSH.md) | Web SSH、Agent CLI 与会话录像当前能力和安全边界 |
| [JOBS.md](./JOBS.md) | SSH 作业、批量/模板/定时计划、Agent exec、命令复核与审计 |
| [TESTING.md](./TESTING.md) | Testify、PostgreSQL/HA、race 与浏览器端到端统一验证 |
| [ACCESS-REVIEWS.md](./ACCESS-REVIEWS.md) | SSH 登录复核配置、一次性许可、API 与边界 |
| [COMMAND-FILTERS.md](./COMMAND-FILTERS.md) | SSH 命令过滤规则、优先级、PTY 执行和解析边界 |
| [SFTP.md](./SFTP.md) | SSH 文件管理器、传输接口、授权与审计边界 |
| [AUTH.md](./AUTH.md) | 本地用户认证、初始化与当前授权边界 |
| [RBAC.md](./RBAC.md) | 系统角色、权限委派、用户/组绑定及变更审计 |
| [OIDC.md](./OIDC.md) | OIDC 统一登录、受控建号、本地 MFA 与身份源停用 |
| [LDAP.md](./LDAP.md) | LDAP/AD 安全目录登录、受控建号、MFA 与身份源停用 |
| [CAS.md](./CAS.md) | CAS 2/3 服务票据、浏览器绑定、本地 MFA 和配置审计 |
| [SSHMONITOR.md](./SSHMONITOR.md) | SSH 主机监控指标、采集方式与权限边界 |
| [PASSWORD-ROTATION.md](./PASSWORD-ROTATION.md) | SSH 账号每 7 天密码轮换、凭据保护与单机验收边界 |
| [CLUSTER-HA.md](./CLUSTER-HA.md) | PostgreSQL 单活热备、共享存储配置、健康探针与验收边界 |

## English

| Doc | Purpose |
|---|---|
| [PLAN.en.md](./PLAN.en.md) | Master plan: scope, competitor statement, stack, architecture, roadmap (authoritative for scope) |
| [BASELINE.en.md](./BASELINE.en.md) | Research snapshot of the JumpServer Community feature baseline (requirement source) |
| [WEBSSH.en.md](./WEBSSH.en.md) | Current Web SSH, agent CLI, recording, and security boundaries |
| [JOBS.en.md](./JOBS.en.md) | SSH jobs, batches/templates/schedules, Agent exec, reviews, and audits |
| [TESTING.en.md](./TESTING.en.md) | Unified Testify, PostgreSQL/HA, race, and browser verification |
| [ACCESS-REVIEWS.en.md](./ACCESS-REVIEWS.en.md) | SSH login review policy, one-time permits, API, and limits |
| [COMMAND-FILTERS.en.md](./COMMAND-FILTERS.en.md) | SSH command-filter rules, priority, PTY enforcement, and parser limits |
| [SFTP.en.md](./SFTP.en.md) | SSH file manager, transfer API, grants, and audit boundaries |
| [AUTH.en.md](./AUTH.en.md) | Local user authentication, bootstrap, and current authorization boundary |
| [RBAC.en.md](./RBAC.en.md) | System roles, delegated permissions, user/group bindings, and change audit |
| [OIDC.en.md](./OIDC.en.md) | OIDC SSO, controlled provisioning, local MFA, and provider disablement |
| [LDAP.en.md](./LDAP.en.md) | LDAP/AD directory login, controlled provisioning, MFA, and disablement |
| [CAS.en.md](./CAS.en.md) | CAS 2/3 tickets, browser binding, local MFA, and audits |
| [SSHMONITOR.en.md](./SSHMONITOR.en.md) | SSH host metrics, collection, and access boundaries |
| [PASSWORD-ROTATION.en.md](./PASSWORD-ROTATION.en.md) | Seven-day SSH password rotation, credential protection, and standalone acceptance boundary |
| [CLUSTER-HA.en.md](./CLUSTER-HA.en.md) | PostgreSQL active/standby, shared storage, health probes, and acceptance boundary |

仓库根目录另有 `AGENTS.md` / `AGENTS.zh.md`（AI agent 工作约定）与 `README.md` / `README.en.md`（快速开始）。

[Agent 事件与集中审计](./AGENT-EVENTS.md)

[systemd 原生 Agent 守护](./AGENT-SYSTEMD.md)
