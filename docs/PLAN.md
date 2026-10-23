# jumpserver233 总体规划

> 中文 | [English](./PLAN.en.md)

2026-10-23 [Web 全面改版](./WEB-REDESIGN.md)：实现与本地验收 10/10，剩余 0 项。本批覆盖共享界面、快捷搜索、主机/SSH/文件及移动交互；完整回归后修复补验，72 项用例已闭环。Edge 与隔离 Docker 验证通过，测试资源已重复清理。当前改版未发布，线上仍为 v0.3.2；下方保留之前的验收记录。

当前维护：[原生 SSH 表格工作台](./NATIVE-SSH.md) v0.3.2 已发布并单次升级，六项界面门槛实现和验收均为 6/6。完整 CI、生产浏览器 70/70、BuildWorld #9（1041）、重启前后默认登录、真实 SSH/SFTP、监控及保数通过。固定 mini 清单仍为 12/12；界面证据为真实 Go 帧及协议验收，没有原生 XTerminal UI 自动操作。

新增 [2222 原生 SSH/SFTP](./NATIVE-SSH.md) 已完成：完整实现后统一验证，8/8 新增门槛通过。v0.3.0 已单次发布、内网升级；BuildWorld #7（1014）六阶段成功，root/root、搜索、中转、文件往返、监控与重启保数通过。既有 mini 清单 12/12 保持独立统计。

[当前维护补丁](./MAINTENANCE.md)：v0.2.2 已发布并完成内网升级，包含 Playbook 竞态修复。CI 补验通过；BuildWorld 构建 #6（997）六个阶段全部成功，root/root 登录、真实 SSH、主机监控及重启后原数据保留均已验收。

## 当前产品范围（2026-10-21）

独立 mini SSH 跳板机，面向中小公司单机部署，少依赖、易用、安全高效和易维护。[PRODUCT-SCOPE](./PRODUCT-SCOPE.md)是当前权威范围；完成门槛为 [PROGRESS](./PROGRESS.md) 的 S01–S12，不再是企业版 42 组。云同步、更多协议、应用市场和复杂企业能力不作为默认待办。

以下功能条目、阶段与旧计数保留开发历史；其中此前的企业全量目标和 42 组验证门禁均已被本次用户修正覆盖。未验证源码仍未验证，不能因收缩范围增加验收数。

## mini 稳定版验收

统一验证后 S01–S12：**12/12 已验收**。源码与实际边界见 [mini 验收报告](./MINI-ACCEPTANCE.md)。

## 历史实现记录

[Windows/数据库账号 PAM](./ACCOUNT-PAM.md)：Windows 本机 SAM 与 PostgreSQL/MySQL/MariaDB/SQL Server 收集/纳管、固定身份的原生改密/核验、统一计划与恢复、加密/权限/幂等、中英 Web、CLI/SDK 和用例已编写。E18 实现待验；该历史企业版扩展被明确要求后单独验证，不新增部署依赖。

[AI 助手与对话审计](./AI-ASSISTANT.md)：组织模型配置/只写密钥、平台权限、原生 HTTPS、对话回执/修订、撤权取消、加密历史及归档、中英 Web、CLI/SDK 和用例已编写。E34 实现待验，仍须全部 42 组就绪后统一验证。

[交互 SSH 可信提交目录](./INTERACTIVE-DIRECTORIES.md)已编写原生私有帧、内核 cwd/输入队列证明、一次性租约、审批重测、共享控制者和加密审计，并与批量/模板/计划/Playbook 目录链路共同组成 E14。代码、Testify 与既有原生/中英浏览器入口已编写，未执行；该历史企业版扩展被明确要求后单独验证。

[全局组织汇总](./GLOBAL-ORGANIZATIONS.md)已编写独立全局只读权限、跨组织库存/缓存监控/活动计数、中英 Web、CLI/SDK、撤权/并发/重开及既有主备接管用例。E08 实现待验；仍等待全部 42 组编写完成后统一验证。

[登录短信 MFA](./SMS-MFA.md)已编写原生平台通道、首次/个人绑定、强制策略、一次性能力、限流/加密、TOTP/RADIUS/复核贯通、中英 Web、CLI/SDK 和用例。E06 实现待验；未运行测试、构建、浏览器或 Docker，历史 42 组门禁已由当前 mini 发布清单取代。

[原生云短信与企业机器人](./NATIVE-NOTIFICATIONS.md)已编写三类云短信、CMPP 2.0、四类群机器人、配置幂等/秘密隔离、中英 Web、CLI/SDK、协议/权限/重开及浏览器用例，E22 实现待验。复用既有 TLS/CONNECT 夹具与临时组织，仅保留必要截图并重复清理；未执行验证。E06 见独立短信 MFA 文档。

[企业扫码登录](./ENTERPRISE-LOGIN.md)已编写企微、钉钉、飞书/Lark 原生授权、企业与内部成员校验、独立身份源、MFA/复核/审计、中英 Web、CLI/SDK 和用例；E05 实现待验。未运行测试、构建、浏览器或 Docker，实际企业租户与手机扫码留待统一验收。

[多身份源与目录同步](./IDENTITY-SOURCES.md)已编写具名 LDAP/OIDC/CAS/SAML、独立加密/回调/凭据撤销、LDAP 完整采集、组/组织映射、计划/重试/中止、中英 Web、CLI/SDK 与用例；E04 实现待验，未启动验证。

[固定验收清单与总进度](./PROGRESS.md)：分别统计 SSH 稳定版和完整功能基线，列明已闭环、部分完成、待交付、本次增量与收尾门禁。进度以该清单和具名验收为准，不按测试数量或阶段数量推算。

2026-10-20 用户追加流程要求：完整清单全部功能、用例和双语说明实现后，再统一运行测试、构建、浏览器和 Docker 验证。SSH 保持开发优先；此前 SSH 小批次先验收的安排不再适用。[平台公告](./ANNOUNCEMENTS.md)与[组织标签](./LABELS.md)源码、用例和双语文档已补齐，E41 实现待验；未执行验证，不计入验收完成数。

Phase 7 新增 [SSH 账号连接性检测](./ACCOUNT-CHECKS.md)：默认/具名账号的密码与密钥认证、独立周期、结果与失败通知、显式重试及中断不重放。完整企业版仍在进行。

E36 [SSH 用户证书](./SSH-CERTIFICATES.md)的内置 CA/OpenBao、短期签发、账号/网关路由、两步 CA 轮换、Web/CLI/SDK、用例与双语说明已编写，等待全量实现后的统一验证。

E35 [录像外部存储](./REPLAY-STORAGE.md)的 S3/OSS/COS/OBS/SFTP/PostgreSQL 对象后端、加密归档/重试、生命周期与排空、鉴权回放、受控本地清理、缓存/备份、中英 Web、CLI/SDK 和用例已编写，进入实现待验。真实 SSH/SFTP、Web SSH 输出、一次重启、回执和中英窄屏场景接入既有统一入口；不提前运行验证。

Phase 7 新增[SSH 改密单项与批量重试](./ROTATION-RETRIES.md)：已结束运行的失败项选择、成功项排除、别名合并、当前计划修订、一次来源占用、Web/CLI/SDK、关联审计和持久化接管。完整企业版仍在进行。

新增[固定密码计划与幂等保存](./FIXED-PASSWORDS.md)：指定/随机来源、独立权限、只写输入、保存回执、不可变快照、组织约束和恢复。默认七天自动改密继续随机生成；完整企业版目标继续推进。


新增[SSH 生成密码策略](./SSH-PASSWORD-POLICY.md)：组织级随机密码规则、每七天/手动/计划共用生成器、共享账号约束合并、独立权限、Web/CLI、加密回执及备份保留。逐计划附加约束与运行快照已接入；完整企业版对齐仍在进行。

## 当前优先级：SSH 稳定版（2026-10-19 用户调整）

新增[受控 SSH 执行目录](./EXECUTION-DIRECTORIES.md)：单命令 Web/CLI 可选择工作区内的真实起始目录，审批绑定根/目录对象与命令策略，支持精确、子树与整路径 RE2 规则。Go/Testify 1598、Linux race 171、完整生产回归 86/86、六平台原生及新布局的中英桌面/窄屏验收通过；从源码 Docker 构建和浏览器冒烟也通过，见[测试记录](./TESTING.md)。既有[SSH/SFTP 登录复核](./ACCESS-REVIEWS.md)继续绑定连接/网关与工作区根对象。完整交互式 cwd、任意 shell 语义和完整 Enterprise 仍在进行。

新增[正式发布检查与原生制品](./UPDATES.md)：Web/CLI/SDK 检查、可选自动检查、修订与幂等回执、归档校验、六平台打包与暂存；[单机安装事务](./INSTALLATION.md)接通加密快照、离线预检、首次启动健康与业务门禁、放行前回滚和旧服务恢复。放行后保留新数据；新增[单机定时安装](./INSTALLATION-SCHEDULE.md)连接固定候选、排空、停机、快照和首次启动；新增[自动准备与窗口安装](./AUTOMATIC-UPDATES.md)，默认关闭、官方摘要绑定、策略修订与一次尝试回执；固定历史源码到当前源码的保数演练已通过；正式历史 Release/更早格式迁移仍待完成，新增[升级前排空](./SERVICE-MAINTENANCE.md)，支持单机 Web/CLI、跨组织活动计数及进程实例绑定；通用更新器尚未完成。

本批[单机整站加密备份与恢复](./BACKUP.md)已通过统一验证：原生 `jms backup`、服务互斥、外部 key 指纹校验、格式/路径/完整性预检、Docker 挂载点恢复及幂等恢复/回滚日志。Go/Testify 1,523 项、Linux race 745 项、生产浏览器 85/85 和 Docker 7/7 通过，详见[验证记录](./TESTING.md)。

先交付[够用、稳定、低依赖的 SSH 跳板机](./SSH-FIRST.md)：默认单机本地持久化，优先 Web/CLI SSH、更新检查与升级保数、整站备份导入/导出、敏感命令留痕与复核及可信目录规则。完整 Enterprise 对齐保留为长期参考，其他协议、更多云厂商和复杂企业扩展后续按需补齐，不作为当前稳定版的发布门槛。单机停机备份已落地；通用更新器、强目录限制、集群备份和在线热备仍待补齐，不能用 macOS 部署回滚或命令正则替代相应验收。

本批[云主机 SSH IP 自动迁移](./ASSET-DISCOVERY.md)已通过统一验证：固定实例身份与已有主机密钥、父子账号凭据保留、待确定操作隔离、旧 SSH 连接绑定失效、迁移回执及中英 Web/CLI/SDK。真实 OpenSSH/网关、全量 Go、Linux race、85 项生产浏览器及 Docker 重启验证见[验证报告](./TESTING.md)。未部署内网或创建正式 Release。

Phase 7 已落地 [LAN 资产发现与同步](./ASSET-DISCOVERY.md)：来源与策略、受限并发扫描、固定 SSH 网关、一次性纳管、元数据同步、缺失处理、原生定时、组织权限和中英 Web/CLI/SDK；分层验收结果见[自动化验证](./TESTING.md)。AWS 国际区/中国区、阿里云 ECS/腾讯云 CVM 清单适配已通过签名夹具、Go/race、隔离 Docker 和完整生产浏览器验证；真实云账号验收、其他云平台、多节点及其他企业功能后续按需推进。已取消内网部署，SSH 稳定版确认后仅发布一次。

Phase 7 已补齐[品牌外观](./BRANDING.md)：双语站点/登录标题、五种主题、四类图片、页脚备案、全局权限与审计、CLI/SDK 和 PostgreSQL 单活接管；统一验证结果见[自动化验证](./TESTING.md)。企业版整体仍在进行。

Phase 3/5 新增[SSH 监控历史](./MONITOR-HISTORY.md)：加密小时分段、七天分钟数据、缺失/离线区分、当前绑定与资产查看授权、Web 原生曲线和 CLI/SDK，支持 PostgreSQL 单活接管读取。企业版整体目标继续推进。

新增 BuildWorld 内网 `builtin` macOS 单机部署入口和默认 `Jenkinsfile_mac_single`，使用持久化数据、同端口前端、幂等激活与失败回滚。部署验收边界见[说明](./BUILDWORLD.md)；整体企业版和生产 HA 目标继续按阶段推进。

平台本地密码策略、历史与有效期、受限改密、独立授权的密码/TOTP 恢复接入 Web/CLI/SDK，支持 v3 用户文档接管；见[密码安全](./PASSWORD-SECURITY.md)。企业版扩展属于历史范围，见[当前产品范围](./PRODUCT-SCOPE.md)。

平台身份编辑、到期、归档恢复、撤销凭证、原子批量变更和元数据审计接入 Web/CLI/SDK，见[用户生命周期](./USERS.md)。企业版扩展属于历史范围，见[当前产品范围](./PRODUCT-SCOPE.md)。

原生 PAP RADIUS 主登录、双向 TLS、多轮挑战和统一附加因子接入 Web/CLI/SDK，保留本地 MFA 与平台登录审批；见 [RADIUS 认证](./RADIUS.md)。企业版扩展属于历史范围，见[当前产品范围](./PRODUCT-SCOPE.md)。

Go 原生 Playbook 支持工作空间版本、组织发布、源码快照、顺序 SSH 模块、条件/循环/重试、持久化恢复和 Web/CLI/SDK；见[原生 Playbook](./PLAYBOOKS.md)。完整 Ansible 和企业版整体仍在进行。

SSH 命令计划支持五段 cron、显式时区、夏令时、错过触发策略、预览、版本编辑和变更审计，并提供完整 Ops CLI；见[日历调度](./SCHEDULING.md)。

Phase 5 新增[运营报表](./REPORTS.md)：12 类组织来源与显式全局身份统计、UTC 日趋势、沿用原生权限、部分结果标注、先审计后下载的 CSV、Web/CLI/SDK 和 PostgreSQL 组织回执接管。定时报表、PDF、完整历史仓库及企业版整体对齐继续进行。

Phase 5 已接入[平台登录审计与独立平台通知](./LOGIN-AUDIT.md)：全局认证步骤、MFA、会话签发前提交、原生复核游标、权限过滤、CSV、Web/CLI/SDK 和 PostgreSQL 单活接管。原生云短信、IM 和完整企业版对齐仍在进行。

Phase 3/5 新增[原生 SSH 监控告警](./MONITOR-ALERTS.md)：八类条件、主机/节点范围、连续样本与持续时间、恢复阈值、维护静默、确认、通知中心和 Web/CLI/SDK。组织加密和 PostgreSQL 单活恢复已接入；升级策略与生产 HA 验收仍待完成。

Phase 5 新增[通知中心](./NOTIFICATIONS.md)：站内未读、个人订阅与联系方式验证、TLS SMTP、签名 HTTPS Webhook、自定义短信网关、工单/SSH 作业/改密结果、送达回执及显式重试，支持组织加密与 PostgreSQL 单活恢复。安全消息已覆盖资产/命令原生复核、SSH 命令阻断、风险扫描、主机监控和 Agent 修复报告；详情按当前权限直接复核。平台登录聚合已接入独立全局通知；原生云短信和即时通信渠道仍待完成。

Phase 5/7 新增[访问授权工单](./ACCESS-TICKETS.md)：管理员发布资产/节点及账号范围、1–5 级不同审批人、用户/组/角色选择器、抄送讨论、调整重审、限时原生授权、撤销与故障恢复，覆盖 Web/CLI/SDK 和组织加密。外部投递见通知中心；生产多活、阶段及完整企业版目标保持进行中。

Phase 7 新增 [SSH 账号改密计划](./ROTATION-PLANS.md)：多主机密码/密钥、可选特权账号、手动/单次/每周周期、逐项结果、取消恢复和 Web/CLI/SDK，支持组织加密及 PostgreSQL 单活接管。Windows/数据库改密、风险自动闭环及生产 HA 验收仍待完成。

Phase 7 新增 [SSH 账号风险检测](./ACCOUNT-RISKS.md)：七类本地检查、人工处置、元数据 CSV、周期计划和 Web/CLI/SDK，支持组织加密、当前权限与 PostgreSQL 单活接管。平台保留审计用于使用风险，远端 OS 密码有效期、登录历史、自动批量修复和完整企业版验收仍待完成。

远端 Linux 普通账号的原生创建、停用、恢复、保留目录删除及显式恢复见 [远端账号生命周期](./REMOTE-ACCOUNTS.md)。

Phase 7 新增 SSH 多账号托管：独立加密凭据、账号级授权/启停/轮换、发现身份关联、具名网关、Web SSH/SFTP/工作台和平台 CLI，支持单机与 PostgreSQL 单活接管。CSV/XLSX 批量凭据导入已支持多主机新增/更新、预览、原子提交与幂等回执，见[账号导入](./ACCOUNT-IMPORT.md)。其他协议账号管理仍待完成，见 [SSH 多账号托管](./MANAGED-ACCOUNTS.md)。企业版总体目标保持进行中。

Linux 本地账号收集支持原生 Go 组件、固定网关、两类审批、持续授权、完整分页后提交、加密发现/缺失记录、人工确认和 Web/CLI。新增间隔计划、逐轮审批隔离、暂停取消、凭据修订刷新与独立运行归档，支持单机和 PostgreSQL 单活接管，见[计划账号收集](./SCHEDULED-ACCOUNT-DISCOVERY.md)。其它平台发现及保留策略仍待完成。

Phase 6/7 新增 RDP 实时只读监看：独立 `audit.desktops.monitor_all`、观看者持久审计、来源/组织/当前权限复查、Web/CLI 截图与有界帧解码。历史回放权限不能读取他人活动画面；单机优先，在线状态不迁移，见 [RDP 实时监看](./RDP-LIVE-MONITOR.md)。各阶段总体状态仍为进行中。

Phase 4/7 新增终端会话协作：指定平台用户、限时验证码、只读/单写入者接管、踢出/撤销、持续授权、双身份命令复核与协作事件审计，提供 Web/CLI 与中英界面。默认关闭、独立 `sessions.share` 权限；在线状态不迁移，RDP 分享仍待完成，见 [会话协作](./SESSION-SHARING.md)。各阶段总体状态仍为进行中。

Agent 生命周期已支持账号级开机启动、每分钟崩溃恢复、停用守护和保留数据卸载，新增固定版本升级/回退、中断检查点及独立授权的 SSH 防护策略。配套原生 Go 组件已验证隔离 Linux 的实际 cron、容器重启及内核表丢失后的封禁恢复；使用已有 cron，不自动提权。集中恢复事件与计划采集见 [AGENT-EVENTS.md](./AGENT-EVENTS.md)；构建及其它剩余范围见 [远程工具与 Agent 运维](./HOST-PLUGINS.md)。

SSH 远程工具与原生 Agent 运维已纳入本轮目标：检测、安装、状态和生命周期优先接入 banhack233 与 node_exporter，复用平台身份、组织、复核和任务审计。本批 Linux 安装、托管进程、API/CLI/UI 已通过 Go/race 和完整浏览器验收，见 [远程工具与 Agent 运维](./HOST-PLUGINS.md)。

RDP 新增 Go 原生桌面连接、Web 键鼠与 Unicode 文字、平台身份 CLI 截图、独立复核、通道策略、加密图形回放和显式文本剪贴板。实际 Windows NLA 与完整企业高清桌面仍待验收，见 [RDP](./RDP.md)。

Telnet 新增原生 Web/CLI 终端、设备提示正则、NVT 协商/窗口尺寸、校验 TLS/固定网关、独立登录复核、命令/录像审计及单活接管。设备 MFA、脚本登录、Telnet 自动改密仍待完成，见 [Telnet](./TELNET.md)。

Kubernetes 新增集群资产、命名空间/Pod/容器选择、Web 与 CLI 终端、TLS/固定网关、独立登录复核、命令/录像审计及单活接管。文件传输、容器作业、资源管理及云令牌刷新仍待实现，见 [Kubernetes](./KUBERNETES.md)。

Redis/MongoDB 新增原生数据协议与 JSON 命令控制台、浏览键/集合、固定 TLS/网关、CLI、复核/脱敏审计及单活接管；MongoDB 支持认证数据库、分批游标、NULL 与缺失字段区分。自动节点发现、原生 TCP 客户端代理等仍待完成。见 [NoSQL](./NOSQL.md)。

ClickHouse 新增官方 HTTPS SQL 访问：验证 TLS、类型参数、固定 SSH 网关、UI/CLI、服务端只读、取消清理、复核与脱敏审计。配置/索引支持现有单活 HA；原生 TCP 代理及完整企业数据库对齐仍待完成。见 [ClickHouse](./CLICKHOUSE.md)。

企业数据库新增 SQL Server：官方 Go TDS 驱动、验证 TLS、@p1 参数、批次与多结果集、固定 SSH 网关、UI/CLI、复核和脱敏审计。只读采用受限 SELECT/CTE 与结束回滚，写入保留服务端事务语义及不确定结果。配置/审计与现有单活 HA 共用存储；Windows 集成身份、过程输出参数和原生 TCP 客户端代理仍待完成。见 [SQL Server](./SQLSERVER.md)。

Phase 3 数据库新增 MySQL/MariaDB：原生驱动、默认 TLS/只读策略、参数绑定、网关、浏览器/CLI、复核审计和单活接管。写入使用自动提交，取消后不承诺撤销已完成变更；存储过程单独标明事务由服务端管理。其它协议与持久事务仍待完成。见 [MySQL/MariaDB](./MYSQL.md)。

Phase 3 数据库当前能力：原生 PostgreSQL，默认校验 TLS/只读事务，浏览器 SQL 控制台与 jms db、参数绑定、查询取消/超时、结果上限、登录/SQL 复核及加密脱敏审计；单机与 PostgreSQL 单活热备索引。其他数据库协议、持久事务和数据库自动改密仍待实现。 [PostgreSQL](./POSTGRESQL.md).

相同 SSH 私钥的纳管副本支持统一提交与旧钥撤销，覆盖同组织、跨组织及归档组织，详见 [密钥轮换](./SSH-KEY-ROTATION.md)。

相同 SSH 密码账号的纳管副本支持统一远端改密、加密决策恢复及各组织保管库同步（含停用/归档组织），详见 [密码轮换](./PASSWORD-ROTATION.md)。

组织通过 `X-JMS-ORG`、浏览器切换和 Agent CLI 选择隔离资源、角色与运维审计，支持单机存储和 PostgreSQL 单活 HA。详见 [组织隔离](./ORGANIZATIONS.md)；企业版扩展属于历史范围，见[当前产品范围](./PRODUCT-SCOPE.md)。

平台登录审批与站内通知已接入：认证后等待、原来源一次性兑换、加密持久化及 PostgreSQL 单活 HA。详见 [平台登录复核](./PLATFORM-LOGIN-REVIEWS.md)；企业版扩展属于历史范围，见[当前产品范围](./PRODUCT-SCOPE.md)。

来源、每周时段及执行通道限制支持单机和单活 HA，详见 [访问策略](./ACCESS-POLICIES.md)；完整企业版对齐仍在推进。

SSH 密钥安装、验证后轮换、显式启用的七天计划及持久化阶段恢复见 [SSH 密钥轮换](./SSH-KEY-ROTATION.md)。

目标资产与网关现支持导入 SSH 私钥：输入只写、保管库加密、公钥指纹及验证后恢复历史版本。密码轮换仍按密码凭据调度，详见 [SSH 私钥](./SSHKEYS.md)。

SSH 网关现支持最多三跳，监控、Web SSH、CLI、SFTP、任务和改密共用逐跳指纹校验连接。配置与加密凭据支持单机及 PostgreSQL 单活 HA，详见 [SSH 网关](./GATEWAYS.md)。完整企业版对齐仍在推进。

Passkey 注册、设备验证登录、本地 MFA、撤销与 HA 恢复见 [Passkey](./PASSKEY.md)。

SAML 签名断言、浏览器绑定、本地 MFA、SP 身份加密和配置审计见 [SAML](./SAML.md)；其余协议配置及生产 IdP 对接仍待完成。

用 Go + React 技术栈对齐 JumpServer 企业版全部软件功能，社区版功能是实现阶段的基础。本文档是需求基线与阶段路线，范围争议以本文档为准。

## 1. 范围

交互会话安全新增全局可配置的空闲时间、最大连接时长与创建时身份水印，覆盖 Web / CLI 终端和 RDP；RDP 水印由服务端写入画面，终端录像保存兼容元数据。详见 [交互会话安全](./SESSION-SECURITY.md)。

活动 SSH / Telnet / Kubernetes 终端支持只读实时监看、独立监看权限和观看者审计；SSH 持续复查当前授权与连接修订。详见 [在线终端监看](./LIVE-SESSIONS.md)。终端协作与 RDP 只读监看已分别落地；RDP 分享、协同控制及完整企业版仍在进行。

### 1.1 当前产品与参考对象

- 参考产品为 [JumpServer 企业版](https://www.jumpserver.org/enterprise.html)，只吸收适合 mini SSH 跳板机的交互与安全能力，不要求全量复刻。
- 默认单机：一个 Go 服务、静态网页、本地数据目录，无外部数据库、Redis、云平台或企业身份服务前置依赖。
- 保留已有 PostgreSQL 单活热备的可选边界；多活、Kubernetes 分布式和生产集群演练不列入当前 mini 目标，按明确需求再决定。

功能基线来源：JumpServer 官方文档（v5）、lina 前端路由、jumpserver 后端 apps/ 目录结构、jumpserver.org 企业版与版本对比页。详见 [BASELINE.md](./BASELINE.md)。

### 1.2 历史企业版功能研究（当前不继续扩展）

以下为之前按竞品整理的研究条目，保留已有实现和证据；不会按此清单逐项自动新增需求：

- 扫码登录（企微/钉钉/飞书）、短信 MFA、RADIUS 二次认证、登录复核
- RBAC 角色管理页面、多组织管理、全局组织（组织切换 API 保留但不提供管理页）
- 授权工单二级审批、登录/资产登录 ACL、数据脱敏、剪贴板 ACL、连接方式 ACL
- 账号收集/批量改密/账号备份、Vault 账号存储
- 云资产同步、虚拟应用、界面个性化（主题/LOGO）
- Oracle/SQLServer/PostgreSQL/ClickHouse/DB2/达梦 数据库协议、高清晰度 RDP、报表
- 组件：Magnus、Razor、Nec、Panda、JDMC、Video Worker
- Web 资产脚本代填、应用商店高级远程应用、每 7 天自动轮换纳管 SSH 账号密码
- 资产规模 ≤ 5000 台（社区版限制，企业版旗舰不限；本项目不设硬限制）
- 人脸识别（enterprise.html 企业版独有）
- 热备/分布式高可用部署（企业版旗舰能力，Phase 7+）

### 1.3 社区版必须实现的核心

- SSH / Telnet / K8s / SFTP；RDP（Web 端）；数据库：MySQL、MariaDB、Redis、MongoDB（Web GUI）
- 资产树（节点继承）+ 网域/网关多级代理；平台与账号管理
- SSH 主机分组与监控：在线状态、连接延迟、CPU/核心数、内存、网络收发速率、磁盘容量与占用
- Web SSH 与通用 Agent CLI 通过服务端跳板代理操作；远端 SSH 密码不返回浏览器或 CLI，命令与会话进入审计
- 授权规则（用户/组 × 资产/节点 × 账号 × 动作 × 时间）
- 命令过滤 ACL；标签；会话分享；水印
- 审计：会话（在线/录像/实时监控/中断）、命令、文件传输、登录、操作、改密、作业、工单
- 认证：本地、LDAP、CAS、OAuth2、OIDC、SAML2、SSO、Passkey；MFA（OTP）
- 通知：邮件、短信（基础）、站内信；作业中心（快捷命令、Adhoc/Playbook）；工单 1–5 级审批
- 个人设置：密码/SSH 密钥、AccessKey、临时令牌、MFA 绑定
- REST API 全量（/api/v1，Swagger）
- AI 助手（ChatAI，OpenAI 兼容后端）

## 2. 技术栈（已确认）

| 层 | 选型 | 版本 |
|---|---|---|
| 后端 | Go（单体 Core + 连接器边界分层） | 1.27 |
| 前端构建 | Vite | 8.x |
| 前端框架 | React + TypeScript | 19.x |
| 工具链 | vite+（Void 官方工具链，lint/format） | 1.x |
| UI 动效 | reactbits（shadcn CLI 源码引入） | latest |
| 视觉 | WebGL shaders（装饰性背景/过渡） | — |
| 终端 | @xterm/xterm | 6.x |
| 国际化 | i18next + react-i18next（zh-CN / en 自动识别） | 26.x / 17.x |

## 3. 架构

官方是 Django 单体（Core）+ 多语言连接器（koko/chen/lion）。Go 复刻对应：

```
server/                 Go 模块
  cmd/server/           入口：Core API + WebSocket 网关
  internal/core/        用户/用户组/组织/认证/RBAC/资产/授权/审计/设置（对应 Django apps）
    assets/             分组、资产清单、加密凭据与监控状态
  internal/gateway/     会话 WebSocket 网关（xterm ↔ 连接器）
  internal/connector/   协议连接器
    sshclient/          主机密钥固定校验的 SSH + SFTP（Go x/crypto/ssh）
    postgresclient/     原生 PostgreSQL 参数化查询、校验 TLS、SSH 网关和事务边界
    mysqlclient/        原生 MySQL/MariaDB、校验 TLS、SSH 网关和自动提交结果
    sqlserverclient/    原生 TDS、校验 TLS、SSH 网关、批次与多结果集
    redisclient/        有界 RESP、TLS/网关、只读命令与原生结果
    mongodbclient/      官方 Go BSON 驱动、分批游标、TLS/网关及命令边界
    kubeclient/         Kubernetes TLS API、WebSocket v5/SPDY 和固定 SSH 网关
    telnetclient/       NVT、设备提示登录、校验 TLS/固定网关和终端尺寸
    databasewire/       固定目的地与 TLS 连接
    sqlclient/          数据库请求/结果边界与各协议审计脱敏
  cmd/jms/              Agent CLI：调用服务端授权会话，不读取远端密码
  internal/recorder/    录像（asciinema 兼容 replay.json.gz）与回放
  api/v1/               REST 路由，兼容 JumpServer 资源路径风格
web/                    Vite 8 + React 19 前端
docs/                   PLAN/BASELINE/AGENTS 文档
```

### 3.1 外部兼容性关键面（不可随意更改）

1. REST 认证兼容目标：Session cookie、一次性 Bearer Token（POST /api/v1/authentication/auth/）、永久 Token、AccessKey/Secret HTTP Signature（hmac-sha256）；以上四种认证方式均已实现。浏览器短期会话使用 HttpOnly `jms_sessionid` Cookie，长期 Token 由用户创建和撤销，服务端只保存摘要。
2. 多租户头 `X-JMS-ORG`
3. 会话 WebSocket（二进制帧终端 I/O + resize/剪贴板/文件传输消息）
4. 录像 asciinema 兼容 `replay.json.gz`
5. MFA 流程：密码 → OTP 验证 → 有效期窗口免重复

### 3.2 协议实现策略（已确认）

- SSH + SFTP：真实实现（Phase 4）
- PostgreSQL、MySQL、MariaDB、SQL Server 使用真实驱动，ClickHouse 使用官方 HTTPS 接口，Redis 使用有界原生 RESP，MongoDB 使用官方 BSON 驱动；均支持校验 TLS 与 SSH 网关，各协议的只读及事务边界见对应文档。Kubernetes 支持真实容器终端，RDP 支持 Go 原生图形桌面；其余数据库协议和高级桌面能力仍待实现
- Telnet：原生终端与服务端账号登录，复用授权、复核、审计与网关；其他协议跟随对应阶段，接入点统一走 connector 接口

## 4. 阶段路线

| 阶段 | 内容 | 状态 |
|---|---|---|
| Phase 1 | 项目骨架：Go 后端、Vite/React 前端、AGENTS.md 文档体系、lint/build/test 基线、i18n、release/changelog 流程 | 已完成 |
| Phase 2 | 用户/用户组/本地认证/MFA OTP/token 认证/权限/基础设置 API | 进行中 |
| Phase 3 | 资产/平台/节点树/网域网关/账号/授权规则/命令过滤/标签/SSH 主机监控 | 进行中 |
| Phase 4 | 真实 SSH+SFTP、Web SSH、Agent CLI 跳板、会话/命令/文件记录、录像回放 | 进行中 |
| Phase 5 | 审计全量、通知、作业中心、工单、仪表盘 | 进行中 |
| Phase 6 | LDAP/OIDC/CAS 等认证后端、RDP/K8s/DB mock 转真实、Web 资产、AI 助手 | 进行中 |
| Phase 7 | 企业版对齐（竞品）：RBAC、多组织、访问控制/复核、资产同步、企业数据库协议、账号收集/改密/备份、SSH 账号每 7 天自动轮换、应用市场、人脸识别、界面个性化、热备/分布式 | 进行中 |

每阶段完成标准：测试/lint/构建通过（命令见 AGENTS.md §4；Makefile 提供 `make test/lint/build` 封装，Windows 可直接用其中的原始命令），功能可在 UI 走通，更新本文档状态。

Phase 2 当前切片：本地管理员初始化、密码登录、12 小时内存态 Bearer 会话、登出撤销、管理员/操作员角色、用户列表与创建 API；密码以 scrypt 派生哈希保存，登录失败按来源 IP 限流。用户可在个人设置验证当前密码后修改登录密码，系统重新派生哈希、保留当前会话并撤销该账号的其他会话。个人设置支持最多 10 个 AccessKey，Secret 以 Vault key AES-GCM 加密且仅创建时返回；REST API 支持签入 `(request-target) date` 的 HMAC-SHA256 HTTP Signature，`jms ssh` 可用 `JMS_ACCESS_KEY_ID` 与 `JMS_ACCESS_KEY_SECRET` 调用会话 API。可选 TOTP MFA 支持绑定、确认、停用及密码+第二因素登录；密钥使用 Vault key 进行 AES-GCM 加密，已消费验证码时间步不能重放。用户可在验证当前密码及新验证码后生成 10 个一次性恢复码；仅保存 SHA-256 摘要，登录使用后即消费，重新生成会作废旧码，停用 MFA 会清除剩余码。管理员可在系统设置配置 `disabled`、`admins` 或 `all` 全局 MFA 策略；未登记账号通过短期设置挑战完成绑定，目标账号不能停用 MFA。管理员可在访问控制页创建用户组、维护操作员成员，并按用户或组、资产或节点、SSH 账号、动作与有效时间维护授权；资产列表、SSH 会话和 SFTP 会按直接授权、用户组成员与节点祖先授权过滤。Phase 3 当前切片：资产节点树提供 CRUD、资产节点归属、按节点及后代继承授权；Linux SSH 主机监控以固定 SHA256 主机指纹采集延迟、CPU、内存、根磁盘与网络速率，默认每分钟采集、资产页每 15 秒刷新；指标按主机行显示并使用 CPU/内存与网络/磁盘双列布局，详见 [AUTH.md](./AUTH.md) 与 [SSHMONITOR.md](./SSHMONITOR.md)。Phase 4 当前切片：资产列表可启动服务端 SSH PTY，WebSocket 使用一次性短期票据传输终端 I/O 和窗口大小；`jms ssh <asset-id>` 复用相同授权会话；会话开始/结束与认证操作员身份写入审计索引，asciinema v2 gzip 录像使用本地 Vault key 加密后存储；审计台提供会话列表、中断活动会话和已结束录像回放。资产文件入口支持授权后的真实 SFTP 目录浏览、文件夹创建、文件上传/下载/删除和独立文件传输审计，审计台提供传输记录页签；路径限定在 SFTP 初始目录且不跟随符号链接，单文件限制 1 GiB。命令审计识别常见 shell 提示符下按 Enter 提交的命令行，审计内容按会话加密并在落盘成功后才转发终端输入，管理员与会话所属操作员可查询；密码提示输入省略，常见凭据参数脱敏。管理员可配置按用户/组、资产/节点、SSH 账号、匹配模式、优先级和有效时间限定的 allow/deny 规则，Web SSH 与 Agent CLI 在共享网关执行；拒绝结果进入加密命令审计。过滤器解析 PTY 输入行，适用规则下无法识别的输入会拒绝；管理员可在系统设置中批准或拒绝命令复核，5 分钟超时自动拒绝，Web SSH 与 Agent CLI 共用队列并记录加密审计；完整 shell 语义和命令结果/退出码仍待实现。详见 [SFTP.md](./SFTP.md)、[WEBSSH.md](./WEBSSH.md) 与 [COMMAND-FILTERS.md](./COMMAND-FILTERS.md)。

Phase 7 当前切片：纳管 Linux SSH 账号支持每 7 天自动轮换，并提供管理员手动触发、凭据验证后提交、失败恢复和审计；失败轮换的重试退避状态在服务重启和单活 HA 接管后保留。资产可单独开启 SSH/SFTP 登录复核；操作员必须先通过对应的 `connect` 或 `sftp` 授权检查，再由管理员批准。SSH 许可绑定用户/资产/账号且一次性消费，Web SSH 与 Agent CLI 共用该流程；SFTP 许可用于签发 30 分钟、服务端仅保存摘要的浏览器会话令牌，所有文件操作均校验令牌，复核和审批身份持久化到本地文件或 PostgreSQL 文档。SFTP 会话令牌为进程内状态，服务重启或 HA 接管后失效。另提供 PostgreSQL 选主锁协调的单活热备。资产、资产节点、用户、用户组、授权、登录复核和登录 token 摘要保存在 PostgreSQL 共享 JSONB 文档中，旧 JSON 文件在首次启动时导入；审计索引、录像及轮换日志仍需共享读写文件存储。活动节点独占 API、监控与轮换调度；登录会话可在切换后继续使用，在线 SSH 会话和监控内存快照不迁移。多活、Kubernetes 与生产故障演练仍待完成。详见 [ACCESS-REVIEWS.md](./ACCESS-REVIEWS.md)、[PASSWORD-ROTATION.md](./PASSWORD-ROTATION.md) 和 [CLUSTER-HA.md](./CLUSTER-HA.md)。

**竞品 = [https://www.jumpserver.org/enterprise.html](https://www.jumpserver.org/enterprise.html) 的 JumpServer 企业版功能**（含 X-Pack）。对外宣称与功能差距均以该页面及 BASELINE.md 第 5 节逐项核对。

Phase 7 凭据备份切片：凭据历史使用 AES-GCM 加密，密码修改与轮换自动保留最近 10 个版本；恢复时通过固定主机密钥的 SSH 改密并验证远端账号，成功后才更新 Vault。备份管理仅管理员可用，API 与页面均不返回凭据明文。详见 [PASSWORD-ROTATION.md](./PASSWORD-ROTATION.md)。

Phase 7 RBAC 当前能力：全局系统角色管理、自定义权限组合、用户/用户组绑定、乐观版本控制及变更审计已接入。服务端在每次请求/计划派发时计算当前权限；管理、连接、凭据操作、读取全局审计与中断/取消分别授权。兼容管理员保留完整权限，委派用户管理不能单独创建管理员。`admins` MFA 策略包含系统角色账号。单机文件和 PostgreSQL 单活 HA 均支持；跨组织汇总与自动组织映射仍待实现。详见 [RBAC.md](./RBAC.md)。

Phase 5 当前能力：工作台和无 TTY 的 `jms exec` 支持 SSH 命令作业，包含 stdout/stderr、退出码、超时/取消、请求去重、命令复核和加密执行审计。工作台另提供最多 50 台主机的批量派发、带版本的个人命令模板、命令快照、一次性及间隔计划、暂停/恢复和逐主机结果。实际派发重新检查授权、登录复核和命令策略；周期任务合并错过次数并避免重叠。单机优先，计划与执行索引支持 PostgreSQL 单活 HA，已领取且结果不明确的任务不自动重放。完整 Ansible 及其他工单类型仍待实现；cron/日历调度见[日历计划](./SCHEDULING.md)；授权工单和外部通知见 [访问工单](./ACCESS-TICKETS.md) 与 [通知中心](./NOTIFICATIONS.md)。详见 [JOBS.md](./JOBS.md)。

Phase 6 OIDC 当前能力：单身份提供方 Authorization Code + PKCE、服务端 ID Token/JWKS 校验、精确 issuer/subject 受控建号、HttpOnly 浏览器票据、本地强制 MFA 与恢复码、Secret 加密及配置审计。外部声明不能关联本地管理员或提升权限；停用提供方会阻止其平台身份入口。配置、账号映射及已完成的共享会话支持单活 HA；未完成流程在重启/接管后需重新发起。多 provider、组织/组声明映射及联合退出仍待完成。详见 [OIDC.md](./OIDC.md)。

Phase 6 LDAP 当前能力：单目录 LDAPS/强制 StartTLS、搜索账号只写加密、稳定 ID 受控建号、目录用户 Bind、本地 MFA/恢复码、HttpOnly 平台会话和身份源停用检查。单机优先，配置、账号映射和已完成登录会话支持 PostgreSQL 单活 HA；未完成流程切换后重启。目录同步、自动组映射、多目录和生产 AD/OpenLDAP 对接仍待完成，详见 [LDAP.md](./LDAP.md)。

Phase 6 CAS 当前能力：单提供方 CAS 2/3 服务票据、精确 service/浏览器证明绑定、强制 renew、本地 MFA/恢复码、受控建号、配置版本与审计、身份源停用。单机优先，配置、映射和已完成共享会话支持 PostgreSQL 单活 HA；未完成流程切换后重启。联合退出、多 CAS、属性映射与生产 CAS 对接仍待完成，详见 [CAS.md](./CAS.md)。

## 5. Agent 文档约定

- 仓库根 `AGENTS.md`：给 AI agent 的项目指令，参考 deepseek-harness 的 AGENTS.md 组织方式（everything-is-a-plugin 的分层文档、docs/ 目录索引）
- 指令写法遵循 GPT-6《Using GPT-6》规范（developers.openai.com/api/docs/guides/latest-model/gpt-6-astra.md）：用户指令优先于 skill/guideline、避免含糊措辞、明确行为边界与验收标准
- 结构见 [../AGENTS.md](../AGENTS.md)

## 6. 国际化与发布约定

- 前端：i18next 中英双语，首屏按浏览器语言自动识别，手动切换持久化到 localStorage（`jms233.lang`）；所有静态文案走 i18n key，禁止硬编码
- 文档：每个 .md 提供中英两版（`X.md` / `X.en.md`，中文版顶部链接英文版，英文版顶部链接中文版）
- 提交：Conventional Commits（`feat:` / `fix:` / `chore:` 等）
- Changelog：平时不手写；**仅在 release 时**由 release-please 工作流生成/更新 `CHANGELOG.md` 并创建 GitHub Release

Agent 当前切片：原生组件版本 2 增加有界恢复日志与哈希链；服务端分页补采、检测断档/重置并按组织加密归档。类型化采集计划复用现有权限与审批，执行前刷新凭据绑定，终态回执归档后释放热历史；提供中英界面、CLI 与显式旧组件升级。详见 [AGENT-EVENTS.md](./AGENT-EVENTS.md)。该切片不代表 Phase 4/7 或企业版整体完成，多活、生产 HA、完整协议与企业扩展范围仍按计划推进。

Agent 版本 3 增加常驻 Go 监督与 root/普通账号的 systemd 服务管理，保留显式 cron 兼容。生命周期动作共用平台授权和审计，升级/策略切换期间暂停服务并重新核验固定启动器；实际验证边界见 [systemd 原生守护](./AGENT-SYSTEMD.md)。
