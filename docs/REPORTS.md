# 运营报表

> 中文 | [English](./REPORTS.en.md)

`/console/reports` 提供当前可见库存、仍保留的审计统计、UTC 日趋势和有审计回执的 CSV。Web、`jms reports` 和 Go SDK 使用同一来源权限；单机优先，导出回执支持组织级 PostgreSQL 单活接管。

## 统计口径

- 库存统计当前可见资产、纳管 SSH 账号，忽略时间筛选。SSH 状态来自绑定校验后的真实探测；超过三分钟未更新标为过期，其他协议标为未监控。
- 历史按记录的开始或首次观察时间筛选，区间为 `[from, to)`，最多 366 天。状态是本次采集时的值；成功作业计入其创建日，不构成成功状态转换次数。
- 每个来源分别显示范围、采集时间、可见保留数量、区间数量、最早/最新观察时间和状态分布。不同记录单位不相加。首次和末次 UTC 日期可能只包含部分时段。
- 历史仅限各原生模块仍保留的索引。最早观察时间不证明该日期之后的数据完整；修改筛选不会恢复已经清理的历史。
- 采集依次完成，来源各有采集时间；这不是跨所有模块的数据库事务快照。页面每 30 秒在可见状态刷新，手动刷新保持当前固定区间；7/30/90 天按钮重新确定截止时间。
- `denied` 表示缺少来源权限，不显示数量；`unavailable` 表示读取失败，不显示伪造的零。`limited` 表示达到容量边界，已读取数量可能只是部分结果。后两种标记整份报表为部分结果，导出前必须显式允许。

## 来源与权限

| API 来源 | 数据和原生范围 |
|---|---|
| `assets`、`accounts` | 当前可见资产/SSH 账号；`assets.view_all` 或 `assets.manage` 可见全组织，否则沿用资产、节点、账号和组授权 |
| `terminal_sessions` | SSH/Telnet/Kubernetes 会话；自己的记录，或 `audit.sessions.view_all` / `audit.sessions.monitor_all` 的全组织记录 |
| `rdp_sessions` | RDP 会话；自己的记录，或 `audit.sessions.view_all` / `audit.desktops.monitor_all` 的全组织记录 |
| `database_queries` | 自己的查询作业，`database.audit.view_all` 可见全组织 |
| `ssh_jobs` | 自己的 SSH/工具作业，`jobs.view_all` 可见全组织 |
| `rotation_runs` | 改密运行；要求 `accounts.rotation.view` 和 `assets.view_all` |
| `account_risks` | `accounts.risks.view` 与当前可见账号；凭据版本改变标记 `outdated` |
| `monitor_alerts` | `monitoring.view` / `monitoring.manage` 与当前可见主机 |
| `access_tickets` | 沿用原生工单的申请、审批、抄送及管理可见性 |
| `agent_alerts` | 主机 Agent 报告观察索引；`audit.agents.view_all` 或插件权限与当前连接授权 |
| `file_transfers` | 沿用原生文件审计的操作人范围；`audit.files.view_all` 可见全组织 |
| `platform_logins` | 显式包含全局身份时启用；自己的身份记录，`audit.logins.view_all` 可见全平台 |
| `platform_users` | 显式包含全局身份时启用；自己的身份，`users.manage` 可见全平台用户 |

后两项使用全局权限并明确标注平台范围，组织角色不能授予全局身份能力。文件操作沿用原生审计的用户名关联。Agent 统计的是平台保留的主机观察索引（最多 20,000 条/30 天），未重新解析命令输出或主机原始事件。终端索引没有结束记录且已不在线的会话显示 `interrupted`；RDP 同样核对当前活动会话。

`reports.export` 只允许导出自己当前能统计的数据，不扩大任何来源权限。`reports.audit` 允许查看当前组织全部导出回执。默认只列自己的回执，且两个权限都属于组织能力。采集及导出过程中重新校验身份和角色快照，授权写入与采集使用现有访问锁；已在浏览器下载的文件无法通过后续撤销追回。

## API、CLI 和 SDK

```text
GET /api/v1/reports/capabilities
GET /api/v1/reports/overview?from=RFC3339&to=RFC3339&sources=ssh_jobs,assets
GET /api/v1/reports/export.csv?sources=ssh_jobs&allow_partial=true
GET /api/v1/reports/exports?scope=mine&offset=0&limit=25

jms reports overview --sources ssh_jobs,assets
jms reports overview --include-platform --sources platform_logins
jms reports export --sources ssh_jobs
jms reports exports --all --offset 0 --limit 25
```

鉴权和 `X-JMS-ORG` 使用现有平台协议，CLI 使用已有环境变量。SDK 提供 `ReportOverview`、`ExportReport`、`ReportExportHistory`。CSV 输出只含有限状态码、时间、范围和数量，不含凭据、命令、SQL、结果、路径、主机名和账号名。回执包含操作人 ID、区间、来源范围、摘要和字节数。

导出流程先生成并校验 CSV，再持久化加密回执，成功后才返回文件；审计失败返回 503，无 CSV。响应头 `X-JMS-Report-ID` 和 `X-JMS-Report-SHA256` 标识回执及文件 SHA-256。Web 和 SDK/CLI 完整缓冲并核对摘要后才保存/输出；这用于发现传输不一致，不能替代 HTTPS 或可信服务端。

## 存储与性能边界

回执证明报表已生成并在响应前完成审计；网络中断或下载取消仍可能留下回执，不能作为客户端已保存文件的证明。

- 每次采集最多 15 秒、每来源 100,000 条、64 种状态；CSV 最大 4 MiB。接口最多选 20 个来源。
- 终端/文件旧索引各最多读取 64 MiB、单行 1 MiB；RDP 最多检查 100,000 个会话目录、总索引 64 MiB、单索引 2 MiB。超限明确返回来源限制，损坏索引明确显示不可用。
- 导出回执以 AES-GCM 独立加密保存于组织 `report-exports.json` 或对应 Documents 作用域，最多 2,000 条/365 天，明文总量 4 MiB；超量从最旧回执开始清理。只保存回执，不归档 CSV。
- 选择 SSH 作业等非库存来源时跳过库存扫描。Agent 权限按主机/账号缓存于单次采集。趋势使用原生 SVG 和可展开数据表；报表路由懒加载。
- 登录文字动画改用 [Web Animations API](https://developer.mozilla.org/en-US/docs/Web/API/Element/animate)，支持减少动态效果和完整可访问标题，移除 Motion 运行时依赖。

计划定时生成、邮件报表、PDF、外部 BI、完整历史仓库以及生产多活验收仍待实现。企业版整体目标继续按 [PLAN](./PLAN.md) 推进。

## 验证证据

2026-10-18，本机独立 Docker、真实 OpenSSH 作业的英文界面：

![运营报表英文](./images/reports.en.png)

中文 390px 窄屏：

![运营报表中文](./images/reports.zh.narrow.png)

Testify 覆盖来源授权/撤销、部分导出确认、加密/损坏、容量与 TTL、PostgreSQL 作用域接管、审计写失败及摘要验证。浏览器覆盖真实 SSH 数据归属、跨组织回执隔离、Web/CLI 导出一致性、中英文窄屏和登录减少动态效果。具体测试结果见 [TESTING](./TESTING.md)。
