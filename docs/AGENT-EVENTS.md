# Agent 事件与集中审计

[English](./AGENT-EVENTS.en.md) | [文档索引](./README.md)

原生 `jms-agent` 版本 2 及以上在受管 Linux 主机记录恢复事件，平台通过已验证的 SSH 路由分页采集。主机无需开放新端口或保存平台凭据。

## 记录与边界

- 恢复前持久化 `repair_started`，完成或失败后追加终态；下次恢复会明确记录上次未完成的尝试。
- 每条事件包含主机时间、触发方式、配置 SHA-256、有效封禁数、尝试 ID、序号与前一条哈希。监督恢复与平台生命周期操作分别标记。
- 本机保留最近 1024 条，单次读取最多 64 条。读取不会确认、删除或初始化日志。断档、日志丢失、事件流重置会成为独立审计记录；回滚和不一致的链被拒绝。
- 这些是主机报告的事实，主机 root 可以修改它们。哈希链不提供对 root 的防篡改保证。平台单独记录采集任务、当前服务端身份及接收时间。

## 使用

1. 在资产“工具与 Agent → 诊断与详情”执行“更新原生组件”。旧组件和启动脚本不会被执行；替换前备份未知的普通文件，拒绝符号链接和特殊文件。已有原生版本升级需要这一步。
2. 执行“同步事件”，然后展开“Agent 事件审计”。重复同步不会重复导入。
3. 管理员可选择 60 秒至一天的自动采集间隔。控制台提供 60/300/900/3600 秒。统一审计入口为 `/console/agent-audit`。
4. 停止自动采集仅停用计划。已开始任务可以在运维任务中取消；停用不会删除远端记录或平台历史。

CLI 使用现有平台身份认证：

```sh
jms plugin ASSET banhack233 agent_update
jms plugin ASSET banhack233 events
jms agent-events ASSET --before 0
jms agent-events all
jms agent-events ASSET collection --enable --interval 300
jms agent-events ASSET collection --disable
```

`next_before` 为零表示已读完当前历史。源端 `more_events=true` 表示还有保留事件可补采，需要再次同步或等待下次计划。

## 权限、持久化与高可用

- 资产历史需要当前目标账号的 `connect` 授权，以及 `plugins.inspect/manage/protect` 之一。单纯 `view` 不开放事件或采集。
- 全局审计要求 `audit.agents.view_all`。启停计划和更新组件需要 `plugins.manage`；每次远程执行仍检查 SSH 授权、来源/时段策略与登录/命令审批。
- 自动采集复用服务端内部类型化 Operations/Jobs，不接受客户端自定义 shell。每次派发前解析当前凭据和网关绑定，凭据轮换后无需持有旧秘密。撤权后执行被拒绝。
- 采集终态回执先写入加密分段审计，再移出热任务和计划历史；普通任务保留原有容量规则。最新归档回执可由任务/计划运行 ID 查询，更早回执在 Agent 历史中分页读取。
- 本地文件或 PostgreSQL 文档都使用组织密钥 AES-GCM 加密。分段先写入，随后原子发布索引及源游标；失败不推进游标。组织隔离沿用独立路径、文档作用域和派生密钥。
- 仍遵循已有单活 HA 所有权。失去租约或关闭组织后拒绝迟到写入。该功能不代表多活写入或生产 HA 已验收。

## API

- `GET /api/v1/assets/{id}/agent-events?before=0&limit=30`
- `GET /api/v1/audit/agent-events?before=0&limit=30`
- `GET/POST /api/v1/assets/{id}/agent-events/collection`
- 显式插件任务动作 `events` / `agent_update`；`events_collect` 只允许内部计划派发。

页面默认显示主机事件，采集回执和全部记录可单独切换，避免空轮询挤占恢复事件。首次使用 PostgreSQL 时，会从同组织本地加密历史导入索引、分段与游标。

![Agent 事件集中审计，2026-10-16 本机隔离环境](./images/agent-events.zh-CN.png)
