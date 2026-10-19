# 单机升级前排空

[English](./SERVICE-MAINTENANCE.en.md) | [文档索引](./README.md)

系统设置 → 安全策略 → 软件更新 → 准备升级可开始、查看和取消排空。需要全局 `security.manage`；组织管理员不会因此获得平台控制权。此能力只支持单机，集群维护需另行协调。

开始排空后，新 API 写操作、新 WebSocket 和新 SSH 连接被拒绝，运维计划和资产监控周期暂停。现有终端仍可使用；已获准的请求、作业、改密和监控周期可完成后续步骤，包括改密后的凭据验证。操作许可在完成后失效。取消作业、关闭会话、平台登录和排空控制保留访问。通过已有 SSH 通道启动的远端进程不会被自动杀死。

状态汇总当前进程中所有已加载组织的 SSH 连接、请求/连接、终端与待连接票据、桌面、SSH 作业和数据库查询，以及监控、凭据操作和计划派发。多项计数可能代表同一业务链路，不是去重主机数。待复核作业、未派发的计划和平台内存状态不等于正在执行的远端操作；排空不承诺冻结所有本地定时写入。

## API、CLI 与重试

`GET /api/v1/settings/security/maintenance` 返回 `supported`、`instance`、`pid`、`revision`、`draining`、`ready` 和 `activity`。`PUT` 必须提供当前 `instance` / `revision`、8–80 字符的 `request_id` 和 `draining`。允许的请求 ID 字符是字母、数字、下划线和连字符。

```sh
jms update drain-status
jms update drain-start --instance INSTANCE --revision 1 --request-id upgrade-20261020 --wait 60s
jms update drain-cancel --instance INSTANCE --revision 2 --request-id cancel-20261020
```

CLI 使用平台身份，不需要远端密码。`--wait` 仅等待同一实例、同一修订；取消、进程变化或超时会非零退出，超时不会自动恢复接入。先写更新审计，再切换状态；审计写入失败时状态不变。请求回执在内存中保留最近 100 项，绑定操作者及完整输入。重复开始请求在取消之后返回当前状态和原应用修订，不重新开始排空。旧修订、同 ID 改参、不同操作者和旧进程实例被拒绝。

排空和回执是进程内状态，重启后恢复接入并产生新的实例 ID；审计保存在更新存储中。这个状态不是可跨重启的安装授权。

## 完成升级

`ready=true` 仅表示当前跟踪的活动工作已结束。随后仍须正常停止服务，使用[加密整站备份](./BACKUP.md)和[受控安装事务](./INSTALLATION.md)。数据目录的 OS 排他锁继续负责停机一致性；不能根据一次 `ready` 响应在线复制或替换数据。此批不包含自动安装调度、进程停止控制或真实历史发布格式迁移。
