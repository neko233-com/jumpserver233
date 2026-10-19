# 单机定时安装

> 中文 | [English](./INSTALLATION-SCHEDULE.en.md)

原生受管版本可安排一次定时安装：固定暂存包摘要、安装修订和时间，由前台监督进程完成排空、停机、加密快照、离线预检与首次启动验收。默认关闭，不会随官方最新版本变化而改变目标。自动检查仍只读取正式稳定 Release；下载和暂存仍由已有命令执行。完整无人值守下载策略、历史发布数据迁移与集群更新另行完善。

## 部署与启动

先按[受控安装](./INSTALLATION.md)完成原生基线接管。普通 `jms update run` 继续可用；启用调度时，将服务管理器的前台命令改为：

```sh
jms update supervise --root /srv/jumpserver233-releases --passphrase-file /run/secrets/jms-update-passphrase
```

- 使用绝对受管根目录，绑定的数据目录与版本不可任意改绑。快照口令文件必须是私有普通文件；不接受 stdin 或命令行口令。监督进程启动先检查文件，每次安装和首次验收再读取，读完清除内存缓冲。
- 配置 `JMS_SERVER_URL` 为子服务的 HTTP/HTTPS 回环 IP 来源，例如 `http://127.0.0.1:8080`；拒绝远端地址、代理、URL 内凭据、路径前缀与重定向。仍按现有机制配置 TLS 信任。
- 使用已有 `jms auth` 受保护身份文件，或现有平台凭证配置。身份必须在每次维护请求时拥有全局 `security.manage`。监督程序不持有远端 SSH 密码；撤销平台身份会阻止后续控制。不得把平台令牌或快照口令写进仓库、日志和报告。
- 同一根目录只允许一个监督进程，OS 锁随进程退出释放。监督进程只管理自己启动并确认 PID 的候选；不根据 HTTP 返回的任意 PID 发送信号。
- 受管启动自动绑定 `JMS_RELEASE_ROOT`；普通原生 `run` 也可查看和安排计划，但执行计划需要 `supervise`。页面只展示监督进程最近报告时间，不将历史时间/PID 当作当前存活证明。
- 该流程为单机原生安装。Docker 镜像及 PostgreSQL HA 继续使用各自部署流程，不在线改写容器镜像或集群数据。

## Web 与 CLI

系统设置 → 安全策略 → 软件更新 → 定时安装。展开“安排暂存版本”，显式刷新已校验候选，选择版本/摘要、当地时间和最长排空等待。候选必须是同平台、声明预检/验收协议且比当前版本新的完整暂存包。刷新会核对文件字节；状态轮询不反复哈希程序。

```sh
jms update schedule-status --root /srv/jumpserver233-releases
jms update schedule --root /srv/jumpserver233-releases --sha256 VERIFIED_SHA256 --revision 1 --installation-revision 2 --request-id install-20261020 --at 2026-10-21T02:00:00+08:00 --drain-timeout 60s
jms update schedule-cancel --root /srv/jumpserver233-releases --revision 2 --request-id cancel-20261020 --plan-id PLAN_ID
```

时间允许当前一分钟以内至未来 366 天，排空等待 5–86400 秒。CLI 使用秒为整数的 duration。CLI 本地计划依赖本机文件权限，Web 计划依赖全局平台权限；组织管理员和普通操作员不能管理全局安装。

API 为 `/api/v1/settings/security/updates/installation`：`GET` 状态、`GET /candidates` 显式校验候选、`POST` 安排、`POST /cancel` 取消。计划输入包含 `revision`、`request_id`、`installation_revision`、`archive_sha256`、RFC3339 `not_before` 和 `drain_timeout_seconds`；取消包含修订、请求 ID 和 `plan_id`。状态/回执不返回口令或身份凭证。

计划与最近 100 条活动/请求回执保存在受管根的私有 `.jms233-schedule.json`，与安装事务分开。相同请求 ID、原始完整输入和操作者重放返回当前状态；取消或成功后重放旧安排不会重新安装。同 ID 改参/换操作者、新请求旧修订、目标版本不新或安装修订变化均拒绝。

## 到时执行与失败处理

1. 复核口令文件、安装修订、暂存字节、平台授权及子进程 PID；不接管其他操作者已有的排空。
2. 写 `draining` 后，按当前进程/修订开始排空。现有 SSH 会话和已接纳的工作继续；新会话/新作业被拒绝。计划可在 `scheduled` 或 `draining` 取消。
3. 排空超时或取消时，仅在原实例、原修订仍由本计划控制时恢复接入。另一操作者的状态不被覆盖。恢复接入失败会留错误，需检查排空状态。
4. 已排空后，以修订比较提交 `stopping`。全局维护停机 API `POST /api/v1/settings/security/maintenance/stop` 必须提供同实例/修订、唯一请求 ID 和 `draining=true`；拒绝未排空、旧修订与不同身份重放。审计持久化后封闭取消，刷新响应后正常关闭服务；重复回执不会重复停机回调。
5. 监督进程收到停机确认，并等待自身子进程退出，最多 30 秒。未确认或未退出不继续安装。随后[安装事务](./INSTALLATION.md)取得数据 OS 锁，创建快照、预检并选择候选，再执行门禁首次启动。确认放行后记录 `succeeded`。
6. 预检/放行前失败恢复旧数据与旧受管服务，计划记录失败；不可逆放行后保留新版本与数据，要求向前修复。新实例清除进程内排空状态。

重启不会重复完成或取消的计划。中断的运行中计划不会自动重做安装；若已有目标事务，由原安装/首次启动守卫决定恢复或放行，状态保留明确结果。无法证明安装日志或数据锁状态时停止，并按 `install-status` / `install-recover` 处理。监督进程的正常退出仍遵循已有子进程信号转发与 12 秒终止兜底；计划排空超时本身不会触发该终止机制。

实现和验收边界以[测试记录](./TESTING.md)为准。同源码注入版本演练不能证明真实历史版本迁移兼容；源版本必须遵守升级守卫。页面显示成功表示受管候选通过首次启动门禁，部署特定的反向代理、真实业务和生产恢复仍需对应验收。
