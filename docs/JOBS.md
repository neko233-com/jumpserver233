# SSH 作业与非交互 Agent CLI

> 中文 | [English](./JOBS.en.md)

Go 原生 Playbook 支持工作空间版本、组织发布、源码快照、顺序 SSH 模块、条件/循环/重试、持久化恢复和 Web/CLI/SDK；见[原生 Playbook](./PLAYBOOKS.md)。完整 Ansible 和企业版整体仍在进行。

主机插件也提供 `jms plugin` 结构化接口，复用任务去重、复核、所有者审计及加密输出；操作期间持续检查当前授权，详见 [主机工具与 Agent](./HOST-PLUGINS.md)。

来源、每周时段及执行通道限制支持单机和单活 HA，详见 [访问策略](./ACCESS-POLICIES.md)；完整企业版对齐仍在推进。

全局作业读取、取消、审批及计划读取/管理分别支持 [RBAC 权限](./RBAC.md)委派；后台派发检查最新角色，个人模板仍仅创建人可见。本文“管理员”管理操作也可由对应权限角色执行。

工作台 `/workbench` 可提交 SSH 单命令、批量命令、一次性或周期计划，管理个人命令模板，查看 stdout/stderr、退出码、取消执行及审批命令复核。Agent CLI 支持单命令的相同服务端链路，无需 TTY，也不接受或获取远端 SSH 密码。

```powershell
# JMS_TOKEN 使用平台短期 Bearer Token；也可使用既有 AccessKey 环境变量。
$env:JMS_SERVER_URL = 'http://127.0.0.1:8080'
go run ./cmd/jms exec <asset-id> --timeout 60 --json -- 'uname -a'
# 已配置 SSH 工作区时可选择起始目录，详见执行目录文档。
go run ./cmd/jms exec <asset-id> --directory /srv/work/deploy --json -- pwd
```

CLI 默认将远端 stdout/stderr 分别写到本地对应流，作业 ID 写入 stderr。`--json` 输出完整作业结果。远端退出码 1–255 由编译后的 CLI 原样返回；`go run` 自身会包装子进程失败，脚本应使用编译后的 `jms`。执行超时、拒绝和连接错误返回非零状态。

## 授权与审计

- 提交需要资产账号的 `connect` 权限，解析用户组、节点祖先及授权时间；`view` 不允许执行。管理员遵循现有资产管理权限。
- 开启登录复核的资产先完成既有一次性 SSH 登录复核。CLI 会等待批准后继续，网页会提示批准后重新提交。
- 命令过滤规则在执行前生效。deny 写入拒绝审计且不连接远端；review 创建待审批作业，5 分钟内由管理员批准或拒绝。批准时重新校验原提交人的当前资产授权、账号和命令策略。
- 有适用过滤规则时，包含 shell 组合、替换、重定向等操作符的命令保守拒绝。规则匹配提交的完整字符串，不解析远端 shell AST，也不能证明别名或远端脚本的行为。
- 命令及结果使用 Vault key 的 AES-GCM 加密后写入 `ssh-jobs.json`，集群模式写入 PostgreSQL `ssh-jobs` 文档。执行必须先成功保存初始审计。结果只对提交人和管理员可见；命令输出可能包含业务敏感信息，系统不会自动脱敏任意输出。
- 客户端生成 `request_id`，同一用户重复提交相同请求返回同一作业；相同 ID 的不同参数返回 409。此机制不会自动重试远端命令。

## 资源与故障边界

- 执行默认超时 60 秒，允许 1–300 秒；stdout/stderr 合计最多保留 64 KiB，超出后继续排空但不保存。
- 全局最多同时执行 8 个作业、每用户 2 个；每用户最多 20 个待审批作业；审计最多 1000 条，达到后拒绝新作业，不自动删除旧审计。
- 取消、超时或节点关闭会关闭 SSH 传输；远端自行脱离会话的子进程可能继续运行，必须通过后续运维检查确认。
- 重启或 HA 接管把未完成作业标记为中断，不自动重放。失去选主锁的旧节点停止写作业文档。最终审计保存失败显示 `audit_unavailable`，重试前应确认远端实际结果。
- 当前提供 SSH 命令作业、批量派发、模板及间隔调度。完整 Ansible 及其他工单类型仍待实现；cron/日历调度见[日历计划](./SCHEDULING.md)；授权工单和外部通知见 [访问工单](./ACCESS-TICKETS.md) 与 [通知中心](./NOTIFICATIONS.md)。

## 批量、模板与调度

在工作台展开“批量命令与定时任务”，选择 1–50 台已授权主机并创建立即执行、未来一次或按间隔重复的计划。间隔为 60 秒至 31 天，时间在页面按浏览器本地时区输入并转换为 UTC。模板属于创建人，更新/删除需要当前 `revision`；计划保存命令、超时和模板版本快照，后续编辑或删除模板不改变已有计划。

- 每台主机独立创建加密作业，复用 `connect`、当前用户身份、登录复核、命令策略、容量和审计检查。创建时及实际派发时都校验授权，撤销后的定时计划不会连接该主机。管理员可查看全部计划和执行；操作员只可查看自己的计划、执行和模板，管理员也不能读取他人的个人模板。
- 队列只对明确未执行的容量不足及等待登录复核进行重试。登录复核批准后继续派发，拒绝/过期后该目标终止；命令复核在现有作业详情中审批。重复请求不消费额外登录许可，容量不足时也不消费批准。
- 周期以本次派发时间加间隔计算下一次时间；宕机期间错过的次数合并为一次，已有执行或审批未结束时跳过本次触发。暂停只影响后续触发；取消本次执行会停止未派发目标并请求取消已创建的子作业。
- 派发前必须成功持久化目标的领取状态。重启/HA 接管时，已领取目标只关联相同请求 ID 的已有作业；无法确认是否越过执行边界时标记中断，绝不自动重放。未领取目标在重新授权后继续排队。
- 模板、计划及执行索引使用 Vault key AES-GCM 加密，单机存 `operations.json`，单活集群存 PostgreSQL `operations` 文档。旧主节点失去选主锁后停止调度与写入。最多 500 个模板、1000 个计划、1000 次执行；历史满后暂停到期计划，不自动清除审计。子作业另受 1000 条审计上限约束。

## API

`POST /api/v1/ops/jobs` 提交 `{asset_id, command, timeout_seconds, request_id}`；`GET /api/v1/ops/jobs?limit=50&offset=0` 列表；`GET /api/v1/ops/jobs/{id}` 详情；`DELETE /api/v1/ops/jobs/{id}` 取消；管理员通过 `POST /api/v1/ops/jobs/{id}/review` 的 `{approve: true|false}` 审批。登录复核待审批时提交返回 202 和 `review_id`，作业创建返回 201。

模板：`GET/POST /api/v1/ops/templates`、`PUT /api/v1/ops/templates/{id}`、`DELETE /api/v1/ops/templates/{id}?revision=N`。创建/更新内容 `{name, command, timeout_seconds, revision}`。

计划：`GET/POST /api/v1/ops/plans`。创建内容 `{name, asset_ids, command, timeout_seconds, kind, request_id}`；使用 `template_id` 时省略 `command`；`kind` 为 `batch`、`once`（必填未来 `run_at`）、`interval`（必填 `interval_seconds`，可选未来 `run_at`）或 `cron`（五段 `cron_expression` 与显式 `timezone`）。`PUT /api/v1/ops/plans/{id}` 的 `{enabled: true|false, revision: N}` 暂停/恢复未完成计划。

执行：`GET /api/v1/ops/runs?limit=50&offset=0`、`GET /api/v1/ops/runs/{id}`、`POST /api/v1/ops/runs/{id}/cancel`。每个目标包含 `state`、`job_id`、`review_id` 或 `error_code`，通过作业详情读取实际输出。

## 连接与工作区审批证明

普通 SSH 作业记录服务端生成的 `connection_scope`，请求正文不能设置该字段。登录/命令复核作业在提交时固定真实工作区根身份，执行时经原生 helper 的 FD 校验；配置或目录变更会阻止使用旧证明。证明作为作业的一部分加密保存，新目录/策略证明记录使用认证加密 envelope v6，继续读取 v1–v5。单命令 Web/CLI 支持 `working_directory`，审批绑定真实起始目录与活动策略；字段与边界见[受控执行目录](./EXECUTION-DIRECTORIES.md)。缺少上下文校验器不会回退普通执行；旧版没有当前策略证明的待命令审批普通作业需要取消后重新提交。重复 request ID 保留原作业与结果，不启动第二次执行。

这固定的是整个工作区根，未实现命令实际 cwd 或精确/正则目录命令规则。插件、发现和远端账号操作沿用单独的类型化执行器。详见[登录复核](./ACCESS-REVIEWS.md)与[工作区](./SSH-WORKSPACES.md)。

## 自动化验证

Testify 用例覆盖模板隔离/版本/快照、加密、本地与 PostgreSQL 恢复、容量排队、批量取消、错过触发合并、避免重叠、领取恢复防重放、权限撤销、两种复核及失主停止写入。设置 `JMS_TEST_DATABASE_URL` 后运行 `go test ./...`；Linux CI 运行完整 `go test -race ./...`。`pnpm test:e2e` 使用独立临时数据和真实合成 SSH 服务，覆盖双主机批量、模板快照的一次性调度、周期暂停/恢复、中英界面及 view-only 拒绝。HA 集成用例检查接管后登录会话、模板和未来计划保留。
