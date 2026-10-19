# 局域网资产发现与同步

> 中文 | [English](./ASSET-DISCOVERY.en.md)

竞品为 [JumpServer 企业版](https://www.jumpserver.org/enterprise.html)，来源与同步流程参考其[官方资产文档](https://docs.fit2cloud.com/jumpserver/manual/admin/console/assets/assets_list/)。本模块实现 LAN 来源。公有云、私有云厂商 API 适配及其他企业功能仍按 PLAN 推进。

## 使用

1. 控制台打开“资产发现”，新增来源，填写 IP、CIDR 或起止范围、排除范围和端口。选择协议模板与可选 SSH 网关。
2. 先扫描。SSH 在认证前获取主机密钥；其他协议只确认 TCP 端口可达，不代表登录成功。扫描不使用纳管凭据。
3. 配置新增资产的用户名与凭据后保存来源，重新扫描。凭据只写入，服务端加密，读取、审计和导出均不返回凭据。
4. 创建策略并确认来源版本，配置名称前缀、节点、分组和 CIDR 筛选。自动纳管、自动信任新 SSH 密钥分别显式开启。
5. 勾选主机，预览并核对指纹后纳管。预览五分钟有效、一次消费。同请求重试返回原回执。

修改来源会暂停引用它的策略。重新扫描并保存策略，确认新的来源版本。凭据只初始化新增资产；已有密码、私钥和轮换结果保留。每七天轮换沿用原有凭据管理规则。

## 同步与限制

- 资产 ID 由来源和端点确定，重试和进程重启不重复创建。
- 不接管人工资产或其他来源资产。单一已有端点标记为已存在，多项匹配报告冲突。
- 策略只更新名称、节点、分组和备注。人工修改或策略归属不同默认冲突；显式覆盖可接管元数据，不能覆盖端点、用户名、凭据或已有 SSH 主机密钥。
- 缺失默认保留；可在连续缺失 1–10 次后停用本来源资产。只有本次实际扫描范围参与计数，移除范围不会删除旧资产。同步停用的主机恢复可达后重新启用，人工修改受到保护。
- 最多 1,024 个地址、16 个端口、8,192 个端点；并发 1–32，探测超时 100–5,000 毫秒。每来源一个活动任务，组织最多四个。
- 每批最多 500 台，在内存暂存后统一持久化；发现结果按批次写入。
- 不接受 DNS 扫描目标。网关采用现有固定主机密钥的 SSH 链路，最多三跳，一个扫描复用一条网关连接。登录复核绑定任务与当前路由，不能重放旧批准。

## 定时、权限与恢复

支持单次、间隔和带 IANA 时区的五字段 cron，复用原生计划的错过执行和夏令时重复时间规则；前次任务活动时跳过重叠触发。执行时重新检查账号状态、组织成员、权限、访问控制和网关授权。计划保留执行者与可信来源 IP，撤销权限不会保留旧执行能力。

只编辑策略元数据会保留下一次执行时间、跳过计数和夏令时去重状态。已执行的单次计划不会因重命名或重新启用而再次触发。

需要 `assets.view_all` 和相应的 `assets.discovery.view/manage/execute/import/trust/export` 权限；纳管还需要 `assets.manage`，均属于组织作用域。

单机使用独立加密文件；HA 使用 PostgreSQL 共享文档和组织密钥。接管时把扫描、同步、等待复核任务标为中断，不自动重放不确定的网络操作。已领取纳管回执配合确定性资产 ID 支持同请求恢复。存储确认不确定时先从权威存储加载，再允许写入。

保留最多 32 个来源、128 个策略、16,384 个发现结果、200 个任务、128 个预览、200 个回执和 1,000 条审计。预览、回执、审计另有字节上限；预览令牌只保存 HMAC。

## API / CLI

前缀 `/api/v1/asset-discovery`：`sources`、`policies` 提供列表、创建、详情、更新和带 revision 的删除；`runs` 提供创建、列表、详情和 `/{id}/cancel`；`findings`、`findings.csv` 必填 source_id；`import-preview`、`import` 使用一次性能力及稳定 request_id；`audit` 返回脱敏配置快照；`schedules/preview` 计算计划时间。列表采用 offset/limit。

`jms discover sources|policies|runs|findings|audit` 查看数据。`source save [ID] --file CONFIG.json`、`policy save [ID] --file CONFIG.json` 保存配置；`run start --file RUN.json` 扫描；`source|policy delete ID --revision N` 删除配置；`run show|cancel ID` 查询或取消；`preview|import --file INPUT.json` 纳管；`export --source ID` 导出。`--file -` 从标准输入读取，复用现有认证与 `JMS_ORG_ID`。重试保持 request_id 不变。

SDK：`server/internal/sessionclient/asset_discovery.go`。来源 template 不允许内联凭据，使用独立 credential；省略保留，空对象清除。更新需 revision，策略需 source_revision。

## 验收

2026-10-19：最终 Go/Testify 1324 项通过、48 项跳过；Linux race 559 项通过、8 项跳过；完整生产浏览器 83/83 通过。调度元数据修正另经最终全量 Go/race 和 Docker 定时用例验证，窄屏样式经 Docker 实际浏览器复核；本机与 Docker 的最终 CSS 摘要一致。最终 Docker 功能验证 8 项通过，包括 API 重启后的凭据/回执恢复，以及已执行单次任务的重命名不重放。

详细阶段、清理和本地报告位置见[自动化验证](./TESTING.md)。本次不包含内网部署和正式 Release；整体确认后仅发布一次。
