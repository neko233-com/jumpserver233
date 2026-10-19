# 资产发现与同步

> 中文 | [English](./ASSET-DISCOVERY.en.md)

竞品为 [JumpServer 企业版](https://www.jumpserver.org/enterprise.html)，来源与同步流程参考其[官方资产文档](https://docs.fit2cloud.com/jumpserver/manual/admin/console/assets/assets_list/)。本模块实现 LAN 发现及 AWS 国际区/中国区原生清单。其他公有云、私有云厂商 API 及企业功能仍按 PLAN 推进。

## AWS 国际区和中国区

选择 `aws` 或 `aws_cn`，填写固定的 12 位 AWS 账号 ID、明确的地域列表，以及私有 IPv4、公网 IPv4 或 IPv6。云凭据与新资产的 SSH 凭据独立。Access Key ID、Secret Access Key 和可选的 STS Session Token 仅写入、按组织加密保存，来源读取、审计、CSV 和 CLI 输出均不回显。编辑来源默认保留云凭据，明确选择替换后才更新。同一来源不能更换提供商或账号；其他账号应创建新来源，当前账号内允许轮换密钥。

连接器使用官方地域 HTTPS 地址，先调用 STS `GetCallerIdentity`，再使用 SigV4 签名 POST Query 请求，分页获取 EC2 `DescribeInstances`。不跟随重定向，不提供自定义端点、不安全 TLS 或云资源写接口。只读身份需具备 `ec2:DescribeInstances`，STS 身份查询遵循 [AWS 权限约定](https://docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html)。地域启用及账号可访问性由运维人员配置；这两个适配器不含 AWS GovCloud 或隔离分区。

所有选定地域和分页成功后才发布清单。接口失败、无效响应、循环分页、账号或资源所有者不符均保留原发现结果，不计缺失。限制为 32 个地域、每地域 500 页、单响应 8 MiB、规范化云元数据总量 4 MiB、8,192 个观察实例/端点。元数据预算在探测和发布前计算，包含每个所选端口及缺失资源，防止标签与端口展开放大内存占用。限流请求最多重试两次，支持取消并受现有 15 分钟任务时限约束。

发现结果记录稳定的提供商/账号/地域/实例身份、名称、状态、地址和标签。运行中且存在所选 IP 的实例继续执行现有的不认证 SSH 指纹观察或 TCP 探测，可经固定密钥的 SSH 网关。停机或缺少所选 IP 的实例仍显示，不计缺失；只有完整成功清单中消失、且位于当前地域和端口范围内的实例才累计缺失。移除地域会保留旧资产。沿用现有阈值停用、一次性预览与纳管流程。

实例 IP 变化仍保持相同发现和资产 ID。本批对既有端点或 SSH 指纹变化返回冲突，保留原生凭据和信任；自动迁移 IP、多节点映射仍待完成。此类变化需在资产清单中明确核对处理，再确认来源和策略。实例名称更新遵守现有元数据归属保护。没有真实 AWS 账号时，不宣称真实云账号验收；签名协议夹具与 API/浏览器验证分别记录。

Web、SDK 与 `jms discover source save --file -` 共用 `provider`、`cloud`（`account_id`、`regions`、`address_mode`）及仅写的 `cloud_credential`（`access_key_id`、`secret_access_key`、`session_token`）字段。通过受保护的标准输入传入凭据，不放到命令参数或提交的配置中。`jms discover source show` 只返回公开设置和凭据配置状态。

## 使用

1. 控制台打开“资产发现”，新增来源，填写 IP、CIDR 或起止范围、排除范围和端口。选择协议模板与可选 SSH 网关。
2. 先扫描。SSH 在认证前获取主机密钥；其他协议只确认 TCP 端口可达，不代表登录成功。扫描不使用纳管凭据。
3. 配置新增资产的用户名与凭据后保存来源，重新扫描。凭据只写入，服务端加密，读取、审计和导出均不返回凭据。
4. 创建策略并确认来源版本，配置名称前缀、节点、分组和 CIDR 筛选。自动纳管、自动信任新 SSH 密钥分别显式开启。
5. 勾选主机，预览并核对指纹后纳管。预览五分钟有效、一次消费。同请求重试返回原回执。

修改来源会暂停引用它的策略。重新扫描并保存策略，确认新的来源版本。凭据只初始化新增资产；已有密码、私钥和轮换结果保留。每七天轮换沿用原有凭据管理规则。

## 同步与限制

- LAN 资产 ID 由来源和端点确定；AWS 由来源、提供商/账号/地域/实例、协议和端口确定。重试和进程重启不重复创建。
- 不接管人工资产或其他来源资产。单一已有端点标记为已存在，多项匹配报告冲突。
- 策略只更新名称、节点、分组和备注。人工修改或策略归属不同默认冲突；显式覆盖可接管元数据，不能覆盖端点、用户名、凭据或已有 SSH 主机密钥。
- 缺失默认保留；可在连续缺失 1–10 次后停用本来源资产。只有本次实际扫描范围参与计数，移除范围不会删除旧资产。同步停用的主机恢复可达后重新启用，人工修改受到保护。
- LAN 最多 1,024 个地址、16 个端口、8,192 个端点。各来源探测并发 1–32，超时 100–5,000 毫秒。每来源一个活动任务，组织最多四个。
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
