# 资产发现与同步

> 中文 | [English](./ASSET-DISCOVERY.en.md)

竞品为 [JumpServer 企业版](https://www.jumpserver.org/enterprise.html)，来源与同步流程参考其[官方资产文档](https://docs.fit2cloud.com/jumpserver/manual/admin/console/assets/assets_list/)。本模块实现 LAN 发现及 AWS 国际区/中国区、阿里云 ECS、腾讯云 CVM 原生清单。其他公有云、私有云厂商 API 及企业功能仍按 PLAN 推进。

## 阿里云 ECS 和腾讯云 CVM

`aliyun` 填写阿里云账号 UID，`tencentcloud` 填写腾讯云主账号 UIN；这些字段不填 RAM 用户 ID、腾讯云 AppID 或子账号 UIN。已有来源的提供商和账号固定。明确指定地域后，地址选择、可选固定密钥 SSH 网关、一次性纳管、策略、定时、来源修订、审计和元数据归属沿用 AWS/LAN 流程，云凭据与 SSH 纳管凭据独立。

共用仅写的 `cloud_credential` 字段，分别对应阿里云 AccessKey ID/Secret 和可选 STS Token，或腾讯云 SecretId/SecretKey 和可选 STS Token。腾讯云临时 ID 和密钥最多 1024 字节，Token 最多 4096 字节。密钥不进入请求 URL，不通过来源读取、审计、CSV 或 CLI 回显，也不会替换原生资产的既有凭据。新增来源表单切换提供商会清空已输入的云密钥。提供商原始状态与统一电源状态共同保留；新状态或未知状态仍显示，不探测、不计缺失。

- 阿里云先核对 [STS GetCallerIdentity](https://www.alibabacloud.com/help/en/ram/developer-reference/api-sts-2015-04-01-getcalleridentity)，再通过地域 [ECS DescribeInstances](https://www.alibabacloud.com/help/en/ecs/developer-reference/api-ecs-2014-05-26-describeinstances) 的 `MaxResults=100` 与 `NextToken` 分页。采用官方 [RPC 签名](https://www.alibabacloud.com/help/en/sdk/product-overview/rpc-mechanism)、独立随机 nonce 和 HTTPS POST 表单。每个地域枚举前后，都要求 `DryRun=true` 返回 `DryRunOperation`。权限不足可能被普通查询表示为空列表；预检被拒或无法确认时，整次任务失败并保留旧清单。
- 腾讯云先通过 STS `GetCallerIdentity` 核对主账号 UIN，再使用 [CVM DescribeInstances](https://cloud.tencent.com/document/product/213/15728) 的 `Limit=100`、偏移量及 [TC3-HMAC-SHA256](https://www.tencentcloud.com/document/product/1176/55147)。每页必须明确包含总量和实例数组；途中总量变化、重复 ID、未取完就出现空页、接口错误或部分地域失败，都会中止整次任务。签名凭据日期采用 UTC。

两个适配器均使用固定的提供商 HTTPS 地址，不跟随重定向，限制响应、实例和元数据总量，限流或暂时服务错误最多重试两次并支持取消。统一私有/公网 IPv4、IPv6、名称、可用区和标签，无厂商 SDK 新依赖。IPv6 选择稳定地址，阿里云 EIP 优先于普通公网 IPv4，不调用云资源写接口。

启用自动缺失处理前，应授予所选地域的完整清单可见权限。身份查询和预检不能证明生产 RAM/CAM 资源策略展示了所有资产；资源范围可见性变化及云接口最终一致性仍需运维核对，并采用保守缺失阈值。签名协议夹具、加密重启、API/CLI 和浏览器验证，与真实云账号验收分别记录。真实阿里云/腾讯云账号、私有云变体及其他云平台的剩余边界见 PLAN。

## AWS 国际区和中国区

选择 `aws` 或 `aws_cn`，填写固定的 12 位 AWS 账号 ID、明确的地域列表，以及私有 IPv4、公网 IPv4 或 IPv6。云凭据与新资产的 SSH 凭据独立。Access Key ID、Secret Access Key 和可选的 STS Session Token 仅写入、按组织加密保存，来源读取、审计、CSV 和 CLI 输出均不回显。编辑来源默认保留云凭据，明确选择替换后才更新。同一来源不能更换提供商或账号；其他账号应创建新来源，当前账号内允许轮换密钥。

连接器使用官方地域 HTTPS 地址，先调用 STS `GetCallerIdentity`，再使用 SigV4 签名 POST Query 请求，分页获取 EC2 `DescribeInstances`。不跟随重定向，不提供自定义端点、不安全 TLS 或云资源写接口。只读身份需具备 `ec2:DescribeInstances`，STS 身份查询遵循 [AWS 权限约定](https://docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html)。地域启用及账号可访问性由运维人员配置；这两个适配器不含 AWS GovCloud 或隔离分区。

所有选定地域和分页成功后才发布清单。接口失败、无效响应、循环分页、账号或资源所有者不符均保留原发现结果，不计缺失。限制为 32 个地域、每地域 500 页、单响应 8 MiB、规范化云元数据总量 4 MiB、8,192 个观察实例/端点。元数据预算在探测和发布前计算，包含每个所选端口及缺失资源，防止标签与端口展开放大内存占用。限流请求最多重试两次，支持取消并受现有 15 分钟任务时限约束。

发现结果记录稳定的提供商/账号/地域/实例身份、名称、状态、地址和标签。运行中且存在所选 IP 的实例继续执行现有的不认证 SSH 指纹观察或 TCP 探测，可经固定密钥的 SSH 网关。停机或缺少所选 IP 的实例仍显示，不计缺失；只有完整成功清单中消失、且位于当前地域和端口范围内的实例才累计缺失。移除地域会保留旧资产。沿用现有阈值停用、一次性预览与纳管流程。

实例 IP 变化保持相同发现和资产 ID，SSH 可按下节显式开启自动迁移。默认仍对端点变化返回冲突，SSH 指纹变化始终冲突。实例名称更新遵守现有元数据归属保护。其他协议地址迁移、多节点映射仍待完成。没有真实云账号时，不宣称真实云账号验收；签名协议夹具与 API/浏览器验证分别记录。

Web、SDK 与 `jms discover source save --file -` 共用 `provider`、`cloud`（`account_id`、`regions`、`address_mode`）及仅写的 `cloud_credential`（`access_key_id`、`secret_access_key`、`session_token`）字段。通过受保护的标准输入传入凭据，不放到命令参数或提交的配置中。`jms discover source show` 只返回公开设置和凭据配置状态。

## 云主机 SSH IP 自动迁移

同步策略的 `migrate_cloud_ssh_address` 默认关闭，仅适用于云来源的 SSH 模板，并要求 `update_existing=true`。Web 在“更新来源拥有的资产元数据”下提供开关；CLI/SDK 使用同一字段。关闭元数据更新会同时关闭迁移，LAN 和其它协议不提供此开关。

仅迁移本来源、本策略拥有的同一提供商/账号/地域/实例与端口。新地址必须是字面 IPv4 或 IPv6，实例运行中且本轮实际观察到的 SSH 指纹与资产既有信任一致。端口、用户名、协议、网关和主机密钥均不能随迁移改变。指纹观察不发送目标凭据，后续登录仍由原生 SSH 固定主机密钥校验。

人工改过元数据、目标端点被其它资产占用、策略归属不同、父/子账号正在轮换或远端账号操作待确定时，保留原地址并报告冲突。元数据覆盖开关不能绕过迁移时的人工修改或策略归属检查。跨组织共享凭据和新目标上的待确定操作沿用统一协调器校验。与人工资产端点匹配不代表来源拥有该资产；关闭自动纳管后不会因其地址变化意外创建资产。

迁移保留资产与托管账号 ID、凭据密文及修订、备份历史和轮换时间；子账号继承新地址，旧账号收集绑定清除。资产的 `discovery.last_address_change` 保存前后地址、策略 ID 和时间，发现结果标为 `address_updated` 并计入更新数量。相同地址重试不产生第二次迁移或改写回执时间。批次取消、持久化确认不明确和进程恢复沿用原子暂存及权威存储复核。

SSH 连接绑定包含地址。迁移后的持续授权检查会关闭旧 SSH 连接，持有旧路由绑定的待执行任务需重新发起。登录复核和临时 SFTP 会话继续使用平台既有的用户、资产、账号及动作绑定规则；同一云实例的身份未改变。固定 SSH 网关本身保持不变。缺失清单、停机、无地址、失败探测或变更密钥不能触发迁移。

## 使用

1. 控制台打开“资产发现”，新增来源，填写 IP、CIDR 或起止范围、排除范围和端口。选择协议模板与可选 SSH 网关。
2. 先扫描。SSH 在认证前获取主机密钥；其他协议只确认 TCP 端口可达，不代表登录成功。扫描不使用纳管凭据。
3. 配置新增资产的用户名与凭据后保存来源，重新扫描。凭据只写入，服务端加密，读取、审计和导出均不返回凭据。
4. 创建策略并确认来源版本，配置名称前缀、节点、分组和 CIDR 筛选。自动纳管、自动信任新 SSH 密钥分别显式开启。
5. 勾选主机，预览并核对指纹后纳管。预览五分钟有效、一次消费。同请求重试返回原回执。

修改来源会暂停引用它的策略。重新扫描并保存策略，确认新的来源版本。凭据只初始化新增资产；已有密码、私钥和轮换结果保留。每七天轮换沿用原有凭据管理规则。

## 同步与限制

- LAN 资产 ID 由来源和端点确定；云资产由来源、提供商/账号/地域/实例、协议和端口确定。重试和进程重启不重复创建。
- 不接管人工资产或其他来源资产。单一已有端点标记为已存在，多项匹配报告冲突。
- 策略更新名称、节点、分组和备注；SSH 云 IP 迁移另需显式开关及上述连续信任检查。人工修改或策略归属不同默认冲突；显式覆盖可接管元数据，不能覆盖用户名、凭据或已有 SSH 主机密钥。
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

`sources`、`policies` 支持 `--source`、`--offset` 和 `--limit`；来源列表按 ID、策略列表按来源 ID 筛选，`total` 表示分页前筛选后的总量。

SDK：`server/internal/sessionclient/asset_discovery.go`。来源 template 不允许内联凭据，使用独立 credential；省略保留，空对象清除。更新需 revision，策略需 source_revision。

## 验收

2026-10-19：最终 Go/Testify 1324 项通过、48 项跳过；Linux race 559 项通过、8 项跳过；完整生产浏览器 83/83 通过。调度元数据修正另经最终全量 Go/race 和 Docker 定时用例验证，窄屏样式经 Docker 实际浏览器复核；本机与 Docker 的最终 CSS 摘要一致。最终 Docker 功能验证 8 项通过，包括 API 重启后的凭据/回执恢复，以及已执行单次任务的重命名不重放。

详细阶段、清理和本地报告位置见[自动化验证](./TESTING.md)。本次不包含内网部署和正式 Release；整体确认后仅发布一次。
