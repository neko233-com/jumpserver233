# 录像外部存储

> 中文 | [English](./REPLAY-STORAGE.en.md)

## 当前状态

E35 **实现待验**。对象后端、归档引擎、主进程/组织生命周期、会话结束入队、历史补入、鉴权回放、受控本地清理、备份/缓存收尾、中英 Web、CLI/SDK 及配套用例已编写。默认仍为仅本地，启用外部归档需要管理配置；本轮没有运行验证，也不据此声明生产可用。

遵循用户要求，全部 42 组功能、用例和双语文档实现就绪后才统一运行测试、构建、浏览器和 Docker。本文不提供新的通过结果、性能测量或云服务兼容性承诺。

## 已编写的后端

| 存储 | 源码设计 |
|---|---|
| S3 | SigV4、HTTPS、对象条件创建；支持路径式端点。 |
| 阿里云 OSS | 原生 V4 签名、禁止覆盖请求头。 |
| 腾讯云 COS | 原生 HMAC-SHA1 签名、禁止覆盖请求头。 |
| 华为云 OBS | 原生 OBS 请求头签名、禁止覆盖请求头。 |
| SFTP | 复用现有 SSH/SFTP 传输、Vault 账号/短期证书、主机指纹、网关与工作区；独占临时文件、摘要校验、无覆盖重命名、拒绝链接父目录。绑定固定目标，密码轮换不改变存储位置。 |
| PostgreSQL | 复用可选共享状态连接池；按组织隔离的元数据与 1 MiB 密文块，一个事务提交。单机默认不增加数据库依赖。 |

HTTP 签名实现参考 [AWS S3 SigV4](https://docs.aws.amazon.com/AmazonS3/latest/developerguide/sig-v4-header-based-auth.html)、[阿里云官方 OSS V4 实现](https://github.com/aliyun/alibabacloud-oss-python-sdk-v2/blob/master/alibabacloud_oss_v2/signer/v4.py)、[腾讯云 COS 请求签名](https://www.tencentcloud.com/document/product/436/7778)和[华为云 OBS 请求头认证](https://support.huaweicloud.com/intl/en-us/api-obs/obs_04_0010.html)。各供应商独立签名，当前未增加云 SDK 依赖。签名用例与本地 HTTPS 夹具尚未执行，也未连接真实云账号。

云端点限制为 HTTPS 源地址，不接受 URL 用户信息、查询、片段或路径前缀；仅回环夹具允许 HTTP。拒绝 HTTP 重定向，支持显式根证书及临时令牌。每次操作有时限，不在错误和审计中保存服务响应正文或凭据。条件创建行为取决于供应商及桶版本配置，归档完成必须再执行完整读回校验。

## 配置与任务

- `replay-archive.json` 使用 Vault 密钥做 AES-GCM 加密；PostgreSQL 模式保存同一加密文档。API 结果类型移除密钥和令牌，只提供存在标志。
- 配置采用修订号与请求回执。历史位置保留；相同位置优先使用更新凭据，不把旧对象重新指向新桶。空白密钥仅能在原位置、原 AccessKeyID 下保留旧值；令牌清空需要明确指定。
- 首次打开默认 `local`、禁用外部归档，不创建缓存目录、启动工作器或访问网络。运行时仅在活动节点通过离线预检/升级激活门禁后显式 `Start`；配置变更取消在途上传。后台上传计入 `replay_archive` 活动，排空期间不领取新任务，已获准任务可以完成。
- 结束通知按录像类型和会话 ID 幂等入队。对象标识含组织密钥派生的命名空间、会话摘要和密文 SHA-256；上传前持久化清单，响应丢失后可重试同一标识。
- 上传或发现同名对象后，都完整 GET 并验证长度与 SHA-256，才能标记 `stored`。失败最多自动尝试 10 次，之后等待显式重试；失败只保留固定错误码。本地原件不自动删除。
- 每组织最多 20,000 条归档清单、1,000 个配置修订、4,000 条管理请求回执和 2,000 条滚动管理审计；加密状态明文上限 32 MiB。达到上限明确拒绝，不能静默丢弃历史定位。

## 录像格式与缓存

终端保留现有 `JMSREC1` 密文格式，准备上传时要求本地审计标记已结束，并认证完整 asciinema gzip 流。桌面要求结束索引，逐帧认证后将 `.png.enc` 放入确定性的无压缩 ZIP；不在 ZIP 中放明文截图或索引。归档不更改会话 WebSocket 帧或授权回放格式。

单对象上限 1 GiB，终端验证解压总量上限 8 GiB，桌面沿用既有帧与录像限制。远程密文先下载到 `replay-cache/` 并校验整对象，再交给录像解密器。缓存至多四个对象、总预留 1 GiB，活跃读取不驱逐；下载合并，缓存满时明确返回容量错误。桌面帧读取复用缓存，无需为每一帧重新下载整个 ZIP。显式远程校验绕过缓存。缓存额度不包含最多两个桌面临时打包文件；打包另受既有录像大小限制，工作器结束即清理。

临时打包失败、下载失败和缓存驱逐只清理本实例创建的文件。关闭时取消并等待上传、校验、清理与下载操作，再关闭缓存文件租约并删除缓存；读取者重复关闭安全。活动节点启动时只清理缓存目录中 `.replay-cipher-数字`、`.replay-pack-数字` 的已知临时文件，拒绝链接并保留其他文件。离线预检不执行清理。运行状态、密文缓存和中断原子写入均已被 Git/Docker 忽略。

## 管理、回放与清理

管理页为 `/console/replay-storage`。配置使用 `replay_storage.view/manage`，历史归档和重试使用 `.archive`，完整远程校验使用 `.verify`，清理本地原件使用 `.evict`，审计使用 `.audit`。SFTP 配置还需要 `assets.manage`、`assets.sftp_all`；目标要求登录审批时还需要 `login_review.bypass`。服务端重新计算存储目标绑定，忽略客户端伪造的绑定值。资产改指其他主机、路由、工作区或登录审批要求后拒绝使用原绑定；需要恢复原资产绑定才能读取对应历史对象，不自动猜测或迁移旧位置。

所有归档记录、单项操作和带会话引用的审计均按现有自有/全部录像权限过滤，再分页和计数。存储权限不授予其他人的回放权限。原回放入口优先读取本地；只有本地文件缺失才使用已验证归档，损坏的本地文件不会被静默替换。接口不返回对象地址或预签名 URL。

“清理本地原件”先重新下载并完整校验远程副本，再检查本地密文与已归档内容一致；不匹配时拒绝删除。只删除已结束录像的密文文件，保留审计索引、配置、密钥与远程对象。桌面已部分清理后可以继续重试；请求 ID 回执防止重复执行。它不是远程对象删除或自动保留策略。

单机停机导出保留加密配置、历史定位、回执、密钥、索引与本地原件，排除根目录及组织目录的 `replay-cache/`；已有备份保持原清单校验语义。外部对象不包含在单机备份中，需要存储端独立备份和保留策略；PostgreSQL 集群整库备份仍属于 E37。

## API / CLI / SDK

配置路径为 `/api/v1/settings/replay-storage`：GET 返回 `{config, postgres_available}`，PUT 接受配置、`revision`、`request_id` 并返回不含密钥的配置。`/records`、`/audit` 使用 `offset/limit`，每页最多 100 条。单项路径 `/records/{terminal|desktop}/{sessionID}` 支持 GET，后缀 `/archive`、`/retry`、`/verify`、`/evict` 支持 POST；请求体为 `{"request_id":"reusable-unique-request-ID"}`。重试同一请求必须保持请求 ID 和参数不变；新意图使用新 ID。

```sh
jms replay-storage settings
jms replay-storage save --file -
jms replay-storage records --offset 0 --limit 20
jms replay-storage get terminal SESSION_ID
jms replay-storage archive terminal SESSION_ID --request-id REQUEST_ID
jms replay-storage verify terminal SESSION_ID --request-id REQUEST_ID
jms replay-storage evict terminal SESSION_ID --request-id REQUEST_ID
jms replay-storage retry terminal SESSION_ID --request-id REQUEST_ID
jms replay-storage audit --limit 20
```

CLI 沿用 `JMS_SERVER_URL`、平台 Token/AccessKey 和组织选择，不读取目标 SSH 密码。`save` 的 JSON 可从标准输入提交，SDK 输出再次移除密钥/令牌。Go SDK 提供 `ReplayStorage`、`SaveReplayStorage`、`ReplayStorageRecords`、`ReplayStorageRecord`、`ReplayStorageAction` 与 `ReplayStorageAudit`，复用原鉴权/组织头。

## 待统一验收的用例

Testify 源码覆盖签名/HTTPS、SFTP 独占清理、数据库事务/组织隔离、配置回执与历史凭据、丢失响应、并发通知、排空、重启、损坏拒绝、加密终端/桌面格式、部分清理重试、缓存收尾、API 权限与隐藏计数、CLI 脱敏和备份恢复。`replay-storage.spec.ts` 编写真正 SSH/SFTP、Web 设置、回放、本地清理、请求重放与中英 390px 场景；`scripts/replay-storage-qa.mjs` 复用现有原生包 OpenSSH/证书夹具和一次重启，并检查存储账号实际改密后的绑定保持、历史位置读取及真实 Web SSH 输出在远程回放中保留。Linux race 入口包含归档、对象、数据库、API、CLI 和桌面收尾用例。

上述用例均待全量实现后统一执行；没有新增通过、性能或体积结果，不计入[已验收进度](./PROGRESS.md)。
