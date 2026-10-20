# AI 助手与对话审计

> 中文 | [English](./AI-ASSISTANT.en.md)

`/console/assistant` 提供组织独立的文本运维问答、历史对话、归档与审计。Web、`jms assistant` 和 Go SDK 使用同一平台身份；模型不会执行 SSH、读取资产凭据或批准操作。E34 代码、用例与本文已编写，**尚未运行统一验证**，不代表真实模型服务已验收。

## 配置与权限

默认关闭，无模型运行时、向量数据库、额外进程或监听端口。管理员配置完整 HTTPS Chat Completions 地址、模型 ID、只写 API 密钥、生成 Token 上限，可追加信任 CA。模型和地址必须显式填写，不自动选择供应商、资费或型号。

| 权限 | 范围 |
|---|---|
| `assistant.use` | 提问、读取自己的历史、归档自己的对话 |
| `assistant.manage` | 查看/修改本组织模型配置；不单独授予提问或他人对话读取 |
| `assistant.audit` | 显式选择本组织全部对话、读取正文及元数据审计；不授予执行能力 |

三项是独立的组织能力，普通操作员不会自动取得；系统管理员沿用既有完整权限。配置、对话和回执分别使用当前组织密钥与 Documents 作用域，不能跨组织查找。默认组织数据在 `assistant.json`，其它组织位于既有组织目录。单机不增加数据库依赖；既有 PostgreSQL 单活接管保存同样状态，在线请求不迁移。

`PUT /api/v1/assistant/settings` 使用 `revision` 和 `request_id`。同一身份、请求 ID 和内容返回原配置回执；请求 ID 改换内容或修订落后返回 `409`。密钥字段省略保持现值，空字符串删除；已启用配置不能没有密钥。响应只返回 `configured`，不会返回密钥；保存新修订会取消当前组织进行中的模型请求。GET 的 `configured` 是只读字段，不能原样复制到 PUT。

## 模型通道与数据范围

原生 Go 连接器发送 `messages`、`model`、`max_completion_tokens`、`store:false`、`stream:false`，只接收一个文本 assistant choice。协议字段依据 [OpenAI Chat Completions 官方参考](https://developers.openai.com/api/reference/resources/chat/subresources/completions/methods/create)。兼容服务必须支持该字段组合；不宣称所有厂商或所有模型已兼容。

TLS 最低 1.2，校验证书和主机名，拒绝跳转、URL 用户信息、查询密钥和 fragment，不读取环境代理或环境凭据。地址由具有配置权限的用户明确选择，可连接受信任的内网 HTTPS 服务。请求最多 45 秒，响应正文最多 256 KiB、有效回复最多 32 KiB；HTTP/协议错误只保存有限状态，不返回供应商错误正文。

用户在发送前明确同意把文本和最近已完成的对话发给配置的供应商。只发送本对话最近至多十二轮已完成的问答，并按 120 KiB 截断最早轮次；不自动收集主机清单、Vault、终端、录像、SQL、文件或其他用户上下文。只写密钥仅用于认证头；已知当前供应商密钥若出现在问答中会替换为 `[redacted]`。无法识别所有用户自行粘贴的第三方秘密，因此页面明确要求不要粘贴凭据。

请求不包含工具或函数，工具调用回复会拒绝；回复按纯文本显示，不执行 HTML/Markdown 脚本或命令。需要执行某项建议时，用户进入既有控制台操作，继续接受资产授权、敏感命令规则与审批。

## 幂等、撤权和恢复

每次提交先原子保存加密意图及请求摘要，再调用一次模型。相同 `request_id` 重试只读取原回执：进行中返回 `202`，终态返回 `200`，改变内容返回 `409`。新一轮需要当前对话修订，同一对话一次只能有一个待处理请求。明确的新请求仍可能产生供应商费用；平台不重试网络错误、429 或未知结果。

提交前、进行中的定时检查、结果保存及响应前均复查当前平台凭证、组织资格与角色。权限/配置变化取消在途 I/O，并扣留回复。撤销无法追回此前已经发送给供应商的文本。中断或关机使远端结果不确定时记为 `uncertain`；启动和读取可恢复孤立意图，但不会重新调用模型。即使供应商已返回、结果落盘失败，后续重试也不重复调用。

升级排空统计 `assistant` 工作并拒绝新调用，已经取得租约的请求可以完成；组织关闭或节点退出会取消并等待现有调用。共享状态接管保留回执，不把未完成调用当成安全可重放任务。

## 保留与审计

每组织最多 256 个对话，每对话 32 轮；输入最多 12,000 UTF-8 字节。最近更新时间超过 90 天的对话在后续写入清理并从列表隐藏，归档保留正文供授权审计，不等于立即删除。请求/配置/归档回执保留 365 天，最多 4,000 条；元数据审计最多 4,000 条/365 天；加密状态明文上限 16 MiB。容量不足先拒绝新提交，不先调用付费服务。每组织最多四个在途请求，每用户十分钟最多三十次新请求，重放回执不增加模型调用。

正文、密钥、意图和结果用 AES-GCM 加密，原子文件替换或既有 Documents 单次保存。审计元数据记录提交、完成、失败、中断、扣留、配置及归档，不重复放入正文或密钥。整站加密备份包含此状态；恢复后相同请求仍返回原结果。历史对话只保证本产品保留窗口内的记录，不是供应商侧删除或永久历史仓库。

## API 与 CLI

```text
GET  /api/v1/assistant/capabilities
GET  /api/v1/assistant/settings
PUT  /api/v1/assistant/settings
POST /api/v1/assistant/turns
GET  /api/v1/assistant/conversations?all=false&archived=false&offset=0&limit=20
GET  /api/v1/assistant/conversations/{id}?all=false
POST /api/v1/assistant/conversations/{id}/archive
GET  /api/v1/assistant/audit?offset=0&limit=20
```

```sh
jms assistant settings
jms assistant configure --file -
jms assistant ask --file question.json
jms assistant list
jms assistant show chat_ID
jms assistant audit --offset 0 --limit 20
```

以下提问文件不包含模型密钥；已有对话另填 `conversation_id` 和当前 `revision`。

```json
{"message":"解释 pwd 的作用","locale":"zh-CN","consent":true,"revision":0,"request_id":"example-assistant-question-001"}
```

配置秘密通过安全 stdin/文件输入，不放在命令行参数、终端历史、报告或截图。`JMS_TOKEN` / AccessKey 与 `X-JMS-ORG` 沿用既有平台协议。

## 已编写但未执行的用例

Testify 覆盖真实本机 HTTPS、CA/重定向/工具/容量拒绝、一次调用与并发回执、修订冲突、写失败后恢复、撤权/配置取消、重复 Close、排空、加密及 PostgreSQL 组织隔离/重开。API/CLI/SDK 覆盖独立权限、主体不可伪造、密钥只写、他人对话不可见及 `202`。

既有组织生命周期与整站备份用例增加配置/对话及回执恢复。`assistant.spec.ts` 复用现有 OAuth/企业服务 HTTPS 夹具，实际经过 API/模型连接器，覆盖纯文本显示、同一请求重放、修改冲突、跨组织拒绝、归档、中英与 390px 窄屏；最多保留两张已清除密钥的截图，重复归档所属临时组织，临时数据由原有隔离根目录清理。

上述入口将在全部 42 组实现就绪后统一执行，未新增通过结果、生产供应商验收或性能测量。前端按路由加载本页和双语资源，不新增第三方运行时依赖；现有总体体积上限不因本批放宽。
