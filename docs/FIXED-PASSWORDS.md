# 固定密码改密与幂等保存

> 中文 | [English](./FIXED-PASSWORDS.en.md)

SSH 改密计划支持随机生成和管理员指定两种来源，对齐[竞品官方说明](https://docs.fit2cloud.com/jumpserver/v3/guide/admin/account/account_change_secret/)中的指定/随机策略。默认继续随机生成；固定密码通过独立只写输入进入服务端。公开 Web/CLI/SDK 计划、运行、审计和 CSV 不返回该值。

## 配置与执行

计划编辑器选择「受保护的固定密码」。创建时输入密码；编辑时输入框始终为空，留空保留已保存值，新输入替换。切换为随机生成会清除计划内保存的固定值。保存更新计划配置，执行按钮或调度负责改密。未结束运行保留提交时的原值快照，新配置用于后续运行。

固定值为 16–128 个允许字符，字符集见 [SSH 密码规则](./SSH-PASSWORD-POLICY.md)。它还必须满足计划和所有参与组织的当前规则；默认组织最短 43 且四类各至少一个。冲突在远端修改前拒绝，归档/停用组织也参与共享账号检查。仅密码账号使用固定值；混合计划的密钥账号沿用密钥流程，纯密钥计划拒绝固定模式。

周期计划会重复使用固定值。需要每次产生新密码时选择随机模式；内置每七天自动轮换仍随机生成。远端 PAM/密码历史也可能拒绝固定值。

## 权限与输入

独立权限 `accounts.rotation.fixed_password` 用于配置、执行和恢复，并叠加现有计划、资产改密及可选特权账号权限。普通 SSH/Agent CLI 用户继续通过平台身份连接。该权限不提供读取密码的接口；请求、重放和执行重新检查当前授权。

API POST/PUT 保存接收 `request_id`、普通 PlanInput 及可选只写 `fixed_password`。固定模式必须带请求 ID；创建或从随机切为固定时必须输入密码。已有固定计划省略密码则保留。公开响应只含 `password_mode`、`save_request_id` 等元数据。Go SDK 使用 `SaveRotationPlanRequest` / `RotationPlanSaveInput`，公开 DTO 独立定义。

CLI JSON 只包含元数据：

```json
{"name":"Controlled SSH reset","kind":"manual","password_mode":"fixed","targets":[{"account_id":"managed-account-id"}]}
```

```sh
jms account rotation create --file plan.metadata.json --request-id fixed-plan-001 --fixed-password-file -
jms account rotation update PLAN_ID --file edited.metadata.json --request-id fixed-plan-002 --fixed-password-file /secure/fixed.jms-secret
```

标准输入支持管道和不回显终端；文件需为普通文件，Unix 下仅所有者可访问。命令参数不接受密码明文，省略文件参数可保留现有值。私密文件应放在工作区外，Git/Docker 同时忽略 `*.jms-secret`。CLI 和新 Web 保存总带请求 ID，显式 CLI ID 可用于重试。

## 重放与数据

同一 ID 绑定操作者、目标路径和完整解析输入，摘要使用组织密钥派生的 HMAC。原输入重放返回当前计划，不增加修订或保存审计；改内容、换操作者或路径返回 409。新保存检查当前修订。删除后的原请求返回 404，避免重建计划。变更时回收超过 90 天的回执；上限 10000，满时新保存返回 429，已有回执仍可重放。旧随机 API 不带 ID 的兼容路径保留原行为。

计划值和未完成运行快照保存在组织 AES-GCM 文档中，运行结束清除运行内的固定值副本。资产改密回执只保留随机操作身份；凭据字段继续加密。待确定操作使用原日志已选密码恢复。整站备份保留配置、回执和未完成运行；空白或缺少必须块的已有文档拒绝加载。

当前限于已有 Linux SSH 改密通道；其它协议和完整企业版继续推进。验证见[测试记录](./TESTING.md)。
