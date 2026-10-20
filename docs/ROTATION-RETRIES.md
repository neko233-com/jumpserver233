# SSH 改密单项与批量重试

> 中文 | [English](./ROTATION-RETRIES.en.md)

改密结果支持「重试此账号」和「重试未成功账号」，对齐 [JumpServer 企业版官方功能记录](https://docs.fit2cloud.com/jumpserver/v3/change_log/)中的单账号及批量重试。创建关联的新运行，原执行结果保留；成功和未到期项不参与。范围沿用现有 Linux SSH 密码／密钥轮换器。

## 使用

1. 在执行历史打开已结束记录，选择一项或全部未成功项。
2. 确认当前计划修订、密码来源及附加规则。重试使用当前计划配置，并捕获新的不可变快照；固定值不返回浏览器。
3. 查看新运行中的逐账号结果，可返回原记录或从原记录打开重试。共享远端账号的历史别名自动一起处理，仍只执行一次远端操作。
4. 重试再次失败时，从该重试记录继续。每个来源项只能创建一个后续尝试，换请求 ID 也不能重复消费；其他尚未重试的项可独立提交。

可选状态为 `failed`、`denied`、`changed`、`cancelled`、`interrupted`。整个原运行必须结束；存在待恢复项时先核对已有操作。服务端先检查原 Vault 回执，已成功、来源改变、待确定或检查失败时拒绝新操作。已派发来源的凭据版本若变化，也拒绝重试；需要明确重新执行时使用检查后的新计划运行。还未派发的来源变化项可在修正并保存计划后重试。

当前计划必须仍包含选中账号，资产身份、用户名与凭据种类相同；修订冲突、目标移除、权限或绑定变化均拒绝或记录为来源变化。独立账号失败不重复修改已成功账号。重试不修改周期计划的启用状态或下次派发时间。

## API、CLI 与 SDK

`POST /api/v1/accounts/rotation-runs/{runID}/retry` 返回 202：

```json
{"request_id":"ssh-retry-001","plan_revision":3,"item_ids":["rotation-item-example"]}
```

省略 `item_ids` 选择剩余所有可重试项；显式列表最多 500 项，重复或非法 ID 拒绝。原运行、请求 ID、操作者、计划修订及排序后的选择共同绑定请求。精确重放返回原新运行的当前状态，不再派发；更换输入返回 409。重新发送原整计划执行请求不能借用重试请求 ID。

```sh
jms account rotation show-plan PLAN_ID
jms account rotation retry RUN_ID --plan-revision CURRENT_REVISION --items ITEM_ID --request-id ssh-retry-001 --wait
jms account rotation retry RUN_ID --plan-revision CURRENT_REVISION --request-id ssh-retry-bulk-001 --wait
```

CLI 沿用平台身份和组织，不需要远端密码。SDK 提供 `RetryRotationRun` / `RotationRetryInput`。公有 DTO 和 CSV 只增加 `parent_run_id`、`source_item_id`、`retry_run_id` 等关联元数据；密码、内部凭据身份和执行意图不对外返回。

## 权限、持久化与恢复

沿用 `accounts.rotation.execute`、`assets.rotate`、组织全资产查看及运行负责人边界；处理其他负责人需 `accounts.rotation.manage_all`。实际所选特权账号、固定密码策略分别重新检查独立权限，执行每一步继续检查当前访问策略。精确重放也重新授权。

来源项占用、新运行和 `retried` 审计在同一加密组织文档中提交。并发相同请求得到同一运行，竞争请求不能重复消费。结果写入失败或 PostgreSQL 单活接管后沿用原意图检查 Vault 回执，不重复执行已有远端效果。整站备份保留关联与快照。

终态运行原保留期为 90 天；有关联链中任何成员仍需保留时，整条链保留，避免悬空关联及来源项被重新消费。整条链均已过期后在下一次变更时回收。既有 512 批次及 64 MiB 容量限制保持。新关联字段由旧程序严格拒绝，降级须使用兼容时点的整站备份。

中英界面及语言资源按需加载，无新增依赖。原生 Docker/OpenSSH 验证入口为 `scripts/native-package-qa.mjs --batch rotation-retry`，统一验证结果见[测试记录](./TESTING.md)。完整企业版目标继续推进。
