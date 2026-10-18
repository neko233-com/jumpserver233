# 平台用户生命周期

> 中文 | [English](./USERS.en.md)

`/console/users` 管理跨组织平台身份：显示名称、备注、角色、启用状态、到期时间、归档、恢复、撤销凭证及最多 100 项的原子批量操作。创建账号沿用系统设置。竞品基线为 [JumpServer 企业版](https://www.jumpserver.org/enterprise.html)；企业版整体功能对齐仍在进行。

## 权限与恢复

需要全局 `users.manage`；管理管理员或提升角色还需要 `roles.manage`。外部来源用户只能是操作员。禁止通过管理接口变更自己的安全状态；必须保留一位启用且没有到期时间的本地管理员。

归档保留原用户 ID、用户名、外部身份、MFA 绑定、授权、组成员、角色绑定和历史，用户名不能再次注册。恢复后保持禁用，管理员需检查现有授权再启用；原授权届时继续生效。现有计划在执行前复查当前身份，启用后可能恢复执行。归档不是永久擦除。

## 凭证与会话

实际改变角色、状态、到期时间以及归档、恢复或撤销凭证会递增 `auth_generation`，删除永久 Token、AccessKey 和待完成 MFA 设置，撤销登录会话。密码和已绑定 MFA/Passkey 保留；重新认证可以签发新会话。仅修改显示名称或备注保留会话。

本地及外部认证、四种 REST 认证方式、RADIUS 附加因子、平台登录审批和 Passkey/SSO 待完成流程检查当前有效状态或身份代次。活动 SSH、会话监看、协作、RDP、Telnet、Kubernetes 等持续授权使用最初身份代次；状态禁用后快速恢复也不能让旧连接继续授权。到期检查发生在认证、请求或持续授权复查时，并非精确到毫秒的后台定时器。SSO/Passkey 代次绑定覆盖身份验证后、平台会话签发前的待完成票据；上游身份提供方自身的会话由其管理。

## API / Go SDK / CLI

管理查询：`GET /api/v1/users/management?scope=current|archived|all&q=…&offset=0&limit=25`，`GET /api/v1/users/{id}`。分页上限 100。旧的 `/api/v1/users` 数组接口保留并排除归档用户。

`PUT /api/v1/users/{id}` 使用当前 `revision` 和可选 `name`、`comment`、`role`、`is_active`、RFC3339 `date_expired`，或 `clear_date_expired: true`。`DELETE …/{id}?revision=N` 归档；`POST …/{id}/restore` 与 `/revoke` 接收 `{"revision":N}`。

`POST /api/v1/users/actions` 接收 `{"changes":[{"id":"user-…","action":"update","revision":1,"is_active":false}]}`。支持 update/archive/restore/revoke，拒绝重复 ID；任意修订冲突、权限不足或恢复保护失败，整批不提交。请求严格拒绝未知字段，上限 64 KiB。`GET /api/v1/users/audit` 可按 `user_id` 分页。

Go SDK：`ManagedUsers`、`ManagedUser`、`UpdateUser`、`ChangeUsers`、`UserAction`、`UserAudit`。CLI 使用已有平台认证，`jms user list|show|update|archive|restore|revoke|batch|audit`；update/batch 用 `--file` JSON 或 `--file -` 标准输入，归档/恢复/撤销必须 `--revision N`。凭据使用既有受保护认证文件，不写入 JSON 或命令行。

## 持久化与边界

单机优先，支持 PostgreSQL 单活 HA。用户状态、凭证撤销及生命周期审计原子保存在 v2 用户文档。兼容读取旧数组并在写入时迁移；迁移后旧二进制不能读取，升级前备份、为所有接管节点部署兼容版本。禁止多个活动写入者。

会话文档清理失败时，用户文档中的代次仍阻止旧会话在接管后复活；清理是尽力执行。新的管理变更会清理六个月前的审计，最多保留 5000 条；未设置定时擦除。记录仅包含动作、字段名、操作者、身份 ID、状态和修订，不复制名称/备注内容或任何凭据。当前生命周期列表仅记录四类管理变更，不包含创建、个人改密和 MFA 变更。

当前不提供永久删除、批量用户导入、管理员重置密码/MFA、外部目录状态回写或企业版所有身份治理功能。验证记录见[测试说明](./TESTING.md)。
