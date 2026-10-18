# 平台密码安全与凭据恢复

> 中文 | [English](./PASSWORD-SECURITY.en.md)

平台本地密码支持按角色配置最少长度、字符类别、历史防复用及有效天数；管理员可独立重置密码或本地 TOTP。Web、Go SDK 和 CLI 共用原生 Go 实现。默认管理员仍按首次启动规则创建，之后的策略不会重置已有密码。远端 SSH 密码继续使用[七天改密计划](./ROTATION-PLANS.md)。

策略项参考 [JumpServer 官方字段定义](https://raw.githubusercontent.com/jumpserver/jumpserver/dev/apps/settings/serializers/security.py)，调研日期 2026-10-18；竞品仍为 [JumpServer 企业版](https://www.jumpserver.org/enterprise.html)。整体对齐继续进行。

## 策略与生效范围

系统设置 → 安全 → 密码安全，需要全局 `security.manage`。操作员与管理员分别设置 12–128 字节的下限、0–36500 天的有效期；上限 256 UTF-8 字节，拒绝控制字符。大写、小写、数字及符号可分别要求。有效期为 0 时关闭；长度/字符类别仅约束新密码，有效期也约束已有本地密码。旧数据以创建时间作为首次改密时间。

历史窗口为 0–24；仅约束已记录的历史，关闭时不追溯记录新的旧密码。已知密码以用户 ID 和 Vault key 派生密钥计算 HMAC-SHA256 指纹，不记录明文；迁移前不知道明文的当前密码保留一份原 scrypt 盐/哈希供历史检查。记录受到数量限制，历史检查通常只需指纹比较。启用历史或有效期需要 Vault key；存储标记验证节点使用一致的密钥。

策略发生变化时，使用修订号原子保存策略、审计及所有本地身份的新代次。所有本地会话、永久 Token、AccessKey 和待完成登录撤销，包括操作者；界面返回登录。相同配置与当前修订返回原策略，不写审计、不撤销凭证；旧修订返回冲突。界面未改动时禁用提交。外部身份的密码由提供方管理，此策略不变更外部账号。

## 到期或强制改密

有效密码/Passkey → 本地 MFA/强制登记 → 必需的 RADIUS 因子 → 受限改密 → 重新登录 → 登录审批和会话。改密流程不签发可操作资产的会话；不绕过原有访问策略、MFA 或因子。

受限能力绑定当前身份代次、原登录证明、策略修订、来源 IP 和五分钟有效期，每个用户最多一条；只存摘要及加密证明。浏览器使用 HttpOnly、SameSite=Lax、限定路径的 Cookie，响应不返回 token；CLI 能力保存在 POSIX 0600 / Windows 受保护 DACL（当前用户与 SYSTEM）的状态文件，标准输出只包含下一步和元数据。刷新可恢复，取消或成功消费后不能重放。重启和 PostgreSQL 单活接管后可继续；提供方、RADIUS、MFA、凭据、来源或策略变更仍需重新检查。

改密成功会清除强制改密状态并撤销原会话及 API 凭证，随后用新密码重新登录。个人设置的常规改密保留当前登录会话和既有 API 密钥/永久 Token，撤销其它登录会话；身份代次阻止失败的会话清理写入在接管后复活旧会话。清理写入为尽力执行，接管时当前会话也可能需要重登。到期在认证、请求和持续授权时检查，未设置精确时刻的后台擦除。

## 管理员恢复

平台用户页提供“重置密码”和“重置 TOTP”。需要 `users.manage` 加独立 `users.credentials.manage`；管理管理员另需 `roles.manage`。禁止用管理接口恢复自己的凭据。修订冲突拒绝提交；归档账号先恢复，禁用账号仍保持禁用，授权和组关系不变。

密码重置仅适用于本地身份，默认要求下次登录修改；可以显式关闭该要求。新密码受当前策略和历史检查约束，不返回响应、审计或 CLI 标准输出。TOTP 重置清除本地 TOTP 密钥、已消费时间步和恢复码；已登记 Passkey 保留，应通过其独立管理入口撤销。全局 MFA 要求保持有效，下次认证仍需重新登记。

## API / SDK / CLI

- `GET|PUT /api/v1/settings/security/passwords`：策略及修订；`GET …/audit?offset=0&limit=25`：分页审计，最多 100。
- `GET /api/v1/authentication/password-policy`：公开的密码要求，无凭据或审计。
- `POST /api/v1/users/{id}/password/reset`：`revision`、`new_password`、可选 `force_change`（默认 true）。`POST …/{id}/mfa/reset`：`revision`。
- 登录返回 HTTP 202、`password_change_required`；SDK 另收到 `change_token`，浏览器用限定 Cookie。`GET …/authentication/password-change/pending` 用于浏览器恢复；POST 同路径支持 CLI 的 `change_token`。
- `POST …/password-change/complete`：`new_password` 和可选 CLI `change_token`；`POST …/cancel`：可选 `change_token`。完成后返回 `password_changed: true`，没有平台 token。
- Go SDK：`PasswordPolicy`、`SavePasswordPolicy`、`PasswordPolicyAudit`、`ResetPassword`、`ResetMFA`、`ChangePassword`；`Authentication` 支持 password-status/complete/cancel。
- CLI：`jms auth password-settings|password-save|password-audit`；`jms user reset-password <id> --file -`、`reset-mfa <id> --revision N`、`password --file -`。受限流程用 `jms auth login|status|continue --state-file PATH`，输入 JSON 通过标准输入，改密后下一步为 login。

## 持久化与审计

单机优先，支持 PostgreSQL 单活。写入采用 v3 用户文档，兼容读取旧数组和 v2。旧版本不能写 v3；升级前备份，并为所有接管节点部署兼容版本。活动 SSH/RDP/监看等使用原身份代次，在持续授权复查时关闭；在线连接不迁移。

用户审计增加 password_change/password_reset/mfa_reset，仅记录字段名和身份元数据。密码策略审计记录修订前后设置与受影响数量；不包含任何密码、MFA 密钥、恢复码或能力。新变更清理六个月前审计；用户事件最多 5000 条、策略事件最多 1000 条。未设置定时擦除。

密码到期提醒邮件、泄露密码库、密码邮件重置、目录密码回写、闲置禁用、可配置账号/IP 锁定、批量用户导入及生产 HA 演练仍待完成。本功能不代表整体企业版验收。
