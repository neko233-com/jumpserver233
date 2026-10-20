# 登录短信 MFA

> 中文 | [English](./SMS-MFA.en.md)

E06 的原生短信登录因子、个人绑定、管理策略、中英 Web、CLI/SDK 和用例已编写，**未运行验证**。全部 42 组实现就绪后统一验收。厂商签名与模板开通、真实运营商送达及生产接管仍需实际环境证据。

## 配置与登录顺序

先在平台通知设置启用[原生短信](./NATIVE-NOTIFICATIONS.md)：阿里云、腾讯云、华为云或 CMPP 2.0。短信 MFA 仅使用平台短信通道，默认关闭；组织通道、自定义网关、群机器人与通知联系人的验证不充当登录因子。供应商的号码、签名、模板及内容限制继续生效。

系统设置 → 短信 MFA，需要全局 `security.manage`。策略为 `opt_in`（已绑定用户）、`admins`（管理员及具有全局委托权限的身份）、`all` 或 `selected`（指定用户 ID）；用户自愿绑定后也需要此因子。强制策略只影响新的登录，配置保存不会批量撤销现有平台/API 会话。绑定或解绑会增加用户身份代次，撤销该用户旧会话、永久 Token、AccessKey 和待完成登录。

顺序为主认证/Passkey/企业 SSO → 已要求的本地 TOTP/登记 → RADIUS 附加因子 → 短信 MFA → 受限改密 → 平台登录复核 → 正式会话。主认证成功但短信未完成时，不返回可操作资产的会话。多步流程保留原主认证时间与绝对截止时间；短信操作或复核不会延长原证明期限。

首次被强制要求时，先完成已有主认证与因子，再登记 E.164 号码并验证六位验证码。已登录用户在个人设置绑定、更换或解绑：本地身份重新提供密码；外部身份需要五分钟内的提供方登录会话；已启用 TOTP 时还需当前 TOTP/恢复码，已绑定短信的身份还需当前短信验证会话。强制策略禁止个人解绑。

管理员通过用户页“重置 MFA”恢复其他身份，需要 `users.manage`、`users.credentials.manage`，目标为管理员时另需 `roles.manage`。它同时清除 TOTP、恢复码和短信绑定，保留 Passkey；强制 MFA 策略保持有效，不能借此取消下一次登记。不能用管理接口重置自己的身份。已有受保护的管理员 API 凭据可用于应急修正错误配置。

## 能力、限流与持久化

- 浏览器能力保存在路径 `/api/v1/authentication/sms` 的 HttpOnly、SameSite=Lax Cookie，HTTPS 设置 Secure；响应不返回能力或平台 Token。CLI/SDK 使用请求体 `factor_token`，不放 URL。
- 能力绑定来源 IP、用户身份代次/凭据摘要、原登录证明、策略修订及平台通知通道修订。归档、停用、身份源撤销、凭据或配置改变使待完成流程失效。RADIUS 与短信完成标记独立保存，并随改密/复核继续检查。
- 每个流程最多五分钟，并受原证明截止时间限制；验证码仅存带随机 nonce 的 SHA-256 摘要。错误格式也占用五次尝试预算。显式重发生成新验证码，不延长流程、不自动重试发送。
- 每用户/号码最多每小时六次发送、间隔至少 60 秒；来源 IP 每小时最多 120 次。发送并发上限四个；总流程上限 1000，单流程请求回执最多 32。相同请求 ID 和内容返回原结果，改变号码或动作的冲突拒绝；配置使用修订 CAS 和最多 2000 条幂等回执。
- 先持久化发送意图再发网路请求。进程重启将未决发送标为 `uncertain`，不重放厂商请求；已收到的验证码仍可核验，用户可显式重发。厂商受理不等于手机送达。
- 先持久化一次性消费再绑定号码或恢复会话；消费写入失败不执行回调。后续写入失败撤销新会话，已成功保存的绑定可保留，需要重新登录向前恢复，不能重复使用旧能力。
- `sms-mfa.json` / PostgreSQL 文档 `sms-mfa` 使用平台 Vault key 做 AES-GCM；号码另在用户文档加密，短信码不进入通知收件箱/队列。审计最多 1000 条，仅记录身份 ID、修订、动作与时间；公开状态只显示号码末四位。

关闭与维护排空使用 `sms_mfa` 活动计数，关闭取消在途发送并等待退出；构造/离线预检不连接厂商、不监听端口。单机优先，PostgreSQL 使用现有单活文档边界，不能据此声明生产多活已验收。

## API、SDK 与 CLI

| 接口 | 用途 |
|---|---|
| `GET/PUT /api/v1/settings/security/sms-mfa` | 读取或保存 enabled/policy/user_ids/revision；保存需要 request_id |
| `GET …/sms-mfa/audit` | 受保护的策略与因子审计 |
| `GET /api/v1/users/me/sms-mfa` | available/enabled/forced/masked_phone |
| `POST …/users/me/sms-mfa/enroll` | phone/password/otp；空 phone 请求解绑 |
| `GET/POST /api/v1/authentication/sms/pending` | Cookie 或请求体能力恢复 |
| `POST …/sms/bind` | 首次登录登记 phone/request_id |
| `POST …/sms/resend` | request_id；显式重发 |
| `POST …/sms/complete` | code；一次性完成后继续后续登录步骤 |
| `POST …/sms/cancel` | 幂等取消 |

Go SDK 提供 `SMSMFASettings`、`SaveSMSMFASettings`、`SMSMFAAudit`、`SMSProfile`、`BeginSMSBinding`，`Authentication` 支持 sms-pending/bind/resend/complete/cancel。CLI 管理入口为 `jms auth sms-settings|sms-save|sms-audit|sms-profile`；个人绑定为 `sms-enroll --state-file PATH --file -`。密码/号码/验证码以 JSON 标准输入传入。`auth login|continue|status|sms-resend|sms-cancel` 使用受保护的状态文件；stdout 仅显示下一步、掩码号码和到期时间。首次登记下一步为 sms-bind，再为 sms-complete；完成绑定后重新登录。所有阶段使用平台身份，不返回目标 SSH 凭据。

## 升级与待验用例

用户写入格式提升为 **envelope 4**，新版读取旧数组及 v2/v3/v4；旧格式中出现短信标记/号码字段会拒绝读取。策略启用先保存 v4 用户边界，再启用短信要求，避免旧程序忽略新因子。旧程序不能直接打开 v4；降级需升级前快照，不能删除新字段绕过。与[升级兼容矩阵](./UPGRADE-COMPATIBILITY.md)、[密码安全](./PASSWORD-SECURITY.md)一起维护。新增共享会话字段保留原认证时间、重新签发时间与证明截止时间；旧共享会话可读取，其余合法性仍校验。

已编写 Auth、核心服务、失败注入、PostgreSQL 重开、API、CLI/SDK 用例，覆盖加密、修订/幂等、一次性重放、错误预算、限流、配置/通道变更、关闭排空、先消费后回调和慢速多因子截止时间。`sms-mfa.spec.ts` 复用既有 HTTPS/CONNECT 夹具，覆盖本地及企业 SSO、首次号码、错误码、重放、个人状态与中英窄屏；只保留两张脱敏截图，恢复策略并两次清理合成身份。**以上仅为用例编写，未执行测试、构建、浏览器或 Docker。**
