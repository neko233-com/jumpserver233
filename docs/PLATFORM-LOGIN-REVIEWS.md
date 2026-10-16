# 平台登录复核

> 中文 | [English](./PLATFORM-LOGIN-REVIEWS.en.md)

平台登录策略支持「需要审批」和「站内通知」。身份验证、已有 MFA 要求和 Passkey 验证先完成；审批通过后由原申请端换取平台会话。资产授权、SSH/SFTP 复核和命令复核继续独立执行。竞品为 [JumpServer 企业版](https://www.jumpserver.org/enterprise.html)，本功能属于持续实现的企业版范围。

## 配置与使用

在「访问策略 → 用户登录」选择用户或用户组、来源、时区和周时段，并将动作设为需要审批。可指定审批用户或组；留空允许任一其他具备 `reviews.platform_login.manage` 权限的用户审批。所选人员仍须具备此权限，不能审批自己的请求。内置管理员和 access-reviewer 角色具备复核权限。

申请端完成认证后显示等待面板，刷新页面可恢复。请求五分钟内有效；审批后须在一分钟内且不超过原截止时间完成。原来源、原票据、当前身份、当前策略 ID 与修订均须匹配。口令、角色、MFA、身份源/Passkey 可用性或匹配策略变化会使请求失效；审批人的权限和人员/组匹配在完成时再次检查。等待不会延长原会话有效期或最近认证时间。

「平台登录复核」可通过、拒绝并查看历史和审计。审批本身不创建会话；申请端自动完成一次性兑换。拒绝、取消、过期及重复兑换均不签发会话。取消与兑换并发时，服务端可撤销刚完成的对应会话。

「站内通知」保存已验证登录事件并正常登录，管理员在登录通知页查看。当前没有邮件、短信或外部消息投递。已有 cookie、Bearer、永久令牌、AccessKey 不因审批/通知动作重新登录，但所有请求仍执行拒绝规则；这些动作不会赋予新权限。

## API 与凭据边界

- 浏览器新登录返回 HTTP 202、请求 ID 和截止时间；不返回登录令牌或审批票据。审批票据存入 HttpOnly、SameSite=Lax、专用路径的 cookie，HTTPS 使用 Secure。
- 非浏览器密码登录返回 `review_token`，仅用于 POST `/api/v1/authentication/login-review/status`、`complete` 或 `cancel`，不能作为 API 身份凭据。请求体字段为 `review_token`；不得放入 URL。
- GET `/api/v1/authentication/login-review/pending` 供原浏览器恢复等待状态；状态、完成和取消接口检查 Origin 与 API 识别的来源。
- GET `/api/v1/login-reviews?state=pending&limit=25&offset=0`、GET `/audit` 需要复核权限；POST `/{id}/approve` 或 `/{id}/deny` 还检查是否为允许的审批人。
- 列表和审计不包含认证证明、票据、会话令牌或摘要。认证证明采用 AES-GCM 封装，只保存在服务端加密复核存储；原临时认证会话在返回 202 前撤销。仅保存随机票据的 SHA-256 摘要。

## 单机、HA 与保留

默认本地加密文件 `platform-login-reviews.json`；PostgreSQL single-active HA 使用共享 `platform-login-reviews` 文档及同一 Vault key。完成身份认证后已进入等待/通过状态的请求可在接管后继续；尚未完成认证的 SSO/Passkey 临时流程仍需重启。审计、录像和其它文件的共享要求见 [CLUSTER-HA](./CLUSTER-HA.md)。

请求最多 5,000 条，已结束请求最长保留七天；达到容量可提前清理较早结束项。每人最多五个有效请求，总有效请求最多 4,096 个；审计保留最近 10,000 条。持久化失败不返回新会话，若完成状态写入失败，会撤销刚创建的会话。

自动化用例覆盖认证证明与凭据变化、票据/来源/一次性兑换、拒绝与取消并发、存储回滚、加密重启、权限撤销、SSO/Passkey 公共入口、双节点接管和中英浏览器流程。统一验证入口见 [TESTING](./TESTING.md)。多组织审批、审批链和外部通知渠道仍待实现。
