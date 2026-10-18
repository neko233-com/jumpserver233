# RADIUS 登录与附加认证

> 中文 | [English](./RADIUS.en.md)

Go 原生 PAP RADIUS 支持主身份登录、多轮 Access-Challenge 和附加 RADIUS 因子。设置入口为 `/console/radius`，全局 `security.manage` 权限控制。竞品范围是 [JumpServer 企业版](https://www.jumpserver.org/enterprise.html)；完整企业版功能仍在进行，本文只描述已经接入的认证边界。

## 配置

1. 首选 RadSec：配置主机、端口（默认 2083）、验证名称、CA、客户端证书和私钥。使用 TLS 1.2+ 双向验证，无关闭证书验证选项。RadSec 的协议共享值固定为 RFC 6614 规定的值。
2. 旧服务可显式允许 UDP（默认 1812），另配置 16–256 字节共享密钥。UDP 的 PAP 密码遮蔽不能代替传输加密。请求和响应均强制 Message-Authenticator，并验证 Response Authenticator；未满足的旧服务器不能登录。
3. 主登录可单独启用，支持管理员预置身份或允许自动创建普通操作员。身份以 realm + subject 精确绑定；不会关联或提升同名本地管理员。
4. 附加因子可选关闭、所有用户、管理员/委派系统角色或指定用户。可使用独立服务器。本地用户名默认作为 RADIUS 用户名；其他身份来源须显式映射，已验证 RADIUS 主身份自动映射。

   附加端点应由 RADIUS 服务验证独立的 OTP、推送或其他因子；再次验证同一个主密码不构成独立因子。
5. 保存需要当前 revision，并清除所有未完成认证。密钥写入后不返回；留空保留，勾选清除才删除。探测只返回经过认证的响应代码，不完成挑战、不创建会话。

## 登录顺序和恢复

本地、LDAP、OIDC、SAML、CAS、Passkey 和 RADIUS 的新登录统一经过来源策略、附加 RADIUS、平台登录审批和审计提交，最后签发会话。已有本地 TOTP/强制绑定仍有效，在附加因子之前完成。此项是额外因子；如果只需要密码加 RADIUS，可保持本地 TOTP 策略关闭。附加因子策略不自动吊销旧会话；禁用 RADIUS 主认证或更换身份域，则会使既有 RADIUS 身份的凭据不可用。

服务端支持时，可提交空应答请求挑战，再继续提交验证码。界面切换到 UDP 会清除 TLS 公共证书字段；切回 TLS 后补齐证书，已保存私钥按保留/清除设置处理。

浏览器使用 HttpOnly、SameSite=Lax、按认证路径限定的挑战 Cookie；响应不包含最终 token。非浏览器客户端接收一次性能力，不能用它访问资产。能力绑定来源 IP，最多存活五分钟，最多四轮挑战、五次验证。服务器保留 4096 个有界加密流程，同一身份最多五个活动流程，同时最多八次远端验证。

每次远端请求前持久化 `verifying`，成功消费先于恢复会话。网络错误、崩溃或写入失败产生的不明结果要求重新登录，不自动重放验证码。待处理挑战可在单机重启、PostgreSQL 单活接管后恢复；进程内主认证完成票据和本地 MFA 绑定票据在重启后失效。配置、来源、凭据、用户状态与审批权限在完成时复核。平台的生产 HA 故障演练仍须按部署环境验收。

## API、SDK 和 CLI

- 管理 API：`GET/PUT /api/v1/settings/security/radius`；`GET .../audit?offset=0&limit=25`；`POST .../check`；`GET .../users` 仅返回映射所需的 ID/用户名；`POST .../users`（subject、可选 username，普通操作员）。
- 主认证：`POST /api/v1/authentication/radius/login` → 可重复 `/challenge` → `/complete`。Cookie 模式发送 `X-JMS-Browser-Session: cookie`；其他客户端携带返回的 `challenge_token` 或 `pending_token`。
- 附加因子：主登录返回 202 `radius_factor_required` 后调用 `POST /api/v1/authentication/factor/complete`，传入 `response` 和非浏览器的 `factor_token`。挑战后继续同一路径，取消用 `/cancel`。
- Go SDK：`Client.Authentication`、`RadiusSettings`、`SaveRadiusSettings`、`RadiusAudit`、`ProbeRadius`。
- CLI：`jms auth login|radius-login --state-file PATH --file -`；将 JSON 输入通过标准输入提供。继续使用 `jms auth continue --state-file PATH --file -`，输入当前要求的 response、otp 等；审批等待期间可稍后重试。`jms auth status --state-file PATH` 查看下一步。完成后以 `JMS_TOKEN_FILE=PATH` 使用已有 SSH/作业命令。
- 管理 CLI：`jms auth radius-settings|radius-save|radius-audit|radius-check`，沿用当前平台 token、Token 文件或 AccessKey。

CLI 状态文件只保存下一步所需的能力、MFA 绑定材料及最终平台会话，不保存输入密码或验证码，也不把能力打印到 stdout。文件绑定精确服务器 URL，写入原子替换，POSIX 权限 0600；Windows 还应使用仅当前用户可读的目录 ACL。它是敏感认证文件，使用结束后按需删除，不提交仓库。状态响应不打印绑定密钥；需要绑定时由受信本地客户端读取受保护文件。

## 验证和协议边界

自动化包含 Testify 协议/核心/API/SDK/CLI 用例、真实 FreeRADIUS UDP 和双向 TLS、浏览器挑战刷新、附加因子、权限、英文桌面/中文手机和认证后真实 SSH CLI。`web/e2e/radius.spec.ts` 由完整 Playwright 临时环境启动自有 FreeRADIUS 容器；Docker 端口仅暴露到回环。夹具只包含合成身份，私钥不写进测试报告。执行结果见[自动化验证](./TESTING.md)。

实现依据 [RFC 2865](https://www.rfc-editor.org/rfc/rfc2865.html)、[RFC 3579](https://www.rfc-editor.org/rfc/rfc3579.html) 和 [RFC 6614](https://www.rfc-editor.org/rfc/rfc6614.html)。当前不实现 EAP、MS-CHAP、RADIUS 1.1、计费、完整远端角色映射或多活挑战消费。

## 真实界面（2026-10-18）

英文桌面与中文 390px 手机截图来自隔离 Docker、真实双向 TLS FreeRADIUS 的验证场景。

![英文 RADIUS 设置](./images/radius.en.png)

![中文手机 RADIUS 设置](./images/radius.zh-CN.png)
