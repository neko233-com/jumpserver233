# Passkey 登录

> 中文 | [English](./PASSKEY.en.md)

支持本地与已接入身份源账号的 WebAuthn Passkey 注册、可发现凭据登录、重命名和移除。账号来源、角色和资产授权保持由服务器记录决定，不按设备提供的名称建号或关联账号。竞品仍为 [JumpServer 企业版](https://www.jumpserver.org/enterprise.html)，完整企业版对齐目标尚未完成。

## 启用与使用

1. 配置 `JMS_PUBLIC_URL` 为控制台的可信 HTTPS 域名源地址，所有 HA 节点保持一致。生产需要浏览器信任的 TLS；IP 地址不能作为 WebAuthn RP ID。本地独立开发实例可使用 `http://localhost:<port>`。既有身份源的回调也必须与其公共源配置一致。
2. 在控制台「Passkey 登录」启用，需要 `security.manage`。默认关闭；缺少受支持的公共源时不能启用。RP ID 固定取公共域名，origin 校验包含协议、主机和端口；不依赖任意请求头决定可信域名。
3. 在个人设置注册命名凭据，需要支持 WebAuthn 的浏览器、设备 PIN/生物验证或支持可发现凭据及用户验证的安全密钥。服务器只接收公钥与认证数据，私钥由认证器管理；允许认证器自己的备份/同步机制。
4. 本地账号注册和移除需要当前密码；已启用 MFA 时还需要新的动态验证码或未使用恢复码。外部账号须先在五分钟内重新通过其原身份源登录，Passkey 会话不能代替此次 SSO 证明。
5. 登录页选择 Passkey，完成设备验证后仍执行本地 MFA、恢复码及全局强制绑定策略。未完成第二因素前仅有一次性 HttpOnly 待登录票据。登录 JSON 不返回平台 Bearer Token，不把凭据放入 URL 或 localStorage。

## 校验、撤销与审计

- 使用 `go-webauthn/webauthn v0.18.2` 校验 attestation/assertion。注册强制可发现凭据与用户验证，登录强制用户验证和 presence。检查可信 origin、RP ID 哈希、用途、挑战、user handle、credential ID 和签名，拒绝跨源使用。
- 挑战最多保留五分钟、一次使用、绑定流程类型和配置版本；注册还绑定当前平台会话、服务器用户及密码/MFA 状态指纹；安全状态改变后旧挑战失效。单次输入限 64 KiB，验证并发最多四个，流程最多 4096，每用户最多十个凭据、总计最多一万个。第二因素有用户/主机预算和一次性五次尝试限制。
- 签名计数持久化且并发更新检查版本。认证器报告计数异常时拒绝登录并停用该凭据；计数持续为零的标准凭据可正常使用，不把它当作必然克隆。无远端元数据下载或自建密码学验签。
- 会话绑定配置代次与随机凭据记录 ID。配置保存（包括停用再启用）使旧 Passkey 会话失效；移除后重新录入同一原始 credential ID 也不会复活旧会话。普通密码/SSO 会话及独立用户 API 凭据不因 Passkey 配置修改自动撤销。
- 外部身份源停用也会阻止其 Passkey 登录和既有会话。Passkey 不授予资产或系统权限。个人只能管理自己的凭据，其他用户的凭据返回 404。
- 管理页保留最近 1000 条配置、注册、验证、重命名、移除和计数异常事件，界面显示最近 50 条；不记录私钥、密码、验证码或原始断言。

## 保存和 HA

凭据、计数、配置及事件以 Vault Key 的 AES-GCM 加密保存到 `passkeys.json`，PostgreSQL 共享文档名为 `passkeys`。共享登录会话保存凭据代次绑定及 token 摘要。单活 HA 接管可恢复凭据、计数和已完成会话；未完成挑战/MFA 票据留在进程内，接管后重新发起。备份需要包含数据库/数据目录和相同 Vault Key。

## 自动化验证

Testify 使用临时 ES256 私钥生成真实 CBOR attestation 和签名 assertion，覆盖错误 origin/端口/RP/挑战/handle、缺少 UV/UP、跨源、伪造签名、浏览器/用户绑定、MFA/恢复码、重放、撤销不复活、计数异常和加密恢复。PostgreSQL 与双节点接管测试覆盖凭据及已完成 Passkey 会话。

Playwright 使用 `localhost:15178` / API `127.0.0.1:18185` 的独立临时实例和 Chromium 虚拟认证器，验证原生 `navigator.credentials.create/get`、取消、注册、重命名、MFA 绑定、恢复码、全局停用和凭据移除。它证明浏览器协议链路，不等于真实 Windows Hello、手机同步或所有硬件安全密钥验收。

## 当前边界

仅支持显式发起的同源、可发现 Passkey 登录；暂不提供条件式自动填充、跨 RP/Related Origins、企业硬件 attestation 白名单或管理员代用户删除界面。默认不替代本地 MFA，也不创建无其他恢复路径的账号；设备丢失后通过密码、原身份源及本地恢复码恢复。后续能力仍在整体目标中。

参考：[JumpServer Passkey 设置](https://docs.jumpserver.org/zh/latest/guide/system/authentication/passkey/)、[WebAuthn Level 3](https://www.w3.org/TR/webauthn-3/)、[Go WebAuthn](https://github.com/go-webauthn/webauthn)。

2026-10-15：上述 Go/PostgreSQL/HA/race 检查及 14 条浏览器用例全部通过；内置浏览器已核对中英界面。
