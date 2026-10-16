# OIDC 统一登录

> 中文 | [English](./OIDC.en.md)

Passkey 注册、设备验证登录、本地 MFA、撤销与 HA 恢复见 [Passkey](./PASSKEY.md)。

`/console/identity` 可配置 OpenID Connect Authorization Code 登录。登录页提供 SSO 入口，服务端交换并验证 ID Token，完成本地 MFA 后只签发 HttpOnly 平台会话；浏览器和 Agent CLI 均不会收到远端 SSH 密码。默认关闭 OIDC 和首次自动建号。

## 配置

1. 保留一个本地管理员作为恢复入口，先完成平台初始化。外部身份不能成为第一个管理员。
2. 生产环境设置 `JMS_PUBLIC_URL=https://console.example.com`，并通过该 HTTPS 源访问。反向代理保留请求与 Cookie；服务端只信任显式公共源，不依赖任意 `X-Forwarded-Proto`。此配置也让普通登录 Cookie 标记 `Secure`。
3. 在身份提供方登记精确回调 `https://console.example.com/api/v1/authentication/oidc/callback`，启用 code flow、PKCE S256，并返回 `auth_time`。系统请求 `max_age=300`，要求近期主认证。
4. 在统一登录页填入 discovery issuer、Client ID、回调地址和 Client Secret。支持 `client_secret_basic`、`client_secret_post` 和 PKCE 公共客户端 `none`。Secret 只写入；留空保留，清除需显式勾选。
5. 本地开发可勾选允许 HTTP 的选项，但仅接受字面 loopback IP（例如 `127.0.0.1` 或 `::1`）。生产端点要求 HTTPS，不能关闭 TLS 证书验证。回调源必须匹配 `JMS_PUBLIC_URL`；未配置公共源时只接受本机回调。
6. 保存后可检查 discovery 与端点元数据。这项检查不等于真实登录验收。

管理接口需要 `security.manage`。配置按 `revision` 防止并发覆盖；使用 Vault key AES-GCM 加密到单机 `oidc.json` 或 PostgreSQL `oidc-config` 文档。Secret、provider token 和授权码不会进入配置审计；审计保存认证操作人、时间与非秘密配置快照，最多 1000 条。修改配置会作废未完成的 OIDC 流程。

## 账号与权限

- 外部账号只按精确 `issuer + sub` 标识，存储 subject 摘要。邮箱、显示名、`preferred_username` 及 provider 角色声明不会关联或提升本地账号。
- 默认由管理员在页面预先准备账号，填写准确 subject 和可选的未占用用户名（沿用 3–64 位 ASCII 用户名规则）。也可显式启用首次建号，生成稳定的 `oidc.<摘要>` 用户名。
- 新账号始终是操作员，没有资产授权、管理员角色或自动用户组成员关系。后续通过现有授权/RBAC 管理，不能从 ID Token 自行取得平台管理能力。外部建号总用户数上限为 10000。
- 外部账号不能用本地密码登录或修改主密码。身份提供方启用且 issuer 匹配时，账号仍可创建平台 AccessKey/永久 Token 供既有 Agent CLI 使用；SSH 凭据继续保留在服务端。
- 停用提供方或更换 issuer 会在下一次认证检查时阻止其会话、永久 Token 和 AccessKey。已被检查为失效的短期会话会移除；重新启用相同 issuer 后，未撤销的 API 凭据可再次使用。更换 issuer 不会自动迁移旧账号或授权。

## 浏览器和 MFA

服务端使用随机 state、nonce、PKCE verifier 及 HttpOnly 浏览器证明 Cookie。回调只接受对应浏览器的一次性流程；state 最长 10 分钟。OAuth token、ID Token 和 Client Secret 不返回前端、不保存到 localStorage。

回调验证成功后产生最长 5 分钟的 HttpOnly 待登录票据，跳转地址仅含流程标记。用户点击“完成登录”，本地 TOTP/恢复码与强制 MFA 策略继续生效。SSO 的强制绑定挑战必须经过对应待登录票据，不能借普通本地 MFA 完成接口绕过。每个待登录票据最多 5 次请求，第二因素错误还按用户跨流程累计，5 次失败后限制 15 分钟。

MFA 恢复码管理或停用 MFA 需要最近五分钟内签发的平台 SSO 会话，加上新第二因素。认证时间随共享会话持久化，HA 接管后可继续检查；不能拿永久 Token 或 AccessKey 代替近期登录证明。平台退出只撤销平台会话，暂不实现 IdP 联合退出/后端退出通知。

## 校验与故障行为

使用 [go-oidc](https://pkg.go.dev/github.com/coreos/go-oidc/v3/oidc) 和 [OAuth2 PKCE](https://pkg.go.dev/golang.org/x/oauth2) 库，遵循 [OIDC Core](https://openid.net/specs/openid-connect-core-1_0.html)。校验签名算法、JWKS、issuer、audience/azp、有效期、签发时间、nonce、近期 `auth_time` 及存在时的 `at_hash`；支持 RSA/ECDSA/EdDSA 非对称签名，不接受 HMAC/none 身份断言。JWKS 支持签名密钥轮换。

上游请求 10 秒超时、响应读取上限约 1 MiB，不跟随 discovery/token/JWKS HTTP 重定向。错误仅返回固定信息，不回显 provider 响应体。state、PKCE、待登录票据仅保留在进程内，重启或单活 HA 接管后必须重新发起未完成的 SSO；已完成的平台登录、账号映射和加密配置可共享恢复。当前提供一个 OIDC provider；多 provider、声明到组织/组映射和联合退出仍在后续范围。

## 自动化验证

Testify 覆盖三种客户端认证、PKCE/state/浏览器绑定、JWT 签名与声明拒绝、JWKS 轮换、账号防关联/提权、Secret 加密及只写、一次性票据、MFA 强制绑定、跨流程错误预算、近期登录证明、停用提供方后的四种身份入口，以及 PostgreSQL 恢复。Playwright 经过真实合成 IdP 的重定向与授权页面，完成本地 MFA，检查 HttpOnly 会话和无资产授权，并验证停用后的失权。合成 IdP 仅用于 loopback 测试，不是生产身份服务。统一入口见 [TESTING.md](./TESTING.md)。

另提供独立的 [LDAP/AD 目录登录](./LDAP.md)，不会合并不同来源的外部身份。

SAML 登录已单独实现，其支持的协议配置与边界见 [SAML.md](./SAML.md)。
