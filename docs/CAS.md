# CAS 单点登录

> 中文 | [English](./CAS.en.md)

`/console/cas` 配置单个 CAS 2.0/3.0 身份提供方。浏览器跳转到 CAS 登录，服务端用精确 service 地址验证一次性服务票据，随后执行本地 MFA，仅签发 HttpOnly 平台会话。CAS 登录和首次自动建号默认关闭；本地管理员保持恢复入口。

## 配置与身份

管理需要 `security.manage`。填写 CAS 基础地址（例如 `https://identity.example.com/cas`）、协议和精确回调 `/api/v1/authentication/cas/callback`。生产设置 `JMS_PUBLIC_URL=https://console.example.com`，回调源必须匹配。CAS 的服务注册需允许该路径及应用生成的 `state` 查询；校验时使用与签发票据时完全相同的 service 地址。

CAS 2.0 调用 `/serviceValidate`，3.0 调用 `/p3/serviceValidate`，均请求 XML。登录和校验始终发送 `renew=true`，要求 CAS 重新执行主认证；不使用 gateway、代理票据或代理授权。

生产端点要求 HTTPS，校验证书链与主机名；可添加私有 CA PEM，不提供关闭校验选项。本地开发可显式允许 HTTP，但仅限字面 loopback IP。上游请求 10 秒超时、约 1 MiB 响应上限且不跟随重定向。端点检查只证明登录端点可访问，不等于服务票据或真实登录验收。

默认由管理员填写精确 CAS `user` 值预建外部操作员，可选未占用的平台用户名；也可显式开启首次自动建号。新账号没有资产授权或自动系统角色。身份按 CAS 基础地址与大小写敏感的原始用户标识绑定；不通过邮箱、显示名、角色等属性关联本地账号。标识不接受前后空白或控制字符，最长 1024 字节。外部建号遵守总用户数 10000 上限。

账号返回 `source: "cas"`，本地密码登录与改密会拒绝。平台 AccessKey/永久 Token 可供已有 Agent CLI 使用；浏览器和 CLI 均不接收 SSH 密码。停用 CAS 或更换基础地址后，其会话、AccessKey 和永久 Token 在下一次身份校验时失效；不会自动迁移或合并身份。CAS、OIDC、LDAP 的身份与停用检查相互独立。

## 浏览器与 MFA

每次发起使用随机 state 和独立 HttpOnly 浏览器证明 Cookie。完整 service 包含随机 state，回调只接受匹配浏览器、配置版本与十分钟内的一次性流程；票据只在服务端向 CAS 校验，回调随后跳转到只含 `cas=continue` 标记的登录页，使用 `Referrer-Policy: no-referrer`。

XML 必须有正确 CAS 命名空间、唯一认证成功结果及唯一直接 `user`。拒绝失败/成功并存、重复用户、嵌套用户名、DTD、未知实体、额外文档、代理授权和过深/过大的文档。用户属性不授予平台权限。CAS 服务端仍负责票据过期、一次性使用、service 绑定与 `renew` 语义。

校验后产生五分钟 HttpOnly 待登录 Cookie；点击完成登录后，本地 TOTP、恢复码及强制绑定策略仍生效。绑定挑战必须通过相应待登录票据，不能经普通本地 MFA 接口完成。每个票据最多五次请求，第二因素错误还按用户跨流程累计，五次失败限制十五分钟。发起和完成请求另受来源 IP 每分钟 30 次限制。取消会消费当前票据。

成功只返回 `browser_session`、用户与过期时间，不返回 bearer token。管理 MFA 需要最近五分钟内的平台 CAS 会话和新验证码。当前退出只撤销平台会话，尚未实现 CAS 服务端联合退出、单点退出通知或代理链。

## 存储与 HA

配置和最多 1000 条非秘密配置审计使用 Vault key AES-GCM，加密保存到单机 `cas.json` 或 PostgreSQL `cas-config`。页面显示最近 50 条审计，API 返回完整列表；保存按 `revision` 防止并发覆盖，并作废未完成的流程。

单机优先；配置、用户映射和完成后的共享平台会话可从 PostgreSQL 恢复。state、浏览器证明、待登录票据和限流是进程内状态，重启或单活 HA 接管后未完成登录须重新发起。所有节点必须使用相同公共源和 Vault key。主动 SSH 会话不迁移，整体限制见 [CLUSTER-HA.md](./CLUSTER-HA.md)。

## API 与验证

- `GET/PUT /api/v1/settings/security/cas`、`GET .../audit`：配置和审计；`POST .../check`：登录端点检查。
- `POST .../users`：`subject` 与可选 `username`，准备外部操作员。
- `GET /api/v1/authentication/cas/status`、`GET .../start`、`GET .../callback`：状态、发起与回调。
- `GET .../pending`、`POST .../complete`（`otp`、必要时 `setup_token`）、`DELETE .../pending`：查看、完成或取消当前浏览器登录。

Testify 覆盖 HTTPS 信任、CAS 2/3、service/renew/一次性票据、严格 XML、浏览器证明、过期/版本失效、受控建号、防提权、MFA/恢复码共用边界、跨流程错误预算、来源隔离及 PostgreSQL/HA 恢复。Playwright 经真实合成 CAS 授权页面，验证取消、强制 MFA、HttpOnly 会话、默认无资产权限及停用失权。合成验证不等于生产 CAS 对接；多 CAS 提供方、属性到组/组织映射、联合退出与生产服务注册仍待完成。统一入口见 [TESTING.md](./TESTING.md)。

协议依据 [Apereo CAS 2.0 规范](https://apereo.github.io/cas/8.0.x/protocol/CAS-Protocol-V2-Specification.html) 和 [CAS 3.0 协议说明](https://apereo.github.io/cas/development/protocol/CAS-Protocol.html)。
