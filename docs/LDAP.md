# LDAP / Active Directory 登录

> 中文 | [English](./LDAP.en.md)

新增[多身份源与目录同步](./IDENTITY-SOURCES.md)源码：具名身份源与默认入口独立；LDAP 完整同步和组/组织自动关系保留人工授权优先。本批尚未统一验证，以下默认入口的历史验收不能覆盖新增源码。

目录登录与本地账号、OIDC 分开认证。管理员在 `/console/directory` 配置一个目录，用户在登录页选择 LDAP / Active Directory。优先单机部署，也支持 PostgreSQL 单活 HA 的共享配置、身份映射及已完成登录会话。默认关闭目录登录和首次自动建号。

## 配置

管理需要 `security.manage`。先保留本地管理员作为恢复入口，再填写目录地址、用户搜索 Base DN、只读搜索账号 DN/密码、用户过滤器与稳定身份属性。

- `ldaps://host:636` 使用 TLS；`ldap://host:389` 必须成功升级 StartTLS 后才能 Bind。不会降级为明文，证书链和主机名始终校验。默认信任系统 CA；私有 CA 可填 PEM 证书。
- OpenLDAP 常用过滤器 `(uid={username})`、身份属性 `entryUUID`；AD 常用 `(sAMAccountName={username})`、`objectGUID`。过滤器必须只有一个 `{username}`，服务端按 LDAP 过滤器规则转义用户名。AD 的二进制 `objectGUID` 保留原始字节，不按显示文本转换。
- 搜索只在 Base DN 子树内进行，不跟随别名/转介。必须恰好找到一个条目且稳定属性恰好有一个非空值；目录返回的 DN 也检查是否位于指定子树。若返回 `userAccountControl`，禁用标记会被拒绝；实际用户 Bind 仍由目录决定密码、锁定和账户策略。
- 搜索账号必须能读取稳定属性。用户密码通过查得的 DN 进行第二次 Bind 验证，不写入本地密码、配置、审计或浏览器存储。拒绝空密码，避免 LDAP 未认证 Bind 被误认为成功。
- 服务端每次连接有 10 秒总截止时间、取消处理及约 1 MiB 读取预算；搜索限制两条结果、五秒。目录主认证最多四个并发请求，不缓存密码。

搜索账号密码只写入，留空保留，清除须勾选。配置及非秘密变更审计使用 Vault key AES-GCM，加密到单机 `ldap.json` 或 PostgreSQL `ldap-config`。保存使用 `revision` 检测覆盖冲突，并使待完成登录失效。最多保存 1000 条配置审计；页面显示最近 50 条，API 返回完整列表。TLS/Bind 检查只证明搜索账号连接可用，用户登录另行验证。

## 身份与权限

默认由管理员输入目录用户名，服务端查询稳定 ID 后准备外部操作员；可指定未占用的本地显示用户名，也可显式开启首次自动建号。身份绑定目录搜索范围与稳定 ID，用户名、邮箱、组名不会关联本地管理员。新账号始终是无资产授权的操作员，后续用现有授权/RBAC 分配权限；外部建号遵守总用户数 10000 上限。

目录范围由 URL、Base DN、搜索账号 DN、过滤器和稳定属性构成。更改这些设置会产生新的身份范围，旧账号不会自动迁移或合并；CA/搜索密码更新不改变身份范围。目录源停用或范围更改后，其短期会话、永久 Token 和 AccessKey 在下一次身份校验时被拒绝。目录侧的禁用、删除、密码和过滤条件变化在下次目录主认证时检查；当前尚无后台同步或每次 API 调用查询目录的即时撤权。

外部账号返回 `source: "ldap"`，拒绝本地密码登录与改密。可在个人设置创建平台 AccessKey/长期 Token 供 Agent CLI 使用；浏览器和 CLI 均不会收到 SSH 密码。OIDC 与 LDAP 的身份范围和停用检查彼此独立。

## 浏览器与 MFA

登录页通过同源 POST 提交目录用户名/密码，成功验证主密码后清除页面密码字段。若需要 TOTP、恢复码或强制 MFA 绑定，服务器签发五分钟 HttpOnly、SameSite=Lax 待登录 Cookie，每个票据最多五次请求。MFA 设置挑战绑定该票据，不能通过普通本地 MFA 接口绕过。成功后只签发 HttpOnly 平台会话，不向前端返回 bearer token。取消操作会作废当前票据。

每个来源 IP 和目录用户名每分钟最多 30 次主认证请求、15 分钟内最多五次失败。第二因素失败另按平台用户跨流程累计，不能通过重新提交正确密码重置。票据与限流状态保存在进程内；重启或 HA 切换后，未完成登录需重新发起。完成后的共享会话认证时间可恢复，外部账号管理 MFA 需要最近五分钟内的目录登录会话和新验证码。生产应配置 HTTPS `JMS_PUBLIC_URL`，确保平台和待登录 Cookie 标记 Secure。

## API 与验证

- `GET/PUT /api/v1/settings/security/ldap`、`GET .../audit`：管理配置和审计。
- `POST .../check`：检查 TLS 与搜索账号 Bind；`POST .../users`：以 `directory_username` 查询并准备可选 `username` 的操作员。
- `GET /api/v1/authentication/ldap/status`：登录入口状态。
- `POST /api/v1/authentication/ldap/login`：`username/password` 主认证；`POST .../complete`：用对应 Cookie 提交 `otp` 和必要的 `setup_token`；`DELETE .../pending`：取消。

Testify 用例覆盖实际合成 LDAPS/StartTLS、证书拒绝、绑定、过滤器注入边界、不唯一/缺失/越界身份、AD 禁用标记、配置加密/版本/恢复、跨来源隔离、MFA、防重放和错误预算。Playwright 经管理页配置私有 CA、预建账号，并在真实合成 LDAPS 后完成本地 MFA 和停用失权。PostgreSQL/HA 还覆盖加密配置恢复。合成目录不等于真实 AD/OpenLDAP 部署验收；目录同步、自动组映射、多目录、SASL/Kerberos、目录密码修改和生产目录对接仍待完成。统一验证入口见 [TESTING.md](./TESTING.md)。

实现使用 [go-ldap](https://pkg.go.dev/github.com/go-ldap/ldap/v3)，传输和非空密码要求依据 [LDAP Authentication Methods (RFC 4513)](https://www.rfc-editor.org/rfc/rfc4513.html)。
