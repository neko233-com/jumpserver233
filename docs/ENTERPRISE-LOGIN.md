# 企业微信、钉钉与飞书/Lark 登录

> 中文 | [English](./ENTERPRISE-LOGIN.en.md)

E05 的 Go 原生接口、身份源/API、中英 Web、CLI/SDK 和用例已编写，**尚未运行验证**。提供方展示官方扫码/授权页面；本地不伪造厂商二维码。合成授权页与 HTTPS 协议夹具用于未来统一验收，不能证明真实厂商租户、应用审核和手机扫码已经通过。

## 配置与使用

在“身份源”创建 `wecom`、`dingtalk` 或 `feishu`，进入“提供方设置”。每个源拥有独立文件/数据库命名空间、派生密钥、回调、流程 Cookie、用户身份和停用代次；源 ID 与提供方类型不能互换。保留原 LDAP/OIDC/CAS/SAML 默认入口。

提供方设置默认关闭，首次自动创建普通用户也默认关闭。先在厂商后台创建内部应用、配置成员可见范围与必要读取权限，登记完整回调和可信域名，再填写本地参数。生产需要配置本安装的公开 HTTPS 来源；字面回环 IP 的 HTTP 回调只供本地开发显式启用。应用秘密为只写，留空保留；清除秘密与填写新秘密互斥，启用时必须有秘密。

| 提供方 | 应用字段 | 企业边界 | 稳定主体 |
|---|---|---|---|
| 企业微信 | Corp ID、Agent ID、应用 Secret | CorpApp 内部应用令牌与可读取的活跃企业成员；拒绝仅返回 openid 的外部联系人 | `userid` |
| 钉钉 | App Key、App Secret、Corp ID | 返回的 `corpId` 如存在必须匹配；应用自身令牌需将 `unionId` 映射为内部、活跃成员 | `unionId` |
| 飞书/Lark | App ID、App Secret、`tenant_key`、区域 | user_info 的租户精确匹配，再用应用令牌检查通讯录成员身份与状态 | `open_id` |

企微检查激活/启用状态；钉钉拒绝访客、外部联系人和不活跃成员；飞书/Lark 要求明确返回已激活且非冻结、离职、退出、未加入状态。缺少必需身份/状态或权限时拒绝登录，不猜测为空的字段。应用自身凭据决定通讯录范围；钉钉不返回 `corpId` 时仍必须通过应用令牌的内部成员查询。

飞书中国区与 Lark 国际区使用各自官方域名，身份命名空间包含区域。默认 OAuth v3，可显式选择 v2 兼容端点；两者使用 S256 PKCE。额外 scope 由管理员根据应用权限填写，最多 16 个，不接受 `offline_access`；不保存用户 refresh token。飞书/Lark 应用必须有足够权限读取用户稳定 ID、企业标识及成员状态，否则登录拒绝。检查应用凭据成功不代表成员权限或扫码链路已验证。

受控预创建可指定稳定主体和可选平台用户名；也可启用首次登录建号。平台只创建普通用户，不读取厂商管理员角色，不按昵称、邮箱或手机号合并账号，也不自动授予资产或组织管理权限。通过既有用户组/RBAC 再分配需要的权限。主身份通过后继续平台 MFA、RADIUS 附加因子、来源策略及登录复核；完成全部要求才返回平台会话。个人资料页不提供本地密码修改，平台 AccessKey/CLI 沿用当前源与权限检查，目标 SSH 密码不返回。

## 网络、秘密与生命周期

授权、令牌、用户信息和成员查询的端点按提供方/区域固定，不开放自定义 token/user-info URL。附加 CA 只扩展 TLS 信任，始终校验主机名；不跟随 HTTP 重定向，不回退明文，不解压不受控响应。单响应最多 128 KiB，响应头最多 16 KiB，嵌套 JSON 与字段数受限，拒绝重复 JSON 键。协议错误只返回固定错误码，不把厂商原始响应、授权码、带秘密的 URL 或令牌写入日志。

授权 state、浏览器证明、飞书 PKCE verifier 使用独立随机数。流程最长 10 分钟，一次消费；MFA 暂存最长 5 分钟。Cookie 使用 HttpOnly、Lax、当前源路径及源代次 HMAC，HTTPS 安装使用 Secure。回调只接受单个 state/授权码；钉钉支持其 `code` 或 `authCode` 单一参数。失败清理流程 Cookie，取消和重放不能换取会话。配置修订变更会使在途结果与旧暂存失效，停用/重新启用源不会恢复旧凭据或 Cookie。

共享原生客户端最多 16 个网络操作、32 个令牌获取协调项、256 个应用令牌缓存项；单源最多 4 个身份交换、1,000 个授权流程。应用令牌按秘密、应用、企业、区域、CA 等配置隔离，按厂商过期时间提前刷新，支持同配置并发合并。用户令牌只在当前交换中使用；应用令牌仅保留内存，不写磁盘。单次 HTTP 最长 15 秒，完整身份交换最长 25 秒。登录/检查参与 `enterprise_login` 排空；源关闭取消并等待在途操作，离线数据检查只读取加密配置，不联网。

配置采用修订和操作者绑定的 `request_id`。同内容重试返回原回执，改变内容或使用旧修订返回冲突；保存失败不发布新配置。最多 2,000 个人工配置回执与最近 1,000 条配置审计，存储总量最多 8 MiB；容量不足保留现有状态并拒绝新写入。每次成功配置写入清理旧流程，审计仅保存操作者、修订及秘密是否发生变更。

单机不增加外部数据库、Redis、厂商 SDK 或常驻认证进程；PostgreSQL 沿用现有文档存储。配置位于数据目录的 `identity-sources/<id>/<kind>.json` 或相应数据库文档，使用站点备份保护原文件及根密钥；集群与在线备份的未闭环部分仍按 E37/E39 记录。

## API 与 CLI

以下均在 `/api/v1/identity-sources/{id}` 前缀下：

```text
GET/PUT /api/v1/settings/security/{wecom|dingtalk|feishu}
GET     /api/v1/settings/security/{kind}/audit
POST    /api/v1/settings/security/{kind}/check
POST    /api/v1/settings/security/{kind}/users
GET     /api/v1/authentication/{kind}/start
GET     /api/v1/authentication/{kind}/callback
GET     /api/v1/authentication/{kind}/pending
POST    /api/v1/authentication/{kind}/complete
DELETE  /api/v1/authentication/{kind}/pending
```

管理操作需要系统 `security.manage`。公开登录列表 `/api/v1/authentication/sources` 只显示可用源名称、ID、种类和启动路径；提供方设置不公开。既有四类 REST 认证、完整 URI 的 HTTP Signature、组织授权、登录审计和复核保留。

```text
jms identity-sources provider <id> wecom settings
jms identity-sources provider <id> dingtalk save --file -
jms identity-sources provider <id> feishu check
jms identity-sources provider <id> feishu audit
jms identity-sources provider <id> wecom prepare --file -
```

JSON 秘密通过标准输入传入，不放在命令参数。SDK 使用独立传输类型，输出过滤未声明的秘密/令牌字段，不把服务器厂商运行时打入 CLI。

## 统一验证入口与外部边界

已编写 testify：三个厂商真实 HTTPS 夹具、飞书/Lark v2/v3、PKCE、租户/成员拒绝、重复 JSON/重定向/超限拒绝、应用令牌并发与刷新、授权码/流程/MFA 重放、设置幂等/修订、秘密隔离、关闭/排空、PostgreSQL 重开、API 登录审计及 CLI 脱敏。

`enterprise-login.spec.ts` 复用现有 OAuth 夹具进程：浏览器官方授权域名由明确标注的合成授权页接管，服务端仍向固定官方 HTTPS 域名发请求，经该隔离实例的 CONNECT 代理到具有正确域名证书的协议夹具。覆盖企微、钉钉、飞书中国区、Lark 国际区、MFA、个人资料、会话撤销、中英 390px 界面。未新增 Docker 容器；仅截取秘密已清空的管理页，失败自动截图/trace 关闭。夹具连接、实例及测试数据由现有生命周期清理，源归档清理可重复执行。

以上用例尚未执行。真实企业账号、厂商应用审批/回调注册、权限可见范围、手机扫码与公网 TLS 必须在最终统一验收时另行确认，不能由本地夹具或应用凭据检查替代。

## 契约参考

- [企业微信 Web 登录](https://developer.work.weixin.qq.com/document/path/98152)、[用户登录身份](https://developer.work.weixin.qq.com/document/path/98176)：官方配置入口；本次抓取页面受限，真实租户对接仍待验收。
- [钉钉 OAuth SDK](https://github.com/alibabacloud-go/dingtalk/blob/master/oauth2_1_0/client.go)、[用户信息 SDK](https://github.com/alibabacloud-go/dingtalk/blob/master/contact_1_0/client.go)、[unionid 成员查询](https://developer.alibaba.com/docs/api.htm?apiId=52234)：核对原生字段与内部成员边界。
- [飞书官方令牌实现](https://github.com/larksuite/oapi-sdk-go/blob/v3_main/core/accesstoken/access_token.go)、[用户信息模型](https://github.com/larksuite/oapi-sdk-go/blob/v3_main/service/authen/v1/model.go)、[成员状态模型](https://github.com/larksuite/oapi-sdk-go/blob/v3_main/service/contact/v3/model.go)：核对 v3、PKCE、企业标识和状态；访问日期 2026-10-20，不引入完整 SDK 依赖。
