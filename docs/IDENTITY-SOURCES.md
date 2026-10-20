# 多身份源与目录同步

> 中文 | [English](./IDENTITY-SOURCES.en.md)

本批已编写 Go、API、中英 Web、CLI/SDK 和用例，**尚未执行验证**。遵循完整 42 组功能实现后统一验证的门禁；生产 IdP 联调结果不能由合成夹具代替。

## 入口与部署

单机默认使用本地加密文件，无需新增数据库或常驻同步进程。PostgreSQL 部署沿用现有文档存储；每个源使用独立命名空间与派生加密密钥。身份源属于安装全局，资源权限仍遵循组织边界。

在 `/console/identity-sources` 创建 LDAP、OIDC、CAS 或 SAML 源，进入对应提供方设置，再启用。原有默认提供方及其 URL 不变；新源与默认源不自动合并。同一个 issuer/subject 在两个源中创建不同普通身份，名称、邮件和角色声明不用于关联本地用户或提权。

新源路径前缀为 `/api/v1/identity-sources/<source_id>`；提供方保留原路径后缀，例如：

```text
/api/v1/identity-sources/idp-<32位小写十六进制>/api/v1/authentication/oidc/callback
/api/v1/identity-sources/idp-<32位小写十六进制>/api/v1/authentication/cas/callback
/api/v1/identity-sources/idp-<32位小写十六进制>/api/v1/authentication/saml/acs
```

OIDC/CAS 回调、SAML ACS/metadata、流程 Cookie 和一次性能力均绑定源。流程 Cookie 另以独立 HMAC 密钥绑定源代次及 Cookie 名称，停用/重新启用或中止同步后，旧回调与旧流程 Cookie 不能改代次后重用；请求中的身份创建也检查捕获的当前代次。浏览器返回 `/login?identity_source=...` 继续本地 MFA；最终平台 Cookie 仍位于 `/`。四类 REST 认证沿用现有行为；具名源请求的 HTTP Signature 绑定原始完整 URI。公开登录源列表只包含 ID、名称、类型和启动路径，不返回端点或密码。

停用或归档源会递增该源用户的认证代次并撤销 AccessKey、永久令牌和未完成能力；重新启用不恢复旧凭据。归档保留来源身份和历史，可以恢复配置后重新登录。提供方秘密仍为只写，空值保留沿用原有规则。

## LDAP 完整采集

在具名 LDAP 源的“目录同步”配置用户过滤器、用户名属性、组 Base DN 和组过滤器。稳定身份属性沿用登录配置的 `entryUUID` 或二进制 `objectGUID`；同步不按显示用户名匹配平台账号。用户过滤器独立于包含 `{username}` 的登录过滤器，不能带该占位符。

采集使用经过证书和主机名校验的 LDAPS 或 StartTLS，绝不回退明文。RFC 2696 每页 500 条，绝对截止 60 秒、读取预算 32 MiB；最多 10,000 个用户、2,000 个组、100,000 条成员边和展开成员关系，嵌套深度最多 16。支持 `member`、`uniqueMember` 和 `memberUid`，使用解析后的 DN 和 Unicode 简单折叠处理等价拼写。

缺失分页控制、重复 Cookie、引用、服务端截断、超限、身份重复、组循环和未经完整展开的 AD `member;range=` 属性都拒绝整次采集。超出范围需要缩小同步过滤器或提高实现边界后再验收，不把部分结果当完整快照。AD `userAccountControl` 的停用位会进入源暂停状态。

## 映射、重试与恢复

映射可把目录组绑定到已有平台组和组织角色。配置及应用需要系统 `security.manage`、`groups.manage`、`roles.manage` 和 `organizations.manage`；目录声明不能自行创建系统管理员。全局组可通过既有 RBAC 获得权限，管理员应按最小需要选择；组织 `admin` 属于明确配置。

自动成员关系保存在独立加密同步状态中，通过不可变索引参与授权。人工平台组成员取并集，人工组织角色（包含显式 `none` 排除）优先。人工停用、归档及过期不被目录恢复覆盖。一次批量创建只持久化一次用户集合。

先采集预览，再应用；预览有效 10 分钟。应用前检查源、提供方与配置修订，持久化意图后暂时阻止此源认证。用户状态与成员快照全部持久化后才恢复认证；失败或重启保留原请求，重试不会创建重复用户或重复应用缺失计数。修改设置和新预览不能覆盖待处理事务。原操作者可重试；其他具备所需权限的管理员可中止，中止会移除自动关系并暂停此源全部用户，后续成功同步才能恢复目录状态。

缺失策略默认 `keep`；`remove` 只移除自动关系；`disable` 移除自动关系并在两次独立完整快照均缺失后暂停用户。LDAP 已停用用户立即暂停。源暂停与人工停用分开保存。采集失败不递增缺失计数，也不移除成员。

周期 `0` 为手动，计划周期为 15–10080 分钟，默认不自动同步。调度器在显式启动及激活后运行，参与 `directory_sync` 排空计数，离线数据检查不联网。关闭会取消采集并等待正在执行的工作结束。每源保留最近 20 个已结束的计划运行及相关计划回执；人工回执、待处理意图和审计各有独立容量限制，达到上限会保留数据并拒绝新变更。

## API 与 CLI

```text
GET/POST /api/v1/identity-sources
GET/PUT  /api/v1/identity-sources/{id}
GET      /api/v1/identity-sources/audit
GET      /api/v1/authentication/sources
GET/PUT  /api/v1/identity-sources/{id}/sync
GET      /api/v1/identity-sources/{id}/sync/entries|runs|audit
POST     /api/v1/identity-sources/{id}/sync/preview|apply|abort
```

写操作包含修订及 `request_id`。相同操作者、相同请求内容重试返回原回执；请求内容变化返回冲突。同步列表支持 `offset` / `limit`，每页最多 200。提供方设置位于源前缀之后的原 `/api/v1/settings/security/<kind>` 路径。

```text
jms identity-sources list
jms identity-sources save --file -
jms identity-sources get <id>
jms identity-sources audit
jms identity-sources sync <id> settings
jms identity-sources sync <id> save --file -
jms identity-sources sync <id> preview --file -
jms identity-sources sync <id> apply --file -
jms identity-sources sync <id> entries --offset 0 --limit 100
jms identity-sources sync <id> runs
jms identity-sources sync <id> abort --file -
```

JSON 从标准输入传入，不在命令参数中放秘密。CLI/SDK 使用传输数据类型，不引入服务器身份提供方运行时。浏览器完成身份认证后，原有平台身份 CLI/AccessKey 继续工作，不暴露目标 SSH 密码。

## 待统一验证

已编写 testify 用例：跨源和默认源隔离、MFA/一次性重放、HTTP Signature 原 URI、停用/恢复、加密密钥隔离、批量持久化、TLS 分页及失败、中断重启与中止、人工授权优先、缺失策略。浏览器用例复用既有 LDAPS 夹具，覆盖真实目录登录、同步、映射、幂等和中英 390px 页面；只保留必要截图，临时实例最终由现有 QA 生命周期清理。实际企业 LDAP/OIDC/CAS/SAML 租户、规模上限和 PostgreSQL 重启链路仍须最终统一验收。
