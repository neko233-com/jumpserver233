# SAML 2.0 登录

> 中文 | [English](./SAML.en.md)

接入单个可信 SAML 2.0 IdP，支持 SP 发起 HTTP-Redirect AuthnRequest、HTTP-POST 断言和本地 MFA。默认关闭，默认不自动建号。竞品基线仍为 [JumpServer 企业版](https://www.jumpserver.org/enterprise.html)，整体对齐目标未完成。

## 配置

1. 设置 `JMS_PUBLIC_URL` 为控制台实际公网源地址；进入控制台「SAML 登录」，需要 `security.manage`。
2. 填写稳定的 SP 实体 ID、同源断言消费地址 `/api/v1/authentication/saml/acs`，粘贴经过可信渠道核对的单个 IdP `EntityDescriptor`。仅使用元数据中的 HTTP-Redirect SSO 和 RSA 2048 位以上签名证书。生产地址要求 HTTPS；HTTP 仅允许显式开启的字面量回环地址。
3. 保存后通过 `/api/v1/authentication/saml/metadata` 取得 SP 元数据，导入 IdP，要求持久 NameID、签名断言及每次重新认证。SP 请求使用 RSA-SHA256 签名，SP 密钥和配置以 Vault Key 的 AES-GCM 加密保存。配置接口和元数据不返回私钥。
4. 优先预建精确持久 NameID。身份命名空间包含 IdP 实体、SP 实体和 NameID 格式；不能按邮箱、显示名或角色声明关联本地管理员。自动建号需显式开启；外部用户均为无资产授权的操作员，资产和系统权限另行授予。

## 校验与会话

- 使用 `crewjam/saml` 校验 XML 签名与断言；XML 签名依赖固定为已修复漏洞的 `goxmldsig v1.6.1`。要求单个签名明文断言、RSA-SHA256/384/512 和 SHA256/384/512 摘要，拒绝弱算法、多断言、重复 ID、DTD、未知条件和超限 XML。
- 校验签名证书、精确 issuer、request ID、Destination、Recipient、所有 audience restriction、有效期、持久 NameID 及限定符。断言窗口最多 10 分钟；认证时间最多 5 分钟前，时钟偏差最多 1 分钟。重放缓存有容量与有效期限制。
- RelayState、请求和配置版本一一绑定。跨站 ACS 不创建用户或会话；303 回到同源 finalize 时必须带原浏览器的 HttpOnly / SameSite=Lax 证明，随后签发一次性本地待登录票据。平台登录仍需本地 MFA/恢复码及全局强制 MFA 策略。
- 不向 URL、localStorage 或登录 JSON 返回平台 Bearer Token。修改配置撤销未完成流程；停用来源阻止其短会话、永久令牌和 AccessKey 身份入口。外部主密码不能在本地修改。

## 单机与 HA

单机优先。加密 `saml.json`、账号映射和已完成会话可随备份恢复；PostgreSQL 使用共享文档 `saml-config`，复用相同 Vault Key 和单活 HA。SP 私钥在重启和接管后保持一致。未完成请求、回调、重放缓存和 MFA 票据在进程内，重启/接管后重新发起。旧响应因缺少已发起请求而被拒绝。备份必须包含 Vault Key。

## 验证与边界

Testify 覆盖签名、请求签名验证、伪造/过期/错误受众等断言、浏览器绑定、一次性票据、配置版本、密钥加密、本地 MFA、来源隔离与停用；Playwright 使用 `12235` 的独立合成 IdP 验证真实表单 POST、取消及 MFA。合成数据不代表生产 IdP 对接验收。

当前不支持 IdP 主动登录、加密断言、SAML Artifact、联合退出/SLO、多 IdP、组织/组声明映射。SP 证书有效期三年，可在配置页选择保存时重新生成证书；随后必须重新导入元数据到 IdP。轮换会撤销未完成流程。仅支持 RSA IdP 签名证书。上述功能以及其余企业版能力仍在整体目标内。

信任材料过期时 SAML 入口拒绝登录，本地管理员仍可登录并修复配置。
