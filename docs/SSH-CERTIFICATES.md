# SSH 用户证书与签发源

> 中文 | [English](./SSH-CERTIFICATES.en.md)

## 实现状态

E36 已编写内置 CA、OpenBao 签发、账号策略、连接集成、Web、CLI/SDK、用例和双语文档，登记为**实现待验**。本轮没有执行测试、构建、浏览器或 Docker；全部 42 组实现后统一验证。不能把签发接口存在、用例源码或既有 SSH 验收当成新证书链路通过。

## 连接与账号策略

入口 `/console/ssh-certificates`。内置 Ed25519 CA 不需要额外服务；也可配置 OpenBao SSH 挂载点、签发角色、只写 token、固定 CA 公钥及可选 TLS 根 CA。OpenBao 请求遵循[官方签发接口](https://openbao.org/docs/secrets/ssh/signed-ssh-certificates/)。签发源属于当前组织，`X-JMS-ORG` 隔离 CA、token、策略、缓存和审计。

先纳管 SSH 资产/具名账号，再为具体账号选择签发源。现有 Vault 密码/私钥保留用于显式恢复；选定证书策略后，普通连接只使用该签发源，签发失败、CA 停用、固定公钥不匹配或端点变更均拒绝连接。只有显式清空策略才恢复使用 Vault 凭据。当前不提供“无初始凭据直接建资产”的向导，也不向调用者导出签发私钥或临时账号私钥。

公共 SSH 路由解析应用于 Web SSH、平台身份 CLI、SFTP、监控、原生 Agent 运维入口和每一跳网关。每份证书只允许当前账号用户名这个 principal，绑定临时密钥，并校验签名、有效期和扩展。仅允许终端及端口转发扩展；临时私钥仅存在服务内存，平台权限继续控制具体动作。主机密钥固定指纹仍然有效。

有效期默认 300 秒，允许 60–600 秒；缓存提前 15 秒失效，同一账号在有效缓存期内复用临时证书。缓存不会保存到磁盘，重启后重新签发；内置序号持久化递增。新握手受证书有效期约束，已建立会话继续执行平台授权和会话时长策略。策略及 CA 修订纳入连接授权绑定，改变后旧授权不能继续兑换或执行，现有终端按持续授权检查撤销。没有证书策略的资产保持原有授权绑定格式。

证书账号的密码/密钥轮换会被拒绝，自动轮换跳过这些账号；共享同一远程账号的别名也参与轮换检查。已有凭据变更未完成时不能绑定证书，先完成恢复。账号连接性检查使用当前有效认证方式。

## 目标机信任和 CA 轮换

1. 创建签发源，取得页面/API 的 `trust_bundle` 公钥文本。
2. 将其安装到目标 SSH 服务的受保护公钥文件，以 `TrustedUserCAKeys` 引用；检查 `sshd -t` 后按目标机运维流程重载。
3. 为对应资产账号启用策略，再使用现有连接、监控或 CLI 入口。

内置 CA 轮换分两步：`rotate` 只生成待用 CA，当前 CA 继续签发；先把包含当前及待用公钥的完整信任包分发到全部相关目标机，再执行 `activate`。激活后旧公钥继续包含于导出的信任包 11 分钟，覆盖最长证书有效期。目标机公钥文件需要运维人员重新分发/清理，平台不会自动修改生产 sshd。OpenBao 的 CA 轮换在 OpenBao 侧管理，再更新此处固定公钥并分发信任材料。

当前证书类型为 SSH 用户证书；主机证书签发、任意客户端私钥下载及目标机信任文件的自动运维不是本入口提供的能力。

## 权限与 API

- `ssh_certificates.view`：查看签发源及公钥；非管理者不返回 OpenBao 地址、角色、命名空间或 TLS 配置。
- `ssh_certificates.manage`：管理签发源、准备/激活内置 CA 轮换、删除。
- `ssh_certificates.assign` 加 `assets.manage`：绑定当前可见 SSH 账号。读绑定也重新校验该账号的当前可见权限。
- `ssh_certificates.audit`：查看当前组织变更和签发元数据。

这些权限均支持组织角色。CA 管理不授予目标账号访问权，普通调用者不能请求任意 principal 或取得签发用私钥。删除仍引用于存活账号的签发源返回冲突；已删除资源的残留绑定可在删除 CA 时清理。读取资源失败时保守保留引用。

API 前缀 `/api/v1/settings/ssh-certificates`：

| 方法与路径 | 用途 |
|---|---|
| `GET /issuers` | 签发源、公钥、信任包、修订及待用公钥 |
| `POST /issuers`、`PUT /issuers/{id}` | 创建/编辑；token 留空保留已存值 |
| `POST /issuers/{id}/rotate` | 准备内置 CA 轮换 |
| `POST /issuers/{id}/activate` | 显式激活待用 CA |
| `DELETE /issuers/{id}` | 删除无存活引用的 CA |
| `GET /bindings/{assetOrAccountID}` | 当前账号策略和端点 |
| `PUT /bindings/{assetOrAccountID}` | 替换策略，issuer_id 为空表示清除 |
| `GET /audit?offset=0&limit=20` | 分页审计，limit 最大 100 |

管理变更使用当前 `revision` 和 8–100 位字母、数字、`_`、`-` 的 `request_id`；相同身份/请求/规范化内容返回原始回执，改变内容或过期修订产生冲突。重复准备、激活、删除和清空不会重做变更；旧绑定回执不会恢复后来清空的策略。每次 API 重试先检查当前权限。

```sh
jms ssh-certificates list
jms ssh-certificates save --file issuer.json
jms ssh-certificates binding ASSET_OR_ACCOUNT_ID
jms ssh-certificates bind ASSET_OR_ACCOUNT_ID --file binding.json
jms ssh-certificates rotate ISSUER_ID --revision 1 --request-id prepare-ca-001
jms ssh-certificates activate ISSUER_ID --revision 2 --request-id activate-ca-001
jms ssh-certificates audit
```

内置 `issuer.json`：

```json
{"name":"Operations CA","provider":"builtin","enabled":true,"ttl_seconds":300,"revision":0,"request_id":"create-ca-001"}
```

`binding.json`：

```json
{"issuer_id":"sshca-0123456789abcdef0123456789abcdef","revision":0,"request_id":"bind-ca-001"}
```

CLI 支持 `--file -`，拒绝未知字段；SDK 为 `SSHIssuers`、`SaveSSHIssuer`、`RotateSSHIssuer`、`ActivateSSHIssuer`、`DeleteSSHIssuer`、`SSHCertificateBinding`、`BindSSHCertificate`、`SSHCertificateAudit`。已有 `jms ssh` / `jms exec` 及 Web 连接自动使用服务器端策略，调用者不接触目标凭据。

## 持久化、性能和验证边界

每组织 `ssh-certificates.json` 或 PostgreSQL `ssh-certificates` 文档使用 Vault 派生密钥的 AES-GCM envelope v1，加密保存 CA 私钥、OpenBao token、配置、管理回执及审计。启动/离线预检拒绝未知格式，停机整站备份包含此文件和密钥。审计仅记录身份、动作、账号 ID、CA ID、修订、序号、临时公钥指纹及期限；不保存临时私钥、token 或命令内容。

上限为 100 个签发源、20000 个账号绑定、4000 个不可变管理回执、最近 2000 条审计、10 个同时保留的旧 CA 和 32 MiB 明文。满回执拒绝新管理变更，不静默丢弃幂等记录。OpenBao 必须使用 HTTPS 和服务端证书校验，只有 loopback 夹具允许 HTTP；禁止重定向，响应最多 64 KiB，单次最长 5 秒。同一账号并发冷签发合并，OpenBao 网络请求不持有配置锁，返回后复查策略；热连接复用缓存。大规模冷启动性能及真实 OpenBao 生产对接仍待最终验证。

已写 Testify 核心/缓存过期/两步轮换/格式拒绝/TLS 签发夹具/PostgreSQL 接管，API 权限、CLI、组织关闭重开、加密备份及中英 390px 浏览器用例。原生 QA 复用既有 OpenSSH 容器和重启，预写证书专用账号、错误初始密码的对照、监控、CLI、SFTP、CA 分发激活、失效拒绝、Web SSH 和在线撤销。最终验证会运行这些入口并按既有保留/幂等清理规则收尾；本轮没有任何新增通过证据。
