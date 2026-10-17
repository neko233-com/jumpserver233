# 集群高可用

> 中文 | [English](./CLUSTER-HA.en.md)

通知中心的组织加密状态、游标和 outbox 使用同一共享文档；接管时未提交回执的发送中记录保留为结果不明确，不自动重放。已验证隔离 PostgreSQL 状态接管，生产提供商送达与多活仍待验收，见[通知中心](./NOTIFICATIONS.md)。

主机插件使用现有加密任务存储，接管后把未完成任务标记为 interrupted，不自动重放安装或启动。远端 Agent 独立于平台节点存活，接管后检测并显式操作；制品缓存可按固定哈希重新下载。见 [主机工具与 Agent](./HOST-PLUGINS.md)。

RDP 图形会话接入组织与进程关闭流程，历史录像依赖共享目录和一致密钥；切换需要重新连接，键鼠输入不自动重放。RDP 专项生产接管演练仍待验收，见 [RDP](./RDP.md)。

Kubernetes 与 Telnet 的配置和审计也支持单活接管，在线终端与一次性票据不迁移。集成用例先验证真实活动连接的输出，再取消主节点，检查旧连接关闭、审计保留及接管后重新连接。边界见 [Kubernetes](./KUBERNETES.md) 和 [Telnet](./TELNET.md)。

原生 PostgreSQL 数据库资产与加密查询审计也支持单活热备。逻辑会话、结果行不迁移，未结束查询不自动重放；接管后重新连接。见 [PostgreSQL](./POSTGRESQL.md)。

组织通过 `X-JMS-ORG`、浏览器切换和 Agent CLI 选择隔离资源、角色与运维审计，支持单机存储和 PostgreSQL 单活 HA。详见 [组织隔离](./ORGANIZATIONS.md)；完整企业版目标仍在进行。

平台登录审批与站内通知已接入：认证后等待、原来源一次性兑换、加密持久化及 PostgreSQL 单活 HA。详见 [平台登录复核](./PLATFORM-LOGIN-REVIEWS.md)；完整企业版目标仍在进行。

来源、每周时段及执行通道限制支持单机和单活 HA，详见 [访问策略](./ACCESS-POLICIES.md)；完整企业版对齐仍在推进。

SSH 密钥安装、验证后轮换、显式启用的七天计划及持久化阶段恢复见 [SSH 密钥轮换](./SSH-KEY-ROTATION.md)。

目标资产与网关现支持导入 SSH 私钥：输入只写、保管库加密、公钥指纹及验证后恢复历史版本。密码轮换仍按密码凭据调度，详见 [SSH 私钥](./SSHKEYS.md)。

SSH 网关现支持最多三跳，监控、Web SSH、CLI、SFTP、任务和改密共用逐跳指纹校验连接。配置与加密凭据支持单机及 PostgreSQL 单活 HA，详见 [SSH 网关](./GATEWAYS.md)。完整企业版对齐仍在推进。

Passkey 注册、设备验证登录、本地 MFA、撤销与 HA 恢复见 [Passkey](./PASSKEY.md)。

SAML 签名断言、浏览器绑定、本地 MFA、SP 身份加密和配置审计见 [SAML](./SAML.md)；其余协议配置及生产 IdP 对接仍待完成。

CAS 加密配置 `cas-config`、映射与已完成共享会话可恢复；未完成流程为进程内状态。详见 [CAS.md](./CAS.md)。

LDAP 的加密 `ldap-config`、外部身份映射及平台会话也支持恢复；待完成登录票据和错误预算为进程内状态。详见 [LDAP.md](./LDAP.md)。

系统角色、用户/组绑定和权限变更审计也保存到 PostgreSQL `rbac` 文档，活动节点接管后重新加载。详见 [RBAC.md](./RBAC.md)。

## 当前模式

服务支持 PostgreSQL 协调的**单活热备**。多个服务节点竞争同一个 PostgreSQL session advisory lock；持锁节点加载共享状态并提供 API，其他节点保持待机。外部负载均衡器只应把业务流量发给 `/readyz` 返回 `200` 的节点。

这是单活热备，不是多活部署。PostgreSQL 同时用于选主和共享资产、资产节点、用户、用户组、授权及登录会话状态：资产、节点、用户、用户组与授权分别保存为 JSONB 文档（节点文档名为 `asset-nodes`）；登录会话只保存 token 的 SHA-256 摘要。资产凭据仍由共享 Vault key 加密。首次启动时，如果数据库中还没有对应文档，系统会从旧 JSON 文件导入；导入后数据库成为这些状态的权威存储。

会话审计索引、文件传输审计 `file-transfers/index.jsonl`、录像、凭据轮换日志及其它文件仍保存在 `JMS_DATA_DIR`，所有节点必须挂载同一份支持可靠原子重命名的共享读写存储。切换时旧节点会关闭 API 和在线 SSH 会话；新节点从 PostgreSQL 加载共享状态，未过期的登录会话可以继续使用，在线 SSH 会话与内存监控快照不会迁移。

## 节点配置

OIDC 的加密 `oidc-config`、用户身份映射和已完成登录的会话认证时间也从 PostgreSQL 恢复。state、PKCE 与待登录票据为进程内状态，切换后需重新登录。所有节点设置相同的 `JMS_PUBLIC_URL`，与 HTTPS 负载均衡器公共源及身份提供方回调一致；不要依赖任意转发头决定 Cookie 安全属性。详见 [OIDC.md](./OIDC.md)。

所有节点使用相同的 `JMS_CLUSTER_MODE=true`、`JMS_CLUSTER_ID`、`JMS_DATABASE_URL`、`JMS_VAULT_KEY`、`JMS_ADMIN_TOKEN` 与共享 `JMS_DATA_DIR`。数据库 URL 必须连接到同一个 PostgreSQL 数据库，因为 advisory lock 的作用域是数据库会话和数据库本身。需要直连 PostgreSQL，或使用保持同一服务端会话的连接方式；PgBouncer 事务池化不能用于此选主连接。

每个节点的 `JMS_ADDR` 使用负载均衡器可达的地址；`JMS_CLUSTER_HEALTH_ADDR` 使用独立端口（默认 `0.0.0.0:8081`）。`JMS_ADMIN_TOKEN` 至少 32 字节并且在所有节点保持一致。所有节点需要使用同一把 base64 编码的 32 字节 Vault key；集群模式不会自动生成 key，也不会自动创建本地数据目录配置。

```text
JMS_CLUSTER_MODE=true
JMS_CLUSTER_ID=jumpserver233-prod
JMS_DATABASE_URL=<同一 PostgreSQL 数据库连接串>
JMS_DATA_DIR=/srv/jumpserver233/shared
JMS_VAULT_KEY=<base64 编码的 32 字节 key>
JMS_ADDR=0.0.0.0:8080
JMS_CLUSTER_HEALTH_ADDR=0.0.0.0:8081
JMS_ADMIN_TOKEN=<各节点相同且至少 32 字节的管理令牌>
```

不要把上述 key 或令牌写入镜像、仓库或日志。用秘密管理系统为每个节点注入相同值。数据库和共享文件存储需要分别部署为可用的服务；应用节点的热备不会自动让它们高可用。

## 健康探针与切换

- `GET /livez`：进程存活时返回 `200`，待机节点也返回 `200`。
- `GET /readyz`：仅在节点持有选主锁且业务 API 正在监听时返回 `200`；待机节点返回 `503`。
- PostgreSQL 会话异常时，活动节点撤销就绪状态并关闭 API，然后重新参与选主。
- 活动节点退出或释放锁后，待机节点轮询并尝试接管。外部负载均衡器负责将流量切换到新的就绪节点。

锁检查间隔为 2 秒，故障识别和负载均衡器摘除时间取决于数据库网络、操作系统 TCP keepalive 和负载均衡器配置。此模式不保证无损会话迁移或零中断。

## 验收边界

当前实现提供 PostgreSQL 单活热备、就绪探针以及资产/资产节点/用户/用户组/授权/登录会话的共享状态文档；可用 PostgreSQL 集成测试验证选主、故障切换和会话延续。会话与文件传输审计索引、录像、凭据轮换日志仍依赖共享文件存储；WebSocket/SSH 在线会话和监控快照不跨节点迁移。PostgreSQL 故障、共享存储故障、严格网络分区 fencing、多活负载均衡、Kubernetes 编排和生产环境故障演练尚未完成。需要严格消除网络分区导致的双主风险时，还需要集群外部 fencing 或带 fencing token 的写入机制。
