# Windows 与数据库账号 PAM

> 中文 | [English](./ACCOUNT-PAM.en.md)

## 当前边界

E18 的代码、用例及双语界面已编写，**尚未运行验证**。按用户要求，完整清单 42 组实现就绪后统一验证。此页描述候选实现，不作为原生 Windows、数据库或生产验收证据。

入口为控制台 `/console/pam`、`jms pam` 和 Go `sessionclient`。复用现有资产 Vault、多账号、纳管回执、改密计划、七天周期、审计与凭据恢复；单机部署没有新增常驻服务、数据库、Agent 或端口。Linux SSH 账号生命周期继续使用[远端账号管理](./REMOTE-ACCOUNTS.md)。

| 目标 | 通道与身份固定 | 收集和改密范围 |
|---|---|---|
| Windows 本地账号 | 现有 OpenSSH、固定 SSH 主机密钥；本机 SAM SID | 系统 PowerShell `Get-LocalUser` / `Set-LocalUser`；采集账号需本机账号管理权限 |
| PostgreSQL | `verify-full` TLS；集群角色 OID | 可登录角色；密码写入 SCRAM-SHA-256 校验值，避免把明文密码放入 DDL |
| MySQL | `verify-full` TLS；精确 `user@host` 与认证插件 | `mysql_native_password`、`caching_sha2_password`、`sha256_password`；有第二密码的账号拒绝改密 |
| MariaDB 10.4+ | `verify-full` TLS；精确 `user@host` 与认证插件 | `mysql.global_priv` / `mysql.user` 的单一 `mysql_native_password` 账号；角色、外部认证和多认证链排除 |
| SQL Server | `verify-full` TLS；实例 SQL login SID | 已启用 SQL login；固定参数化批次、系统标识符引用和改密事务 |

Windows 域账号在其目录身份源管理；本页不修改 AD。Oracle、DB2、达梦等协议的实现仍属于 E26 缺口；不能从此表推断支持。MySQL 没有等同于 PostgreSQL OID 的账号代际标识，固定的是逻辑 `user@host` 和插件，不能识别保持这两者不变的删除重建。

## 使用流程

1. 配置资产及采集凭据。Windows 资产使用 SSH 协议，在 PAM 页选择“Windows 本机账号模式”；需先关闭该记录的 SSH 密钥轮换，目录约束配置不能直接用于此模式。数据库使用对应协议及有效 TLS CA/服务器名称。
2. “收集账号”仅读取身份元数据，不读取远端密码或密码散列，不安装软件，不改密；最多返回 1,000 个身份，超过容量明确失败。
3. 选择账号，预览并确认纳管。新记录需要已知初始密码；已有密码账号留空保留 Vault 中的值。预览重新收集身份并绑定请求、操作者、资产/账号修订和参数；确认仅保存元数据与加密凭据。
4. 纳管后进入[改密计划](./ROTATION-PLANS.md)，选择目标及同一主机/实例的特权采集账号，使用批量、一次性、周期、检测、显式重试和恢复。数据库修改使用本机数据库权限；Linux、Windows 和数据库采集账号不会跨协议混用。

新增 PAM 纳管默认关闭七天自动改密。勾选后使用现有资产七天任务，以目标账号自身操作；它必须能连接并修改自己的密码。RDP 专用 Windows 账号、没有自身改密权限的数据库账号应保持该选项关闭，改用配置特权采集账号的 168 小时周期计划。保存启用的周期计划可能立即执行，页面沿用现有提示。

Windows 认证核验通过采集账号运行固定系统凭据 API，同时核对 SID，因此目标本地账号不必具有 SSH 登录权限。普通 SSH 检测只做 SSH 认证；数据库检测认证后核对实际 OID、`CURRENT_USER()` 或 SID。MySQL 认证使用 `information_schema`，不要求额外授予业务库权限。Windows 监控当前返回 SSH 可达性与延迟，不运行 Linux `/proc` 采样，也不伪造 CPU/内存数据。

## 权限、幂等与恢复

- 所有 PAM 入口要求当前组织 `assets.view_all` 及当前访问策略；收集另需 `accounts.discover`。模式修改需 `accounts.manage` + `assets.rotate`；纳管预览/确认另需 `accounts.import` + `accounts.discover`。
- 通用账号更新/批量导入携带 PAM 元数据也要求独立 `assets.rotate` 权限。轮换、固定密码、特权采集账号和检测沿用各自的 `accounts.rotation.*` 权限；Windows 检测所选特权账号时额外核对其权限和访问策略。
- 密码只写；API、CLI 输出与审计仅包含身份、修订和状态。Windows 请求以 UTF-8 JSON 的 base64 送入加密 SSH 标准输入，命令仅含固定 PowerShell 脚本；密码不进入命令参数、环境变量或脚本字符串。
- 改密前持久化加密旧/新凭据与请求。原生操作前重复校验身份及授权，远端结果未知时认证候选与旧凭据再决定提交/撤销；无法确认则保留待恢复状态。恢复不会再发送一次改密。
- 相同纳管或计划请求重放返回原回执；相同请求改参数、跨操作者确认、过期预览或修订变化拒绝。浏览器丢失响应后保留原请求 ID 和原载荷供重试。
- 多组织中的同一已固定远端身份沿用共享凭据事务，一次改密后同步各自加密 Vault；不会因此新增其他组织的访问权限。不同 MySQL Host 不合并。
- 资产格式新增 envelope **5**；旧数组和 v2/v3/v4 保持其原有读取范围，夹带 PAM 或 PAM 恢复字段拒绝。旧程序不能忽略 v5 后继续启动；降级需恢复升级前完整快照，见[升级兼容范围](./UPGRADE-COMPATIBILITY.md)。

数据库自身审计、SQL 事件/复制配置和运维人员拥有独立日志权限；应用只保证其自身接口、错误与审计不返回明文密码，不能承诺外部数据库不会记录敏感 DDL。PostgreSQL 使用预生成的 SCRAM 校验值；它仍属于敏感认证资料。MySQL 显式保留已固定认证插件，并拒绝存在第二密码的账号，避免把旧密码有效误当作成功撤销。

## REST 与 CLI

| 方法 | 路径（前缀 `/api/v1/assets/{assetID}`） | 用途 |
|---|---|---|
| GET | `/pam/principals` | 当前原生账号元数据 |
| PUT | `/pam/platform` | `platform`, `version`, `request_id`；保存模式 |
| POST | `/pam/import-preview` | 绑定原生身份和纳管参数的预览 |
| POST | `/pam/import-commit` | 同一载荷及 `preview_token`；保存/重放回执 |

纳管载荷包含 `principal`、`version`、`update`、可选 `name`/只写 `password`、`automatic`、`request_id`；确认追加 `preview_token`。`version` 为更新账号或新增账号所属物理资产的当前版本。新账号密码、平台令牌和签名密钥不要写入仓库文件或命令行。

```text
jms pam discover ASSET_ID
jms pam platform ASSET_ID --file -
jms pam preview ASSET_ID --file -
jms pam commit ASSET_ID --file -
```

结构化 JSON 经标准输入传入；平台身份、组织头和签名方式沿用 CLI 既有配置。批量执行使用 `jms account rotation` 的既有接口；Go SDK 为 `PAMPrincipals`、`ConfigurePAMPlatform`、`PreviewPAMImport`、`CommitPAMImport`。纳管需要写入凭据，常规 SSH/Agent 操作继续由服务端使用 Vault，调用者不需要读取目标密码。

## 待统一运行的用例

- Testify：输入/容量/取消，SCRAM 独立盐和密钥，Windows 固定脚本/Unicode 标准输入/错误主机密钥/输出上限，MySQL 插件和 Host，SQL Server SID/UTF-16 长度。
- 应用/API/SDK/CLI：独立权限、伪造身份、过期修订、换操作者、回执重放、元数据格式拒绝、Vault 重开、多组织一次变更、待确定结果恢复、特权采集账号变更。
- 真实 PostgreSQL/MySQL/MariaDB/SQL Server：复用已有 TLS 夹具，独立 `pam_admin` 创建唯一 `pamqa_` 账号，改密后认证新密码、拒绝旧密码、拒绝错误身份；仅删除自建账号，删除重复两次。
- `web/e2e/pam.spec.ts`：四类实际数据库收集、中英/窄屏、纳管预览确认、回执复用、计划改密/认证和清理。复用现有数据库，不启动另一组数据库栈。
- 可选真实 Windows：`TestRealWindowsPAMLocalSAMAndCollectorCredentialProof` 需要显式设置 `JMS_TEST_WINDOWS_PAM_DISPOSABLE=true`，并通过本机环境提供 `JMS_TEST_WINDOWS_PAM_HOST/PORT/USER/PASSWORD/FINGERPRINT`。仅在专用可丢弃 Windows 主机创建唯一 `pamqa_` 本地账号，清理先校验 SID 并重复删除；没有夹具则跳过，不能标记 Windows 原生通过。

本次没有启动夹具或验证资源。最终只保留摘要和必要脱敏截图；由原有隔离运行器清理自有容器、数据、卷和缓存，不清理其他项目资源。

## 原生接口依据

PostgreSQL 接受预生成认证校验值，密码 DDL 需考虑服务端日志：[CREATE ROLE](https://www.postgresql.org/docs/current/sql-createrole.html)。MySQL 的插件及第二密码语义：[ALTER USER](https://dev.mysql.com/doc/refman/8.4/en/alter-user.html)。SQL Server 的原生改密接口：[ALTER LOGIN](https://learn.microsoft.com/en-us/sql/t-sql/statements/alter-login-transact-sql)。Windows 本机改密及凭据核验：[Set-LocalUser](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.localaccounts/set-localuser)、[PrincipalContext.ValidateCredentials](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.accountmanagement.principalcontext.validatecredentials)。

MariaDB 的 `ALTER USER ... IDENTIFIED VIA` 会移除未列出的认证方式，因此本实现拒绝 `auth_or` 多认证链，避免改密时改变登录方式：[MariaDB ALTER USER](https://mariadb.com/docs/server/reference/sql-statements/account-management-sql-statements/alter-user)。
