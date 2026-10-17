# 远端 Linux 账号生命周期

> 中文 | [English](./REMOTE-ACCOUNTS.en.md)

通过已有 SSH 连接创建、停用、恢复和删除普通 Linux 账号。Web：资产 → 托管账号 → 远端 Linux 账号。执行身份使用当前选中的托管账号；账号创建成功后也可直接用于 Web SSH、SFTP 和平台身份 CLI。

## 权限与前置条件

- 需要 `accounts.manage`、相应的 `accounts.remote.create|disable|enable|delete` 和执行身份的 `view` / `connect` 授权。读任务需要 `accounts.view` 或 `accounts.manage`，并满足当前资产与访问策略。
- 每次尝试检查用户状态、当前角色、组织、来源、访问时间、资产和网关绑定。登录审批绑定任务 ID 与尝试序号；命令审批同样保留当前来源与完整操作摘要。普通 SSH 审批不能授权账号变更。
- Linux、普通用户名、UID 1000–60000。不会操作 root、默认凭据、执行身份自身或另一个托管绑定引用的账号；删除也拒绝网关引用。其他已加载组织中相同主机指纹与用户名的引用同样阻止操作。
- root 首次安装已校验的原生 Go 助手。非 root 身份需要管理员预装同版本助手，并预先配置仅允许该文件 `account-admin` 子命令的 `sudo -n` 规则。平台不会自动授予 sudo 或 sudoers 编辑权限。

## 凭据和远端效果

创建先把 Ed25519 私钥加密保存到 Vault，同时预留不可连接的命名账号。远端创建带任务标记的账号、设置单个公钥并验证新的 SSH 登录；验证和最终授权全部成功后才原子开放凭据。接口、CLI 和任务审计不返回私钥、密码或 shadow 哈希。新密钥默认每七天轮换。

停用保存原 Shell 与到期字段，设置过期和 nologin，同时阻断平台连接。恢复仅还原助手保存的停用状态。账号删除保留主目录，将目录归 root 所有并设为 0700；不会递归删除文件、终止进程或强制删除忙碌账号。管理员需另行处理备份和其他 UID 所有的文件。

## 中断与恢复

每次操作先持久化平台任务与主机 root 回执。任务执行前、执行中和凭据开放前检查当前授权。回执位于 `/var/lib/jumpserver233/account-admin`；创建、停用、恢复、删除均有阶段记录。删除还绑定已检查目录的设备和 inode，拒绝用后来替换的 root 目录继续执行。

网络、审批、凭据验证、Vault 写入或 HA 接管失败时，账号保持不可连接。重启或接管不会自动重放远端写操作。先停止旧作业，再选择：

- **查看远端状态**：读取并校验回执；创建还重新验证已暂存密钥，可完成已确认效果的凭据提交。
- **显式重试**：用原任务 ID 与原密钥继续未完成阶段；完成的效果不会重复执行。每次尝试独立重新授权、审批。
- **取消准备**：先在远端持久化取消栅栏，拒绝延迟到达的旧请求，再释放平台准备状态。已有或不能排除远端效果时拒绝取消；停止作业本身不会回滚操作。

新的助手与 root 回执应与 Vault 一起保留。含远端任务的资产文件使用格式 2，作业文件使用认证加密格式 3；旧程序拒绝读取，回退需使用同一时点且兼容的完整备份。

## CLI 和 API

CLI 只需平台身份，不需要取得目标私钥：

```sh
jms --account root accounts remote-create ASSET --username deploy2
jms accounts remote-tasks ASSET --limit 20
jms --account root accounts remote-disable ASSET --username deploy2
jms --account root accounts remote-enable ASSET --username deploy2
jms --account root accounts remote-delete ASSET --username deploy2 --confirm deploy2
jms accounts remote-submit ASSET TASK_ID
jms accounts remote-attempt ASSET TASK_ID --mode inspect --revision REVISION
```

操作返回持久化任务、作业及审批 ID。用 `jms accounts job JOB_ID` 查作业；登录审批通过后用 `remote-submit` 继续原次提交。新尝试必须提供当前任务修订。导入的现有命名凭据需要 `--uid` 明确确认普通 Linux UID；平台创建的账号自动使用已验证 UID。

`GET|POST /api/v1/assets/{collector}/remote-account-tasks` 分页读取或创建；`POST .../{task}/submit` 继续提交，`POST .../{task}/attempts` 接收 `revision` 和 `mode`。创建使用独立 `request_id` 幂等键和账号版本；公有作业接口不能注入内部远端操作类型。

当前仅覆盖本地 Linux 普通账号及单活 HA 的持久化恢复，不含 Windows/LDAP/AD 用户、多活远端任务调度或完整企业账号治理。竞品仍为 [JumpServer 企业版](https://www.jumpserver.org/enterprise.html)，完整对齐继续推进。


## 实测界面

2026-10-17：Docker API 重启后，六条真实 OpenSSH 任务和恢复尝试仍能读取。

![Remote account tasks](./images/remote-accounts.zh-CN.png)
