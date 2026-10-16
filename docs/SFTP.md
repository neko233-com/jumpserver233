# SSH 文件管理器

> 中文 | [English](./SFTP.en.md)

全局 SFTP、跳过登录复核与读取全部传输审计分别由 `assets.sftp_all`、`login_review.bypass` 和 `audit.files.view_all` 控制，详见 [RBAC.md](./RBAC.md)。

## 当前能力

- SSH 资产列表为持有 `sftp` 动作的用户显示“文件”入口。管理员默认持有此动作；操作员必须有资产、配置 SSH 账号和有效时间匹配的 SFTP 授权。`sftp` 自动包含资产 `view`，但不授予 SSH 终端连接。
- 浏览器文件管理器支持目录列表、上级/路径导航、新建文件夹、文件上传、下载和删除。非空目录删除由远端 SFTP 服务拒绝。
- 服务端复用资产内加密保存的 SSH 密码和固定 SHA256 主机指纹，不向浏览器返回凭据。
- 所有路径相对于远端 SFTP 初始目录，拒绝绝对路径、`..` 越界和反斜线；发现符号链接时不跟随。单个上传/下载最大 1 GiB。
- 上传先写入同目录随机临时文件，再重命名到目标。目标已存在时默认返回冲突；用户确认覆盖后优先使用 OpenSSH POSIX rename 扩展。如果服务器不支持原子覆盖，覆盖会失败并保留原文件。

## API 与审计

- `GET /api/v1/assets/{assetID}/files?path=relative/path` 列出目录。
- `POST /api/v1/assets/{assetID}/directories`，JSON `{ "path": "relative/folder" }` 新建目录。
- `PUT /api/v1/assets/{assetID}/files/content?path=relative/file` 上传原始请求体；可传 `overwrite=true` 覆盖已有普通文件。
- `GET /api/v1/assets/{assetID}/files/content?path=relative/file` 下载文件；`DELETE` 同一路径删除普通文件、符号链接或空目录。
- 每次上传、下载、创建目录和删除都会记录操作者、资产、动作、相对路径、字节数、结果码和时间，不记录文件内容或 SSH 凭据。审计位于 `JMS_DATA_DIR/file-transfers/index.jsonl`。`GET /api/v1/file-transfers` 管理员查看全部、操作员查看自己的记录。
- 集群模式下所有活动/候选节点必须共享可读写的 `file-transfers` 目录。

## 当前边界

标准 SFTP 路径检查不替代远端 Linux 账号自身的文件系统权限；管理员仍应使用最小权限 SSH 账号。单文件上限为当前固定值，尚无管理员配置项。
