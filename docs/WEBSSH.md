# Web SSH 与 Agent CLI

> 中文 | [English](./WEBSSH.en.md)

SSH 密钥安装、验证后轮换、显式启用的七天计划及持久化阶段恢复见 [SSH 密钥轮换](./SSH-KEY-ROTATION.md)。

目标资产与网关现支持导入 SSH 私钥：输入只写、保管库加密、公钥指纹及验证后恢复历史版本。密码轮换仍按密码凭据调度，详见 [SSH 私钥](./SSHKEYS.md)。

SSH 网关现支持最多三跳，监控、Web SSH、CLI、SFTP、任务和改密共用逐跳指纹校验连接。配置与加密凭据支持单机及 PostgreSQL 单活 HA，详见 [SSH 网关](./GATEWAYS.md)。完整企业版对齐仍在推进。

默认会话仍按所有者隔离；全局会话读取、录像、命令审计及中断分别需要对应 [RBAC 权限](./RBAC.md)，查看审计不会获得连接或中断能力。

本文说明当前 Phase 4 已交付的 SSH 跳板切片。竞品目标仍是 JumpServer 企业版；本切片优先支持单机部署，不代表企业版功能已全部对齐。

## 当前能力

- 非交互 Agent 可使用 `jms exec` 或工作台执行单命令并取得 stdout/stderr 与退出码，支持复核、超时、取消及加密审计。详见 [JOBS.md](./JOBS.md)；本文后述 PTY 解析限制适用于交互式 SSH 会话。

- 资产列表的“连接”会由服务端读取加密资产凭据并建立 SSH PTY。远端密码不会返回浏览器。
- 开启登录复核的资产会在建立 SSH PTY 前等待管理员批准；Web SSH 批准后会自动继续。CLI 行为与边界见 [ACCESS-REVIEWS.md](./ACCESS-REVIEWS.md)。
- 资产列表的“文件”入口通过固定主机指纹的服务端 SSH/SFTP 通道浏览远端账号 home 目录，可创建文件夹、上传、下载和删除文件；凭据不返回浏览器。路径限定在 SFTP 初始目录下，不跟随符号链接，单文件传输上限为 1 GiB。
- 文件操作追加到 `JMS_DATA_DIR/file-transfers/index.jsonl`，管理员可查询全部记录，操作员只可查询自己的记录。集群模式需要共享此审计目录。
- 浏览器与服务端通过 `/ws/api/v1/sessions/{sessionID}/terminal` 交换终端二进制帧和 resize 消息。浏览器使用 30 秒有效、一次性票据；票据通过 WebSocket 子协议发送，不放入 URL。
- Agent CLI 使用相同的会话 API 和 WebSocket 路径，只需资产 ID；不接受远端 SSH 密码参数。
- SSH 主机密钥必须匹配资产中固定的 SHA256 指纹。
- SSH 资产页还展示主机连接延迟、CPU、内存、根磁盘和网络收发速率；采集方式与限制见 [SSHMONITOR.md](./SSHMONITOR.md)。
- 会话开始和结束会追加到 `JMS_DATA_DIR/sessions/index.jsonl`。asciinema v2 gzip 录像文件以 `.json.gz.enc` 保存，使用本地 Vault key 加密。
- 审计台的会话记录可打开“命令”查看命令行提交记录。`GET /api/v1/sessions/{sessionID}/commands?limit=50&offset=0` 仅管理员或该会话所属操作员可读；记录按 Vault key 派生会话密钥使用 AES-GCM 加密，保存在 `JMS_DATA_DIR/sessions/commands.jsonl`，集群节点需共享此目录。写入并同步审计记录成功后，输入才会转发给远端 SSH PTY。
- 命令采集只识别常见 shell 提示符下通过 Enter 提交的单行输入；密码/口令等已识别提示符中的输入会省略，常见 `--password`、环境变量凭据、`sshpass -p`、数据库 `-p...` 和 URL 用户凭据会脱敏。自定义提示符、交互式应用、多行/粘贴输入、方向键编辑等情况可能无法记录；未知形式的秘密也可能漏过。记录表示“识别到的命令行已提交”，不表示远端成功执行、命令结果或完整命令控制。
- 管理员可在系统设置的“命令过滤”页创建允许/拒绝/复核规则，按用户或组、资产或节点、SSH 账号和时间范围限定；匹配方式支持完整命令、包含文本和正则表达式。较小优先级先匹配，首条匹配规则决定结果；无规则匹配时允许。命中复核规则后命令行文本可能显示在远端终端，但网关暂不提交回车；管理员可在“命令复核”队列批准或拒绝。批准后提交回车，拒绝或 5 分钟超时会发送 Ctrl+C 清除待提交行；等待期间后续输入会丢弃。命令申请与处理结果分别写入加密命令审计。
- 命令过滤解析的是 PTY 输入行，不是 shell AST。自定义提示符、嵌套 shell、终端应用、shell 函数/别名、复合命令的语义以及所有终端按键编码未完全覆盖；不能把它作为绕过服务器授权、限制外部直连的通用安全边界。复核只决定是否提交已识别的单行命令，不提供命令结果/退出码。会话断开会取消待复核项；进程重启后待复核队列不恢复，命令审计读取时将孤立待处理记录显示为已取消。
- 审计台按开始时间倒序展示会话，状态每 10 秒刷新；管理员可查看全部会话，操作员只能查看自己的会话。活动会话可由所属操作员或管理员中断，已结束且录像可用的会话可由所属操作员或管理员回放。
- 本地用户登录后，服务端从已验证的 Bearer 会话取得操作员身份，并将用户 ID/用户名与会话起止事件一起写入审计索引；客户端不能通过创建请求伪造该身份。
- `GET /api/v1/sessions?limit=50&offset=0` 返回会话清单（管理员查看全部，操作员仅查看自己的），`DELETE /api/v1/sessions/{sessionID}` 中断活动会话（仅所属操作员或管理员），`GET /api/v1/sessions/{sessionID}/replay` 返回解密后的 asciinema v2 gzip 流（仅所属操作员或管理员）。
- 回放只呈现远端输出事件，不把录制的输入事件注入终端。浏览器限制单个录像为最多 64 MiB 压缩数据、128 MiB 解压数据，并支持播放/暂停、重播和 0.5×–4× 速度。

## 本地运行

在一个终端启动服务端：

```powershell
cd server
$env:JMS_ADDR = '127.0.0.1:8080'
go run ./cmd/server
```

另一个终端启动前端：

```powershell
cd web
$env:VITE_API_TARGET = 'http://127.0.0.1:8080'
pnpm dev
```

在 SSH 资产页添加主机后，点击“连接”。CLI 要求交互式终端：

```powershell
cd server
$env:JMS_SERVER_URL = 'http://127.0.0.1:8080'
go run ./cmd/jms ssh <asset-id>
```

远程部署时，使用 HTTPS 入口，并通过秘密管理器提供 `JMS_ACCESS_KEY_ID` 与 `JMS_ACCESS_KEY_SECRET`（或现有 `JMS_TOKEN`）；不要把凭据放到命令行参数。AccessKey 使用 HTTP Signature 调用会话 API，WebSocket 后续只接收短期单次会话票据。服务端监听地址不是 loopback 时，`JMS_ADMIN_TOKEN` 必须至少 32 字节，并用于保护资产与会话管理 API。

## 授权与未完成项

管理员可使用本地账号会话或 `JMS_ADMIN_TOKEN` 管理资产、授权与全部会话。操作员需要本人或所属用户组对资产当前配置的 SSH 账号具备有效 `connect` 授权才能新建会话；授权可直接绑定单台资产，也可绑定节点并继承到后代资产；`view` 授权只允许查看资产与监控。操作员可查看、结束和回放自己的会话，不能访问其他操作员的会话。管理员可在系统设置的访问控制页创建用户、用户组、资产节点并维护授权。

录像文件在磁盘上经过认证加密；回放 API 和审计台页面已提供。审计同时记录 SSH 资产账号与已验证的操作员身份；进程重启后未结束会话会标记为中断且不可回放。文件传输与可识别命令行已有独立审计索引；命令审计显示允许、拒绝、待复核、批准、超时和取消等策略状态。命令过滤仍受 PTY 行解析范围限制，命令结果/退出码和完整 shell 语义仍未实现。详见 [AUTH.md](./AUTH.md)、[SFTP.md](./SFTP.md)、[COMMAND-FILTERS.md](./COMMAND-FILTERS.md) 与 [SSHMONITOR.md](./SSHMONITOR.md)。
