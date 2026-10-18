# BuildWorld macOS 单机部署

> 中文 | [English](./BUILDWORLD.en.md)

默认流水线是仓库根的 [Jenkinsfile_mac_single](../Jenkinsfile_mac_single)。BuildWorld 项目 [49 · 内网服务器/jumpserver233](http://192.168.110.42:8080/projects/49) 从 GitHub `main` 读取该文件，在当前 `builtin` macOS 节点构建并部署。未配置启动自动构建、外部 HTTP 触发或分布式 Worker。

## 默认配置

| 项目 | 默认值 |
|---|---|
| 工具链 | Go 1.27.x、Node >=22.12（推荐 24 LTS）、Python >=3.11；pnpm 固定 12.9.1 |
| 构建参数 | `DEPLOY=true`、`RUN_TESTS=true`、`JMS_PORT=8180` |
| 内网入口 | `http://192.168.110.42:8180/`，以实际健康检查通过为准 |
| 服务 | `user/<uid>/com.neko233.jumpserver233`，launchd 后台用户域 |
| 持久化根目录 | `~/.local/share/jumpserver233`；可用节点环境变量 `JMS_DEPLOY_DIR` 指定独立绝对目录 |
| 运行数据 | `data/`，包含加密库存、Vault key、用户、策略和审计 |
| 运行配置 | `runtime.json`，本机生成服务令牌；目录 0700，文件/LaunchAgent plist 0600 |
| 版本 | `releases/<commit>-<manifest-hash>/`，`current` 原子符号链接 |

HTTP 入口用于指定内网。公网使用受控 HTTPS 反向代理，再在本机 `runtime.json` 设置 `JMS_PUBLIC_URL` 和必要的 `JMS_TRUSTED_PROXIES`；未放宽现有 HTTPS origin 校验。首次管理员初始化遵循[认证](./AUTH.md)，后续部署保留已有身份与密码策略。服务令牌和 Vault key 不进入 Git、构建参数、制品或日志。

## 构建与部署

1. 预检本机工具链，锁文件安装前端依赖，生成必需 Linux 原生组件。
2. 统一执行 Python 部署状态机测试、Node QA 辅助测试、双语/来源检查、Go vet/测试和前端 lint。协议夹具和完整生产浏览器套件另见[验证](./TESTING.md)；此流水线未自动启动 Docker 或虚拟机夹具。
3. 前端只构建一次；Go 使用 `CGO_ENABLED=0`、`-trimpath -ldflags=-s -w`。打包原生服务、CLI 和静态网页，记录完整 Git commit、架构、逐文件 SHA-256 和压缩包摘要。归档保留最近 3 次制品、10 次构建记录。
4. 校验所有文件和架构，检查专属目录标记、部署锁、LaunchAgent 归属和监听进程。外来端口占用直接失败；已有部署端口变更要求显式迁移。
5. 停止旧写入者后备份数据、原子切换版本，验证 `/api/health` 的精确 commit、SPA 深链和未登录 API 的 401。`JMS_WEB_DIR` 让同一 Go 监听器直接提供前端、REST 和 WebSocket，无需额外 nginx/Node 常驻进程。

`RUN_TESTS=false` 显式跳过流水线测试，仍执行生产编译和部署健康检查。`DEPLOY=false` 只构建归档。重复部署同一 manifest 且健康检查通过时不重启、不重新生成密钥、不修改数据。

## 回滚与维护

停止时同时等待监听器和已核验 PID 退出，避免端口提前关闭而旧进程仍在写入。激活失败时先停止新进程，再恢复上一版程序、LaunchAgent 和停止写入后的数据快照，并重新检查旧版健康。新程序写过的数据留在 `failed-data/`，供人工核对激活窗口中的写入；不能把旧快照恢复描述成保留了所有新写入。该目录未处理前，后续激活会在停止现有服务之前失败，避免覆盖证据。首次部署失败保留数据供修复。

成功升级保留当前/上一版制品和最近两份数据快照，删除其它归属明确的版本目录。运行日志和异常恢复数据需按实际保留策略维护。不要用 QA 清理工具删除此持久化目录，不要打印或归档 `runtime.json`、LaunchAgent 的 `EnvironmentVariables` 或 `data/`。

静态文件访问使用 Go `os.Root` 限制目录，禁止隐藏路径、缺失资源的 SPA 回退和目录列表；`/api`、`/ws` 始终交给原有路由。前端入口不缓存，带内容哈希的 `/assets/` 可长期缓存。

独立检查入口：`python3 -B -m unittest discover -s scripts -p macos_single_test.py`；Go 静态服务测试在 `server/internal/webui`，使用 testify。部署回执为工作区 `dist/deployment.json`，不包含凭据。本方案是单机内网部署；集群部署仍见[高可用](./CLUSTER-HA.md)。

## 2026-10-18 验证边界

项目 49 的分组、GitHub `main` 和 `Jenkinsfile_mac_single` 已在浏览器保存并读回。Windows Go 静态服务/config/server 测试、vet、前端生产构建和双语检查通过。部署状态机在无网络、只读挂载的临时 Linux 容器中 10/10 通过（launchd 命令由测试替身提供），容器自动删除；Windows 上对应 8 项通过、2 项因符号链接权限跳过。

真实 macOS SCM 校验连续两次在连接 `github.com:443` 约 19 秒后失败，尚未进入构建或部署。需要该节点可用的代理或内网 Git 镜像后继续验收；目前不能把项目创建、Linux 状态机测试或本地 Docker 成功描述成 macOS 服务已经上线。
