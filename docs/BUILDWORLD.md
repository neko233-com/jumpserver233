# BuildWorld macOS 单机部署

> 中文 | [English](./BUILDWORLD.en.md)

源码构建模板是仓库根的 [Jenkinsfile_mac_single](../Jenkinsfile_mac_single)。实际 BuildWorld 项目 [49 · 内网服务器/JumpServer233](http://192.168.110.42:8080/projects/49) 使用私有 `poke-game/deploy_devops_server` 仓库及 `deploy_JumpServer233/JenkinsFile_JumpServer233`，与该部署仓库根的 `Jenkinsfile_mac_single` 一致；校验固定正式原生制品，不在节点重编译。未配置启动自动构建、外部 HTTP 触发或分布式 Worker。下表为源码模板默认值；实际入口为 8180，loopback 后端为 18180。

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

原生 HTTP 支持同源 loopback/内网 IP（含 IPv6 ULA），无需反向代理。可选 `JMS_PUBLIC_URL` 固定 HTTPS 或 loopback/内网 IP HTTP；HTTP 域名与公网 IP 拒绝。公网使用 HTTPS。仅对覆盖转发头的受控代理设置 `JMS_TRUSTED_PROXIES`。默认管理员见[认证](./AUTH.md)，升级保留已有密码。服务令牌和 Vault key 不进入 Git、构建参数、制品或日志。

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

## 历史验证边界，2026-10-18

项目 49 的分组、GitHub `main` 和 `Jenkinsfile_mac_single` 已在浏览器保存并读回。Windows Go 静态服务/config/server 测试、vet、前端生产构建和双语检查通过。部署状态机在无网络、只读挂载的临时 Linux 容器中 10/10 通过（launchd 命令由测试替身提供），容器自动删除；Windows 上对应 8 项通过、2 项因符号链接权限跳过。

当时真实 macOS SCM 在连接 `github.com:443` 时失败，未部署。该历史结果已由下述实际内网运行记录取代。

## 实际 v0.2.0 内网基线，2026-10-21

正式程序只激活一次。下载停滞和嵌套清单适配失败都发生在激活前；构建 989 部署成功，但等待浏览器验收超时。[构建 991](http://192.168.110.42:8080/builds/991) 以 `DEPLOY=false` 补验，3.59 秒完成 6/6 阶段、20 项原生 macOS 用例、归档/CLI 身份、真实 SSH、Linux 监控及有序重启后的资产/审计/Vault key 保留；保存的凭据再次连接成功。组织公共入口已指向服务。

v0.2.0 复用已安装 nginx 的专属 LaunchAgent，严格校验 Origin/Host，后端只监听 loopback，未修改其它 nginx 配置。[维护补丁](./MAINTENANCE.md) 增加原生 IP HTTP，并转发原始 Origin 供两层检查；v0.2.1 本批已完成统一验证和下述升级验收。临时传输归档、SSH 配置、预检程序已清理，精简报告和两张截图保留在 Git 外；只保留一份已验证正式制品缓存以加速后续构建。

## 前序 v0.2.1 验收，2026-10-21

[构建 995，#5](http://192.168.110.42:8080/builds/995) 执行正式 v0.2.0 到 v0.2.1 的唯一一次激活：6/6 阶段、26/26 项原生 macOS 用例，96.79 秒。固定归档及实际原生 CLI 均对应 release commit `c56eeeef0f3eb7768b9633232813337a41921b7a`。Edge 登录、新增真实 SSH 和主机监控通过；随后有序重启保留已有资产、原有/新增会话审计、凭据和相同 Vault key，默认管理员再次登录成功。未额外部署或另发版本。

组织共享入口保持为 [HTTP 8180](http://192.168.110.42:8180/)，后端 loopback 18180。验证与清理证据见[维护验收](./MAINTENANCE.md)。此节点实际 macOS/ARM 内网验收取代先前的排除边界。

## 最终 v0.2.2 部署

用户明确追加授权，针对已验证的运行时竞态修复只再发布一次 v0.2.2。[构建 997，#6](http://192.168.110.42:8080/builds/997) 以 92.04 秒通过 6/6 阶段和 26 项原生 Mac 用例，只激活一次。默认登录、新增真实 SSH、监控和重启保数通过；原有 1 个资产、全部 3 条先前审计 ID、新增第 4 条审计、凭据与 Vault key 均保留。正式源码 commit：`a73132e99f2a420f60ae88d7b43f69b57e767212`；部署 commit：`5967091b977da7cb84d114f600aa39a26d98eda8`。运行中的服务已包含 CI 验证修复。当前入口保持 [HTTP 8180](http://192.168.110.42:8180/)，清理与精确证据见[维护验收](./MAINTENANCE.md)。

## 前序 v0.3.0 原生 SSH/SFTP 部署 — 2026-10-22

[构建 1014，#7](http://192.168.110.42:8080/builds/1014) 单次升级 v0.2.2 → v0.3.0，4 分 43 秒通过 6/6 阶段及原机 34/34 用例。部署仓库固定 `d0c30aa856a76a0ff539b31535f18bbb7a955ae8`，官方运行制品固定 `0f4582783e2cae2e48c7a2b841fc0a4634099d30`。网页保持 8180，新增内置 SSH/SFTP 2222；不新增服务进程或外部运行依赖。

Edge root/root、真实 Web SSH 和主机监控通过；原生客户端完成 title/desc/IP 搜索、选服、Linux SSH、退出返回菜单，以及 55,296 bytes 上传、重命名、下载散列核对和删除。一次有序重启保留 1 个原资产、升级前 4 条原审计 ID 和重启前共 9 条审计 ID、凭据及 Vault key。保存凭据重连及在线 Linux 指标通过。重启后 Web/原生再次登录、相同主机指纹和完整文件往返重复通过。只执行一次激活，无重复发布。

验收及 CI 的准确边界见[原生入口](./NATIVE-SSH.md)。紧凑回执位于忽略的 `.cache/qa-reports/native-ssh-batch/`；清理自有文件、Docker QA 资源、临时可执行文件和传输包，保留正式数据、审计、必要回滚资料及当前已验证制品缓存。

## 前序 v0.3.1 客户端兼容修复部署

[构建 1022，#8](http://192.168.110.42:8080/builds/1022) 用 6 分 14 秒单次激活 v0.3.1，完成 6/6 阶段和原机 34/34 用例；其中业务验收等待包含浏览器、原生客户端及监控采样时间。官方源码 `d4a2fb7eec694ba453285bb12c0151bb9baee874`，部署锁定 `8108be93a8f58cda8191fe1098233dd9c16ec99f`。Web 8180、SSH/SFTP 2222 保持不变。完整 CI 六组和生产浏览器 70/70 通过。

升级前 1 个资产和 11 条会话审计全部保留；一次有序重启保留重启前 13 条审计、Vault key 和保存凭据，并重新采集 Linux 指标。重启前后 root/root、真实 Web/原生 SSH、title/desc/IP 搜索、55,296 bytes 文件散列/删除及监控通过。每次客户端兼容检查回收 20 个无效通道、运行 6 个并发辅助命令和三次现有 XTerminal 监控采样；现有脚本不被替换。用户截图确认监控，但随后要求更清晰且可键盘选择的表格菜单；该后续 UI 维护单独验收，不覆盖已发布制品。

精简回执与发布截图保留在忽略的 `.cache/qa-reports/native-client-live-20261022/`。临时本地程序、监控脚本副本、下载归档和旧节点制品缓存已清理；线上数据、审计、现有监控安装、正式回滚资料和当前已验证包保留。

## 当前 v0.3.2 表格工作台部署

[构建 1041，#9](http://192.168.110.42:8080/builds/1041) 于 2026-10-22 16:53:24 开始，16:56:15 完成，2 分 51 秒通过 6/6 阶段及原机 34/34 用例，只激活一次。正式源码 `6e717232c607a6b2661ae4a189cd3272e5469a1d`，部署锁定 `222cc8f79599551801bd01c0f84fdff70a21e1d9`。完整 CI 六组、生产浏览器 70/70 通过；官方 Mac ARM 包 28,138,076 bytes，SHA-256 `cbed946bf190743058594d9fb2536e77fce9b6d83deddf731c03099aae8d77b6`，与节点缓存及实际原生 CLI 一致。

原有 1 个资产、升级前 14 条审计保留；一次有序重启保留重启前 16 条审计、Vault key 和凭据，重新采集 Linux 指标。重启前后默认登录、真实原生 SSH、title/desc/IP 搜索、返回菜单、55,296 bytes 文件往返与删除、各三次监控采样通过；浏览器重新登录与真实 Web SSH 通过。主机指纹保持。没有再次激活或覆盖旧版本制品。

实际浏览器验收使用已授权的内置浏览器，Edge 两套连接故障没有引入应用改动。精简报告与成功截图位于忽略的 `.cache/qa-reports/native-workbench-live-20261022/`。自有测试文件、下载包、临时客户端、Docker 资源及旧节点制品缓存清理；当前正式包、运行数据、审计与必要回滚资料保留，重复清理安全。
