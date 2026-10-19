# 发布版本检查与原生制品

> 中文 | [English](./UPDATES.en.md)

系统设置 → 安全策略 → 软件更新提供当前版本、稳定版检查、可选自动检查、原生包/校验值与活动。外部检查默认关闭；开启后间隔 1–168 小时，默认 24 小时。检查、下载和暂存不执行包中程序或替换业务数据。[单机升级事务](./INSTALLATION.md)包含加密快照、离线预检、首次启动健康与业务门禁、放行前回滚及旧服务恢复；放行后保留新数据。新增[单机定时安装](./INSTALLATION-SCHEDULE.md)，由独立监督进程执行已校验的固定候选。

## 版本来源与权限

只访问 [官方 GitHub Release](https://github.com/neko233-com/jumpserver233/releases)。忽略未发布标签、草稿和预发布版本，正式标签使用 `vX.Y.Z`。`dev`、源码 SHA 等非正式版本会明确显示无法比较，不伪装成“已经最新”。当前无正式 Release 时显示暂无稳定版。

Web/API/平台 CLI 共用全局 `security.manage` 权限、四种既有认证方式与登录访问策略；组织管理员不会自动获得该权限。`X-JMS-ORG` 仍校验格式，但更新信息属于全局系统配置。自动检查运行在当前活动节点的生命周期内，策略、检查结果、错误码、审计和最近 100 个请求回执支持本地持久化及 PostgreSQL 单活接管。策略保存无变化不新增修订或审计；旧修订冲突，同一检查请求重试返回原回执，新的手动请求至少间隔一分钟。

网络失败保留上次成功结果，错误只保留固定代码，不保存服务器响应正文、认证凭据或重定向签名 URL。关闭自动检查阻止新任务，不会取消已经发出的手动请求。正式包注入版本、源码提交与构建时间；`JMS_VERSION` 仍可供现有部署显式覆盖。

## CLI

```sh
jms --version
jms update check
jms update status
jms update audit
jms update policy --revision 1 --automatic=true --interval-hours 24
jms update check-server --revision 2 --request-id update-check-unique-001
jms update download --version v1.2.3 --out /srv/packages/jumpserver233.tar.gz
jms update verify --file /srv/packages/jumpserver233.tar.gz --sha256 EXPECTED_SHA256
```

`check`、`download` 和 `verify` 为本机原生操作；`status`、`audit`、`policy` 和 `check-server` 使用既有平台登录能力。可为下载/校验指定 `--os linux|darwin|windows --arch amd64|arm64`。下载文件必须不存在，不覆盖旧文件；先写私有临时文件，校验完整长度和 SHA-256 后原子发布。校验失败清理本次临时文件。下载最多 256 MiB、五分钟；元数据请求最多 20 秒。不会执行归档中的程序。

`verify` 不解包，检查整个归档 SHA-256、平台/架构、格式版本、源码提交、稳定版本号、完整文件集合与每文件 SHA-256。拒绝路径穿越、链接、Windows 特殊名称、重复大小写、文件与目录冲突、缺失清单、损坏 gzip 和尾随数据。原生包仅包含两个可执行程序、静态网页和清单，不包含数据库、Vault key、运行配置或业务数据。清单版本不是应用数据迁移兼容性声明。

## 受控版本暂存

使用独立且初始为空的目录，位于源码与业务数据之外。暂存不需要停止服务，也不改变部署正在使用的二进制、网页或配置。

```sh
jms update stage --root /srv/jumpserver233-releases --file /srv/packages/jumpserver233.tar.gz --sha256 EXPECTED_SHA256
jms update stage-status --root /srv/jumpserver233-releases --sha256 EXPECTED_SHA256
jms update stage-clean --root /srv/jumpserver233-releases
```

默认校验当前主机平台；可以显式传入 `--os` 与 `--arch` 为其他平台准备候选，但不会执行它。目录按平台和架构绑定，切换目标须使用另一目录。SHA-256 应来自已核对的官方 Release；自行提供哈希只证明字节一致，不证明来源可信。

程序先建立私有归属记录与进程互斥锁，再复制一份有界的私有归档并完整校验，避免源文件替换影响解包。使用 Go `os.Root` 限制所有解包路径；只创建新文件，拒绝归档链接及特殊文件。写入文件并同步后，复核完整文件集合、逐文件大小/哈希、可执行权限与原生架构，再同卷重命名发布到 `ROOT/releases/SHA256/`。Unix 同步目录；Windows 不宣称同等的断电目录持久性，目录需由部署账号的 ACL 保护。

相同包重试返回 `unchanged=true`，仍核对源归档与已有目录的全部内容。已有文件被改动、缺失、多出文件/目录或回执不符时拒绝覆盖，保留现场。`stage-status` 是本地完整性复核，本地回执不是签名或独立来源证明。普通数据目录、源码目录与未知内容不会被接管为暂存根目录。

每次暂存自动清理已确认归属的中断目录；`stage-clean` 可单独重试。只删除当前受管根目录下、名称及归属回执都匹配的 `.jms233-stage-*`，拒绝链接/归属不明的路径，保留已发布的候选和未知文件。崩溃发生在归属回执写完之前时，会保留目录并报冲突，需要人工核对，不能按名字猜测删除。暂存目录和归档均不包含应用数据；旧候选不会自动淘汰。

暂存不等于升级成功。[安装事务](./INSTALLATION.md)停机备份/预检，再执行首次启动验收；放行前失败恢复快照和旧版本，放行后故障保留新数据并要求向前修复。[升级前排空](./SERVICE-MAINTENANCE.md)提供活动工作计数、接入门禁和取消；新增[定时安装](./INSTALLATION-SCHEDULE.md)连接固定候选与受控停机；真实历史版本迁移验收仍待完成。不要仅将旧程序指向新程序已改写的数据。

## 发布流程

本地验证入口：`node scripts/update-race-qa.mjs` 使用独立网络和内存 PostgreSQL 验证接管与 race；`node scripts/native-package-qa.mjs` 在提交源码后构建六平台包，实际暂存并运行宿主 CLI 和 Linux 单端口服务，再通过已安装的 Playwright Chromium 检查真实登录、中英界面和版本显示。原生 QA 使用独立网页输出，不覆盖正在验证的 `web/dist`；结束后重复清理自有容器、临时制品与运行数据，仅保留精简报告和两张截图。其他平台的包验证不等于真实设备运行验收。

Release 仍由 release-please 在正式发布时维护 changelog。`release-artifacts.yml` 在正式稳定 Release 上构建 Linux/macOS/Windows × amd64/arm64 六个 Go 原生包；网页只构建一次，嵌入组件先经生成链准备。通过 `workflow_call` 连接 release-please，避免依赖 `GITHUB_TOKEN` 创建事件再次触发工作流。手动发布稳定 Release 也可触发；不从普通 push/tag 创建正式 Release。

```sh
cd server
go generate ./internal/agentbundle
go run ./cmd/jms-package --version v1.2.3 --commit FULL_SOURCE_SHA --built-at RFC3339_TIME --target linux/amd64
```

先执行 `cd web && pnpm build`。输出位于忽略的 `dist/`，每包有 `.sha256`。发布器只向已存在的官方稳定 Release 上传；重复运行核对远端大小和 digest，相同制品返回不变，不同字节拒绝覆盖。它不会创建 Release、更新标签或手写 changelog。GitHub 的 HTTPS 元数据及资产 digest 是本轮信任来源，不等同于独立的签名或离线可信根。[Release API](https://docs.github.com/en/rest/releases/releases)、[资产 API](https://docs.github.com/en/rest/releases/assets)。

升级前仍需正常停止服务并完成[整站加密备份](./BACKUP.md)。单机恢复能力不代表 PostgreSQL 集群整库备份或远端密码状态回滚；程序切换与活动 SSH 会话处理继续按 [SSH 稳定版范围](./SSH-FIRST.md)推进。
