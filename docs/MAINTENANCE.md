# 单机维护补丁与发布验收

> 中文 | [English](./MAINTENANCE.en.md)

## 本批范围

保持 [mini SSH 范围](./PRODUCT-SCOPE.md) 的 12 项清单，补齐实际部署发现的问题。实现与用例集中编写后，已在源码 `09bb9b5fdcaf7231bb7af2aff3868f11261757d4` 完成统一验证。v0.2.1 正式发布和唯一一次内网升级已分别完成验收。mini 清单仍为 12 项；后续 race 发现重新打开 S12，维护补丁不增加范围完成信用。

- 原生同端口支持内网 IP HTTP：Origin 的协议、Host 和端口必须与请求一致，或与显式 `JMS_PUBLIC_URL` 一致。隐式信任只允许 loopback 和内网 IP，不查询 DNS；外域、不同端口、`null` Origin 和无 Origin 的跨站浏览器请求拒绝。HTTPS 配置和原开发入口保持兼容。
- 登录区分来源拒绝、请求过多、服务不可用、网络异常与错误凭据；中文英文文案一致。先确认 HttpOnly Cookie 会话可用再进入控制台，避免 Cookie 未建立时跳转循环。不显示后端原始错误或秘密。
- macOS 发布验证根清单与嵌套 Vite 清单，正式版本必须绑定精确 commit；入口选择已安装的 Python >=3.11。升级前拒绝活动 SSH，会后核对已有资产、会话审计和 Vault key；仍由既有停止写入后的快照与回滚逻辑保护数据。
- 已部署环境继续使用其专属 HTTP 入口；新版本转发原始 Origin，由入口与原生服务分别检查。入口配置校验失败恢复旧文件，同配置重复执行保持 PID。产品默认单机使用 Go 原生静态服务，不要求 nginx。

## 统一验证

集中执行 Go/Testify、vet、前端 lint/type/build、中英生产浏览器、Python/Node 发布工具用例及隔离 Docker。重点覆盖默认管理员重启、Cookie 会话、同源/跨源、幂等、清单篡改、升级拒绝与保数。只在统一运行发现失败后修复并重跑受影响部分。

通过后由 release-please 生成补丁版本及 changelog，发布不可变六平台制品。部署仓库锁定版本、commit、大小和 SHA-256；BuildWorld 只升级一次，再验收默认登录、真实 Web SSH、CPU/内存/磁盘/网络和数据保留。清理归属测试资源、临时程序及归档，保留精简报告和最多两张必要截图。

## 已有内网基线

2026-10-21，v0.2.0 已通过 BuildWorld 项目 49 部署；构建 991 使用 `DEPLOY=false` 补验，6/6 阶段、20 项 macOS 用例、真实 SSH、监控和有序重启保数通过。程序只发布一次。详情见 [BuildWorld](./BUILDWORLD.md)。该记录保留为旧版基线，本次升级结果见下文。

## 统一结果，2026-10-21

- Go/Testify：2061 项通过、133 项跳过，100 个包通过；vet 通过。平台/外部集成跳过项不算已验收。
- 生产浏览器：69/69，含新增 14 项中英登录失败用例，共 17.7 分钟。完整套件含真实原生 Agent 重启、防火墙修复和 systemd 监管。
- 发布/QA Node 工具：77/77。源码 Python：11 项，Windows 符号链接权限跳过 2 项。部署 Python：macOS 原机 26/26，无跳过。
- 六平台原生包通过；Windows CLI、真实 Linux SSH/SFTP、受控安装/回滚、加密、备份恢复、密码检查和目录策略通过。原生测试归属资源已幂等清理。
- 纯净 Docker 浏览器通过并清理资源。前端 lint/type/build、双语和来源检查通过；历史 UI 模块保留 5 条既有警告。
- 首屏 JavaScript 496024 bytes、gzip 160149；总 JavaScript 1642958 bytes，既有预算通过，未新增运行依赖。

报告保存在忽略目录 `.cache/qa-reports/maintenance-v021/`、`maintenance-v021-native/` 及对应浏览器/Docker 批次。验证期间产品代码未改变；后续仅发布元数据和证据文档推进 HEAD，不改变已验证 server/web 树。

## CI 夹具隔离

发布 CI 在后端断言之前失败：十个外部服务在同一托管节点并发启动时，K3s 启动以 137 退出。外部集成现分为关系数据库、数据服务和访问协议三个必跑节点分组。每组顺序启动夹具，执行对应连接器/API 用例，并始终清理自有资源。核心 Go/PostgreSQL/SSH/systemd、race、vet、构建、浏览器和 Docker 检查保持必跑。仅调整 CI 调度，v0.2.1 制品不变。

每个外部集成分组也启动受控 OpenSSH 网关，避免网关用例因缺少前置夹具而跳过。常规 push/PR 保持完整门槛；仅显式手动 `external_only` 调度补验复用相同应用代码树的完整运行，使用独立并发组，不中断正在进行的完整回归。

## v0.2.1 内网升级，2026-10-21

[BuildWorld 构建 995，#5](http://192.168.110.42:8080/builds/995) 以 96.79 秒通过 6/6 阶段，包含 26/26 项原生 macOS 部署用例。官方 darwin/arm64 安装包标识源码 `c56eeeef0f3eb7768b9633232813337a41921b7a`，固定 SHA-256 为 `f0feb667fc3198994089c78b5eb78a70b29ed3b1968304f5528490db55113223`；部署仓库 commit 为 `9613c922ed9cc2f44da2b49c0f8e7a84779869ba`。

程序仅激活一次。Edge 确认既有默认管理员登录、新增真实 Web SSH 会话返回 Linux 和 UID 0，以及 CPU/内存/磁盘/网络指标。有序重启一次后，原有 1 个资产、2 条会话审计、新会话审计和 Vault key 均保留；保存的 SSH 凭据重连成功，默认管理员再次登录成功。没有重置密码。访问：[内网服务](http://192.168.110.42:8180/)。

精简回执和脱敏截图保留在忽略目录 `.cache/qa-reports/maintenance-v021/acceptance.json`。临时本地/Mac 程序、传输归档、旧版归档缓存和自有测试资源已清理。保留已验证的当前归档缓存、当前/前一版正式目录及必要的停止写入快照，用于维护和恢复。

## 发布后 race 发现与制品边界

完整 CI 在原生 Playbook 快照读取发现运行时竞态：JSON 解码复用控制器的 `LoopValues` 底层数组，调度线程同时读取。commit `f9b042a17142c2aef402f5f4976a1bf33cc7f12f` 改为向全新存储解码，并增加所有权、嵌套值隔离、nil/空值及并发读取用例。新所有权用例对原 v0.2.1 源码确定性失败；修复后的 operations/API Playbook 用例已在本地重复三次通过。[Linux 修复 CI 39578766877](https://github.com/neko233-com/jumpserver233/actions/runs/39578766877) 已通过 operations/API 全包三轮、既有完整并发状态 race 选集及 auth、vet、构建。[外部网关 CI 39577385755](https://github.com/neko233-com/jumpserver233/actions/runs/39577385755) 三组全部通过。先前完整运行的功能测试、生产浏览器和 Docker 已通过，race 失败作为发现证据保留；此后运行时仅修改快照复制，并完成上述针对性补验，web 树不变。

该运行时修复**不包含在已发布的不可变 v0.2.1 制品**。v0.2.1 唯一一次内网升级、默认登录、SSH、监控和原数据保留的验收仍成立；未二次部署，也未替换 Release 制品。稳定版最终闭环仍需要决定修复后服务的版本，此交付门槛保持未完成。
