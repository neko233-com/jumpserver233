# 单机维护补丁与发布验收

> 中文 | [English](./MAINTENANCE.en.md)

## 本批范围

保持 [mini SSH 范围](./PRODUCT-SCOPE.md) 的 12 项清单，补齐实际部署发现的问题。实现与用例集中编写后，已在源码 `09bb9b5fdcaf7231bb7af2aff3868f11261757d4` 完成统一验证。正式发布和新版本内网升级单独验收。mini 清单仍为 12/12，维护补丁不增加范围完成信用。

- 原生同端口支持内网 IP HTTP：Origin 的协议、Host 和端口必须与请求一致，或与显式 `JMS_PUBLIC_URL` 一致。隐式信任只允许 loopback 和内网 IP，不查询 DNS；外域、不同端口、`null` Origin 和无 Origin 的跨站浏览器请求拒绝。HTTPS 配置和原开发入口保持兼容。
- 登录区分来源拒绝、请求过多、服务不可用、网络异常与错误凭据；中文英文文案一致。先确认 HttpOnly Cookie 会话可用再进入控制台，避免 Cookie 未建立时跳转循环。不显示后端原始错误或秘密。
- macOS 发布验证根清单与嵌套 Vite 清单，正式版本必须绑定精确 commit；入口选择已安装的 Python >=3.11。升级前拒绝活动 SSH，会后核对已有资产、会话审计和 Vault key；仍由既有停止写入后的快照与回滚逻辑保护数据。
- 已部署环境继续使用其专属 HTTP 入口；新版本转发原始 Origin，由入口与原生服务分别检查。入口配置校验失败恢复旧文件，同配置重复执行保持 PID。产品默认单机使用 Go 原生静态服务，不要求 nginx。

## 统一验证

集中执行 Go/Testify、vet、前端 lint/type/build、中英生产浏览器、Python/Node 发布工具用例及隔离 Docker。重点覆盖默认管理员重启、Cookie 会话、同源/跨源、幂等、清单篡改、升级拒绝与保数。只在统一运行发现失败后修复并重跑受影响部分。

通过后由 release-please 生成补丁版本及 changelog，发布不可变六平台制品。部署仓库锁定版本、commit、大小和 SHA-256；BuildWorld 只升级一次，再验收默认登录、真实 Web SSH、CPU/内存/磁盘/网络和数据保留。清理归属测试资源、临时程序及归档，保留精简报告和最多两张必要截图。

## 已有内网基线

2026-10-21，v0.2.0 已通过 BuildWorld 项目 49 部署；构建 991 使用 `DEPLOY=false` 补验，6/6 阶段、20 项 macOS 用例、真实 SSH、监控和有序重启保数通过。程序只发布一次。详情见 [BuildWorld](./BUILDWORLD.md)。该记录是旧版基线，本批结果将在统一验证后更新。

## 统一结果，2026-10-21

- Go/Testify：2061 项通过、133 项跳过，100 个包通过；vet 通过。平台/外部集成跳过项不算已验收。
- 生产浏览器：69/69，含新增 14 项中英登录失败用例，共 17.7 分钟。完整套件含真实原生 Agent 重启、防火墙修复和 systemd 监管。
- 发布/QA Node 工具：77/77。源码 Python：11 项，Windows 符号链接权限跳过 2 项。部署 Python：macOS 原机 26/26，无跳过。
- 六平台原生包通过；Windows CLI、真实 Linux SSH/SFTP、受控安装/回滚、加密、备份恢复、密码检查和目录策略通过。原生测试归属资源已幂等清理。
- 纯净 Docker 浏览器通过并清理资源。前端 lint/type/build、双语和来源检查通过；历史 UI 模块保留 5 条既有警告。
- 首屏 JavaScript 496024 bytes、gzip 160149；总 JavaScript 1642958 bytes，既有预算通过，未新增运行依赖。

报告保存在忽略目录 `.cache/qa-reports/maintenance-v021/`、`maintenance-v021-native/` 及对应浏览器/Docker 批次。验证期间产品代码未改变；后续仅发布元数据和证据文档推进 HEAD，不改变已验证 server/web 树。
