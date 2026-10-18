# Docker 隔离验证与并行调试

[English](./DOCKER-QA.en.md) | [文档索引](./README.md)

生产 API 和网页都在 Docker 中从源码构建，运行时使用独立网络、命名数据卷和本机端口。构建不读取宿主 Go、Node、`node_modules` 或已有原生组件。镜像仅保留运行程序和网页产物；API、Nginx 以普通账号运行，根文件系统只读。

## 快速验证

完整协议回归可用 `cd web && pnpm test:e2e:production`：一次生产构建后复用静态资源，启动全新临时数据和原有真实协议夹具，结束后校验归属并清理。本命令与快速 Docker 冒烟分别计时，避免每个页面触发开发模块转换；不减少测试范围。

需要 Docker Compose 和 Node 24：

```sh
node scripts/docker-qa.mjs verify
```

每次创建随机项目、空数据卷和两个空闲本机端口；验证健康、未登录拒绝、默认登录、会话身份、生产 JS、gzip 与缓存策略，结束后清理本次容器/网络/数据卷。不会复用或删除已命名的调试环境。日志保存在被忽略的 `.cache/docker-qa/`，不记录登录凭据或票据。

已有 `web` 依赖和 Playwright Chromium 时可追加真实浏览器检查：

```sh
node scripts/docker-qa.mjs verify --browser
```

浏览器同时检查中英资产页与账号风险页、按需脚本加载及页面错误；只有随机纯净卷执行一次空账号检测，核对成功回执。`up` 保留环境只读取风险页，不派发检测，避免干扰已有周期计划。风险功能的真实 SSH 改密与周期验证由完整 `pnpm test:e2e` 覆盖。

浏览器验证生产包登录、中英文切换、页面异常，以及已认证控制台不加载登录动画代码。2026-10-16 本机热缓存实测：构建 3.14 秒、独立启动 12.05 秒、HTTP/双环境浏览器检查 3.42 秒，总计约 18.6 秒。首次下载镜像和依赖另需时间。完整 SSH/数据库/真实 systemd 回归见 [测试记录](./TESTING.md)。

## 保留调试环境

```sh
node scripts/docker-qa.mjs up --project jms233-debug-a --web-port 15173 --api-port 18080 --browser
node scripts/docker-qa.mjs up --project jms233-debug-b --host 127.0.0.3 --web-port 15174 --api-port 18081
```

网页分别为 `http://127.0.0.2:15173`、`http://127.0.0.3:15174`；API 分别为 `http://127.0.0.2:18080`、`http://127.0.0.3:18081`。空用户库使用项目默认管理员；已有数据和密码不重置。每个项目的网络、镜像名和数据卷独立。端口只绑定专用回环地址（默认 `127.0.0.2`），不影响 5173 等已有开发实例。

```sh
node scripts/docker-qa.mjs down --project jms233-debug-a
```

`down` 保留数据卷。纯 Docker 入口为 `docker compose -f compose.qa.yml -p jms233-debug up --build --detach --wait`，默认网页/API 端口为 15173/18080，可用 `JMS_QA_WEB_PORT`、`JMS_QA_API_PORT` 和 `JMS_QA_HOST` 调整；不同环境使用不同回环地址以隔离 Cookie。

两套环境启动后，可在同一浏览器上下文验证登录互不覆盖：`node scripts/docker-qa.mjs up --project jms233-debug-a --browser --peer-url http://127.0.0.3:15174`。2026-10-16 已实际通过，已有环境复查约 6.5 秒。

## 缓存与边界

Go modules、Go 编译缓存、pnpm store 与 TypeScript 增量缓存由 BuildKit 管理。先复制锁文件/依赖清单，修改业务源码不会重新下载全部依赖；`.dockerignore` 排除依赖目录、生成程序、运行数据、图片文档及本地工具配置。缓存组织参考 [Docker 官方说明](https://docs.docker.com/build/cache/optimize/)。

当前验收为 Linux amd64 单机生产镜像及本机端口转发。Docker 网络中需要使用服务名或 `host.docker.internal` 访问调试目标；容器的 `127.0.0.1` 指向自身。此入口不创建协议测试主机、不代表集群 HA 或生产部署验收。默认反向代理未声明受信任来源，生产来源 IP 策略需按 [访问策略](./ACCESS-POLICIES.md) 配置实际代理。

2026-10-16 内置浏览器访问独立 Docker 端口的实际截图，空清单来自新数据卷：

![Docker 中文生产控制台](./images/docker-qa.zh-CN.png)
