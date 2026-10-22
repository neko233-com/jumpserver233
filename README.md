# jumpserver233

> 中文 | [English](./README.en.md)

面向中小公司的独立 mini SSH 跳板机：**单机、少依赖、好用、好维护、安全高效**。Go + React，默认运行不需要外部数据库、Redis、常驻 Node、Docker 或云账号。

[JumpServer 企业版](https://www.jumpserver.org/enterprise.html)是参考产品。当前范围以[产品定位](./docs/PRODUCT-SCOPE.md)为准，不追求竞品全功能覆盖。

## 核心能力

- **SSH 运维**：主机与多账号管理、分组搜索、Web SSH、原生 SSH/SFTP 2222、平台身份 CLI/Agent CLI 和固定主机密钥；操作者无需拿到目标密码。
- **安全管控**：用户/角色/资产授权、在线撤权、录像和命令/文件审计、敏感参数脱敏、危险命令拒绝/审核及受控目录规则。
- **主机状态**：CPU、内存、磁盘、网络、在线情况、必要历史和告警。
- **账号维护**：SSH 密码/密钥七天轮换、连接检测、逐项重试和恢复；原生 Agent 与远程工具按需安装。
- **更新与恢复**：检查更新、受控安装/回滚、加密整站导出/导入、幂等恢复，保留资产、凭据、权限和审计。

当前稳定版 **v0.3.1**：mini 清单 **12/12**，原生 SSH/SFTP 与 XTerminal 监控兼容修复已单次升级内网，真实 SSH、文件往返和重启保数通过。[新表格工作台](./docs/NATIVE-SSH.md)按用户视觉反馈继续维护，尚未发布；证据与支持边界见[当前进度](./docs/PROGRESS.md)。

## 单机部署

Go 服务通过 `JMS_WEB_DIR` 在同一端口提供静态网页、API 和 WebSocket；`JMS_DATA_DIR` 保留本地数据及 Vault key。本批执行历史使用内置 SQLite，不新增数据库服务。安装和升级步骤见[单机安装](./docs/INSTALLATION.md)，备份恢复见[BACKUP](./docs/BACKUP.md)。

首次空用户库使用默认管理员 `root / root`，已有账号不会被覆盖；在个人设置修改。自定义初始化见[本地认证](./docs/AUTH.md)。

PostgreSQL 主备、云同步、复杂身份集成、更多协议和企业工具属于已有可选扩展，不是 mini 部署前置条件；本轮不继续扩展。详细边界保留在[文档索引](./docs/README.md)。

## 本地开发

后端默认监听 `127.0.0.1:8080`：

```bash
cd server
go generate ./internal/agentbundle
go run ./cmd/server
```

前端默认 `http://127.0.0.1:5173`，代理 API/WebSocket：

```bash
cd web
pnpm install
pnpm dev
```

生产环境只需构建后的静态资源和 Go 服务；Node/pnpm 用于开发构建。统一验证入口见 [AGENTS](./AGENTS.zh.md) 和[测试说明](./docs/TESTING.md)。先完成 mini 必要实现，再统一验证、修复与幂等清理。

## 界面与维护

中文/英文随浏览器语言自动识别，可手动切换；文档保持中英互链。主界面围绕主机连接、监控、审计、权限和维护展开，低频本地控制项收进“更多功能”。项目级 [oil-ui](./docs/UI-DESIGN.md) 用于 UI 打磨，不增加运行时依赖。

![主机清单与 SSH 监控](./docs/images/inventory.zh-CN.png)

采用 Conventional Commits；`CHANGELOG.md` **只在正式 release 时**由 release-please 生成。当前不部署内网，稳定版门槛满足后再发布一次。

目录：`server/` Go 后端，`web/` React 前端，`docs/` 双语文档，`scripts/` 构建与 QA 工具。

mini 固定清单：[12/12 验收及边界](./docs/MINI-ACCEPTANCE.md)。默认 macOS 单机流水线：[Jenkinsfile_mac_single](./Jenkinsfile_mac_single)，[部署说明](./docs/BUILDWORLD.md)。
