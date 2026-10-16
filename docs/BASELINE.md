# JumpServer 社区版功能基线（调研记录）

> 中文 | [English](./BASELINE.en.md)

本文档是 jumpserver233 的需求来源快照，调研日期 2026-10-14。信息来源：github.com/jumpserver/jumpserver README 与 org 仓库、官方文档 docs.fit2cloud.com（v5）、jumpserver.org/features.html 版本对比页、lina 前端路由源码、jumpserver 后端 apps/ 目录。

## 1. 官方架构组件

| 组件 | 语言 | 职责 | 协议 |
|---|---|---|---|
| JumpServer Core | Python (Django) | 平台核心：用户/权限/资产/审计/API/调度 | REST /api/v1、WebSocket 网关 |
| Lina | Vue | 管理控制台 Web UI | HTTP |
| Luna | TypeScript | Web 工作台、Web 终端、文件管理器、录像回放 | WebSocket、HTTP |
| KoKo | Go | 通用字符协议连接器：SSH/Telnet/K8s/SFTP/数据库字符协议 | SSH/Telnet/K8s exec/SFTP/DB |
| Chen | Java | Web 数据库连接器（Web GUI） | MySQL/MariaDB/PostgreSQL 等 |
| Kael | Go | AI 组件 | OpenAI 兼容 API |
| Tinker | — | Windows 应用连接器（社区版免费） | RDP/应用发布 |
| Video Worker | — | 录像转码（Razor/Lion 录像 → MP4） | — |

注意：

- v5 中 Lion（RDP/VNC）功能已并入 KoKo，不再独立部署
- rufus、koala 不属于 JumpServer org，勿纳入基线
- 许可证 GPL-3.0，版权 FIT2CLOUD/飞致云

## 2. 后端 app 划分（Django apps/）

users、orgs、rbac、assets、accounts、acls、perms、terminal、audits、authentication、settings、ops、notifications、tickets、labels、reports、chat_ai、common。

## 3. 前端三视图（lina 路由实证）

- `/console` 控制台（管理员）
- `/audit` 审计台（审计员）
- `/workbench` 工作台（普通用户）
- `/settings` 系统设置、`/profile` 个人设置
- 权限用 Django permission 字符串（如 `assets.view_asset`）逐路由控制
- 企业版路由带 `licenseRequired: true`

### 3.1 控制台

- 仪表盘：资产/会话/用户统计
- 用户管理：用户列表（创建/详情/导入，密码邮件重置或直接设置）、用户组
- 资产管理：资产列表（统一 + 平台 Tab：Linux/Windows 主机、数据库、网络设备、云、Web、GPT、自定义）、平台列表（协议/账号发现参数）、**节点树**（`/Default` 根节点）、**网域 Zone + 网关 Gateway**、连通性测试
- 账号管理：账号列表（密码/密钥密文）、账号模板、虚拟账号
- 授权管理：资产授权规则（用户+组 × 资产+节点 × 账号 × 动作，节点继承、时间限制）、会话分享
- ACL：命令过滤（CommandFilterACL + 命令组）为社区版
- 标签、PAM（部分 X-Pack，见排除项）

### 3.2 系统设置

- 基本设置；组织管理/角色列表（X-Pack）
- AI 助手（ChatAI：内置 API/iframe、连通测试）
- 通知：邮件（SMTP/SSL/TLS/模板）、短信（基础）、消息订阅（站内信+邮件）
- 功能设置：公告、工单（1–5 级审批、审批人属性筛选、抄送）、作业中心（批量命令开关+黑名单）、账号存储（Vault，X-Pack 存疑）、SSH 证书签发（OpenBao）
- 认证设置：LDAP/LDAP-HA、CAS、RADIUS、OAuth2、OIDC、SAML2、SSO、Passkey、MFA 配置（backends 目录实证：ldap、cas、radius、oauth2、oidc、saml2、passkey、pubkey、token、sso、ukey）
- 存储设置：命令存储、录像存储（DB / S3 / OSS / COS / OBS / SFTP）
- 组件设置：组件（Terminal 端点）状态、Endpoint/EndpointRule、Applet/VirtualApp/AppProvider
- 安全设置：认证安全（验证码、附加码、闲置禁用、异地通知、**全局 MFA 策略：禁用/全员/仅管理员**、MFA 有效期、OTP 参数）、登录限制（失败锁定用户/IP、IP 黑白名单、单设备登录）、密码策略（过期、近 N 次不重复、长度、字符集）、会话安全（**水印**、会话分享、关浏览器过期、空闲/最大时长）
- 系统工具、系统任务列表、License 导入

### 3.3 审计台

仪表盘；会话审计（在线/历史、详情、实时监控与中断、命令记录、文件传输记录、在线用户）；日志审计（登录/操作/改密/AI 对话）；作业日志；工单审计；报表（X-Pack）。

### 3.4 工作台

概览；我的资产（连接列表、Web SFTP 文件管理器、个人凭据）；作业中心（快捷命令、作业/模板管理、执行历史，需 SECURITY_COMMAND_EXECUTION 开关）；**Web 终端**（xterm.js：连接选择、文件传输侧栏、脚本库、AI 助手、终端设置）；组织切换、全局搜索、系统消息、日常工单、语言切换。

### 3.5 个人设置

资料、密码与 SSH 密钥、Passkey、AccessKey（API 签名）、临时令牌、连接令牌、OAuth2 AccessToken、偏好、**MFA 绑定（OTP）**。

## 4. API 特征（外部兼容关键面）

1. REST API v1 + Swagger `/api/docs/`
2. 认证 4 种：
   - Session cookie `jms_sessionid`
   - 一次性 Token：`POST /api/v1/authentication/auth/` {username,password} → `token`，`Authorization: Bearer <token>`
   - Private Token（永久）：`Authorization: Token xxx`
   - Access Key/Secret：HTTP Signature（hmac-sha256 对 (request-target)/date 签名）
3. 多租户头 `X-JMS-ORG`
4. MFA 流程：密码 → OTP/短信/第三方；用户侧绑定 API；全局策略强制；查看密码触发 MFA 后有效期内免重复
5. 会话 WebSocket：`/ws/` 系列，二进制帧承载终端 I/O（xterm.js ↔ 连接器），resize/剪贴板/文件传输消息；录像 `replay.json.gz`（asciinema 兼容）可转 MP4
6. 组件通信：Terminal 组件经 bootstrap_token 向 Core 注册，上报会话/命令/录像

## 5. X-Pack 企业版清单（Phase 7+ 竞品对齐范围，非永久排除）

竞品 = JumpServer 企业版（https://www.jumpserver.org/enterprise.html ）。企业版功能架构：X-Pack 增强包、原厂支持服务、应用商店。X-Pack 功能项（enterprise.html 原文）：

登录类：扫码登录（企微/钉钉/飞书）、短信 MFA（阿里云/腾讯云/华为云/CMPP）、RADIUS 二次认证、登录复核、登录时间段控制。
权限类：RBAC 角色管理页、多组织管理、全局组织；授权工单二级审批、资产登录 ACL、登录 ACL、数据脱敏、剪贴板 ACL、连接方式 ACL。
账号类：Vault 账号存储（以 license 门槛实测为准）、账号收集、批量改密、账号备份。
资产类：云资产同步（23 种）、局域网发现、虚拟应用、界面个性化（LOGO/主题）、数据库企业协议（Oracle/SQLServer/PostgreSQL/ClickHouse/DB2/达梦）、高清晰度 RDP、报表。
组件类：Magnus、Razor、Nec、Panda、JDMC、Video Worker。
其他：Web 资产脚本代填（v5 起）、应用商店高级应用；社区版资产 ≤ 5000 台。

## 6. 社区版保留核心（必须实现）

SSH/RDP(Web)/DB(MySQL/MariaDB/Redis/MongoDB)/K8s/Web 资产/远程应用(Chrome/DBeaver)、资产树+节点授权、动作/时间/协议授权、命令过滤、SFTP 文件管理、六类审计（会话/命令/文件/登录/操作/改密）+ 作业审计、录像回放与云存储、MFA(OTP)、LDAP/CAS/RADIUS/OAuth2/OIDC/SAML2/SSO/Passkey 认证、水印、会话分享、标签、作业中心、定时任务、通知（邮件/短信/站内信）、AI 助手、REST API 全量。

## 7. 复刻偏差提示

1. 官方前端 Vue + Element，本项目 React —— 技术栈替换
2. Django 单体 + 连接器 → Go 分层：Core API/RBAC/审计 与 协议代理分边界
3. 会话 WebSocket 协议、录像格式、X-JMS-ORG、4 种认证是兼容性关键面
4. Lion 已并入 KoKo（v5）；rufus/koala 不存在
