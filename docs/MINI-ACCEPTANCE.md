# mini SSH 稳定版验收

> 中文 | [English](./MINI-ACCEPTANCE.en.md)

## 结论与源码

2026-10-21：按用户确认的中小公司单机 mini SSH 范围完成统一验收，S01–S12 **12/12，100%，本批 +3**。竞品只作参考；原 42 组清单保留研究状态，不获得新增验收分数。

- 完整后端和生产浏览器主体：`a87184611e832f3007f0df587201391d6f9a5185`。本批最终后端树 `69cec02b69ea4406caaac23c0a20cf48ba4c3263` 与该测试源码相同。
- 紧凑控制台布局专项：`d97c729cfadf0f31a68d6c7a090e8312ca12db4e`；随后补齐目录输入可访问名称。
- 完整原生安装/更新及中英浏览器：`79fbd258d67fb37844710229dddd99c5ea0a7c79`，启动时工作区干净，结束时 SHA/工作区未变。后续仅为验收文档，不用文档提交冒充运行源码。

## 统一结果

| 检查 | 结果 | 证据与覆盖 |
|---|---|---|
| 完整 Go/Testify | 2037 通过、133 跳过 | `mini-core-edfe5f3f78/go-final2-summary.json`；完整模块及固定驱动包，保留逐项终态，原始流已压缩为摘要 |
| Linux race | 195 通过、4 跳过 | `mini-race-final-edfe5f3f78/linux-race.json`；历史、作业、计划、网关、工作区、原生辅助及维护路径 |
| 生产浏览器 | 55/55 | `browser-1792534422417/summary.json`；真实 OpenSSH、原生插件/systemd、授权、审计、监控、轮换及更新 |
| 控制台修复 | 1 专项通过 | `browser-1792535575222/summary.json`；1600/1440/1280/900/715/375px × 中英，主机监控与表内操作，搜索/键盘/移动导航 |
| 原生完整入口 | 通过 | `mini-native-final84/native-packages.json`；六平台包、实际 Windows CLI、Linux 同端口/真实 SSH/SFTP、目录、审批、升级与恢复 |
| 隔离 Docker 浏览器 | 通过 | Docker 项目 `jms233-qa-1a046c5f-f035-47a7-b2f3-6bf0d9b278b5`；构建 48.99s、启动 12.19s、业务 smoke 9.37s，双语及重复清理 |
| QA 工具 / 发布工具 / macOS 流水线 | 53 / 2 / 8 通过 | macOS 流水线另有 2 个平台条件跳过；没有运行内网发布 |
| vet、构建、双语内容 | 通过 | lint 无错误，历史模块 5 条既有警告；无新增运行时前端依赖 |

以上报告名相对本机忽略目录 `.cache/qa-reports/`；Docker 摘要位于 `.cache/docker-qa/项目名/summary.json`。没有将本机原始日志、凭据或测试数据提交到仓库。

## 具名验收与限制

S01 单进程 Go + 静态资源 + 数据目录，无强制外部数据库/Redis/Node/Docker；S02–S05 真实 Web/CLI SSH、固定主机密钥、权限撤销、SFTP、审计/回放/监看、敏感命令拒绝/复核；S06 CPU/内存/磁盘/网络、历史/告警；S07 原生 Agent 与 banhack233/node_exporter 检测、安装、恢复、升级/回滚；S08 七天改密/密钥轮换、检查、重试及恢复；S09 停机加密整站备份/导入，含未 checkpoint 的 SQLite WAL 提交；S10 全部受控入口目录；S11 更新保数与版本边界；S12 中英 UI、体积与交付。具体条目见 [PROGRESS](./PROGRESS.md)。

已验证精确/目录树/整路径正则、真实内核 cwd、每个 Playbook 步骤、模板快照、幂等请求、修订冲突、一次性审批拒绝重放、软链接/目录替换拒绝。任意 shell 内部语义不等于文件 ACL；需配合远端账号权限。[目录边界](./INTERACTIVE-DIRECTORIES.md)仍适用。

当前 Jobs 写 v7/读 v1–v7，Operations 写 v6/读 v1–v6，SQLite 历史格式 1。已验未来格式拒绝、逐条历史预检、完整快照、试运行失败回滚、放行后新写入保留及向前恢复。重启后需重新登录，业务数据保留。首个正式稳定版建立支持线；此前 GitHub 正式 Release 列表为空，合成 `v0.0.x` 演练不作为历史正式发布迁移证据。详见[升级兼容](./UPGRADE-COMPATIBILITY.md)。

macOS/ARM 六平台制品通过交叉构建、归档与摘要检查；实际原机执行仅 Windows amd64 CLI 与 Linux amd64。`Jenkinsfile_mac_single` 已提供并通过状态机用例，没有部署内网。可选外部集成跳过、在线热备、生产多活和企业功能全对齐不在当前验收承诺中。

## 性能与清理

总 JavaScript 1,841,868 → **1,641,574 bytes（约 -11%）**；首屏 495,091（gzip 159,909），最大 chunk 478,952，原预算未放宽。Vite 实际构建 176ms，含类型检查和预算的 `pnpm build` 约 1.3s；这是当前机器缓存环境结果，不是通用硬件保证。

原生、race、浏览器和 Docker 均使用归属标识及隔离临时数据。完成后删除自有容器/卷/网络、临时包和可归属缓存，重复清理通过；必要摘要及每批最多两张截图按留存入口整理。失败和中断回执保留，不把重试改写成初次成功。不清理其他项目资源；`.gitignore`/`.dockerignore` 排除运行数据、测试输出及编辑残留。
