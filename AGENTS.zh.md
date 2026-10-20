# AGENTS.md — AI agent 工作约定

> [English](./AGENTS.md) | 中文

写给在本仓库工作的所有 AI agent。组织方式参考 deepseek-harness 的 AGENTS.md 约定（分层文档、`docs/` 索引、一事一文件）；措辞遵循 GPT-6《Using GPT-6》提示规范（developers.openai.com/api/docs/guides/latest-model/gpt-6-astra.md）。

## 1. 指令优先级

1. 当前对话中用户的明确指令。
2. 本文件（AGENTS.md / AGENTS.zh.md）。
3. 子目录中的嵌套 AGENTS.md（如有）。
4. 通用默认（惯用写法、最小改动范围）。

文档与用户指令冲突时，以用户为准并说明。如果某条文档让你停下来，直接说出它所在的文件和原句。

## 2. 项目

jumpserver233 用 Go + React 复刻 JumpServer。竞品是 JumpServer 企业版；路线分阶段（先社区版，后 X-Pack 对齐）。

- 范围与路线：[docs/PLAN.md](./docs/PLAN.md) —— 范围争议以此为准
- 功能基线：[docs/BASELINE.md](./docs/BASELINE.md) —— 上游 JumpServer 调研快照
- 交付计数与剩余缺口：[docs/PROGRESS.md](./docs/PROGRESS.md)
- 文档索引：[docs/README.md](./docs/README.md)

每个 `.md` 都有中英两版并在顶部互链（`X.md` ↔ `X.en.md`），改一处必须同步另一处。

## 3. 仓库结构

```
server/   Go 模块 —— Core API + WebSocket 网关 + 连接器边界
web/      Vite 8 + React 19 前端（reactbits、WebGL shaders、i18n）
docs/     PLAN / BASELINE / 约定（中英双语）
```

不可随意更改的兼容面（见 PLAN §3.1）：四种 REST 认证方式、`X-JMS-ORG` 头、会话 WebSocket 帧协议、asciinema 兼容 `replay.json.gz`、MFA 流程。

## 4. 命令

直接运行后端测试、构建或服务前，先执行 `cd server && go generate ./internal/agentbundle`，嵌入原生 Linux 恢复组件。Make 目标、CI 与 `pnpm test:e2e` 自动准备；不要手改生成的程序或清单。

| 任务 | 命令 |
|---|---|
| 后端测试 | `cd server && go test -timeout 20m ./... github.com/microsoft/go-mssqldb` |
| 后端静态检查 | `cd server && go vet ./... github.com/microsoft/go-mssqldb` |
| 后端运行 | `cd server && go run ./cmd/server`（监听 `:8080`） |
| 前端构建 + 类型检查 | `cd web && pnpm build` |
| 前端 lint | `cd web && pnpm lint`（Vite+ / oxlint，限定 `src`） |
| 浏览器端到端 | `cd web && pnpm test:e2e`（Playwright 启动隔离 API/UI 实例并使用临时数据） |
| 生产前端端到端 | `cd web && pnpm test:e2e:production`（一次静态构建，完整套件与相同隔离夹具） |
| 前端格式化 | `cd web && pnpm format` |
| 完整验证 | `make verify`（Go 测试、Playwright、vet、lint 与生产构建） |
| Docker 纯净快速检查 | `node scripts/docker-qa.mjs verify`（已有 Playwright Chromium 时加 `--browser`） |
| 前端开发 | `cd web && pnpm dev`（`/api`、`/ws` 代理到 `:8080`） |

阶段完成标准：测试、lint、构建全部通过，且功能在 UI 里能走通。

测试前集中完成整批实现和用例，再统一验证。覆盖幂等重试、修订冲突和一次性能力重放。每轮只保留必要摘要、关键截图及脱敏失败诊断；清理自有测试数据、容器、卷、临时程序、无引用 QA 镜像和可确认归属的测试缓存。重复清理必须安全；只有用户明确要求才保留调试实例，不得全局清理其他项目资源。详见 [Docker 验证](./docs/DOCKER-QA.md)。

## 5. 约定

生成的验证证据统一放在忽略的 `.cache/qa-reports/`，可复用 QA 入口放在 `scripts/`。浏览器与 Docker runner 自动保留最近三次成功且清理完成的独立验证，每次最多两张截图；失败摘要与必要诊断不过期。原生包/race 的已完成且清理成功批次也自动精简，包括有有效 runner 回执的历史批次。成功批次删除原始 trace、视频、归档、临时脚本/程序、已退出进程的 PID 文件及已知浏览器附属文件；PID 活动或无法读取时保护整个批次。活动进程、失败诊断及未完成清理受保护。没有 runner 回执的旧专题报告和已结束的已知临时脚本（含 web/.cache QA 配置白名单）使用 `make qa-preview` / `make qa-clean`（或 `cd web && pnpm qa:preview` / `pnpm qa:clean`）。Docker 资源预览不写报告，旧只读快照和成功的零变更执行回执分别最多保留三份；实际变更、失败、未知格式及恢复所需回执继续保留。成功专题截图合计只保留最近三个符合清理条件的批次，每批最多两张；已清理的 Docker 截图也共用三个批次的限额，包含具名预览。较早专题的 JSON 报告保留。Git 和 Docker 忽略浏览器工具会话目录、根目录/web 散落截图、根目录/web/server 的 JUnit 报告、本地 CLI 程序及合并残留。Agent 优先读取当前源码与最终摘要，不把忽略目录里的历史诊断当作实现依据；只有具体未解问题才搜索忽略证据。保留被引用的 `docs/images/` 资源。

**Go（server/）**
- Go 1.27，模块 `github.com/neko233-com/jumpserver233/server`，优先标准库；依赖确有必要才引入。
- 路由按 JumpServer 资源路径风格挂在 `/api/v1` 下；handler 保持薄，业务逻辑进 `internal/core`。
- 结构优先于技巧：`cmd/`、`internal/api`、`internal/core`、`internal/connector`。协议代码走 connector 接口，禁止把协议直接写进 handler。

**前端（web/）**
- TypeScript strict；禁止硬编码用户可见文案 —— 所有文案走 `t('key')`，`src/i18n/locales/` 中英两份必须同时存在。
- 新增 reactbits 组件用 `npx shadcn@latest add "@react-bits/<Name>-TS-CSS"`，然后把文件从 `@/components/`（字面路径）移到 `src/components/`，并补齐它的依赖。
- shader 背景统一用 `ogl`（见 `src/components/ShaderCanvas.tsx`）。
- lint/format 走 Vite+（`vp`）；lint 限定 `src vite.config.ts`，排除 `node_modules`/`dist`。

**文档**
- 中英成对、顶部互链，保持同步。
- 平实表达：结论先行、具体优于抽象、不写车轱辘话（"综上"、"值得注意的是"、"不是 X 而是 Y" 这类）。

**Git**
- Conventional Commits（`feat:`、`fix:`、`docs:`、`chore:` …），中英文皆可。
- 不要手改 `CHANGELOG.md`；它只在 release 时由 release-please 生成。

## 6. 路线纪律

- 分开统计 SSH 稳定版与完整企业版。每次交付更新中英 PROGRESS，并报告已闭环/总项数、比例、本次增量、剩余具名缺口、已验证源码与未验证改动。部分实现或未经验证不计为闭环；变更清单分母必须注明明确需求来源及前后数量。
- 用户 2026-10-20 明确要求以 PROGRESS 全部 42 组为实现门禁：缺失功能、用例和中英说明全部写完后，才运行测试、构建、浏览器或 Docker 验证；SSH 小批次完成不能开启该门禁。分开报告实现就绪和验收完成，写好测试不表示允许提前执行。统一验证后修复失败并复验受影响项，共享路径影响或未解失败才扩大回归。
- 一次只推进一个阶段；阶段落地后更新 docs/PLAN.md 的状态列。
- 留在当前阶段范围内；企业版（X-Pack）功能等 Phase 7，除非用户另有指示。
- 需求不清时问一个聚焦的问题，不要在影响范围的选择上擅自猜测。
