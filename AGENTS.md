# AGENTS.md — Instructions for AI agents

> English | [中文](./AGENTS.zh.md)

Instructions for any AI agent working in this repository. Organization follows deepseek-harness's AGENTS.md conventions (layered docs, `docs/` index, one file per concern); wording follows the GPT-6 "Using GPT-6" prompt guidance (developers.openai.com/api/docs/guides/latest-model/gpt-6-astra.md).

## 1. Instruction priority

1. Explicit instructions from the user in the current conversation.
2. This file (AGENTS.md / AGENTS.zh.md).
3. Per-directory instructions in nested AGENTS.md files, if any.
4. General defaults (idiomatic code, minimal scope).

If a doc conflicts with a user instruction, follow the user and say so. If a doc makes you pause, name the file and the exact sentence you are acting on.

## 2. Project

jumpserver233 reimplements JumpServer in Go + React. The competitor is JumpServer Enterprise; the roadmap is phased (Community first, X-Pack parity later).

- Scope and roadmap: [docs/PLAN.md](./docs/PLAN.md) — authoritative for scope disputes
- Feature baseline: [docs/BASELINE.md](./docs/BASELINE.md) — research snapshot of upstream JumpServer
- Docs index: [docs/README.md](./docs/README.md)

Every `.md` ships a Chinese and an English version linked at the top (`X.md` ↔ `X.en.md`). Update both when you change either.

## 3. Repository layout

```
server/   Go module — Core API + WebSocket gateway + connector boundary
web/      Vite 8 + React 19 frontend (reactbits, WebGL shaders, i18n)
docs/     PLAN / BASELINE / conventions (bilingual)
```

Key compatibility surfaces that must not change casually (see PLAN §3.1): the four REST auth methods, the `X-JMS-ORG` header, the session WebSocket frame protocol, asciinema-compatible `replay.json.gz`, and the MFA flow.

## 4. Commands

Before direct backend tests/builds/run, use `cd server && go generate ./internal/agentbundle` to embed the native Linux recovery helpers. Make targets, CI and `pnpm test:e2e` prepare them automatically; do not hand-edit generated executables or manifests.

| Task | Command |
|---|---|
| Backend tests | `cd server && go test -timeout 20m ./... github.com/microsoft/go-mssqldb` |
| Backend static check | `cd server && go vet ./... github.com/microsoft/go-mssqldb` |
| Backend run | `cd server && go run ./cmd/server` (listens on `:8080`) |
| Frontend build + type check | `cd web && pnpm build` |
| Frontend lint | `cd web && pnpm lint` (Vite+ / oxlint, scoped to `src`) |
| Browser end-to-end | `cd web && pnpm test:e2e` (Playwright starts isolated API/UI instances and uses temporary data) |
| Production frontend end-to-end | `cd web && pnpm test:e2e:production` (one static build, same complete suite and isolated fixtures) |
| Frontend format | `cd web && pnpm format` |
| Full verification | `make verify` (Go tests, Playwright, vet, lint, and production builds) |
| Fast clean Docker smoke | `node scripts/docker-qa.mjs verify` (add `--browser` with installed Playwright Chromium) |
| Frontend dev | `cd web && pnpm dev` (proxies `/api`, `/ws` to `:8080`) |

A phase is done only when tests, lint and build all pass and the feature works in the UI.

Author the complete batch before unified verification. Cover idempotent retries, revision conflicts and one-time capability replay. After every run keep compact reports, essential screenshots and sanitized failure diagnostics; remove owned test data, containers, volumes, temporary executables, unused QA images and attributable test caches. Repeating cleanup must be safe. Do not retain debug stacks unless explicitly requested, and never prune another project's resources. See [Docker QA](./docs/DOCKER-QA.en.md).

## 5. Conventions

**Go (server/)**
- Go 1.27, module `github.com/neko233-com/jumpserver233/server`, stdlib-first; add a dependency only after checking it is actually needed.
- Routes live under `/api/v1` in JumpServer resource-path style; handlers stay thin, business logic goes into `internal/core`.
- Structure before cleverness: `cmd/`, `internal/api`, `internal/core`, `internal/connector`. Protocol code goes behind the connector interface — never wire a protocol directly into handlers.

**Frontend (web/)**
- TypeScript strict; no hardcoded user-facing strings — every string goes through `t('key')` with both `zh-CN` and `en` entries in `src/i18n/locales/`.
- New reactbits components install via `npx shadcn@latest add "@react-bits/<Name>-TS-CSS"` then move the file from `@/components/` (literal path) to `src/components/` and add its dependencies.
- Shader backgrounds use `ogl` (see `src/components/ShaderCanvas.tsx`) for consistency.
- Lint/format run through Vite+ (`vp`); keep lint scoped to `src vite.config.ts` so `node_modules`/`dist` are excluded.

**Docs**
- Bilingual pairs with top-of-file cross-links; keep them in sync.
- Plain language: state the point first, concrete over abstract, no filler ("in short", "it's worth noting", contrastive "X, not Y").

**Git**
- Conventional Commits (`feat:`, `fix:`, `docs:`, `chore:` …), Chinese or English both fine.
- Never hand-edit `CHANGELOG.md`; it is generated only at release time by release-please.

## 6. Roadmap discipline

- Work one phase at a time; update the status column in docs/PLAN.md when a phase lands.
- Stay inside the current phase's scope; enterprise (X-Pack) features wait for Phase 7 unless the user says otherwise.
- When the task is unclear, ask one focused question rather than guessing on scope-affecting choices.
