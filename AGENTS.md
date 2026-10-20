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

jumpserver233 is an independent mini SSH bastion in Go + React for small and medium businesses. Standalone deployment, few runtime dependencies, usability, security and maintenance are the product goals. JumpServer Enterprise is a reference, not a parity requirement. The user's 2026-10-21 correction supersedes the earlier full-Enterprise scope.

- Product scope: [docs/PRODUCT-SCOPE.en.md](./docs/PRODUCT-SCOPE.en.md) — authoritative for scope disputes
- Roadmap: [docs/PLAN.md](./docs/PLAN.md)
- Feature baseline: [docs/BASELINE.md](./docs/BASELINE.md) — research snapshot of upstream JumpServer
- Delivery counts and remaining gaps: [docs/PROGRESS.en.md](./docs/PROGRESS.en.md)
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

Put generated evidence in ignored `.cache/qa-reports/`; put reusable QA entrypoints in `scripts/`. Browser and Docker runners automatically retain three successful, cleaned disposable runs with at most two screenshots each; failed summaries and necessary diagnostics do not expire. Completed, cleaned native package/race batches are also compacted automatically, including historical batches with valid runner receipts. Successful batches discard raw traces, videos, archives, temporary scripts/programs, dead PID files and known browser sidecars; live or unreadable PID files protect their batch. Active processes, failed diagnostics and incomplete cleanup are protected. Use `make qa-preview` / `make qa-clean` (or `cd web && pnpm qa:preview` / `pnpm qa:clean`) for old named reports without runner receipts and known, closed ad hoc helpers, including the explicit web/.cache QA-config allowlist. Docker resource preview writes no report; old read-only snapshots and successful applied no-op receipts are each capped at three. Mutating, failed, unfamiliar and recovery receipts remain. Successful named feature screenshots are capped across the latest three eligible batches (two per batch); cleaned Docker screenshot histories share their own three-batch cap, including named previews. Older named JSON reports remain. Browser tool session directories, root/web screenshot exports, root/web/server JUnit reports, local CLI binaries and merge leftovers are ignored by Git and Docker. Read current source and final summaries first; ignored historical diagnostics are not implementation authority. Search ignored evidence only for a specific unresolved question. Preserve referenced `docs/images/` assets.

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

- The current primary checklist is the 12-item mini SSH release in PROGRESS. The user's 2026-10-21 correction replaces the former 42-group Enterprise objective; preserve that table as historical research, not a completion gate. Report accepted/total, readiness, named gaps and the verified source separately; a scope change grants no completion credit.
- Author the necessary mini stable-release batch, cases and bilingual docs before unified tests, builds, browser and Docker verification. Do not wait for deferred Enterprise modules. After the unified run repair failures and rerun affected checks; expand regression for shared-path impact or unresolved failures.
- Work one phase at a time; update the status column in docs/PLAN.md when a phase lands.
- Do not add cloud vendors, protocols, app markets, face recognition, external runtimes or complex enterprise integrations merely to match the competitor. Require an explicit product use case; keep standalone operation free of external service dependencies.
- When the task is unclear, ask one focused question rather than guessing on scope-affecting choices.

## 7. Project UI skill

For UI design or visual improvements, read the project-local [oil-ui skill](./.agents/skills/oil-ui/SKILL.md), installed from `oil-oil/dsh-oil-ui`. Installation, pinned provenance and the console direction are documented in [UI design](./docs/UI-DESIGN.en.md).

- Reuse the existing compact operational console, brand variables and bilingual components. The user's SSH reference establishes the current direction; routine refinement does not require another style-selection round.
- The upstream skill mentions DeepSeek Harness tools (`oil_ui_*`); this Codex project uses its available file tools, image viewer and browser tools instead. Do not claim unavailable plugin tools are installed or launch another harness.
- User instructions and the full-batch verification gate in section 6 take precedence over the skill's per-page review cadence. Author UI cases now; run browser checks with the unified verification batch. Put evidence in ignored `.cache/qa-reports/`.
- Keep vendored skill files and licenses intact. Project-owned guidance remains bilingual; upstream skill documentation retains its original language and hashes. Update the pinned source only on explicit request.
