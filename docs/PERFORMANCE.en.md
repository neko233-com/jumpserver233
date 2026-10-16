# Performance and packaging baseline

[中文](./PERFORMANCE.md) | [Documentation](./README.en.md)

Local production build measurements on 2026-10-16:

| Metric | Before | After |
|---|---:|---:|
| Main JavaScript entry | 628.26 kB | 442.11 kB (about 29.6% smaller) |
| Main entry gzip | 200.51 kB | 142.26 kB (about 29.1% smaller) |
| Windows server executable | 51,472,896 bytes | 38,855,168 bytes (about 24.5% smaller) |

Login is a separate lazy route. Motion uses `LazyMotion`, `domAnimation` and the smaller `m` component while preserving existing animation. Authenticated consoles do not download login animation code. JavaScript across all routes totals 1,187,416 bytes; the initial graph including shared dependencies is 459,455 bytes, with 148,477 gzip bytes. The entry alone is not the complete download size.

`pnpm build` retains strict type checks. TypeScript and E2E use separate incremental caches under `node_modules/.cache/`. Local Vite bundling took approximately 160–253 ms; the complete command also includes type checking and budget verification. These warm-cache observations do not describe cold builds or other machines.

Builds run `scripts/check-web-bundle.mjs`, enforcing 500,000 bytes for each JS chunk and the complete initial static graph, 1,500,000 bytes for all JavaScript, and a lazy login route. The default Vite chunk warning limit is unchanged. Terminals, protocol dialogs and administration pages remain loaded on demand.

`make build` produces the server, platform CLI and web application. Go delivery binaries use `-trimpath -ldflags="-s -w"`. The native Linux generator reuses verified artifacts when the source digest is unchanged. [Docker verification](./DOCKER-QA.en.md) also reuses Go/pnpm/TypeScript caches. Builds with different cache states were not used to claim a speed improvement.

`.gitignore` excludes dependencies, build/test output, incremental caches, environment files, runtime data and local tool files. Source, lockfiles, required driver source and licenses remain versioned. Runtime logs, private keys, Vault and QA data stay outside commits.
