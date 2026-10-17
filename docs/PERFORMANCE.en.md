# Performance and packaging baseline

[中文](./PERFORMANCE.md) | [Documentation](./README.en.md)

2026-10-17 managed accounts: the lazy dialog is approximately 13.53 kB JS and 1.79 kB CSS. Main entry: 458,230 bytes; initial scripts and static dependencies: 475,574 bytes, 153,689 bytes gzip; total JS: 1,260,364 bytes. Windows stripped server: 39,556,096 bytes; CLI: 12,302,848 bytes. No added dependencies; existing budgets pass. Account lookup uses an O(1) Store read. Inventory snapshots lightweight metadata once; authorized pagination precedes detailed version/status calculation. Each physical host retains one primary-account background probe. Search is explicit and reads abort on close. Fresh-volume Docker browser checks with a second instance took 17.48 seconds (warm build 3.01, startup 12.00, smoke 2.47), separately timed from retained debug volumes. See [Managed SSH accounts](./MANAGED-ACCOUNTS.en.md).

Account collection slice, 2026-10-17: the dialog loads on demand in approximately 8.48 kB JavaScript and 1.35 kB CSS. Main entry is 453,360 bytes; initial scripts and static dependencies total 470,704 bytes, or 152,300 gzip bytes. All JavaScript totals 1,239,297 bytes and passes existing budgets. Stripped Windows server is 39,417,856 bytes; CLI is 12,257,792 bytes. No dependency was added. Collection permits four simultaneous targets per organization and one operation per asset, with 32 records per page and at most 4096 local accounts. All page digests must agree before one atomic import. State loads per asset without a resident organization-wide account index; each asset's plaintext state is capped at 16 MiB and refuses additional writes at capacity. Browser job queries run serially, retry transient failures after two seconds and abort when the dialog closes. See [account collection](./ACCOUNT-DISCOVERY.en.md).

RDP monitoring slice, 2026-10-17: viewer dialog approximately 2.89 kB, viewing activity 2.32 kB and shared renderer 0.85 kB, all loaded on demand. Main entry is 449,777 bytes; initial scripts including static shared dependencies total 467,121 bytes, or 151,089 gzip bytes. All JavaScript totals 1,226,612 bytes and passes existing budgets. Stripped Windows server is 39,245,824 bytes; CLI is 12,233,728 bytes. The server's same-sequence wire-packet test allocates nothing extra. Separate Node tests cover one decode plus latest-frame replacement, preventing an unbounded queue for slow consumers. Zero-allocation evidence excludes PNG re-encoding, network and the remote connector.

Terminal collaboration slice, 2026-10-17: invitation panel approximately 4.83 kB, participant page 5.13 kB and activity list 2.11 kB, all loaded on demand. Main entry is 448,885 bytes; initial scripts including shared static dependencies total 466,229 bytes, or 150,880 gzip bytes. All JavaScript totals 1,218,401 bytes and passes existing budgets. Stripped Windows server is 39,199,744 bytes; CLI is 12,229,120 bytes. Each active terminal retains at most 64 KiB of output tail with bounded participant queues and no copy of the complete recording.

Session security slice, 2026-10-17: settings load on demand in approximately 3.16 kB; the 444.38 kB main entry passes existing budgets. The stripped Windows program is 38,993,408 bytes, approximately 0.36% above the previous baseline. The local production API image is 23,501,151 bytes.

A synthetic 1280×720 static-frame watermark benchmark measured approximately 7.17 ms / 8.34 MB temporary allocations when rendering, versus 14.5 ns and zero allocations for a cached sequence. Network, remote desktop and connector costs are excluded; this is not end-to-end frame latency.

Production Docker contexts exclude Go tests, protocol fixtures, Playwright cases and documentation. Test edits therefore do not invalidate the production source copy layer. CI tests use a complete checkout and remain unaffected by `.dockerignore`. Live monitoring loads on demand, while the main entry retains its existing size budgets.

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
