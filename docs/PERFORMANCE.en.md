# Performance and packaging baseline

[中文](./PERFORMANCE.md) | [Documentation](./README.en.md)

## Platform sign-in audit (2026-10-18)

The page and bilingual resources load on demand, without new dependencies. Main entry: 480,585 bytes; initial JS: 497,929 bytes, gzip 160,599; total JS: 1,490,654. Existing 500 kB / 1.5 MB budgets pass. Vite's build stage took 177 ms, excluding type checking. Windows stripped API: 42,450,944 bytes; CLI: 12,602,880 bytes.

Native review imports use an incremental cursor and batch commits; idle polling does not rewrite segments or the index. With 10,000 cached events and the cursor at the tail, three benchmark runs measured about 12 ns/op, 0 B/op and zero allocations. This only measures the locked cache-tail check, excluding load, history reads, queries, HTTP, encrypted persistence and delivery. Reproduce with `go test -run '^$' -bench BenchmarkReviewFeedIdle -benchmem -count 3 ./internal/core/loginaudit`.

The latest-image focused Docker browser test took 11.9 seconds, 12.3 including its runner. Fresh-volume dual-instance browser smoke took about 22.19 seconds: cached build 5.03, startup 12.14, checks 5.02. Debug UI remains at http://127.0.0.33:15196, API 18103, bound only to loopback. Disposable smoke resources were cleaned. Existing .gitignore / .dockerignore cover reports, caches, builds and generated native artifacts.

## Native monitoring alerts (2026-10-18)

The page loads lazily at about 25.68 kB JS. Main entry: 479,663 bytes; initial JS including shared dependencies: 497,007 bytes, gzip 160,394; total JS: 1,468,408. Existing budgets pass. Vite's build stage took 211 ms, excluding type checking. No dependencies were added. Windows stripped API: 42,288,128 bytes; CLI: 12,576,768. Uncompressed Linux API image: 24,819,360 bytes.

An idle evaluation of 100 rules × 500 healthy hosts improved from about 29.8 ms/op, 22.1 MB/op and 101,259 allocations to 2.40 ms/op, 254 KB/op and 449 allocations. Rules share the source sample watermark for an evaluation; healthy untracked hosts avoid per-rule tracking state. Repeated snapshots do not write to disk. This local in-memory benchmark excludes SSH, HTTP, encrypted persistence, delivery and initial loading; it is not end-to-end latency. Count, age and encoded-size limits bound history and events. Active episodes are not evicted for capacity.

Complete production-frontend regression is reproducible with `cd web && pnpm test:e2e:production`, building once for all pages. Existing .gitignore/.dockerignore rules exclude snapshots, reports and binaries. The real browser case took 30.6 seconds, 31.0 including its runner, covering SSH pause, firing, acknowledgement, recovery, permission withdrawal and bilingual narrow layout. See [verification](./TESTING.en.md) for complete results.

## Security notifications and review details (2026-10-18)

Details load lazily at about 6.60 kB JS. Main entry: 478,877 bytes; initial JS: 496,221 bytes, gzip 160,183; total JS: 1,441,758. Existing budgets pass. The Vite build stage took 222 ms, excluding type checks. No dependencies were added. Windows stripped API: 42,102,784 bytes; CLI: 12,547,584 bytes. Uncompressed Linux API image: 24,754,481 bytes.

Agent notifications read a compact index committed atomically with collection cursors, avoiding recurring decryption of bulky collection_run output. Idle reads with 20,000 interactive alerts took about 188 ns/op, 168 B/op and 5 allocations. This measures an in-memory cursor check, excluding HTTP, event persistence, fsync, delivery and SSH. Ordinary allowed commands add no alert write; deduplicated idle snapshots do not rewrite notification state.

Latest production Docker browser coverage took 11.8 seconds, 12.2 including the runner. Fresh-volume, dual-instance browser verification totaled 19.78 seconds (cached build 3.68, startup 12.15, smoke 3.95). Debug UI remains at http://127.0.0.29:15194, API 18101. Existing .gitignore/.dockerignore rules cover caches, reports, builds and generated native helpers; no binaries entered Git.

## Notification center (2026-10-18)

The page and both locales load lazily at about 27.25 kB JS. Main entry: 478,611 bytes; initial JS: 495,955 bytes, gzip 160,098; total JS: 1,428,607. Existing 500 kB / 1.5 MB budgets pass. The local Vite build stage took 170 ms, excluding preceding type checks. No dependencies were added.

Three same-machine runs over 10,000 messages improved unread queries from 7.3–8.0 ms, 23.3 MB and 45–48 allocations to 4.1–4.5 ms, about 2.25 MB and 4 allocations. Queries preallocate for the caller's messages, filter in place and cap returned slices. Idle Tick over 10,000 messages and 10,000 sent deliveries took 0.24–0.40 ms, 272 B and 4 allocations, excluding event-source reads, HTTP, encrypted persistence and SSH. Benchmarks are in the notification package's performance_test.go; rerun with go test -run '^$' -bench BenchmarkNotification -benchmem -count 3.

Windows stripped API: 41,965,056 bytes; CLI: 12,541,952 bytes. Local Linux API image uncompressed size: 24,702,658 bytes. Pages contain 20 records; the header refreshes every 30 seconds and pauses when hidden. Idle cursors do not write state; senders are bounded to 4. Retention/capacity: [Notifications](./NOTIFICATIONS.en.md). Existing .gitignore/.dockerignore exclude caches, builds, test output and generated native helpers; this slice tracks no binaries.

## Access request tickets (2026-10-18)

The ticket page and both languages load lazily: about 33.89 kB JS / 0.81 kB CSS. Main entry: 476,681 bytes; initial JS and static dependencies: 494,025 bytes, gzip 159,552; all JS: 1,398,372 bytes. Existing 500 kB / 1.5 MB budgets pass with no added dependencies. See [TESTING](./TESTING.en.md) for build sizes and isolated verification timings.

Three same-machine Go runs over 10,000 assets improved from 24.4–25.8 ms/op, about 43.1 MB/op and 349,000 allocations to 7.24–7.66 ms/op, about 9.95 MB/op and 315 allocations. The catalog snapshots minimal metadata, uses composite keys and action bitsets, and materializes only the requested page. These measurements exclude HTTP, encrypted persistence, disk, SSH and browsers. Catalog pages contain 25 entries; ticket/policy/audit pages contain 20. Hidden pages and editors pause polling; closing aborts requests.

Existing `.gitignore` / `.dockerignore` rules exclude builds, tests, caches, generated native helpers and local tooling. This slice adds no binary. See [Access request tickets](./ACCESS-TICKETS.en.md) for behavior and retention boundaries.

2026-10-18 credential rotation: page code and both locales load on demand at approximately 31.09 kB JS / 2.96 kB CSS. Main entry: 475,956 bytes; initial JS: 493,300 bytes (159,378 gzip); total JS: 1,363,715 bytes. Existing 500 kB / 1.5 MB budgets pass. Windows stripped server: 41,263,616 bytes; CLI: 12,449,792 bytes. Local Linux production API image: 24,412,653 bytes uncompressed. No dependencies were added.

Targets page in groups of 25, plans/runs/audit in groups of 20. Only an open unfinished run polls serially; leaving cancels requests. Plan/run lists page before materializing metadata. Credential inspection uses atomic snapshots, and waiting behind another host's rotation respects cancellation/timeouts. Each organization executes accounts sequentially; limits and persistence boundaries are in [Credential rotation plans](./ROTATION-PLANS.en.md).

Final cached clean-volume Docker two-instance smoke: 18.77 seconds, including both rotation/risk languages. Final production-image real SSH rotation: 12.9 seconds, 13.5 including runner. Existing ignore rules exclude builds, caches, test output and local tools; no generated binaries were added.

2026-10-18 account risks: page code and both translations load on demand at approximately 25.48 kB JS. Main entry: 474,835 bytes; initial scripts/static dependencies: 492,179 bytes (159,092 gzip); total JS: 1,331,476 bytes. Existing 500 kB / 1.5 MB budgets pass. Windows stripped server: 40,992,256 bytes; CLI: 12,410,880 bytes. Local Linux production API image: 24,305,254 bytes uncompressed. No dependencies were added. Existing ignore rules exclude builds, caches, test output and local tools.

Three local Go samples for listing 10,000 reuse findings took 6.96–7.30 ms/op, approximately 0.99 MB/op and 61 allocations. Before optimization, the same fixture used approximately 23.69 MB/op and 10,054 allocations. Lightweight IDs are sorted first, only the requested 50 rows are materialized, and visible groups/identity counts are cached within one query. The benchmark includes in-memory filtering/sorting and metadata output; it excludes encryption, persistence, HTTP, disk, audit streaming and browsers. Each scan decrypts current passwords once, streams audit snapshots and publishes atomically. Details cap related records at 20. Web pages contain 50 findings or 10 receipts/audit records, and scans have a 60-second deadline.

Risk translations live in `web/src/i18n/locales/features/account-risks/` and register on page entry. Bilingual key/placeholder checks merge common and feature resources and reject duplicate keys. Production graph checks require both risk and login code to remain dynamic entries. See [Account risks](./ACCOUNT-RISKS.en.md).

Final clean-volume dual-instance Docker browser checks took 17.68 seconds: cached build 2.81, startup 12.09 and smoke 2.78, including bilingual risk pages and an empty-account scan, followed by automatic disposal. The final production-image real SSH risk scenario took 44.8 seconds (45.3 including runner overhead), including actual monitoring and a periodic-worker wait. The worker checks once per minute, so elapsed time depends on its start phase.

2026-10-18 bulk account import: the lazy dialog is approximately 10.80 kB JS / 1.83 kB CSS. Main entry is 473,204 bytes; initial scripts and static dependencies are 490,548 bytes (158,542 gzip); total JS is 1,304,239 bytes. Existing budgets pass. Windows stripped server: 40,775,680 bytes; CLI: 12,377,088 bytes. The local Linux production API image is 24,219,241 bytes uncompressed. No dependencies were added. SDK metadata types keep the full asset service out of CLI dependencies.

Three local Go benchmark samples for previewing 500 password accounts took 3.14–3.73 ms/op and approximately 3.75 MB/op. Separate tests create and update all 500 rows atomically. This benchmark excludes HTTP, file parsing, disk, remote login and encrypted-key KDF work. Preview builds one account index, reuses repeated credential parsing within a request, checks relevant fingerprint/username alias groups and caches decrypted passwords for that validation only. Commit persists once. Web previews show 25 rows per page and history 10 entries, cancelling reads and clearing input on close. Server limits are 10 MiB, 500 rows, 32 MiB ZIP expansion and 256 recent receipts. Test credential files use the system temporary directory and are deleted on exit. Existing `.gitignore` / `.dockerignore` rules exclude build outputs, caches, test results and local tooling; no executable is added to Git. See [Account import](./ACCOUNT-IMPORT.en.md).

Final fresh-volume Docker checks with two browser instances took 17.37 seconds (warm build 2.95, startup 12.14, checks 2.28), with automatic disposal of the temporary instance. Retained debug volumes are timed separately. The latest production image passed the complete import scenario in 10.3 seconds, including both hosts, CLI, Web SSH, XLSX updates and activity correlation.

2026-10-17 remote account lifecycle: the operation panel loads lazily at about 7.83 kB. Main entry is 466,406 bytes; initial JS is 483,750 bytes (156,315 gzip); total JS is 1,285,945 bytes. Budgets pass. Windows stripped server is 40,516,096 bytes and CLI 12,358,656 bytes; the local production API image is 24,110,974 bytes uncompressed. No dependencies were added. Tasks use pages of 20 and serial abortable polling only while the panel is open. Each host allows 2,000 tasks and refuses additional writes when audit capacity is full. Existing `.gitignore` / `.dockerignore` rules exclude caches and generated artifacts. Fresh Docker dual-instance browser verification took 18.01 seconds (build 3.01, startup 12.04, smoke 2.96), followed by automatic disposal; retained debug environments are timed separately.

2026-10-17 scheduled account discovery: main entry 460,668 bytes; initial scripts including shared dependencies 478,012 bytes, 154,440 bytes gzip; total JS 1,271,223 bytes. Budgets pass without added dependencies. Windows stripped server: 39,632,896 bytes; CLI: 12,324,352 bytes. The schedule module loads with the lazy discovery dialog and polls serially only while expanded. Requests time out after 15 seconds and abort on close. Native helpers reuse verified digests; different credentials share one physical-host collection reservation. Archives have segmented storage and bounded indexes, persisting receipts before pruning hot records; archive history still grows. The real production Docker browser case passed in 20.9 seconds. Warm build, startup and fresh-volume isolation timings are recorded separately in [TESTING](./TESTING.en.md).

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
