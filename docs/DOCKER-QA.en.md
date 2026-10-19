# Docker isolation and parallel debugging

[中文](./DOCKER-QA.md) | [Documentation](./README.en.md)

Buildx metadata reads retry RPC Unavailable/EOF at most three times. Permission and deterministic failures are not retried; cleanup failures retain a nonzero exit and a phase-specific receipt. GitHub Docker QA uses an isolated, automatically removed `docker-container` builder instead of relying on the runner's default Docker driver/BuildKit combination. Successful cleanup removes raw logs; failure diagnostics retain at most 16,000 characters. Cleanup remains restricted to demonstrably owned repository resources.

Docker builds the production API and web application from source, with separate networks, named data volumes and localhost ports. Builds do not read host Go, Node, `node_modules` or generated native helpers. Runtime images contain only executables and web output. The API and Nginx run as ordinary users with read-only root filesystems.

Idempotent QA image preparation retries Windows Docker context `meta.json` sharing violations at most three times. Ordinary file locks and permission failures are not retried; container creation and remote commands are never replayed by this helper.

Cleanup identities include streaming SHA-256 with a fixed 64 KiB buffer, detecting changed content even when size and modification time match. Per-deletion runner checks only fingerprint PID files and required receipts, avoiding repeated reads of unrelated large artifacts.

`node scripts/check-content.mjs` also rejects unreferenced `docs/images/` assets to prevent product screenshot accumulation. The automatic cleaner never deletes product screenshots.

## Fast verification

Both backend and frontend CI runners are pinned to `ubuntu-22.04` and record `uname -r`, retaining the real MongoDB 8.0 fixture. After correcting the frontend, backend `verify` confirmed the same MongoDB kernel guard rejection and now receives the same fix. On the previous `ubuntu-latest` run, MongoDB refused startup through its kernel guard. MongoDB documents an allocator incompatibility with certain kernels, also shared by Docker containers. The baseline uses the 6.8 kernel listed in the [GitHub Ubuntu 22.04 inventory](https://github.com/actions/runner-images/blob/main/images/ubuntu/Ubuntu2204-Readme.md); see [MongoDB production notes](https://www.mongodb.com/docs/manual/administration/production-notes/). No guard is disabled and no MongoDB test is skipped. Confirm the new remote CI result against its exact commit.

Production browser builds use `web-dist/` under their owned temporary run root. Preview and bundle checks use that same directory, removed with the run data. Independent `pnpm build` keeps `web/dist/`, allowing parallel verification.

Frontend CI reuses the single build in `pnpm test:e2e:production` while running the complete suite, removing the preceding duplicate standalone build. Backend state-machine checks explicitly select Python 3.11 for `hashlib.file_digest`; all ten state-machine cases passed in a read-only Linux container. These cases use a fake runtime and deploy no intranet service.

Browser and Docker runners apply file retention on completion: each keeps the latest three completed, successfully cleaned disposable runs, with at most two screenshots (PNG/JPEG/WebP), preferring one English and one Chinese image. Current and historical native package/Linux race batches with valid runner receipts are also compacted after results and cleanup pass; runner and child PIDs protect concurrent runs. Successful named and Docker batches discard raw trace/ZIP/TAR files, videos, HTML/HAR, profiles and temporary test programs, retaining JSON reports and other unrecognized files. Failed results retain compact summaries; Docker failures keep the existing 16,000-character diagnostic log. Active PIDs, incomplete fixture cleanup and intentionally retained debug environments are skipped. Expired disposable run directories are deleted; named feature JSON reports remain. Successful named feature screenshots share a limit of three eligible batches, ordered by image timestamps, with at most two images each. Batches without images consume no slot. Docker screenshots share a separate three-batch limit across successfully cleaned disposable runs and named previews. The current runner takes one slot first. Older named feature and Docker preview reports remain after their images expire. Updating an old summary does not extend image retention. A failed final lifecycle protects named and Docker diagnostics.

Preview and clean historical files manually:

```sh
node scripts/qa-retention.mjs --legacy
node scripts/qa-retention.mjs --apply --legacy
node scripts/qa-retention.mjs --apply --legacy
```

`--legacy` also compacts successful named reports without runner receipts and removes known branding/discovery/migration/monitor-history ad hoc helpers directly under `.cache/`, older than one hour and without a recorded active QA run. Unknown tools are preserved. Default automatic retention only handles demonstrably completed browser/Docker report directories and successful batches with valid native/race receipts. Every candidate checks workspace boundaries, ancestors, links and file identity since preview. All selected files and runner receipts are revalidated before deletion begins; each deletion checks its runner again. Newly created/changed receipts or a process becoming active since preview refuse deletion. The fixed `.cache/qa-reports/retention.json` receipt does not accumulate copies. Repeated cleanup should remove zero files.

The three-run limit counts successful batches only; failed browser/Docker summaries and necessary diagnostics do not expire when later runs pass. `--legacy` also removes an explicit allowlist of historical QA configs and `run-security-production-full.mjs` under `web/.cache/`, subject to the same one-hour age and recorded-run checks. Unknown configs and historical result directories remain. Git ignores `screenshots/` at every depth, nested protocol-fixture `artifacts/` and editor swap/backup files. Docker additionally excludes local automatic-update and scheduled-installation state.

Successful batches also discard temporary JS/TS, Shell/PowerShell/Python and CMD/BAT scripts, known extensionless jms executables and browser `error-context.md` / `.last-run.json` sidecars. Reusable scripts belong in `scripts/`. PID files are removed only when they contain a valid process ID that has exited; live or unreadable PID files protect their entire batch. The PID file set and identities are rechecked before deletion to detect a new task starting after preview. Other Markdown, TXT and JSON evidence remains.

Use `make qa-preview` / `make qa-clean`, or `pnpm qa:preview` / `pnpm qa:clean` under `web/`, for file retention. Docker resource previews no longer write files; at most three old successful read-only snapshots remain. Successful applied no-op receipts with no resource candidates or changes are separately capped at three. Receipts containing actual deletions, ownership evidence, remaining resources, failures, incomplete results or unfamiliar fields remain for recovery and review. Historical named reports without native/race receipts still require explicit `--legacy`.

Git and Docker also ignore `.playwright-mcp/`, `.playwright-cli/`, screenshot/codex-clipboard image exports directly under the root or `web/`, `junit*.xml` directly under the root/web/server, locally built jms executables and `.orig`/`.rej` merge leftovers. These rules do not delete files. Automatic cleanup remains confined to verified QA directories and does not scan or delete development dependencies, business data, unknown historical results or product documentation images. Default searches honor `.gitignore`; search ignored directories only when investigating a specific historical issue.

Git and Docker contexts also exclude test screenshots and artifacts in script/protocol fixture directories, coverage at any depth, PID and PID lock files. Image and archive extensions are not globally ignored; product images must still pass documentation reference checks.

`.gitignore` and `.dockerignore` exclude backups/keys, browser output, profiles, temporary builds, QA evidence and local Node/Go/Vite caches. `test-results/`, `playwright-report/` and `blob-report/` are ignored at every depth. Images and archives are not globally ignored. Ignore rules do not delete files. Referenced product screenshots remain in `docs/images/`, outside the cleaner's scope. Commit reusable tools under `scripts/` and keep temporary work in ignored directories. File retention and resource cleanup are separate; the Docker resource commands below still check container/volume ownership.

After testing, retain compact summaries and PNG evidence only: browser reports under `.cache/qa-reports/browser-*/`, Docker smoke reports under `.cache/docker-qa/<project>/`. Authentication request traces are disabled. Cleanup removes this run's temporary data, protocol containers/anonymous volumes, certificates, plugin test cache and unused QA images. Development dependencies, shared base images and unscoped shared BuildKit caches are excluded from global pruning.

Preview historical resources, apply cleanup, then repeat:

```sh
node scripts/qa-cleanup.mjs --include-legacy-fixtures --test-caches
node scripts/qa-cleanup.mjs --apply --include-legacy-fixtures --test-caches
node scripts/qa-cleanup.mjs --apply --include-legacy-fixtures --test-caches
```

Cleanup checks the workspace path, `compose.qa.yml`, labels and immutable container IDs; the second invocation should remove zero resources. Permission/connection errors are not missing resources. Partial-cleanup reports retain ownership evidence for retries. New fixtures carry workspace labels; legacy fixtures require the explicit flag and known name/image combinations. Saving identical password settings has no side effects; stale reset revisions conflict, and one-time password-change capabilities must reject replay.

Run `cd web && pnpm test:e2e:production` for complete protocol regression: build the frontend once, serve static output, and start fresh temporary data with the existing real protocol fixtures. Owned resources are checked and cleaned afterward. This is timed separately from fast Docker smoke and avoids development module transforms without reducing test scope.

Requires Docker Compose and Node 24:

```sh
node scripts/docker-qa.mjs verify
```

Each run creates a random project, empty data volume and two free localhost ports. It checks health, unauthenticated rejection, default login, session identity, production JavaScript, gzip and caching, then removes its containers/network/volume. Named debug environments are never reused or deleted. Logs stay in ignored `.cache/docker-qa/` without login credentials or session tokens.

With existing `web` dependencies and Playwright Chromium, add real browser checks:

```sh
node scripts/docker-qa.mjs verify --browser
```

Browser checks cover English/Chinese inventory and account-risk pages, lazy scripts and page errors. Only the random clean volume runs an empty-account scan and verifies its successful receipt. Retained `up` environments only read risk pages, avoiding interference with existing periodic policies. Real SSH rotation and periodic risk checks run in the full `pnpm test:e2e` suite.

The browser checks production login, Chinese/English switching, page exceptions and that an authenticated console does not load login animation code. Local warm-cache measurements on 2026-10-16: build 3.14 seconds, isolated startup 12.05 seconds, HTTP/parallel-browser checks 3.42 seconds, approximately 18.6 seconds total. Initial image/dependency downloads take additional time. Full SSH/database/real-systemd regression is recorded in [verification records](./TESTING.en.md).

## Historical source upgrade rehearsal

For cross-source native upgrades, separately run `node scripts/native-package-qa.mjs --historical`; see [installation transactions](./INSTALLATION.en.md). The old service and frontend are built from pinned historical source while an independent current CLI performs checkpoint, preflight and first-start acceptance. Real SSH, identities/grants, seven-day rotation timestamps and prior audit records must survive. This reuses six-platform packages, recovery, directory controls and bilingual browser checks; its duration is outside the fast Docker smoke budget.

## Retained debug environments

```sh
node scripts/docker-qa.mjs up --project jms233-debug-a --web-port 15173 --api-port 18080 --browser
node scripts/docker-qa.mjs up --project jms233-debug-b --host 127.0.0.3 --web-port 15174 --api-port 18081
```

Web URLs are `http://127.0.0.2:15173` and `http://127.0.0.3:15174`; APIs use `http://127.0.0.2:18080` and `http://127.0.0.3:18081`. Empty stores use the project default administrator; existing data and passwords are preserved. Each project has separate networks, image names and volumes. Published ports bind only to a dedicated loopback address (`127.0.0.2` by default), preserving existing development instances such as 5173.

```sh
node scripts/docker-qa.mjs down --project jms233-debug-a
```

`down` removes this QA project's data volume by default; pass `--keep-data` explicitly to retain it. Docker-only startup is `docker compose -f compose.qa.yml -p jms233-debug up --build --detach --wait`. Default web/API ports are 15173/18080; override with `JMS_QA_WEB_PORT`, `JMS_QA_API_PORT` and `JMS_QA_HOST`. Use different loopback addresses to isolate cookies.

After starting both environments, verify that login does not overwrite the other session in a shared browser context: `node scripts/docker-qa.mjs up --project jms233-debug-a --browser --peer-url http://127.0.0.3:15174`. This passed on 2026-10-16; checking existing environments took approximately 6.5 seconds.

## Caching and scope

BuildKit caches Go modules, compiled Go packages, the pnpm store and incremental TypeScript state. Lockfiles/dependency manifests are copied first, so source edits do not download all dependencies again. `.dockerignore` excludes dependencies, generated programs, runtime data, documentation images and local tool configuration. Cache organization follows [Docker documentation](https://docs.docker.com/build/cache/optimize/).

Acceptance covers Linux amd64 standalone production images and localhost forwarding. Use service names or `host.docker.internal` to reach debug targets; container `127.0.0.1` refers to that container. This entry does not create protocol fixtures or prove cluster HA/production deployment. The default proxy declares no trusted source; configure actual proxies for production source-IP rules as described in [access policies](./ACCESS-POLICIES.en.md).

Actual in-app browser screenshot from the separate Docker port on 2026-10-16. The empty inventory belongs to a fresh data volume:

![Docker English production console](./images/docker-qa.en.png)

Test cleanup also prunes reclaimable jms233 compilation/dependency cache records by their descriptions and immutable IDs. Unattributed shared layers remain. Repeating cleanup checks for zero additional removals. The next cold build may download dependencies again; report cold and warm durations separately.

Browser runs place `GOTMPDIR` inside their owned temporary root, so cleanup also removes Go run executables. Shared Go compilation and dependency caches remain reusable.
