# Mini SSH stable-release acceptance

> [中文](./MINI-ACCEPTANCE.md) | English

## Result and source

2026-10-21: unified acceptance closes the user-approved SMB standalone mini SSH checklist: **S01–S12, 12/12, 100%, +3 this batch**. The competitor remains a reference; the archived 42-group research gains no new acceptance credit.

- Full backend and main production-browser source: `a87184611e832f3007f0df587201391d6f9a5185`. The final backend tree remains `69cec02b69ea4406caaac23c0a20cf48ba4c3263`, identical to that tested source.
- Compact-console regression: `d97c729cfadf0f31a68d6c7a090e8312ca12db4e`; the directory input subsequently gained its accessible name.
- Complete native installation/update and bilingual browser run: `79fbd258d67fb37844710229dddd99c5ea0a7c79`, clean at start, unchanged SHA/worktree at completion. Later acceptance documentation is not represented as runtime-tested source.

## Unified results

| Check | Result | Evidence and coverage |
|---|---|---|
| Complete Go/Testify | 2037 passed, 133 skipped | `mini-core-edfe5f3f78/go-final2-summary.json`; complete module and pinned drivers, per-test terminal events retained instead of raw streams |
| Linux race | 195 passed, 4 skipped | `mini-race-final-edfe5f3f78/linux-race.json`; history, jobs, operations, gateway, workspaces, native helpers and maintenance |
| Production browser | 55/55 | `browser-1792534422417/summary.json`; actual OpenSSH, native plugins/systemd, authorization, audit, monitoring, rotation and updates |
| Repaired console | One focused case passed | `browser-1792535575222/summary.json`; 1600/1440/1280/900/715/375px × English/Chinese, metrics/actions, search/keyboard/mobile navigation |
| Complete native entrypoint | Passed | `mini-native-final84/native-packages.json`; six archives, actual Windows CLI, Linux single port/SSH/SFTP, directories, reviews, upgrade and recovery |
| Isolated Docker browser | Passed | Project `jms233-qa-1a046c5f-f035-47a7-b2f3-6bf0d9b278b5`; build 48.99s, startup 12.19s, business smoke 9.37s, bilingual UI and repeated cleanup |
| QA / publisher / macOS pipeline tools | 53 / 2 / 8 passed | macOS tools additionally have two platform skips; no intranet deployment |
| Vet, build, bilingual content | Passed | Lint has no errors and five existing legacy warnings; no added frontend runtime dependency |

Report names are relative to the locally ignored `.cache/qa-reports/`; Docker uses `.cache/docker-qa/project/summary.json`. Raw local logs, credentials and disposable data are not committed.

## Named acceptance and limits

S01 is one Go service, static assets and a data directory without mandatory database/Redis/Node/Docker. S02–S05 cover actual Web/CLI SSH, pinned host keys, revocation, SFTP, audit/replay/live monitoring and command deny/review. S06 covers CPU/memory/disk/network, history and alerts. S07 covers native Agent and banhack233/node_exporter detection/install/recovery/upgrade/rollback. S08 covers seven-day password/key rotation, checks, retries and recovery. S09 covers encrypted offline site backup/import, including uncheckpointed SQLite WAL commits. S10 covers controlled execution directories; S11 update/data/version boundaries; S12 bilingual UX, size and delivery. See [PROGRESS](./PROGRESS.en.md).

Actual verification covers exact/tree/full-path regex rules, kernel cwd, every native Playbook step, immutable templates, idempotency, revision conflicts, one-use approval replay refusal, symlinks and directory replacement. Arbitrary internal shell semantics are not filesystem ACLs; remote account permissions remain necessary. [Directory boundaries](./INTERACTIVE-DIRECTORIES.en.md) still apply.

Jobs write v7/read v1–v7, Operations write v6/read v1–v6, SQLite history format is 1. Future-format rejection, per-row history checks, complete checkpoints, trial rollback, post-acceptance writes and forward recovery pass. Restart requires sign-in again while business data remains. The first stable release establishes the support line. The prior official GitHub Release list was empty; synthetic `v0.0.x` drills do not prove migration from an official historical release. See [upgrade compatibility](./UPGRADE-COMPATIBILITY.en.md).

All six macOS/ARM-inclusive archives pass cross-build/archive/digest checks; actual native execution is Windows amd64 CLI and Linux amd64. `Jenkinsfile_mac_single` and its state-machine tests are provided; no intranet deployment occurred. Skipped optional external integrations, online backup, production multi-active operation and full Enterprise parity are outside this acceptance promise.

## Performance and cleanup

Total JavaScript falls from 1,841,868 to **1,641,574 bytes (about -11%)**. Initial JavaScript is 495,091 bytes (gzip 159,909), largest chunk 478,952; budgets are unchanged. Vite took 176ms and the complete type-check/budget/build command about 1.3s on the current cached machine, not a general hardware guarantee.

Native, race, browser and Docker runs use owner identities and isolated temporary data. Owned containers/volumes/networks, temporary archives and attributable caches are removed with repeated cleanup checks. Retain compact receipts and at most two screenshots per successful batch through the existing retention entrypoint; failed/interrupted receipts remain. Other projects are untouched. Git/Docker ignore rules exclude runtime data, test output and editor leftovers.
