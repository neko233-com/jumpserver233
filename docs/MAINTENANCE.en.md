# Standalone maintenance patch and release acceptance

> [中文](./MAINTENANCE.md) | English

## Batch scope

Keep the 12-item [mini SSH scope](./PRODUCT-SCOPE.en.md) and address issues found in actual deployment. Implementation and cases were authored together and unified verification passed on source `09bb9b5fdcaf7231bb7af2aff3868f11261757d4`. The official v0.2.1 release and its single intranet upgrade have now passed their separate acceptance gates. The mini checklist retains 12 items; the later race finding reopens S12 and maintenance adds no scope credit.

- Native single-port intranet IP HTTP: Origin scheme, Host and port must match the request or explicit `JMS_PUBLIC_URL`. Implicit trust accepts only loopback/private IPs without DNS resolution. Foreign hosts, different ports, `null` Origins and originless cross-site browser requests are denied. HTTPS configuration and existing development origins remain compatible.
- Login distinguishes origin refusal, rate limiting, service failure, network failure and invalid credentials in Chinese and English. Confirm the HttpOnly cookie session before entering the console, avoiding navigation loops when no session was established. Never display raw backend errors or secrets.
- macOS publication verifies the root manifest and nested Vite manifest; stable versions require an exact commit. The entry selects an installed Python >=3.11. Upgrades refuse active SSH and compare existing assets, session audit and the Vault key afterwards. Existing stopped-writer snapshots and rollback protect data.
- The deployed environment retains its dedicated HTTP entry. The new version forwards the original Origin for independent entry and native-service checks. Invalid entry configuration restores the previous file; repeating unchanged configuration preserves PIDs. Default standalone operation uses Go static serving without nginx.

## Unified verification

Run Go/Testify, vet, frontend lint/type/build, bilingual production browser tests, Python/Node release-helper cases and isolated Docker together. Cover administrator reopen, cookie sessions, same/cross origins, idempotence, manifest tampering, upgrade refusal and persistence. Repair discovered failures and rerun affected checks after the unified run.

After passing, release-please generates the patch version and changelog; publish immutable six-platform artifacts. Pin version, commit, size and SHA-256 in the deployment repository. Upgrade once through BuildWorld, then verify default sign-in, real Web SSH, CPU/memory/disk/network and data retention. Remove owned test resources, temporary programs and archives; keep compact reports and at most two essential screenshots.

## Existing intranet baseline

On 2026-10-21, v0.2.0 was deployed through BuildWorld project 49. Build 991 performed acceptance with `DEPLOY=false`: 6/6 stages, 20 native macOS cases, real SSH, monitoring and graceful-restart persistence passed. The program was published once. See [BuildWorld](./BUILDWORLD.en.md). This remains the preceding baseline; the current upgrade is recorded below.

## Unified result, 2026-10-21

- Go/Testify: 2061 passed, 133 skipped, 100 packages passed; vet passed. Skipped platform/external integrations are not claimed as accepted.
- Production browser: 69/69, including 14 new bilingual login-failure cases; 17.7 minutes. The complete suite includes actual native-agent reboot, firewall recovery and systemd supervision.
- Release/QA Node helpers: 77/77. Source Python: 11 cases, two Windows symlink skips. Deployment Python: 26/26 on native macOS, zero skips.
- Six native targets passed; the Windows CLI and real Linux SSH/SFTP, managed installation/rollback, encryption, backup/recovery, password checks and directory controls passed. Owned native resources were removed idempotently.
- Clean Docker browser passed with its resources removed. Frontend lint/type/build and bilingual/provenance checks passed. Five existing warnings in historical UI modules remain.
- Initial JavaScript: 496024 bytes, gzip 160149; total JavaScript: 1642958. Existing budgets passed; no new runtime dependency.

Reports remain in ignored `.cache/qa-reports/maintenance-v021/`, `maintenance-v021-native/` and the associated browser/Docker batches. Product code was unchanged during verification. Release-only metadata and evidence documentation may advance HEAD without changing the verified server/web trees.

## CI fixture isolation

The release CI failed before backend assertions: K3s startup exited with code 137 while ten external services started concurrently on one hosted runner. External integrations now use three mandatory runner groups: relational databases, data services and access protocols. Each group starts fixtures sequentially, runs its connector/API cases and always cleans owned resources. Core Go/PostgreSQL/SSH/systemd, race, vet, build, browser and Docker checks remain mandatory. This changes CI scheduling only; v0.2.1 artifacts are unchanged.

Each external group also starts its controlled OpenSSH gateway so gateway cases cannot skip for a missing prerequisite. Normal pushes/PRs retain every gate. Only an explicit manual `external_only` scheduling regression reuses full-suite evidence for identical application trees; its separate concurrency group preserves the running full regression.

Only generated `CHANGELOG.md` and `.release-please-manifest.json` changes skip duplicate runtime suites. Source, tests, scripts and CI configuration still use every default gate. Publication separately verifies six-platform artifacts; deployment then verifies actual identity and business behavior.

## v0.2.1 intranet upgrade, 2026-10-21

[BuildWorld build 995, #5](http://192.168.110.42:8080/builds/995) passed 6/6 stages in 96.79 seconds, including 26/26 native macOS deployment cases. The official darwin/arm64 archive identifies source `c56eeeef0f3eb7768b9633232813337a41921b7a`; pinned SHA-256 is `f0feb667fc3198994089c78b5eb78a70b29ed3b1968304f5528490db55113223`. The deployment repository commit is `9613c922ed9cc2f44da2b49c0f8e7a84779869ba`.

The program was activated once. Edge confirmed the existing default administrator login, a newly completed real Web SSH session returning Linux and UID 0, and CPU/memory/disk/network metrics. One graceful restart then preserved the original asset, both original session audits, the newly completed session audit and the unchanged Vault key. Stored SSH credentials reconnected; the default administrator signed in again afterwards. No password reset was performed. Access: [intranet service](http://192.168.110.42:8180/).

Compact receipts and the sanitized screenshot are in ignored `.cache/qa-reports/maintenance-v021/acceptance.json`. Disposable local/Mac programs, transfer archives, the preceding archive cache and owned test resources were cleaned. Keep the verified current archive cache, current/preceding production directories and required stopped-writer snapshots for maintenance and recovery.

## Post-release race finding and artifact boundary

The full CI run found a runtime race in native Playbook snapshot reads: JSON decoding reused the controller's `LoopValues` backing array while the scheduler read it. Commit `f9b042a17142c2aef402f5f4976a1bf33cc7f12f` decodes into fresh storage and adds ownership, nested-value isolation, nil/empty and concurrent-reader cases. The new ownership case fails deterministically against the original v0.2.1 source; repaired operations/API Playbook cases passed three repetitions locally. [Linux repair CI 39578766877](https://github.com/neko233-com/jumpserver233/actions/runs/39578766877) passed three complete operations/API repetitions, the full existing concurrent-state race selection plus auth, vet and build. [External gateway CI 39577385755](https://github.com/neko233-com/jumpserver233/actions/runs/39577385755) passed all three groups. The preceding full run already passed all functional tests, production browser and Docker; its race failure is retained as the discovery evidence. Only the runtime clone changed after that baseline, with targeted regression above; the web tree is unchanged.

This runtime repair is **not in the immutable published v0.2.1 artifact**. The accepted single intranet upgrade, default login, SSH, monitoring and original-data retention remain valid for v0.2.1. No second deployment or replacement release artifact was made. Final stable-release closure requires a version decision for the repaired server; keep that delivery gate open.
