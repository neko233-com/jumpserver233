# Standalone maintenance patch and release acceptance

> [中文](./MAINTENANCE.md) | English

## Batch scope

Keep the 12-item [mini SSH scope](./PRODUCT-SCOPE.en.md) and address issues found in actual deployment. Implementation and cases were authored together and unified verification passed on source `09bb9b5fdcaf7231bb7af2aff3868f11261757d4`. Publication and the new intranet upgrade remain separate gates. The mini checklist remains 12/12; maintenance adds no scope credit.

- Native single-port intranet IP HTTP: Origin scheme, Host and port must match the request or explicit `JMS_PUBLIC_URL`. Implicit trust accepts only loopback/private IPs without DNS resolution. Foreign hosts, different ports, `null` Origins and originless cross-site browser requests are denied. HTTPS configuration and existing development origins remain compatible.
- Login distinguishes origin refusal, rate limiting, service failure, network failure and invalid credentials in Chinese and English. Confirm the HttpOnly cookie session before entering the console, avoiding navigation loops when no session was established. Never display raw backend errors or secrets.
- macOS publication verifies the root manifest and nested Vite manifest; stable versions require an exact commit. The entry selects an installed Python >=3.11. Upgrades refuse active SSH and compare existing assets, session audit and the Vault key afterwards. Existing stopped-writer snapshots and rollback protect data.
- The deployed environment retains its dedicated HTTP entry. The new version forwards the original Origin for independent entry and native-service checks. Invalid entry configuration restores the previous file; repeating unchanged configuration preserves PIDs. Default standalone operation uses Go static serving without nginx.

## Unified verification

Run Go/Testify, vet, frontend lint/type/build, bilingual production browser tests, Python/Node release-helper cases and isolated Docker together. Cover administrator reopen, cookie sessions, same/cross origins, idempotence, manifest tampering, upgrade refusal and persistence. Repair discovered failures and rerun affected checks after the unified run.

After passing, release-please generates the patch version and changelog; publish immutable six-platform artifacts. Pin version, commit, size and SHA-256 in the deployment repository. Upgrade once through BuildWorld, then verify default sign-in, real Web SSH, CPU/memory/disk/network and data retention. Remove owned test resources, temporary programs and archives; keep compact reports and at most two essential screenshots.

## Existing intranet baseline

On 2026-10-21, v0.2.0 was deployed through BuildWorld project 49. Build 991 performed acceptance with `DEPLOY=false`: 6/6 stages, 20 native macOS cases, real SSH, monitoring and graceful-restart persistence passed. The program was published once. See [BuildWorld](./BUILDWORLD.en.md). This is the preceding baseline; update the current batch results after unified verification.

## Unified result, 2026-10-21

- Go/Testify: 2061 passed, 133 skipped, 100 packages passed; vet passed. Skipped platform/external integrations are not claimed as accepted.
- Production browser: 69/69, including 14 new bilingual login-failure cases; 17.7 minutes. The complete suite includes actual native-agent reboot, firewall recovery and systemd supervision.
- Release/QA Node helpers: 77/77. Source Python: 11 cases, two Windows symlink skips. Deployment Python: 26/26 on native macOS, zero skips.
- Six native targets passed; the Windows CLI and real Linux SSH/SFTP, managed installation/rollback, encryption, backup/recovery, password checks and directory controls passed. Owned native resources were removed idempotently.
- Clean Docker browser passed with its resources removed. Frontend lint/type/build and bilingual/provenance checks passed. Five existing warnings in historical UI modules remain.
- Initial JavaScript: 496024 bytes, gzip 160149; total JavaScript: 1642958. Existing budgets passed; no new runtime dependency.

Reports remain in ignored `.cache/qa-reports/maintenance-v021/`, `maintenance-v021-native/` and the associated browser/Docker batches. Product code was unchanged during verification. Release-only metadata and evidence documentation may advance HEAD without changing the verified server/web trees.
