# Standalone maintenance patch and release acceptance

> [中文](./MAINTENANCE.md) | English

## Batch scope

Keep the 12-item [mini SSH scope](./PRODUCT-SCOPE.en.md) and address issues found in actual deployment. Implementation and cases are authored together; this batch's unified verification and new intranet upgrade have not completed. Previous 12/12 acceptance does not establish acceptance of these changes.

- Native single-port intranet IP HTTP: Origin scheme, Host and port must match the request or explicit `JMS_PUBLIC_URL`. Implicit trust accepts only loopback/private IPs without DNS resolution. Foreign hosts, different ports, `null` Origins and originless cross-site browser requests are denied. HTTPS configuration and existing development origins remain compatible.
- Login distinguishes origin refusal, rate limiting, service failure, network failure and invalid credentials in Chinese and English. Confirm the HttpOnly cookie session before entering the console, avoiding navigation loops when no session was established. Never display raw backend errors or secrets.
- macOS publication verifies the root manifest and nested Vite manifest; stable versions require an exact commit. The entry selects an installed Python >=3.11. Upgrades refuse active SSH and compare existing assets, session audit and the Vault key afterwards. Existing stopped-writer snapshots and rollback protect data.
- The deployed environment retains its dedicated HTTP entry. The new version forwards the original Origin for independent entry and native-service checks. Invalid entry configuration restores the previous file; repeating unchanged configuration preserves PIDs. Default standalone operation uses Go static serving without nginx.

## Unified verification

Run Go/Testify, vet, frontend lint/type/build, bilingual production browser tests, Python/Node release-helper cases and isolated Docker together. Cover administrator reopen, cookie sessions, same/cross origins, idempotence, manifest tampering, upgrade refusal and persistence. Repair discovered failures and rerun affected checks after the unified run.

After passing, release-please generates the patch version and changelog; publish immutable six-platform artifacts. Pin version, commit, size and SHA-256 in the deployment repository. Upgrade once through BuildWorld, then verify default sign-in, real Web SSH, CPU/memory/disk/network and data retention. Remove owned test resources, temporary programs and archives; keep compact reports and at most two essential screenshots.

## Existing intranet baseline

On 2026-10-21, v0.2.0 was deployed through BuildWorld project 49. Build 991 performed acceptance with `DEPLOY=false`: 6/6 stages, 20 native macOS cases, real SSH, monitoring and graceful-restart persistence passed. The program was published once. See [BuildWorld](./BUILDWORLD.en.md). This is the preceding baseline; update the current batch results after unified verification.
