# BuildWorld macOS single-node deployment

> English | [中文](./BUILDWORLD.md)

The source-build template is [Jenkinsfile_mac_single](../Jenkinsfile_mac_single) at the repository root. The live BuildWorld project [49 · 内网服务器/JumpServer233](http://192.168.110.42:8080/projects/49) now uses the dedicated private [poke-game/deploy-jumpserver233](http://192.168.110.42:3000/poke-game/deploy-jumpserver233) repository and its root `Jenkinsfile_mac_single`. The former `deploy_devops_server` directory remains historical. The pipeline verifies pinned official native artifacts without rebuilding source on the node. Startup builds, external HTTP triggers and distributed Workers are disabled. The defaults below describe the source-build template; the live entry uses port 8180 and loopback backend 18180.

## Defaults

| Setting | Default |
|---|---|
| Toolchain | Go 1.27.x, Node >=22.12 (24 LTS recommended), Python >=3.11; pinned pnpm 12.9.1 |
| Parameters | `DEPLOY=true`, `RUN_TESTS=true`, `JMS_PORT=8180` |
| Intranet URL | `http://192.168.110.42:8180/`, subject to actual health verification |
| Service | `user/<uid>/com.neko233.jumpserver233`, launchd background user domain |
| Persistent root | `~/.local/share/jumpserver233`; node environment `JMS_DEPLOY_DIR` may select a dedicated absolute directory |
| Runtime data | `data/`: encrypted inventory, Vault key, identities, policies and audit |
| Runtime configuration | `runtime.json`, locally generated service token; directory mode 0700, configuration/LaunchAgent plist mode 0600 |
| Versions | `releases/<commit>-<manifest-hash>/`, atomic `current` symlink |

Native HTTP supports same-origin loopback/private-IP access, including IPv6 ULA, without a reverse proxy. An explicit `JMS_PUBLIC_URL` pins the canonical HTTPS or loopback/private-IP HTTP origin; HTTP DNS names and public IPs are rejected. Public access uses HTTPS. Configure `JMS_TRUSTED_PROXIES` only for a controlled proxy that overwrites forwarding headers. Initial administrator provisioning follows [authentication](./AUTH.en.md); upgrades preserve existing passwords. Service tokens and Vault keys never enter Git, build parameters, artifacts or logs.

## Build and deployment

1. Check the native toolchain, install locked frontend dependencies, and generate required native Linux helpers.
2. Run the complete Python deployment state-machine tests, Node QA helper tests, bilingual/provenance checks, Go vet/tests and frontend lint. Protocol fixtures and the complete production browser suite are documented under [testing](./TESTING.en.md); this pipeline does not automatically start Docker or VM fixtures.
3. Build the frontend once and compile Go with `CGO_ENABLED=0`, `-trimpath -ldflags=-s -w`. Package the native server, CLI and static frontend with the full Git commit, architecture, per-file SHA-256 and archive digest. Retain 3 archived artifact sets and 10 build records.
4. Validate all files and architecture, the dedicated directory marker, deployment lock, LaunchAgent ownership and listener executable. A foreign port owner fails the deployment. Changing an existing deployment's port requires explicit migration.
5. Stop the old writer before snapshotting data, atomically activate the release, and verify the exact commit at `/api/health`, a SPA deep link and a protected API returning 401 without authentication. `JMS_WEB_DIR` serves the frontend, REST and WebSocket on the Go listener without a persistent nginx/Node process.

`RUN_TESTS=false` explicitly skips pipeline tests while retaining production compilation and deployment health checks. `DEPLOY=false` only builds and archives. Redeploying the same healthy manifest does not restart the process, regenerate keys or modify data.

## Recovery and maintenance

Stopping waits for both the listener and verified PIDs to exit, so an early listener close cannot leave an old writer running. Failed activation stops the new process, restores the preceding binary, LaunchAgent and stopped-writer data snapshot, then verifies the old version's health. Data written by the new binary remains in `failed-data/` for inspection of activation-window writes; restoring an old snapshot does not preserve all new writes. Further activation fails before stopping the running service until that directory has been reconciled. Failed initial provisioning retains data for repair.

Successful upgrades retain the current/preceding artifacts and two latest data snapshots, removing other owned release directories. Maintain runtime logs and failed recovery data under an appropriate operational retention policy. QA cleanup must never delete this persistent deployment root. Never print/archive `runtime.json`, LaunchAgent `EnvironmentVariables` or `data/`.

Static file access is confined with Go `os.Root`. Hidden paths, missing-asset SPA fallback and directory listings are blocked. `/api` and `/ws` always use the original routes. Entry pages use revalidation and content-hashed `/assets/` use immutable caching.

Independent check: `python3 -B -m unittest discover -s scripts -p macos_single_test.py`. Go static-serving tests in `server/internal/webui` use testify. The workspace `dist/deployment.json` receipt contains no credentials. This is an intranet single-node deployment; see [HA](./CLUSTER-HA.en.md) for clusters.

## Historical verification boundary, 2026-10-18

Project 49's group, GitHub `main` and `Jenkinsfile_mac_single` were saved and read back in the browser. Windows Go static-serving/config/server tests, vet, frontend production build and bilingual checks passed. The deployment state machine passed 10/10 in a network-disabled, read-only-mounted temporary Linux container with launchd test doubles; the container was removed automatically. Windows passed 8 cases and skipped 2 because symlink privileges were unavailable.

The real macOS SCM validation at that time failed before deployment connecting to `github.com:443`. That historical result is superseded by the actual deployment below.

## Live v0.2.0 baseline, 2026-10-21

Official v0.2.0 was activated once. A stalled download and nested-manifest adapter failure happened before activation; build 989 then deployed successfully but its browser-acceptance wait expired. [Build 991](http://192.168.110.42:8080/builds/991) passed 6/6 stages in 3.59 seconds with `DEPLOY=false`, including 20 native macOS tests, exact archive/CLI identity, real SSH, Linux monitoring and unchanged asset/audit/Vault identities across graceful restart. Stored SSH credentials reconnected afterwards. The organization shared entry points to the intranet service.

v0.2.0 uses the already installed nginx with a dedicated LaunchAgent to enforce exact Origin/Host checks and a loopback backend; unrelated nginx configuration is untouched. The [maintenance patch](./MAINTENANCE.en.md) adds native IP HTTP and forwards the original Origin for both checks. The v0.2.1 batch completed unified verification and upgrade acceptance below. Temporary transfer archives, SSH configuration and preflight programs were removed; compact reports and two screenshots remain outside Git. One verified production artifact cache supports fast subsequent builds.

## Preceding v0.2.1 acceptance, 2026-10-21

[Build 995, #5](http://192.168.110.42:8080/builds/995) performed the only activation from official v0.2.0 to v0.2.1: 6/6 stages, 26/26 native macOS cases, 96.79 seconds. Pinned archive and executed native CLI match release commit `c56eeeef0f3eb7768b9633232813337a41921b7a`. Edge sign-in, newly completed real SSH and host monitoring passed. A subsequent graceful restart retained the existing asset, original/new session audits, credentials and unchanged Vault key. The default administrator signed in again. No additional deployment or release was performed.

The shared organization entry remains [HTTP port 8180](http://192.168.110.42:8180/), with loopback backend 18180. See [maintenance acceptance](./MAINTENANCE.en.md) for verification and cleanup evidence. This replaces the previous exclusion of actual macOS/ARM intranet acceptance for this node.

## Final v0.2.2 deployment

The user explicitly authorized one additional v0.2.2 publication for the verified runtime race repair. [Build 997, #6](http://192.168.110.42:8080/builds/997) passed 6/6 stages and 26 native Mac cases in 92.04 seconds, with one activation. Default login, new real SSH, monitoring and restart retention passed. One original asset, all three previous audit IDs, the new fourth audit, stored credentials and the Vault key survived. Official source commit: `a73132e99f2a420f60ae88d7b43f69b57e767212`; deployment commit: `5967091b977da7cb84d114f600aa39a26d98eda8`. The running server now includes the CI-verified repair. Current access remains [HTTP 8180](http://192.168.110.42:8180/). Cleanup and exact evidence are in [maintenance acceptance](./MAINTENANCE.en.md).

## Previous v0.3.0 native SSH/SFTP deployment — 2026-10-22

[Build 1014, #7](http://192.168.110.42:8080/builds/1014) upgraded v0.2.2 to v0.3.0 once, passing 6/6 stages and 34/34 native Mac cases in 4m43s. Deployment configuration is pinned to `d0c30aa856a76a0ff539b31535f18bbb7a955ae8`; the official running artifact is pinned to `0f4582783e2cae2e48c7a2b841fc0a4634099d30`. Web stays on 8180; embedded SSH/SFTP adds 2222 without another process or external runtime dependency.

Edge root/root, real Web SSH and host monitoring passed. A native client completed title/desc/IP search, selection, Linux SSH, return to menu, and a 55,296-byte upload/rename/download hash check followed by deletion. One graceful restart retained the original asset, all four pre-upgrade audit IDs and all nine pre-restart audit IDs, credentials and the Vault key. Stored credentials reconnected with online Linux metrics. Post-restart Web/native login, the unchanged host fingerprint and a repeated complete file round trip passed. Only one activation occurred, with no republication.

See [native entry](./NATIVE-SSH.en.md) for precise acceptance and CI boundaries. Compact receipts are ignored under `.cache/qa-reports/native-ssh-batch/`. Owned files, Docker QA resources, temporary executables and transfer archives are removed; production data/audit, necessary rollback material and the current verified artifact cache remain.

## Previous v0.3.1 client compatibility repair deployment

[Build 1022, #8](http://192.168.110.42:8080/builds/1022) activated v0.3.1 once in 6m14s, passing 6/6 stages and 34/34 native Mac cases. Duration includes browser, native-client and monitor acceptance. Official source: `d4a2fb7eec694ba453285bb12c0151bb9baee874`; deployment pin: `8108be93a8f58cda8191fe1098233dd9c16ec99f`. Web 8180 and SSH/SFTP 2222 stay unchanged. All six full CI jobs and 70/70 production browser cases passed.

The original asset and all 11 pre-upgrade session audits survived. One graceful restart retained all 13 pre-restart audits, the Vault key and stored credentials, then reconnected for Linux metrics. Before/after checks passed root/root, real Web/native SSH, title/desc/IP search, a 55,296-byte file hash/deletion round trip, and monitoring. Each client-compatibility check recycled 20 invalid channels, ran six parallel auxiliary commands and sampled the existing XTerminal monitor three times without replacing it. The user's screenshot confirms monitoring but requests a clearer, keyboard-selectable table. That subsequent UI maintenance has separate acceptance and does not overwrite published artifacts.

Compact receipts and the release screenshot remain ignored under `.cache/qa-reports/native-client-live-20261022/`. Temporary local programs, script copies, downloaded archives and old node artifact cache were removed. Production data/audit, the existing monitor installation, formal rollback material and the current verified package remain.

## Previous v0.3.2 table workbench deployment

[Build 1041, #9](http://192.168.110.42:8080/builds/1041) started at 2026-10-22 16:53:24 and finished at 16:56:15, passing 6/6 stages and 34/34 native Mac cases in 2m51s with one activation. Official source: `6e717232c607a6b2661ae4a189cd3272e5469a1d`; deployment pin: `222cc8f79599551801bd01c0f84fdff70a21e1d9`. Full CI passed six jobs and 70/70 production browser cases. The official Mac ARM archive is 28,138,076 bytes, SHA-256 `cbed946bf190743058594d9fb2536e77fce9b6d83deddf731c03099aae8d77b6`, matching the node cache and executed native CLI.

The original asset and all 14 pre-upgrade audit IDs survived. One graceful restart retained all 16 pre-restart audit IDs, the Vault key and credentials, then reconnected for Linux metrics. Default login, real native SSH, title/desc/IP search, menu return, 55,296-byte file round trips/removal, and three monitoring samples passed before and after restart. Browser reauthentication and real Web SSH passed. The host fingerprint stayed unchanged. There was no second activation or replacement of earlier release artifacts.

Browser acceptance used the authorized in-app browser; failures in both Edge connections required no application changes. Compact receipts and the successful-build capture are ignored under `.cache/qa-reports/native-workbench-live-20261022/`. Owned test files, downloads, temporary clients, Docker resources and obsolete node artifact cache are cleaned. The current official package, runtime data, audit and necessary rollback material remain; repeated cleanup is safe.

## Current v0.4.0 Web workspace deployment

[Build 1078 / #10](http://192.168.110.42:8080/builds/1078) started at 2026-10-23 14:22:47 and finished at 14:26:46, taking 239.653 seconds with 6/6 stages and 34/34 Mac deployment cases passed. One trigger produced one activation, followed only by an ordered retention restart. Application commit: `e21d403a0e78822803d9918fc63cd67e29a8aac3`; deployment lock commit: `d90a8c18596e47a7f0e855c93e4b761631d964b1`. Full CI passed 6/6 and production browser regression 72/72.

The user authorized automatic connection handling for later upgrades, so SSH/SFTP entries need not reach zero. Snapshotting still waits for the old process to exit; authentication, authorization and audit remain enforced. Default login, real Web/native SSH, a 61,600-byte SFTP hash-verified round trip, an 8,960-byte Web content comparison, three monitoring observations and original data retention passed. The original asset, all 17 audit IDs, Vault key and host fingerprints survived. The ordered restart retained the then-current 18 audits and reconnected using stored credentials.

Local BuildWorld HTTP Token API access is configured and verified without resetting passwords. Automatic default provisioning was separately pushed in its source repository; the BuildWorld service version was not replaced. Compact reports and two screenshots are in ignored `.cache/qa-reports/web-release-20261023/`. See [Web acceptance](./WEB-REDESIGN.en.md).
