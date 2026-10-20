# Delivery progress and fixed acceptance checklist

> [中文](./PROGRESS.md) | English

## Current assessment (2026-10-20)

| Scope | Closed | Implementation awaiting verification | Partial | Undelivered | Closure by acceptance items |
|---|---:|---:|---:|---:|---:|
| Current stable SSH release | 9/12 | 0 | 3 | 0 | **75%** |
| Full baseline (Community core, Enterprise enhancements and user additions) | 16/42 | 2 | 16 | 8 | **38%** |

Denominators were first fixed on 2026-10-20 without reconstructing historical percentages. The user subsequently required **all features implemented before unified verification**. Separate implementation readiness and acceptance: 16 accepted groups plus E41 labels/announcements and E36 SSH user certificates awaiting verification make **18/42 implementation-ready (43%)**, with **24 groups** still needing code/cases/docs. Acceptance remains **16/42 (38%)**, with 26 unclosed groups. This E36 batch adds **one implementation-ready group and zero accepted groups**. Directory/upgrade source remains unverified and does not close its groups' other gaps. The checklists overlap and cannot be added together.

The percentage is closed capability groups divided by the fixed checklist total. Partial implementations receive no fractional credit. It does not measure code volume, remaining hours or production readiness; groups differ in effort. Changing or splitting the denominator requires the requirement source, reason and before/after counts. Vendor support, commercial licensing and supplier SLAs are excluded from software scope.

The competitor is [JumpServer Enterprise](https://www.jumpserver.org/enterprise.html). Scope comes from [BASELINE](./BASELINE.en.md), [PLAN](./PLAN.en.md) and user additions. Delivery order follows [stable SSH](./SSH-FIRST.en.md); other Enterprise extensions do not enter this release's closing scope.

## Status and evidence

- **Closed**: committed implementation and relevant acceptance evidence within the boundary stated in the row; this does not cover every extension in the competitor's equivalent module.
- **Implementation awaiting verification**: code, cases and bilingual docs are authored and await the full-scope unified run; contributes no closed credit.
- **Partial**: implementation exists, but gaps, unverified changes or acceptance remain; contributes zero closed items.
- **Undelivered**: no complete accepted delivery; this does not infer absence of all source from a keyword search.

The last accepted and pushed functional baseline is `4b96cb3ebc8b92cc813c05abd70db3d0619b0e40`. Its preceding verification recorded **1744 Go passes, 114 skips**, **350 Linux race passes** and **87/87 production-browser passes**. The full browser suite used `04bf60a`; the mobile result correction at `8188747` received native-lifecycle and bilingual narrow-screen acceptance without repeating all 87 cases. The final baseline commit updated acceptance docs. See [verification](./TESTING.en.md) and the locally ignored `.cache/qa-reports/account-checks/summary.json`; test counts do not determine feature completion.

Unverified source includes directory propagation, Go/API/CLI cases, real SSH/bilingual browser entrypoints, the [upgrade compatibility matrix](./UPGRADE-COMPATIBILITY.en.md), [platform announcements](./ANNOUNCEMENTS.en.md), [organization labels](./LABELS.en.md) and [SSH user certificates](./SSH-CERTIFICATES.en.md). Checkpoint `87505d6` contains directory/upgrade work, `04e822d` notices and `d47def7` labels; this certificate batch also awaits verification. None is an accepted stable release. This batch only authors/formats source without tests, builds, browser or Docker runs. Previous passes do not cover new source.

## Stable SSH: 12 fixed items

| ID | Acceptance item | Status | Boundary / remaining work |
|---|---|---|---|
| S01 | Standalone, few dependencies, same port and native artifacts | Closed | Local encrypted persistence; no external database, Redis or permanent Node runtime. |
| S02 | Web SSH and platform-identity CLI | Closed | Real SSH/gateways, host-key verification and platform identities without returning target credentials. |
| S03 | Assets, managed accounts, grants and revocation | Closed | Asset/node/account grants, organization isolation and live revocation; global organization aggregation is later Enterprise scope. |
| S04 | SFTP, audit, replay and monitoring | Closed | Real transfers, session/file records, replay and ongoing authorization. |
| S05 | Sensitive-command deny/review and redaction | Closed | Rules/reviews for recognized interactive input and controlled exec; directory coverage is S10. |
| S06 | Host monitoring, history and alerts | Closed | CPU/memory/disk/network, history, offline and threshold notifications. |
| S07 | Remote tools and native-agent lifecycle | Closed | Detection/install, supervised recovery, upgrade/rollback and audit. |
| S08 | Seven-day SSH password/key rotation and checks | Closed | Per-item results/retries, recovery history, periodic authentication, authorization and idempotency. |
| S09 | Standalone offline full-site export/import | Closed | Encryption/integrity, idempotent restore, no overwrite on invalid input and restart retention; cross-version upgrades are S11. |
| S10 | Directory controls across all controlled execution entrypoints | Partial | Single jobs passed; batch/template/schedule/Playbook changes are unverified. Unknown interactive cwd must deny conservatively and direct users to controlled exec; arbitrary shell semantics are not promised. |
| S11 | Update checks, data-preserving upgrades and supported-version boundaries | Partial | Install/rollback and a historical-source drill exist; freeze the minimum supported version, historical artifact/format migration and rejection of older versions. |
| S12 | Final unified verification and delivery after all implementation | Partial | Complete all 42 groups, cases and bilingual docs, then verify, clean, report, commit and push once; include bilingual, performance and size gates. |

## Full baseline: 42 fixed groups

Each row names a capability group and its accepted boundary or remaining extensions. Contract-level subfeature parity requires an explicit revision of this checklist; group counts must not be presented as coverage of every competitor subfeature.

| ID | Capability / evidence entrypoint | Status | Accepted boundary / gap |
|---|---|---|---|
| E01 | [Standalone deployment and native packages](./SSH-FIRST.en.md) | Closed | Same-port Go Web/API/WS, local encrypted persistence and six platform artifacts; runtime evidence covers Windows CLI and Linux. |
| E02 | [Users, groups, RBAC and local password security](./PASSWORD-SECURITY.en.md) | Closed | Identity lifecycle, permissions, password policy/history/expiry and restricted recovery. |
| E03 | [Local MFA, Passkey and RADIUS](./RADIUS.en.md) | Closed | OTP, Passkey, RADIUS primary/additional factors and platform review; cloud SMS is E06. |
| E04 | [Enterprise directories and federated sign-in](./LDAP.en.md) | Partial | Bounded LDAP/OIDC/CAS/SAML implementations exist; directory sync, group/organization mapping, multiple providers and production IdP acceptance remain open. |
| E05 | [WeCom, DingTalk and Feishu QR sign-in](./BASELINE.en.md) | Undelivered | No accepted end-to-end delivery. |
| E06 | [Cloud SMS/CMPP MFA](./NOTIFICATIONS.en.md) | Undelivered | Custom SMS notifications do not establish Alibaba/Tencent/Huawei/CMPP MFA. |
| E07 | [Asset trees, SSH gateways and grants](./GATEWAYS.en.md) | Closed | Node inheritance, account/action/time grants, host-key pinning and multiple hops; tags are E41. |
| E08 | [Organizations and global organization features](./ORGANIZATIONS.en.md) | Partial | Isolation, switching and roles exist; cross-organization aggregation, automatic identity mapping and production drills remain open. |
| E09 | [Source, schedule, method and sign-in review](./ACCESS-POLICIES.en.md) | Closed | Platform/asset reviews, one-use completion, current authorization and source/time/method restrictions. |
| E10 | [Web SSH and platform-identity CLI](./TESTING.en.md) | Closed | Real OpenSSH, gateways, revoked permissions and platform identities without returning target credentials. |
| E11 | [SFTP and file-operation audit](./SSH-WORKSPACES.en.md) | Closed | Real transfers, authorization, workspace-root binding and operation records. |
| E12 | [SSH session audit, replay and collaboration](./SESSION-SHARING.en.md) | Closed | Encrypted replay, read-only monitoring, interruption, named-user collaboration, watermarks and duration limits; RDP is E28. |
| E13 | [Sensitive-command rules, audit and review](./COMMAND-FILTERS.en.md) | Closed | Exact/contains/RE2 rules, deny/review and redaction for recognized commands; arbitrary shell semantics are outside this completed claim. |
| E14 | [Trusted directory controls across execution paths](./EXECUTION-DIRECTORIES.en.md) | Partial | Single-job trusted cwd/kernel workspace passed; batch/template/schedule/Playbook propagation is unverified work in progress, and full interactive cwd remains open. |
| E15 | [Encrypted credentials, managed accounts and imports](./MANAGED-ACCOUNTS.en.md) | Closed | Vault, named SSH accounts, account grants and atomic/idempotent CSV/XLSX imports. |
| E16 | [Linux SSH account discovery and lifecycle](./REMOTE-ACCOUNTS.en.md) | Closed | Regular-account discovery, schedules, approval, creation/disable/restore and deletion preserving home data; other platforms are E18. |
| E17 | [SSH password/key rotation and authentication checks](./ACCOUNT-CHECKS.en.md) | Closed | Seven-day schedules, per-item results/retries, credential recovery history, periodic authentication and no replay after restart. |
| E18 | [Windows/database account PAM](./ROTATION-PLANS.en.md) | Undelivered | Windows/database account discovery, bulk rotation and recovery have no accepted delivery. |
| E19 | [SSH host monitoring, history and alerts](./MONITOR-ALERTS.en.md) | Closed | CPU/memory/disk/network, historical charts, authorization, offline/threshold alerts and notifications. |
| E20 | [Remote tools and native agent](./HOST-PLUGINS.en.md) | Closed | banhack233/node_exporter detection/install, startup/recovery, upgrade/rollback, policy and audit. |
| E21 | [Jobs, templates, schedules and Playbooks](./PLAYBOOKS.en.md) | Partial | Bounded Go orchestration and cron exist; full Ansible scope, directory propagation and long-term history capacity remain open. |
| E22 | [Enterprise notification channels](./NOTIFICATIONS.en.md) | Partial | In-app, TLS mail, signed Webhooks and custom SMS exist; native cloud SMS/IM providers remain open. |
| E23 | [Multi-stage access-request tickets](./ACCESS-TICKETS.en.md) | Closed | One to five review stages, published scopes, amendment reset, temporary grants, revocation and recovery. |
| E24 | [Enterprise operations reports](./REPORTS.en.md) | Partial | Authorized statistics, UTC trends and CSV exist; scheduled reports, PDF and a full historical warehouse remain open. |
| E25 | [Cloud inventory coverage and live-cloud acceptance](./ASSET-DISCOVERY.en.md) | Partial | LAN/AWS/Alibaba ECS/Tencent CVM exist; cloud adapters use signed fixtures, with real-account acceptance and remaining providers open. |
| E26 | [Enterprise SQL database protocols](./SQLSERVER.en.md) | Partial | PostgreSQL/MySQL/MariaDB/SQL Server/ClickHouse exist; Oracle/DB2/Dameng and complete native-client proxying remain open. |
| E27 | [Redis/MongoDB and native-client proxying](./NOSQL.en.md) | Partial | Native protocol consoles exist; node discovery and native TCP client proxying remain open. |
| E28 | [Enterprise RDP desktops](./RDP.en.md) | Partial | Go desktops, input, text clipboard, monitoring and replay exist; real Windows NLA, full high-definition scope and sharing remain open. |
| E29 | [Kubernetes operations](./KUBERNETES.en.md) | Partial | Web/CLI Pod/container terminals exist; files, jobs, resource management and cloud-token refresh remain open. |
| E30 | [Telnet network-device operations](./TELNET.en.md) | Partial | Real terminals/gateways/audit exist; device MFA, scripted sign-in and rotation remain open. |
| E31 | [Web assets and scripted autofill](./BASELINE.en.md) | Undelivered | No accepted end-to-end delivery. |
| E32 | [Virtual applications and app marketplace](./BASELINE.en.md) | Undelivered | Remote Chrome/DBeaver application delivery and an application marketplace are unaccepted. |
| E33 | [Facial recognition](./BASELINE.en.md) | Undelivered | No accepted end-to-end delivery. |
| E34 | [AI assistant and conversation audit](./BASELINE.en.md) | Undelivered | No accepted end-to-end delivery. |
| E35 | [External/cloud replay storage](./BASELINE.en.md) | Undelivered | Local encrypted replay exists; S3/OSS/COS/OBS/SFTP replay backends have no accepted delivery. |
| E36 | [SSH user certificate issuance](./SSH-CERTIFICATES.en.md) | Implementation awaiting verification | Built-in Ed25519 CA/OpenBao, short-lived account/gateway credentials, two-phase CA rotation, permissions/audit, Web/CLI/SDK and cases are authored. Operators distribute target trust; actual end-to-end unified acceptance has not run. |
| E37 | [Backup/recovery across versions and deployments](./BACKUP.en.md) | Partial | Standalone offline encrypted export/idempotent import passed; cross-version migration, online backup and PostgreSQL cluster backup remain open. |
| E38 | [Updates and historical-release migration](./INSTALLATION.en.md) | Partial | Checks/staging/install transactions/rollback and a fixed historical-source drill exist; actual historical-release compatibility remains unaccepted. |
| E39 | [Production cluster availability](./CLUSTER-HA.en.md) | Partial | PostgreSQL single-active takeover exists; strict partition fencing, database/shared-storage failures, multi-active operation and production drills remain open. |
| E40 | [Complete REST and component compatibility](./BASELINE.en.md) | Partial | Four auth methods, organization headers and session/replay contracts remain; full API and upstream component registration parity lack a complete acceptance map. |
| E41 | [Labels](./LABELS.en.md) and [platform announcements](./ANNOUNCEMENTS.en.md) | Implementation awaiting verification | Catalog, asset/node inheritance, filtering after authorization, independent permissions, audit and organization isolation; platform notice management/publication/readings. Encryption, bilingual Web, CLI/SDK and cases are authored and await unified verification. |
| E42 | [Branding and Chinese/English presentation/UI/docs](./BRANDING.en.md) | Closed | Brand configuration, bilingual strings, automatic locale selection, paired docs and release-only changelog generation. |

## Closing order and verification gate

1. **Implement all 42 groups with cases and bilingual docs first.** SSH remains the development priority, but completing an SSH-only batch cannot start verification. Preserve directory/upgrade source and address remaining groups. If no historical formal Release exists, state support boundaries without fabricating release-migration evidence.
2. **Run unified verification only after every implementation is ready.** Until then, run no tests, builds, browser or Docker verification. Author idempotency, revision conflict, approval replay, restart, recovery and cross-module cases in advance, then run existing entrypoints together. Repair failures and rerun affected checks; expand regression for shared-path impact or unresolved failures.
3. **Clean and deliver.** Keep summaries and essential screenshots, clean owned resources safely and idempotently, then commit and push accepted scope. Intranet deployment remains cancelled; publication/changelog follow existing authorization and workflow. The complete Enterprise objective and 42-group denominator remain unchanged.

Every delivery must update this document and tell the user the **current scope, closed/total and percentage, batch delta, named remaining gaps, verified source and unverified changes**. New requirements must identify which scope changes. Do not keep starting more features and full regressions without this information, and do not equate passing tests with complete functionality.
