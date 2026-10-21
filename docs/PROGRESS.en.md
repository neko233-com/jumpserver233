# Delivery progress and acceptance checklist

> [中文](./PROGRESS.md) | English

[Current maintenance batch](./MAINTENANCE.en.md): native IP HTTP, accurate login failures, cookie verification, manifest integrity and upgrade persistence. Official v0.2.1 publication and its single intranet upgrade passed. BuildWorld #5 completed 6/6 stages; default login, real SSH, monitoring and restart persistence passed. Subsequent CI found a native Playbook runtime race, repaired in source but absent from the published artifact; stable-release closure remains open.

## Current result — 2026-10-21

The accepted objective is an independent mini SSH bastion for small and medium businesses: standalone deployment, few dependencies, easy operation, security and maintenance. [PRODUCT-SCOPE](./PRODUCT-SCOPE.en.md) defines the scope; JumpServer Enterprise is a reference. Cloud parity and the archived 42-group research checklist do not create release requirements.

**Implementation ready: 12/12. Accepted: 11/12 (92%). S12 remains open because the published v0.2.1 artifact does not contain the subsequent runtime race repair.** The former 12/12 functional baseline is retained below; a subsequent CI race finding reopens S12 without changing scope. This is checklist coverage, not a guarantee about arbitrary shells, every deployment or competitor parity.

| Scope | Accepted | Remaining | Coverage |
|---|---:|---:|---:|
| Current mini SSH checklist | 11/12 | S12 stable artifact closure | **92%** |
| Historical Enterprise research | 16/42 | Outside current objective | **38%, archived** |

The unpublished cloud-provider, Ansible runtime and PDF/email warehouse expansion was withdrawn. Seventeen Enterprise pages leave the default frontend graph; asset labels and useful local controls remain. Existing compatibility APIs and data are retained. Local files plus embedded encrypted SQLite history require no database service.

## Initial mini verification baseline

See the [mini acceptance report](./MINI-ACCEPTANCE.en.md) for source identities, commands, reports and limits. Go/Testify: **2134 passed, 51 skipped**; Linux race: **195 passed, 4 skipped**; production browser: **55/55**; repaired console: **six widths × two languages**; Docker browser: **passed**; final native installation/upgrade suite: **passed**, source unchanged, six archives, real Windows CLI/Linux SSH/SFTP, directory enforcement, data recovery and update paths. Owned resources were removed twice. Skipped external integrations are not claimed as accepted.

Frontend total JavaScript is **1,641,659 bytes**, about **11% below** the initial batch build (1,841,868); initial JavaScript is 495,091 bytes (gzip 159,911). Budgets are unchanged. Vet/build/content pass; lint has no errors and retains five existing warnings in legacy modules. The subsequent v0.2.0 macOS intranet baseline passed; see [BuildWorld](./BUILDWORLD.en.md). Release notes remain generated only by release-please.

## Current maintenance acceptance

Maintenance adds no checklist item. Go/Testify: 2061 passed, 133 skipped; complete production browser: 69/69; native Mac deployment: 26/26; six-platform archives and isolated Docker browser passed. Official v0.2.1 was upgraded once; default sign-in, real SSH, host monitoring and original data retention passed. See [maintenance acceptance](./MAINTENANCE.en.md).

## Fixed mini checklist

| ID | Acceptance item | Status | Verified boundary |
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
| S10 | Directory rules across controlled execution paths | Closed | Real SSH jobs, templates, batches, once/interval/cron plans, every native Playbook step, interactive kernel cwd, review/replay refusal and encrypted audit; unknown cwd fails closed. Arbitrary internal shell semantics and filesystem ACL enforcement are excluded. |
| S11 | Update checks, data preservation and version boundaries | Closed | The first stable release establishes the support line. Known format migration, future-format refusal, backup/import, trial rollback, post-acceptance write preservation, forward recovery, scheduled and automatic installation pass. The actual official v0.2.0 → v0.2.1 macOS upgrade retained existing asset/audit/key identities. Synthetic version drills do not establish compatibility with arbitrary releases. |
| S12 | Final mini verification and delivery | Open after CI race finding | Unified backend/race/production-browser/Docker/native acceptance, bilingual UI/docs, compact inventory, bundle budgets, project-local UI skill, Jenkinsfile_mac_single, scoped cleanup and committed delivery. Native macOS/ARM and the actual v0.2.0 → v0.2.1 intranet upgrade passed in BuildWorld #5; see maintenance acceptance. |

## Historical Enterprise research: 42 groups, outside the current objective

Each row names a capability group and its accepted boundary or remaining extensions. Contract-level subfeature parity requires an explicit revision of this checklist; group counts must not be presented as coverage of every competitor subfeature.

| ID | Capability / evidence entrypoint | Status | Accepted boundary / gap |
|---|---|---|---|
| E01 | [Standalone deployment and native packages](./SSH-FIRST.en.md) | Closed | Same-port Go Web/API/WS, local encrypted persistence and six platform artifacts; runtime evidence covers Windows CLI and Linux. |
| E02 | [Users, groups, RBAC and local password security](./PASSWORD-SECURITY.en.md) | Closed | Identity lifecycle, permissions, password policy/history/expiry and restricted recovery. |
| E03 | [Local MFA, Passkey and RADIUS](./RADIUS.en.md) | Closed | OTP, Passkey, RADIUS primary/additional factors and platform review; cloud SMS is E06. |
| E04 | [Enterprise identity and federation](./IDENTITY-SOURCES.en.md) | Implementation awaiting verification | Named LDAP/OIDC/CAS/SAML, isolated callbacks/encryption/revocation, complete LDAP collection, group/organization mapping, schedules/retry/abort, Web/CLI/SDK and cases are authored; actual enterprise IdPs and unified acceptance remain unverified. |
| E05 | [WeCom, DingTalk and Feishu QR sign-in](./ENTERPRISE-LOGIN.en.md) | Implementation awaiting verification | Native authorization, tenant/internal membership checks, Feishu/Lark v2/v3 with PKCE, isolated sources/secrets, MFA/review/audit, bilingual Web, CLI/SDK and cases are authored; actual tenants, mobile scanning and unified validation have not run. |
| E06 | [Cloud SMS/CMPP MFA](./SMS-MFA.en.md) | Implementation awaiting verification | Native platform transport, initial/personal enrollment, enforcement, capability/limits/encryption, restart/drain, TOTP/RADIUS/review, bilingual Web, CLI/SDK and cases are authored; actual carriers and unified acceptance have not run. |
| E07 | [Asset trees, SSH gateways and grants](./GATEWAYS.en.md) | Closed | Node inheritance, account/action/time grants, host-key pinning and multiple hops; tags are E41. |
| E08 | [Organizations](./ORGANIZATIONS.en.md) and [global overview](./GLOBAL-ORGANIZATIONS.en.md) | Implementation awaiting verification | Existing isolation/roles plus LDAP organization mapping, independent global authority, inventory/cached health/activity summaries, bilingual Web, CLI/SDK and revocation/reopen/existing-takeover cases are authored; unified acceptance and production multi-organization drills have not run. |
| E09 | [Source, schedule, method and sign-in review](./ACCESS-POLICIES.en.md) | Closed | Platform/asset reviews, one-use completion, current authorization and source/time/method restrictions. |
| E10 | [Web SSH and platform-identity CLI](./TESTING.en.md) | Closed | Real OpenSSH, gateways, revoked permissions and platform identities without returning target credentials. |
| E11 | [SFTP and file-operation audit](./SSH-WORKSPACES.en.md) | Closed | Real transfers, authorization, workspace-root binding and operation records. |
| E12 | [SSH session audit, replay and collaboration](./SESSION-SHARING.en.md) | Closed | Encrypted replay, read-only monitoring, interruption, named-user collaboration, watermarks and duration limits; RDP is E28. |
| E13 | [Sensitive-command rules, audit and review](./COMMAND-FILTERS.en.md) | Closed | Exact/contains/RE2 rules, deny/review and redaction for recognized commands; arbitrary shell semantics are outside this completed claim. |
| E14 | [Trusted directory controls across execution paths](./EXECUTION-DIRECTORIES.en.md) | Implementation awaiting verification | Single jobs were accepted; batch/template/schedule/Playbook plus [native interactive submission cwd](./INTERACTIVE-DIRECTORIES.en.md), one-use leases, remeasurement, sharing/encrypted audit, bilingual display and cases are authored. Unified verification has not run; arbitrary internal shell semantics are excluded. |
| E15 | [Encrypted credentials, managed accounts and imports](./MANAGED-ACCOUNTS.en.md) | Closed | Vault, named SSH accounts, account grants and atomic/idempotent CSV/XLSX imports. |
| E16 | [Linux SSH account discovery and lifecycle](./REMOTE-ACCOUNTS.en.md) | Closed | Regular-account discovery, schedules, approval, creation/disable/restore and deletion preserving home data; other platforms are E18. |
| E17 | [SSH password/key rotation and authentication checks](./ACCOUNT-CHECKS.en.md) | Closed | Seven-day schedules, per-item results/retries, credential recovery history, periodic authentication and no replay after restart. |
| E18 | [Windows/database account PAM](./ACCOUNT-PAM.en.md) | Implementation awaiting verification | Windows local SAM and PostgreSQL/MySQL/MariaDB/SQL Server identity collection/enrollment, native batch reset/check/recovery, permissions/encryption/idempotence/reopen/shared transactions, bilingual Web, CLI/SDK and native/browser cases are authored. Actual runs await unified acceptance; other database protocols remain E26. |
| E19 | [SSH host monitoring, history and alerts](./MONITOR-ALERTS.en.md) | Closed | CPU/memory/disk/network, historical charts, authorization, offline/threshold alerts and notifications. |
| E20 | [Remote tools and native agent](./HOST-PLUGINS.en.md) | Closed | banhack233/node_exporter detection/install, startup/recovery, upgrade/rollback, policy and audit. |
| E21 | [Jobs, templates, schedules and Playbooks](./PLAYBOOKS.en.md) | Historical extension | Retain native Go jobs/plans, encrypted history, durable request deduplication and directory security. This batch's Ansible/Docker entrypoint is withdrawn and outside mini scope. |
| E22 | [Enterprise notification channels](./NATIVE-NOTIFICATIONS.en.md) | Implementation awaiting verification | Existing inbox/TLS mail/gateway plus native Alibaba/Tencent/Huawei/CMPP 2.0 SMS, WeCom/DingTalk/Feishu/Lark bots, receipts, permissions/queue, bilingual Web, CLI/SDK and cases are authored; actual vendors/carriers and unified verification have not run. |
| E23 | [Multi-stage access-request tickets](./ACCESS-TICKETS.en.md) | Closed | One to five review stages, published scopes, amendment reset, temporary grants, revocation and recovery. |
| E24 | [Enterprise operations reports](./REPORTS.en.md) | Historical extension | Preserve original statistics/CSV; withdraw this batch's unpublished PDF/scheduling/mail/warehouse. Outside the mini objective. |
| E25 | [Cloud inventory coverage and live-cloud acceptance](./ASSET-DISCOVERY.en.md) | Partial | LAN/AWS/Alibaba ECS/Tencent CVM exist; cloud adapters use signed fixtures, with real-account acceptance and remaining providers open. |
| E26 | [Enterprise SQL database protocols](./SQLSERVER.en.md) | Partial | PostgreSQL/MySQL/MariaDB/SQL Server/ClickHouse exist; Oracle/DB2/Dameng and complete native-client proxying remain open. |
| E27 | [Redis/MongoDB and native-client proxying](./NOSQL.en.md) | Partial | Native protocol consoles exist; node discovery and native TCP client proxying remain open. |
| E28 | [Enterprise RDP desktops](./RDP.en.md) | Partial | Go desktops, input, text clipboard, monitoring and replay exist; real Windows NLA, full high-definition scope and sharing remain open. |
| E29 | [Kubernetes operations](./KUBERNETES.en.md) | Partial | Web/CLI Pod/container terminals exist; files, jobs, resource management and cloud-token refresh remain open. |
| E30 | [Telnet network-device operations](./TELNET.en.md) | Partial | Real terminals/gateways/audit exist; device MFA, scripted sign-in and rotation remain open. |
| E31 | [Web assets and scripted autofill](./BASELINE.en.md) | Undelivered | No accepted end-to-end delivery. |
| E32 | [Virtual applications and app marketplace](./BASELINE.en.md) | Undelivered | Remote Chrome/DBeaver application delivery and an application marketplace are unaccepted. |
| E33 | [Facial recognition](./BASELINE.en.md) | Undelivered | No accepted end-to-end delivery. |
| E34 | [AI assistant and conversation audit](./AI-ASSISTANT.en.md) | Implementation awaiting verification | Organization providers/write-only keys, text advice, independent authority, receipts/revisions, revocation, encrypted history/archive/audit, drain/recovery/backup, bilingual Web, CLI/SDK and HTTPS/browser cases are authored; unified and real-provider acceptance have not run. |
| E35 | [External/cloud replay storage](./REPLAY-STORAGE.en.md) | Implementation awaiting verification | S3/OSS/COS/OBS/SFTP/PostgreSQL, encrypted queue/retries, lifecycle/drain integration, authorized replay, local-copy removal, cache/backups, bilingual Web, CLI/SDK and cases are authored; actual SSH/SFTP and one-restart entrypoints await unified acceptance after full implementation. |
| E36 | [SSH user certificate issuance](./SSH-CERTIFICATES.en.md) | Implementation awaiting verification | Built-in Ed25519 CA/OpenBao, short-lived account/gateway credentials, two-phase CA rotation, permissions/audit, Web/CLI/SDK and cases are authored. Operators distribute target trust; actual end-to-end unified acceptance has not run. |
| E37 | [Backup/recovery across versions and deployments](./BACKUP.en.md) | Partial | Standalone offline encrypted export/idempotent import passed; cross-version migration, online backup and PostgreSQL cluster backup remain open. |
| E38 | [Updates and historical-release migration](./INSTALLATION.en.md) | Partial | Checks/staging/install transactions/rollback and a fixed historical-source drill exist; actual historical-release compatibility remains unaccepted. |
| E39 | [Production cluster availability](./CLUSTER-HA.en.md) | Partial | PostgreSQL single-active takeover exists; strict partition fencing, database/shared-storage failures, multi-active operation and production drills remain open. |
| E40 | [Complete REST and component compatibility](./BASELINE.en.md) | Partial | Four auth methods, organization headers and session/replay contracts remain; full API and upstream component registration parity lack a complete acceptance map. |
| E41 | [Labels](./LABELS.en.md) and [platform announcements](./ANNOUNCEMENTS.en.md) | Implementation awaiting verification | Catalog, asset/node inheritance, filtering after authorization, independent permissions, audit and organization isolation; platform notice management/publication/readings. Encryption, bilingual Web, CLI/SDK and cases are authored and await unified verification. |
| E42 | [Branding and Chinese/English presentation/UI/docs](./BRANDING.en.md) | Closed | Brand configuration, bilingual strings, automatic locale selection, paired docs and release-only changelog generation. |
