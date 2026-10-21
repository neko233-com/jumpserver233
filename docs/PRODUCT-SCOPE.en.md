# Product definition and current delivery scope

> [中文](./PRODUCT-SCOPE.md) | English

On 2026-10-21 the user corrected the objective: **an independent mini SSH bastion for small and medium businesses, deployed on one machine, with few dependencies, easy operation and maintenance, security and efficiency.** This supersedes the earlier full-Enterprise-parity and all-42-groups interpretation. JumpServer Enterprise is a usability/security reference; a competitor feature does not create an implementation requirement.

## Required now

1. **Simple access:** host inventory, groups, search, favorites and multiple accounts; Web SSH, platform-identity CLI/Agent CLI and SFTP. The platform holds target credentials so operators need not obtain passwords.
2. **Reliable authorization and audit:** user/role/asset access, online revocation, host-key verification, recordings, file/command evidence, redaction, command denial and review. Controlled execution enforces exact/subtree/regex directory policies.
3. **Practical operations:** CPU, memory, disk, network, availability, necessary history/alerts; seven-day SSH password/key rotation, checks, retry and recovery. Enable native host agents and tool detection/installation when needed.
4. **Recoverable updates/data:** update checks, controlled install/rollback and idempotent export/import. Preserve assets, credentials, grants and audit across upgrades. State the supported version range and exercise recovery.
5. **Light deployment:** one Go service, static web assets and one persistent data directory. Runtime does not require Node, Redis, PostgreSQL, Docker, cloud accounts, an external identity platform or AI. Preserve existing encrypted local files; embedded SQLite execution history adds no resident service.
6. **Maintainable delivery:** Chinese/English introductions, UI/docs and automatic language choice; release-only changelog; finish build speed, size, performance, `.gitignore` and idempotent QA cleanup together.

## No expansion in this delivery

Cloud sync/23-provider parity, additional database protocols, app markets/virtual apps, face recognition, complex enterprise identity integrations, BI/PDF/email reports, multi-active clusters and mandatory Ansible/Docker runtimes are outside the current objective. Preserve delivered capabilities/user data and withdraw this batch's unpublished extensions unrelated to mini use; stop filling competitor gaps. Add extensions only for an explicit use case.

Standalone is the default acceptance environment. Existing PostgreSQL standby support is an optional legacy extension. The default frontend packages only the mini SSH workflow. Seventeen cloud, AI, complex identity, database audit, external replay storage and related Enterprise pages leave the product routes/build graph. Source, compatible backend APIs and existing data remain. Less frequent local controls sit under “More features”; visibility does not replace server authorization.

## Progress and verification

The primary checklist is [PROGRESS S01–S12](./PROGRESS.en.md), **12 items**. The former primary goal had 42 groups; the user's explicit product correction changes it to 12. Keep E01–E42 as historical research, exclude them from current remaining work, and give no completion credit for changing scope.

The historical SSH baseline was **9/12 (75%)**. Unified verification and delivery close **12/12 (100%), +3**; changing scope itself earns zero credit. See the [mini acceptance report](./MINI-ACCEPTANCE.en.md) for source identity, results, skips and deployment limits.

Author the necessary mini stable-release batch, then run unified Go/Testify, relevant race checks, production builds, bilingual browser and isolated Docker verification. Include idempotence, restart, revocation, upgrade/recovery, performance and size. Retain compact reports/essential screenshots and clean owned resources idempotently. Do not wait for 42 Enterprise groups or repeatedly run the whole suite after tiny changes. No intranet deployment now; publish once after the stable-release gate is met.
