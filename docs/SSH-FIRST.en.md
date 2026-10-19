# Stable SSH bastion release

> [中文](./SSH-FIRST.md) | English

On 2026-10-19 the user prioritized a practical, stable enterprise SSH bastion with few deployment dependencies. [JumpServer Enterprise](https://www.jumpserver.org/enterprise.html) remains the competitor and long-term reference. Other protocols, cloud providers and complex Enterprise features are no longer prerequisites for this stable release. This document changes delivery order; it does not claim that pending capabilities are implemented.

## Default deployment

Prefer a single machine. The current default uses local persistent files and a Vault key under `JMS_DATA_DIR`, without an external database, Redis or a resident Node process. Go serves static pages, API and WebSocket on one port through `JMS_WEB_DIR`. Preserve existing file compatibility. Any later SQLite adoption must include verified, recoverable, idempotent migration without asking users to recreate assets or credentials.

PostgreSQL is an explicitly enabled option for single-active cluster failover; see [cluster HA](./CLUSTER-HA.en.md) for configuration and production limits. Cluster support must not make PostgreSQL a standalone installation requirement.

## Stable release acceptance

| Priority | Capability | Current state and completion criteria |
|---|---|---|
| P0 | SSH access and usability | Web SSH, `jms ssh` / `jms exec`, pinned host keys, multiple gateways, SFTP, grants and session replay exist. Verify real SSH connections, reconnects, revoked access and bilingual UI |
| P0 | Update checks and data preservation | [Published-release checks](./UPDATES.en.md), optional automatic checks and staging are integrated. [Installation transactions](./INSTALLATION.en.md) provide checkpoints, offline preflight, first-start health/traffic gates, rollback before release and old-service resumption; new data is preserved after release. Automatic installation scheduling and active SSH session handling remain pending. Formal Releases produce updates/changelogs |
| P0 | Full export and import | [Offline standalone backup](./BACKUP.en.md) passed acceptance: native CLI captures assets, organizations, identities, policies, Vault, audit, recordings and keys, with encrypted/versioned integrity preflight, idempotent import, retained old data and recovery journals. Wrong passphrases, damaged archives and unsupported archive formats do not replace business data. Application schema migration, live backup and PostgreSQL cluster backup remain pending |
| P0 | Upgrade and recovery rehearsal | Existing same-source injected-version evidence covers selection/retries, preflight recovery, actual SSH and identity/permission/command-audit retention. First-start fault fixtures are described in [installation](./INSTALLATION.en.md); final results belong in [testing](./TESTING.en.md). Historical-release format migrations remain unverified |
| P0 | Sensitive command audit and review | Encrypted command audit, exact/contains/RE2 rules, allow/deny/manual review, timeout rejection and a shared Web/CLI gateway exist. Verify parameter redaction, approval linkage and that rejected commands never execute |
| P0 | Directory rules | Optional [execution workspaces](./SSH-WORKSPACES.en.md) use a native helper and Linux kernel to confine whole-tree content access for Web/CLI shells and ordinary jobs; this batch's final testing determines acceptance. Exact/regex directory command policies and confined SFTP remain pending. Command text or inferred `cd` does not establish filesystem isolation |
| P1 | Daily SSH operations | Preserve monitoring, account/credential rotation, plugin detection/installation and Agent audit. Prioritize defects affecting core SSH use |
| Later | Complex Enterprise expansion | Add protocols, cloud providers, multi-active operation and integrations as needed; they do not block this SSH release |

## Data and command boundaries

Restore the Vault key together with encrypted `JMS_DATA_DIR` contents. An external `JMS_VAULT_KEY` must be retained separately with the same value. Existing [credential history backups](./PASSWORD-ROTATION.en.md) recover remote accounts; they are not full-site exports. Copying a live directory does not prove snapshot consistency.

Existing [PTY command filtering](./COMMAND-FILTERS.en.md) audits and blocks common interactive input. Arbitrary shells, aliases, scripts, symlinks, command substitution and root privileges affect directory semantics. Strong directory restrictions need a trusted Agent or controlled execution channel, combined with remote account permissions or isolation. A visible prompt, `PWD` variable or command string cannot be the sole authority. Clearly identify uncovered channels rather than silently allowing them while claiming protection.

## Delivery discipline

Complete each implementation batch before unified Go/Testify, race, production-browser and isolated-Docker verification. Cover idempotency, revision conflicts, restart and recovery. Keep essential reports; clean attributable test resources and prove repeated cleanup is safe. Maintain Chinese/English introductions, docs and automatic language detection. Do not deploy to the intranet; publish one formal release after this scope passes acceptance.
