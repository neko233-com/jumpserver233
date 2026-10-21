# Upgrade compatibility scope

> [中文](./UPGRADE-COMPATIBILITY.md) | English

## Official support line

The first official stable release establishes the published-version support line. Before closing this batch, the GitHub Release API returned no official releases on 2026-10-21; manifest `0.1.0` is an unpublished baseline. Earlier Alpha/development builds receive actual-format preflight without a version-number compatibility promise or forced data recreation.

Every subsequent stable release must identify the preceding official tag, source SHA, archive digest and data format, retaining actual old-to-new upgrade, export/import and rollback evidence. Renumbered `v0.0.x` packages built from identical source exercise installation transactions, not historical official-release migration.

## Known formats and rejection

| Object | Current boundary | Rejection behavior |
|---|---|---|
| Native archive | Manifest schema 1, preflight/activation protocol 1 | Verify paths/digests/platform/permissions; reject incompatibility |
| SSH jobs | Read envelope v1–v7, write v7; directory proof requires v6+ | Reject new semantics in old formats, corruption or unknown versions |
| Batch/schedules/Playbook | Read envelope v1–v6, write v6; directories require v5+, native Playbook v4+ | Preserve template/source snapshots; reject directory fields in old formats |
| Embedded history | SQLite application_id `0x4a4d5333`, user_version 1, encrypted metadata/body 1 | Reject wrong keys, unknown/corrupt formats and orphan WAL/SHM; do not create missing databases |
| Site backup | Archive format 1, integrity and Vault-key binding | Wrong passphrases, unknown formats, unsafe paths and corrupt archives never overwrite business data |
| Other state | Every module opens/validates its known encrypted format offline | Never infer compatibility from version strings; any failure blocks acceptance |
| Downgrade/rollback | Managed versions reject downgrades, different builds of the same version and data-root rebinding | Restore the entire old checkpoint before acceptance; preserve new writes and recover forward afterward |

Older software must not silently ignore new fields and execute. Rollback requires matching complete data, history and keys, not only executable replacement or history deletion. Restart requires sign-in again; business data and execution receipts remain.

## Actual batch evidence

- Passing complete Go/Testify cases verify every archived summary/body, disabled/archived organizations, corrupt/future formats and orphan WAL rejection. A native child exits after committing; offline backup restores WAL, original-request lookup and repeated imports that preserve later records.
- Valid Operations v1–v4 documents migrate to v6; forged directory fields reject without changing original bytes. Separate history cases cover the current write format.
- The complete native entrypoint passes future-envelope 999 refusal with original-byte preservation, users/grants/Vault/audit/template/plan retention, real SSH, trial rollback, post-acceptance writes and forward recovery.
- Scheduled/automatic installation performs actual stop/checkpoint/restart/acceptance; retries and restarts do not reinstall.

See [mini acceptance](./MINI-ACCEPTANCE.en.md) for source, reports, skips and six-platform limits. The earlier drill from pinned source `4367285202054181344e386096b89e8ea3059703` is historical evidence, not rebuilt by this batch's default entrypoint. Independently audit it with `node scripts/native-package-qa.mjs --batch historical-upgrade --historical`; an unrun entrypoint is not a pass.

Offline preflight opens no listener, starts no worker and executes no remote operation. Site backups require downtime. Online backup, PostgreSQL cluster backup, production multi-active operation and arbitrary migrations among all historical versions are outside this batch's promise.
