# Durable execution history

> [中文](./EXECUTION-HISTORY.md) | English

This batch moves terminal ordinary SSH jobs, Playbook child jobs and operation runs out of bounded dispatch state. Standalone uses embedded SQLite without an extra service; clusters reuse PostgreSQL. Source and cases are authored; unified verification has not run.

## Retention and access

- Hot state remains limited to 1,000 records. At 800 records, a pass moves up to 64 oldest terminal records. Playbook reservations reaching 18,000 steps also trigger compaction. Active execution, review, dispatch and unsettled cancellation remain hot. Existing capacity limits still apply when active or dedicated collector records fill the window.
- Jobs preserve commands, stdout/stderr, identity, directory proofs and original request IDs. Runs preserve complete steps and the original Playbook source, even after that source leaves hot state.
- `/api/v1/ops/jobs` and `/api/v1/ops/runs` merge hot and durable pages. Existing detail routes and ownership permissions apply. Historical run list summaries omit large step arrays; opening browser details fetches the full record. Output permissions are checked separately.
- Retrying an actor/request identity returns its original job or run. Changed parameters or trigger origin conflict. Historical runs never enter dispatch or replay remote operations.
- Commit the archive transaction before removing hot copies. A failed hot save retains the original records. Queries exclude duplicate IDs and repeated compaction reuses immutable evidence. Storage errors retain evidence and surface as failures.

## Storage

Each organization's `execution-history.sqlite` uses WAL, full synchronization and an application format identifier. Bodies and summaries are compressed and encrypted with its existing AES-GCM key. Owner, receipt and body digest indexes use context-separated HMAC; credentials are never stored in plaintext. Organization, kind, owner and timestamp indexes let lists avoid loading full output.

A body is limited to 16 MiB and a summary to 512 KiB. History has no automatic expiry; monitor disk capacity. Reads validate directory, time, record ID, index identity and ciphertext bindings. Unknown SQLite/encrypted formats and wrong keys fail closed. PostgreSQL scopes derive from the existing namespace/prefix and share the existing pool.

SQLite physical user_version and encrypted metadata both use format 1; unknown versions fail closed. SSH job statistics stream archived summaries by time/ID without loading output bodies. There is no separate report-fact table or permanent statistics warehouse.

## Upgrade and recovery

Jobs write v7 and read v1–v7; Operations write v6 and read v1–v6. Older binaries cannot read the new formats. Rollback requires the complete pre-upgrade data and key; replacing binaries or deleting the history database is insufficient.

Backups must include hot state, history and the key. Archive the complete data directory after stopping the service. Copying a running SQLite main file alone does not produce a consistent snapshot; use a backup entrypoint with consistency support. PostgreSQL backups must include `jms233_history_meta` and `jms233_history_records`; JSON document export alone cannot recover historical evidence.

## Cases awaiting the unified run

Standalone `--check-data` authenticates every archived summary/body before listeners/workers, including disabled/archived organizations. Memory is bounded by one row. Missing history is not created; orphan WAL/SHM, corruption and unknown formats reject activation. Offline backups retain database/WAL/SHM. Cases simulate process exit with uncheckpointed commits, recovery and original-request lookup; they are authored and unrun.

Authored Testify cases cover retention beyond 1,000 records, owner isolation, deep pagination, output/source recovery, durable request replay, changed-input conflicts, transaction rollback, failed hot saves, duplicate crash copies, index/ciphertext tampering, wrong keys, restart, cancellation/dispatch boundaries and PostgreSQL organization takeover. Authored cases do not establish acceptance.
