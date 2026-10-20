# Individual and bulk SSH rotation retries

> [中文](./ROTATION-RETRIES.md) | English

Execution results provide Retry this account and Retry unsuccessful accounts, following the individual/bulk retry features in [JumpServer Enterprise's official history](https://docs.fit2cloud.com/jumpserver/v3/change_log/). A new linked execution preserves the original results. Successful and not-due items are excluded. This uses the existing Linux SSH password/key rotation engines.

## Usage

1. Open a completed execution and choose one or all unsuccessful items.
2. Confirm the current plan revision, password source and extra constraints. Retries use current plan settings and capture a new immutable snapshot. Fixed values never return to the browser.
3. Inspect per-account results in the new execution. Navigate to its original record or open the retry from that record. Historical aliases of the same remote account expand together and share one remote operation.
4. Continue from a failed retry's own results. Each source item creates one subsequent attempt; a different request ID cannot consume it again. Other items without a retry remain independently selectable.

Eligible states are `failed`, `denied`, `changed`, `cancelled` and `interrupted`. The whole source run must be terminal; pending outcomes require recovery first. The server inspects the original Vault receipt before creating another operation. Success, changed source, uncertainty and inspection errors refuse new work. A credential version changed since a dispatched source also refuses retry; an intentional new change needs a reviewed fresh plan execution. A source changed before dispatch may retry after the plan is corrected and saved.

The current plan must still contain the selected accounts, with the same asset identity, username and credential kind. Revision conflicts, removed targets, authority or binding changes refuse or record source changes. An individual failure never repeats already successful items. Retry leaves schedule enablement and next dispatch time unchanged.

## API, CLI and SDK

`POST /api/v1/accounts/rotation-runs/{runID}/retry` returns 202:

```json
{"request_id":"ssh-retry-001","plan_revision":3,"item_ids":["rotation-item-example"]}
```

Omitting `item_ids` selects all remaining retryable items. Explicit lists allow up to 500 entries; duplicate/invalid IDs are refused. Source run, request ID, actor, plan revision and sorted selection bind the request. Exact replay returns the existing child execution's current state without dispatching again. Changed input returns 409. Normal whole-plan execution cannot borrow a retry request ID.

```sh
jms account rotation show-plan PLAN_ID
jms account rotation retry RUN_ID --plan-revision CURRENT_REVISION --items ITEM_ID --request-id ssh-retry-001 --wait
jms account rotation retry RUN_ID --plan-revision CURRENT_REVISION --request-id ssh-retry-bulk-001 --wait
```

CLI uses platform identity and organization without target passwords. SDK provides `RetryRotationRun` / `RotationRetryInput`. Public DTOs and CSV add lineage metadata such as `parent_run_id`, `source_item_id` and `retry_run_id`. Passwords, internal credential identities and execution intents remain private.

## Authority, persistence and recovery

Existing `accounts.rotation.execute`, `assets.rotate`, organization-wide visibility and owner boundaries apply. Other owners require `accounts.rotation.manage_all`. Selected privileged accounts and fixed-password strategy recheck their independent rights; each execution step still enforces current access policies. Exact replays also reauthorize.

Source claims, the new run and its `retried` audit commit in one encrypted organization document. Concurrent identical requests obtain the same execution; competing requests cannot consume a source twice. After failed result persistence or PostgreSQL single-active takeover, existing intents inspect Vault receipts instead of repeating remote effects. Site backups preserve lineage and snapshots.

Terminal executions retain their original 90-day window. If any connected lineage member still needs retention, the whole chain remains to avoid dangling links or reconsuming a source. Once every member expires, the next mutation removes the chain. Existing 512-run/64 MiB limits remain. Older programs strictly refuse the new fields; downgrade through a compatible full-site backup.

English/Chinese UI and feature translations load on demand without dependencies. Native Docker/OpenSSH acceptance uses `scripts/native-package-qa.mjs --batch rotation-retry`; unified results appear in [Testing](./TESTING.en.md). Full Enterprise work remains active.
