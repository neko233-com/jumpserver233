# Fixed-password rotation and idempotent saves

> [中文](./FIXED-PASSWORDS.md) | English

SSH rotation plans support random generation and administrator-specified values, matching the choices in the [competitor's official guide](https://docs.fit2cloud.com/jumpserver/v3/guide/admin/account/account_change_secret/). Random generation remains the default. Fixed values enter through separate write-only input. Public Web/CLI/SDK plans, runs, audit and CSV never return them.

## Configuration and execution

Choose Protected fixed password in the plan editor. Creation requires a value. Editing always shows an empty field: blank preserves the protected value; new input replaces it. Selecting random generation removes the plan's saved value. Saving updates configuration; execution or scheduling changes credentials. Unfinished runs retain the original submitted snapshot. New settings apply to later runs.

Fixed values use 16–128 allowed characters from the [SSH password rules](./SSH-PASSWORD-POLICY.en.md). They must also satisfy plan constraints and every participating organization's current rules. Organization defaults require at least 43 characters and all four classes. Conflicts refuse the account before remote changes; archived/disabled organization stores still participate. Only password accounts use the value. Mixed plans retain normal key rotation; key-only plans reject fixed mode.

Periodic plans reuse the fixed value. Choose random generation when each execution needs a new password. Built-in seven-day rotation continues random generation. Remote PAM/history rules can also reject fixed values.

## Permissions and input

Independent permission `accounts.rotation.fixed_password` controls configuration, execution and recovery alongside existing plan, asset rotation and optional privileged-account rights. Ordinary SSH/Agent CLI users continue using platform identities. This permission provides no password read endpoint. Requests, replays and execution recheck current authority.

POST/PUT saves accept `request_id`, normal PlanInput and optional write-only `fixed_password`. Fixed mode requires a request ID. Creation or switching from random to fixed requires a value. Omitting it on an existing fixed plan preserves the protected value. Public responses contain `password_mode`, `save_request_id` and other metadata only. SDK uses `SaveRotationPlanRequest` / `RotationPlanSaveInput`; public DTOs remain separate.

CLI JSON contains metadata only:

```json
{"name":"Controlled SSH reset","kind":"manual","password_mode":"fixed","targets":[{"account_id":"managed-account-id"}]}
```

```sh
jms account rotation create --file plan.metadata.json --request-id fixed-plan-001 --fixed-password-file -
jms account rotation update PLAN_ID --file edited.metadata.json --request-id fixed-plan-002 --fixed-password-file /secure/fixed.jms-secret
```

Stdin supports pipes and terminals without echo. Input files must be regular; Unix permissions must restrict access to the owner. Plain passwords are not command arguments. Omitting the file flag preserves an existing value. Keep private files outside the checkout; Git/Docker also ignore `*.jms-secret`. CLI and new Web saves always send request IDs; explicit CLI IDs support retries.

## Replays and persistence

A request ID binds actor, target path and complete parsed input using an HMAC derived from the organization key. Exact replay returns the current plan without another revision or save audit. Changed input, actor or path returns 409. New saves check revisions. Replaying a deleted plan's original request returns 404 and never recreates it. Mutations expire receipts older than 90 days; capacity is 10000. New saves at capacity return 429; recorded requests still replay. Legacy random API saves without IDs retain their behavior.

Plan secrets and unfinished run snapshots live in organization AES-GCM documents. Completed runs clear their copy. Asset receipts retain only opaque operation identities; credential fields remain encrypted. Pending operations recover the already selected value. Site backups preserve settings, receipts and unfinished runs. Existing empty documents or documents missing required blocks refuse loading.

This uses the existing Linux SSH rotation channel. Other protocols and full Enterprise work remain active. See [verification](./TESTING.en.md).
