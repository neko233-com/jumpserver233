# SSH account connectivity checks

> [中文](./ACCOUNT-CHECKS.md) | English

Use `/console/rotation-plans` to authenticate stored default or named SSH accounts with passwords, private keys and fingerprint-pinned gateway chains. Checks open no target session, execute no command and change no password, key, credential revision or rotation timestamp. Results describe the captured credential revision at that time, rather than current availability.

## Controls and authority

Choose **Check current credentials** for per-account status, errors, duration and credential revision. Each account record verifies its own credentials, route and access policy, including aliases of the same remote account. One successful record cannot hide another record's configuration error. Fixed-password plans check current Vault credentials, without using the candidate password or privileged collector.

Execution requires `accounts.rotation.check`, `accounts.rotation.view`, `assets.view_all` and `assets.probe`. It requires no rotation execution, fixed-password or privileged-rotation rights. Plan management additionally needs `accounts.rotation.manage`. Organization, owner/`manage_all` scope and current identity permissions still apply to viewing, execution and retries. Checks join the upgrade drain gate and recheck account/gateway bindings, pending credential recovery and access policies before and after authentication.

Periodic checks default to disabled. Choose 1–720 hours; the editor initially suggests 24 hours. Saving an enabled schedule can authenticate immediately. Checks and manual/once/interval rotations have independent schedules with one serial queue per plan. Checks do not move rotation `next_run`; revoked permission or retention capacity pauses only checks. Every check appears in the host's authentication logs; choose intervals appropriate to host lockout policies.

## API, CLI and SDK

```text
POST /api/v1/accounts/rotation-plans/{id}/checks
{"request_id":"check-owned-request-001"}

jms account rotation check PLAN_ID --request-id check-owned-request-001 --wait
```

The API returns 202 and supports the existing four authentication methods and `X-JMS-ORG`. The Go SDK method is `Client.CheckRotationPlan(ctx, planID, requestID)`. Inputs contain only a request ID, accepting no target credentials, commands or candidate passwords. Public runs use `operation: check`; existing rotation runs omit the field. JSON, CSV, notifications and CLI return metadata without authentication capabilities, keys or passwords.

The same actor, plan and request ID returns the original run without authenticating again. Reusing an ID between checking and rotation conflicts; replay still requires current permission. `--wait` exits nonzero for unsuccessful results. Read an existing run with `jms account rotation show-run RUN_ID`.

Terminal failed, denied, changed, cancelled and interrupted items support individual/bulk explicit retries through the existing [retry contract](./ROTATION-RETRIES.en.md), bound to the current plan revision. Check retries use current stored credentials, allowing repaired credentials to be checked again. Successes are excluded; each source item is claimed once, with linked history. Rotation retries retain their existing credential-version protection.

## Interruption, notifications and data

Authentication has an eight-second timeout inside a ten-second work deadline. If an authentication has started but its result cannot be written, or a restart/HA takeover occurs, the item becomes `check_interrupted` without automatically authenticating again. Unclaimed queued items can continue. Only an explicit retry creates another authentication attempt.

Unsuccessful terminal checks generate an `account_checks` source for the owner's `security` notifications; healthy checks stay silent. Details provide account count, state and a result link without credentials. Checks do not count as credential rotations in reports. Delivery, subscriptions and metadata authority follow the [notification center](./NOTIFICATIONS.en.md).

Schedules, runs, audit and retry relationships remain in existing encrypted data and survive backup export/import, with no additional service or database dependency. Older strict readers can reject new fields; downgrade requires a complete backup compatible with the older version. This feature does not establish complete interactive directory audit or full Enterprise parity.
