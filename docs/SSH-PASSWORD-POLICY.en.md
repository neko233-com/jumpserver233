# Generated SSH password policy

> [中文](./SSH-PASSWORD-POLICY.md) | English

Configure lengths, category minima and exclusions for new random SSH password rotations in an organization. Seven-day automatic rotation, manual asset rotation and [credential rotation plans](./ROTATION-PLANS.en.md) share the generator. Passwords go only to encrypted Vault/recovery journals and authorized remote rotation; Web, CLI and policy receipts never return generated passwords.

## Additional plan constraints

[Rotation plans](./ROTATION-PLANS.en.md) accept an optional `password_policy` with the same rules, without the organization policy revision. Omitted or empty rules inherit organization configuration. New passwords must satisfy both the plan and every participating organization policy; conflicts stop that account before changing it. Run records capture the plan rules and pending encrypted journals never regenerate their selected password.

Example public plan metadata:

```json
{"name":"Weekly SSH operations","kind":"interval","enabled":false,"interval_hours":168,"only_due":true,"revision":0,"targets":[{"account_id":"managed-account-id"}],"password_policy":{"min_length":56,"max_length":80,"min_upper":6,"min_lower":5,"min_digits":8,"min_symbols":4,"exclude":"OI1l0"}}
```

## Use

Console → Credential rotation plans → Generated SSH password policy. Expand rules and set minimum/maximum length, uppercase/lowercase/digit/symbol minima and optional exclusions. Independent `accounts.password_policy.view` / `accounts.password_policy.manage` permissions support organization roles. Users with policy permissions can access the card without plan permissions.

Defaults: minimum 43, maximum 128, at least one character per category. Lengths must be 16–128; category minima must fit the maximum. Generated length is the greater of minimum length and summed category minima. Sampling/shuffling uses `crypto/rand`. Alphabet: ASCII letters, digits and `!#%+,-.=?@[]^_{}~`. Exclusions must be unique alphabet characters and leave at least 16 possibilities. Custom regex and scripts are unsupported. [Fixed-password plans](./FIXED-PASSWORDS.en.md) use separate write-only input and the same organization/plan rules.

Rules are read when a new password is generated. Uncertain operations retain their existing encrypted candidate rather than regenerate after policy edits. [Historical credential recovery](./PASSWORD-ROTATION.en.md), imported credentials and platform login passwords are outside this generator policy. OS/PAM may enforce additional restrictions; new credentials commit only after remote verification.

## Shared identities

Duplicate actual host/accounts across organizations combine the strongest category minima, greatest minimum length, smallest maximum length and union of exclusions. Loaded inventories of disabled/archived organizations also participate. Incompatible constraints refuse rotation with a shared-credential conflict; remote passwords and all Vaults retain their previous values. Other organizations' policy details are not disclosed.

## API and CLI

`GET /api/v1/accounts/password-policy` returns current `policy` and up to 200 audit changes. `PUT` accepts `request_id` and complete `policy` including current `revision`. Changes advance revision; identical rules add no revision/audit entry. The latest 100 request receipts bind original input and actor. Replay returns current state; changed contents/actor or stale revisions on new requests return 409. Current identity, permissions and organization are rechecked.

```sh
jms account password-policy show
jms account password-policy set --file ssh-policy.json
```

Public rule example, containing no credentials:

```json
{"request_id":"ssh-policy-001","policy":{"revision":1,"min_length":48,"max_length":64,"min_upper":4,"min_lower":4,"min_digits":5,"min_symbols":3,"exclude":"OI1l0"}}
```

Go clients use `SSHPasswordPolicy` / `SaveSSHPasswordPolicy` with platform authentication and `X-JMS-ORG`, without remote passwords.

Policy, audit and receipts are encrypted with the organization Vault key in `ssh-password-policy.json`. Standalone requires no extra services; PostgreSQL single-active mode uses isolated organization documents. Startup/offline preflight validates policy state, refusing corruption or incorrect keys. Full-site backup carries this file, Vault key and replay receipts together. This does not add live backups or multi-active operation.

## Scope and evidence

The competitor remains [JumpServer Enterprise](https://www.jumpserver.org/enterprise.html); its [official rotation guide](https://docs.fit2cloud.com/jumpserver/v3/guide/admin/account/account_change_secret/) documents specified and random strategies. This implementation uses native Go generation and shared constraints. Other protocol rotations and full Enterprise parity remain pending. Actual Go/Testify, race, native SSH/backup and bilingual browser results appear in [verification records](./TESTING.en.md).
