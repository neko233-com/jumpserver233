# Organization labels and resource inheritance

> [中文](./LABELS.md) | English

## Implementation status

E41 label and [platform announcement](./ANNOUNCEMENTS.en.md) source, Web, CLI/SDK, cases and bilingual docs are authored: **implementation ready, awaiting verification**. No tests, builds, browser or Docker verification ran in this batch. Unified verification starts after all 42 groups are implemented; authored cases are not acceptance evidence.

## Usage

`/console/labels` manages the current organization's shared catalog. Signed-in organization members can read the catalog. Labels have a key, value, color and description; a key can have multiple values. Each resource accepts up to 64 direct labels, with one value per key. Keys are trimmed and case-insensitive; values are case-sensitive. Limits are 64 Unicode characters for keys, 128 for values and 500 for descriptions. Control characters are rejected; colors use `#rrggbb`.

Bind labels to assets or nodes. Direct asset labels take precedence, followed by the nearest node and its parents. Higher precedence overrides the same key. Clearing direct labels restores inheritance; moving an asset changes inheritance immediately. Managed SSH accounts share their physical asset's labels without copying credentials or metadata. Labels support metadata and filtering and do not change SSH, file or asset authorization.

Inventory displays effective labels and supports exact filtering and key/value text search. Its resource-label link opens the relevant binding page. The management page shows direct selections, inheritance sources, revisions and audit. After a conflict, explicitly reload current revisions before selecting again. A failed unchanged network request can be retried directly.

## Permissions and organization scope

- `labels.manage`: create, edit and delete catalog entries in the current organization.
- `labels.assign`: bind labels to currently visible assets; nodes also require `nodes.manage`.
- `labels.audit`: read the organization's label change audit.

All three can be assigned through organization roles. Catalog authority does not grant target access; inaccessible bindings return 404. Every request, including an idempotent retry, rechecks current target authority. Ordinary members can read bindings for authorized assets and their ancestor nodes. The catalog is shared within an organization; `X-JMS-ORG` isolates catalogs, bindings, receipts and audit. `GLOBAL` does not silently select another organization's data.

A label attached to a live resource cannot be deleted. Clear those direct bindings first. When deleting a label, stale bindings can be removed only after their resources are proven absent. Existence-read failures conservatively preserve bindings; live resources are not automatically detached.

## API, CLI and SDK

| API | Purpose |
|---|---|
| `GET /api/v1/labels/labels?search=&offset=0&limit=20` | Search/page catalog, maximum limit 100 |
| `GET /api/v1/labels/choices` | Bounded compact catalog choices without descriptions |
| `POST /api/v1/labels/labels` | Create with revision 0 |
| `PUT /api/v1/labels/labels/{id}` | Edit with current revision |
| `DELETE /api/v1/labels/labels/{id}` | JSON revision and request_id |
| `GET /api/v1/labels/bindings/{asset\|node}/{id}` | Direct binding, effective labels and assignment authority |
| `PUT /api/v1/labels/bindings/{asset\|node}/{id}` | Replace direct labels with label_ids, revision and request_id |
| `GET /api/v1/labels/audit?offset=0&limit=20` | Paginated change audit |
| `GET /api/v1/assets?label=ID&label=OTHER_ID` | AND-match effective labels after authorization filtering |

Writes use the current revision and an 8–100 character alphanumeric, `_` or `-` request ID. The same actor/request ID and normalized content return the original result; changed content conflicts. Replaying an old create/bind receipt does not restore a subsequently deleted label or overwrite cleared bindings. Empty bindings retain revisions, preventing stale revision 0 from recreating them.

```sh
jms labels list --search production
jms labels choices
jms labels save --file label.json
jms labels save LABEL_ID --file update.json
jms labels binding asset ASSET_ID
jms labels bind node NODE_ID --file binding.json
jms labels delete LABEL_ID --revision 2 --request-id delete-label-001
jms labels audit
```

New `label.json`:

```json
{"name":"Environment","value":"production","color":"#58a6ff","description":"Primary hosts","revision":0,"request_id":"create-label-001"}
```

`binding.json`:

```json
{"label_ids":["label-0123456789abcdef0123456789abcdef"],"revision":0,"request_id":"bind-label-001"}
```

CLI accepts stdin via `--file -` and rejects unknown JSON fields. SDK methods are `sessionclient.Labels`, `LabelChoices`, `SaveLabel`, `DeleteLabel`, `LabelBinding`, `BindLabels` and `LabelAudit`; use the existing `WithOrganization` client for organization selection.

## Storage and final verification

The default organization uses `JMS_DATA_DIR/labels.json`; other organizations use their own directories. AES-GCM envelope v1 uses the organization's Vault-derived key. PostgreSQL stores an organization-scoped `labels` document. Startup/installation offline preflight open and validate it; unknown formats are rejected. Stopped-state full backups cover the data directory and keys; the new label recovery path awaits unified verification.

Current per-organization limits are 2000 labels, 20000 bindings, 4000 immutable management receipts and 32 MiB plaintext state. Full receipt capacity rejects new changes while allowing saved retries; records are not silently evicted. An explicit archive/migration policy remains necessary for longer operation; unlimited history is not promised. Audit retains the latest 1000 metadata-only entries: actor, action, resource ID, revision and time. Inventory uses compact labels and the page loads on demand; size and performance have not been measured.

Authored cases cover Go core/concurrency/PostgreSQL, API permissions/filtering, CLI, organization-runtime reopen, full-backup recovery and bilingual narrow-screen Playwright flows. They cover failed-persistence atomicity, revision conflicts, retries, replay after deletion, permission revocation, managed-account ownership, nearest-node inheritance, an unchanged retry after network failure and cleanup. Native packaging reuses its existing restart for label/announcement encryption, persistence and receipts without extra containers or restarts. Linux race includes the label package for the final unified run. This batch produces no new passing report or screenshot.
