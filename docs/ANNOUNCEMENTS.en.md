# Platform announcements

> [中文](./ANNOUNCEMENTS.md) | English

## Implementation status

Core, API, Web, CLI/SDK and authored cases are connected. **Tests, builds, browser and Docker verification have not run.** The user's 2026-10-20 instruction requires all 42 groups to be implemented before unified verification. [Organization label](./LABELS.en.md) source/cases are also authored; E41 is implementation-ready and awaiting verification, with no accepted completion credit.

## Usage

Open `/console/announcements`. Every authenticated platform identity can read active notices. System permission `announcements.manage` controls management and cannot be granted through organization roles. Notices and personal reading receipts are shared across organization switches; they are separate from organization notification channels.

Managers create drafts, publish, pin, edit and delete. Titles/content support English and Chinese with fallback to available content; at least one title and one body are required. Content is plain text without executing HTML, scripts or Markdown. Empty start means immediate publication; empty end means no expiry. The interval is `starts_at <= now < ends_at`. Readers cannot see drafts or inactive windows; managers retain them.

Writes use revisions; stale revisions return `409`. Create/edit/delete require a `request_id` of 8–100 letters/digits/underscores/hyphens. Identical requests by the same platform actor return the original receipt; changed payloads conflict. Failed persistence commits no content, revision or receipt. Replaying creation after deletion does not recreate the notice. Web retries unchanged forms using the same request ID.

Reading confirmations bind the current platform identity and notice revision; requests cannot name another reader. Repeats retain the original timestamp, while content revisions require reading again. Stale revisions conflict, and inactive/unpublished notices cannot be acknowledged. Change audit stores actor, ID, revision, action and time without copying content.

## API and CLI

- `GET /api/v1/announcements?offset=0&limit=20`: active notices, personal reading state and unread count.
- `GET /api/v1/announcements?manage=true`: management view, requiring system notice permission.
- `POST /api/v1/announcements`, `PUT /api/v1/announcements/{id}`: create/edit.
- `DELETE /api/v1/announcements/{id}`: JSON body with `revision` and `request_id`.
- `POST /api/v1/announcements/{id}/read`: JSON body with current `revision`.
- `GET /api/v1/announcements/audit`: paginated management audit.

```sh
jms announcements list
jms announcements list --manage
jms announcements save --file notice.json
jms announcements save NOTICE_ID --file update.json
jms announcements read NOTICE_ID --revision 2
jms announcements delete NOTICE_ID --revision 2 --request-id delete-notice-001
jms announcements audit
```

Example input:

```json
{
  "title": {"en": "Maintenance", "zh-CN": "维护通知"},
  "body": {"en": "SSH access remains available.", "zh-CN": "SSH 访问保持可用。"},
  "severity": "maintenance",
  "published": true,
  "pinned": false,
  "revision": 0,
  "request_id": "create-notice-001"
}
```

The SDK provides Announcements, SaveAnnouncement, DeleteAnnouncement, ReadAnnouncement and AnnouncementAudit, validating IDs before path construction. Platform identity is independent of target SSH credentials.

## Data and boundaries

Standalone data lives in `JMS_DATA_DIR/announcements.json` with AES-GCM using the platform identity-derived key. PostgreSQL uses `platform-identity:announcements`. Startup/offline preflight opens and validates it, rejecting unknown envelopes. The existing full-site offline backup includes this data file and key; actual recovery/takeover acceptance awaits final unified verification.

Limits are 500 notices, 20,000 current reading receipts, 4,000 management request receipts, the latest 1,000 audit events and a 16 MiB decrypted document, whichever is reached first. Capacity failures reject writes without silently dropping idempotency receipts. Each language allows 200 Unicode title characters and 16,000 body characters; pages cap at 100. Attachments, email delivery and legal signatures are outside this implementation; a reading record confirms the current identity's acknowledgement.
