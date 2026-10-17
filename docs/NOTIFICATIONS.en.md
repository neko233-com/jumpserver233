# Notification center

> English | [中文](./NOTIFICATIONS.md)

The console header opens notifications with unread filtering, mark all read and related details. System events generate messages; tests send fixed messages only to the caller's subscriptions. Preferences are per user and organization, default to in-app, and support Chinese, English or automatic delivery language (last interface language).

2026-10-18, isolated Docker, synthetic contacts and a real OpenSSH job:

![Notification center](./images/notifications.en.png)

## Delivered sources

| Event | Recipients and current access |
| --- | --- |
| Ticket submission, amendments and stages | Requester and current CC subjects; eligible current reviewers also receive tasks; stale revisions/completed stages disappear |
| Ticket comments, rejection, cancellation and revocation | Requester and current CC subjects who can still read the ticket |
| Terminal SSH jobs | Owner who can still read the job |
| Terminal rotation plans | Run owner retaining rotation and all-assets view permissions |
| System test | Caller with active account and organization |

Messages contain only type, resource name, state, time, ID and detail link. Commands, stdout/stderr, comment text, target credentials and rotation secrets are excluded. Security alerts, platform/asset login reviews, databases and other protocol events are not connected to this center yet; existing review pages remain available. Native cloud SMS/CMPP, instant messaging adapters and overall Enterprise parity remain pending.

## Configuration and subscriptions

Organization administrators configure external channels with `notifications.manage`; channels default to disabled. Settings/preferences use revisions; stale writes return 409. Organization AES-GCM encrypts SMTP/gateway secrets. Reads never return secrets: omitted/null retains them, empty strings clear them, and the UI offers explicit clear checkboxes.

- **Email**: direct TLS or mandatory STARTTLS, TLS 1.2 minimum, hostname/certificate validation. Additional PEM CAs are supported; private keys/unrelated text are rejected. No plaintext fallback or certificate bypass. SMTP PLAIN happens only after TLS, with UTF-8 MIME and stable Message-ID.
- **Webhooks**: one fixed organization HTTPS endpoint; URL credentials, query strings, fragments and redirects are rejected. JSON includes id, organization_id, user_id, topic, title, text and source (kind/id/event_id/action). Bearer and HMAC-SHA256 are supported.
- **Custom SMS gateway**: HTTPS/Bearer/HMAC also apply. JSON adds to, and verification adds code. A 2xx response with `{"accepted":true}` is required for provider acceptance. The receiver adapts real providers.

Headers: `X-JMS-Notification-ID` (stable delivery ID), `X-JMS-Timestamp` (Unix seconds), `X-JMS-Signature` (hexadecimal HMAC-SHA256). Receivers should enforce timestamp tolerance and deduplicate by organization_id and delivery ID together. Signed bytes:

```text
timestamp + "\n" + delivery_id + "\n" + exact_request_body
```

Email uses ASCII addresses; phones use E.164 (synthetic example `+15555550123`). Save contacts, request verification, then subscribe. UI contact edits clear verification and channel subscriptions; the API rejects unverified subscriptions. Codes expire in 10 minutes and work once: 6 requests/user/hour, 60 seconds between requests for one contact, 8 attempts/code. APIs, CLI and audit never return codes. Tests are limited to 10/user/hour and idempotent by request_id. Disabling in-app affects future events only.

## Persistence, recovery and authorization

- Standalone uses `notifications.json`; cluster mode uses an organization-scoped PostgreSQL document, existing single-active election and organization keys. Notifications stop/drain before event sources. Node clocks must be synchronized.
- New stores persist their event start boundary and skip pre-deployment history. Cursor and messages/outbox commit atomically; stable event IDs deduplicate enqueue. Health retains source history gaps and shows currently unavailable sources.
- Dispatch runs every second with 4 concurrent senders. Organization, account, subscriptions, contacts, settings and source access are checked before sends. Configuration revisions fail old queued records, requiring explicit retry.
- Pre-send connection failures, explicit SMTP 4xx and HTTP 429 use bounded backoff, at most 5 attempts. Post-send disconnection, HTTP 5xx, missing SMS acceptance, receipt persistence failure and takeover of sending records yield uncertain outcomes without automatic replay.
- Manual retries require revisions/current access; uncertain outcomes require duplicate-risk acknowledgement. The original destination remains fixed. Verification codes require a fresh request.
- Provider acceptance proves an SMTP/gateway acknowledgement, not inbox or handset delivery. Revoking permissions cannot recall already accepted messages.
- Messages/deliveries retain 30 days; audit is bounded to 20,000 entries and 365 days. Limits: 20,000 messages, 40,000 deliveries, 64 MiB decrypted state, hourly cleanup. Capacity exhaustion returns errors instead of silently evicting retained messages. Preferences/configuration remain until changed.
- `notifications.audit` reads organization masked deliveries, health and audit; `notifications.retry` retries other users' records. Regular users see only their currently authorized messages and masked delivery history. Audit excludes secrets, codes and bodies.

## API / CLI / SDK

Base `/api/v1/notifications` supports the existing four authentication methods and `X-JMS-ORG`:

| Path | Method |
| --- | --- |
| /inbox?unread=true&offset=0&limit=25 | GET results/total/unread |
| /read | POST id or all=true |
| /preferences | GET / PUT caller preferences |
| /locale | POST language |
| /verification/request, /verification/confirm | POST channel / code |
| /settings | GET / PUT administrator settings |
| /test | POST request_id |
| /deliveries, /audit, /health | GET paged deliveries, audit, health |
| /deliveries/{id}/retry | POST revision / acknowledge_uncertain |

```sh
jms notifications list --unread --limit 25
jms notifications preferences
jms notifications preferences-save --file preferences.json
jms notifications request-code email
jms notifications verify email --code-stdin
jms notifications test --request-id synthetic-test-1
jms notifications deliveries
jms notifications retry delivery-ID --revision 3 --acknowledge-uncertain
jms notifications settings-save --file -
jms notifications health
```

SDK: `internal/sessionclient/notifications.go`. Read codes from stdin instead of process arguments; `--file -` also reads stdin. Operators must protect secret-bearing configuration files and exclude them from Git.

## Verification and evidence

Testify covers atomic cursors, deduplication, reads, permission withdrawal, verification limits, encryption, CAS, receipt failures, shutdown and PostgreSQL takeover. Synthetic capture fixtures exercise TLS/STARTTLS, certificate rejection, MIME, HMAC and gateway outcomes. Playwright covers all three channels, email/phone verification, real SSH jobs, approvals, details, both languages and narrow screens. Acceptance records: [TESTING.en.md](./TESTING.en.md).

The competitor is [JumpServer Enterprise](https://www.jumpserver.org/enterprise.html). Research uses official [in-app messages](https://docs.fit2cloud.com/jumpserver/manual/common/system_message/), [notification settings](https://docs.fit2cloud.com/jumpserver/v3/guide/system/message/) and [personal settings](https://docs.fit2cloud.com/jumpserver/manual/common/profile/) (queried 2026-10-18). This page describes actual implementation scope.
