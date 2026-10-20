# AI assistant and conversation audit

> [中文](./AI-ASSISTANT.md) | English

`/console/assistant` provides organization-scoped text operations advice, conversation history, archiving and audit. Web, `jms assistant` and Go SDK share platform identity. Models cannot execute SSH, read asset credentials or approve actions. E34 code, cases and documentation are authored; **unified verification has not run**, and no actual model provider is accepted yet.

## Configuration and permissions

The feature defaults off without a model runtime, vector database, additional process or listener. Configure an explicit HTTPS Chat Completions endpoint, model ID, write-only API key, completion-token ceiling and optional additional CA. No vendor, pricing tier or model is selected automatically.

| Permission | Scope |
|---|---|
| `assistant.use` | Ask, read own history and archive own conversations |
| `assistant.manage` | Read/change the organization's provider settings; does not independently grant asking or other users' transcripts |
| `assistant.audit` | Explicitly select all organization conversations, read transcripts and metadata audit; grants no execution |

These are separate organization capabilities. Operators do not receive them automatically; system administrators retain existing full permissions. Settings, conversations and receipts use the selected organization's key and Documents scope, with no cross-organization fallback. The default organization uses `assistant.json`; others use their existing directories. Standalone operation adds no database dependency. Existing PostgreSQL single-active takeover retains state but cannot migrate live requests.

`PUT /api/v1/assistant/settings` binds `revision` and `request_id`. Identical actor/request/content returns its original settings receipt. Changed content or stale revisions return `409`. Omit `secret` to preserve the key; an empty string removes it. Enabled settings require a key. Responses contain only `configured`, never the key. A new settings revision cancels current organization requests. GET's `configured` is read-only and must not be copied into PUT.

## Provider channel and data

The native Go connector sends `messages`, `model`, `max_completion_tokens`, `store:false` and `stream:false`, accepting one text assistant choice. Field definitions follow the [official OpenAI Chat Completions reference](https://developers.openai.com/api/reference/resources/chat/subresources/completions/methods/create). Compatible services must support this combination; this does not establish every provider or model's compatibility.

TLS requires at least 1.2 and verifies certificates and hostnames. Redirects, URL credentials, query secrets and fragments are refused; ambient proxies and credentials are ignored. Authorized configuration explicitly selects the destination, including trusted internal HTTPS services. Requests last at most 45 seconds, response bodies at most 256 KiB and accepted replies at most 32 KiB. HTTP/protocol failures retain bounded status without exposing provider diagnostic bodies.

Users explicitly consent to sending text and recent completed exchanges. Only the latest twelve completed exchanges in that conversation are considered; oldest pairs are removed above a 120 KiB context budget. Assets, Vault data, terminals, recordings, SQL, files and other users' context are not collected automatically. The provider key is used only in its authentication header. Occurrences of the known current key in questions/replies become `[redacted]`; arbitrary third-party secrets pasted by users cannot all be detected, so the UI instructs users not to paste credentials.

No tools or functions are requested; tool-call responses are refused. Replies render as plain text without executing HTML, Markdown scripts or commands. Operators use the normal authorized console for any suggested action, retaining asset grants, sensitive-command policy and approvals.

## Idempotency, revocation and recovery

Each turn atomically stores an encrypted intent and request digest before one provider call. Replaying its `request_id` reads the original receipt: pending returns `202`, terminal returns `200`, changed content returns `409`. A new turn requires the current conversation revision, with one pending turn per conversation. Explicit new requests may incur provider costs. Network failures, 429 responses and uncertain outcomes are never retried automatically.

Before submission, periodically during I/O, at result recording and before response, the platform rechecks current credentials, organization eligibility and roles. Access/settings changes cancel I/O and withhold replies. Revocation cannot recall text already sent to a provider. Interrupted requests with unknown remote results become `uncertain`. Startup and reads can recover orphaned intents without resubmitting them. Even a provider reply followed by failed local persistence cannot trigger another call through receipt replay.

Upgrade drain counts `assistant` work and rejects new calls; already admitted calls may finish. Organization closure or node exit cancels and joins current work. Shared-state takeover retains receipts and does not treat incomplete calls as safely replayable jobs.

## Retention and audit

Each organization supports 256 conversations, 32 turns per conversation and 12,000 UTF-8 input bytes. Conversations whose latest update exceeds 90 days are hidden and removed on a later write. Archiving preserves text for authorized audit rather than immediately deleting it. Request/settings/archive receipts retain 365 days, up to 4,000 entries; metadata audit retains 4,000 entries/365 days. The plaintext encrypted-state ceiling is 16 MiB. Capacity refusal precedes any paid call. Organizations allow four concurrent calls; users allow thirty new calls per ten-minute window. Receipt replay adds no provider calls.

Text, keys, intents and results use AES-GCM and atomic file replacement or one existing Documents save. Metadata records submission, completion, failure, interruption, withholding, settings and archive actions without duplicating text or keys. Full encrypted backup includes this state, and restored requests retain their original results. Product retention does not establish provider-side deletion or permanent historical storage.

## API and CLI

```text
GET  /api/v1/assistant/capabilities
GET  /api/v1/assistant/settings
PUT  /api/v1/assistant/settings
POST /api/v1/assistant/turns
GET  /api/v1/assistant/conversations?all=false&archived=false&offset=0&limit=20
GET  /api/v1/assistant/conversations/{id}?all=false
POST /api/v1/assistant/conversations/{id}/archive
GET  /api/v1/assistant/audit?offset=0&limit=20
```

```sh
jms assistant settings
jms assistant configure --file -
jms assistant ask --file question.json
jms assistant list
jms assistant show chat_ID
jms assistant audit --offset 0 --limit 20
```

This question file contains no provider key. Existing conversations additionally supply `conversation_id` and the current `revision`.

```json
{"message":"Explain pwd","locale":"en","consent":true,"revision":0,"request_id":"example-assistant-question-001"}
```

Supply settings secrets through secure stdin/files, excluding command-line arguments, terminal history, reports and screenshots. Existing `JMS_TOKEN`/AccessKey and `X-JMS-ORG` contracts apply.

## Authored, unrun cases

Testify cases cover actual local HTTPS, CA/redirect/tool/capacity refusal, one-call concurrent receipts, revisions, recovery after failed writes, access/settings cancellation, repeated Close, drain, encryption and PostgreSQL organization isolation/reopen. API/CLI/SDK cases cover independent permissions, principal forgery refusal, write-only keys, hidden other-user transcripts and `202` receipts.

Existing organization lifecycle and full-backup cases add settings/transcript/receipt recovery. `assistant.spec.ts` reuses the OAuth/enterprise HTTPS fixture through the actual API/provider connector for plain-text rendering, replay, changed-request conflicts, organization isolation, archive, English/Chinese and 390px layout. It retains at most two screenshots with cleared keys and repeatedly archives only its temporary organization; existing isolated-root teardown removes temporary data.

These entrypoints run only after all 42 groups are implementation-ready. No new passing results, production-provider acceptance or performance measurements are claimed. The page and feature locales load on their route with no new third-party runtime dependency, and this batch does not relax existing total-size limits.
