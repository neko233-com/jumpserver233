# External replay storage

> [中文](./REPLAY-STORAGE.md) | English

## Current status

E35 is **implementation-ready, awaiting verification**. Object backends, archive engine, process/organization lifecycle, completion enqueue, historical requests, authorized replay, controlled local removal, backup/cache cleanup, bilingual Web, CLI/SDK and cases are authored. Defaults remain local-only until an administrator configures external storage. This batch ran no verification and makes no production-readiness claim.

The user requires all 42 groups, cases and bilingual docs before unified tests, builds, browser and Docker verification. This document provides no new passing results, performance measurements or cloud compatibility guarantees.

## Authored backends

| Storage | Source design |
|---|---|
| S3 | SigV4, HTTPS and conditional object creation; path-style endpoints supported. |
| Alibaba Cloud OSS | Native V4 signing and forbid-overwrite header. |
| Tencent Cloud COS | Native HMAC-SHA1 signing and forbid-overwrite header. |
| Huawei Cloud OBS | Native OBS header signing and forbid-overwrite header. |
| SFTP | Existing SSH/SFTP transport, Vault accounts/short-lived certificates, host pins, gateways and workspaces; exclusive temporary files, digest validation, no-overwrite rename and linked-parent refusal. A pinned locator survives password rotation. |
| PostgreSQL | Optional shared-state pool, organization-isolated metadata and 1 MiB ciphertext chunks committed in one transaction. Standalone defaults gain no database dependency. |

HTTP signers reference [AWS S3 SigV4](https://docs.aws.amazon.com/AmazonS3/latest/developerguide/sig-v4-header-based-auth.html), [Alibaba's official OSS V4 implementation](https://github.com/aliyun/alibabacloud-oss-python-sdk-v2/blob/master/alibabacloud_oss_v2/signer/v4.py), [Tencent COS signatures](https://www.tencentcloud.com/document/product/436/7778) and [Huawei OBS header authentication](https://support.huaweicloud.com/intl/en-us/api-obs/obs_04_0010.html). Providers have separate signers without new cloud SDK dependencies. Signature cases and local HTTPS fixtures have not run; no real cloud account has been connected.

Cloud endpoints are HTTPS origins without URL user information, query, fragment or path prefix; HTTP is limited to loopback fixtures. Redirects are refused, explicit root certificates and temporary tokens are supported, and operations have deadlines. Error/audit data omits provider response bodies and credentials. Conditional creation depends on provider and bucket versioning behavior; completion always requires full readback validation.

## Configuration and jobs

- Vault-key AES-GCM protects `replay-archive.json`; PostgreSQL holds the same encrypted document. Public result types omit secrets/tokens and provide presence flags.
- Configuration uses revisions and request receipts. Historical locators remain available; unchanged locations use newer credentials without redirecting old objects to new buckets. Blank secrets retain current values only for the same location and AccessKeyID. Token removal is explicit.
- Opening defaults to disabled external storage with provider `local`, without cache directory creation, worker startup or network access. Only the active runtime explicitly calls `Start` after offline-preflight/upgrade activation gates. Configuration changes cancel uploads. Background work counts as `replay_archive`; draining rejects new claims while admitted work may finish.
- Completion notifications enqueue idempotently by recording kind/session ID. Object identities contain a namespace derived from the organization key, a session digest and ciphertext SHA-256. Persisting the manifest before upload makes lost-response retries reuse the same object identity.
- Successful upload and an existing object both require full GET/length/SHA-256 verification before `stored`. Automatic retries stop after 10 attempts pending explicit retry; failures retain fixed error codes. Local originals are never automatically deleted.
- Per organization: at most 20,000 manifests, 1,000 configuration revisions, 4,000 management receipts and 2,000 rolling management audit entries; state plaintext is limited to 32 MiB. Limits refuse new work explicitly rather than silently losing historical locators.

## Formats and cache

Terminal ciphertext retains `JMSREC1`; preparation requires a local ended audit event and authenticates the complete asciinema gzip stream. Desktop preparation requires an ended index, authenticates each encrypted frame and packs `.png.enc` files into a deterministic uncompressed ZIP, without plaintext screenshots or an index. The archive does not change session WebSocket frames or the authorized replay format.

Objects are limited to 1 GiB, terminal validation expansion to 8 GiB, and desktops retain existing frame/recording limits. Downloads enter `replay-cache/`, undergo whole-object verification and then reach the recording decoder. The cache reserves at most four objects and 1 GiB total; active leases are not evicted, downloads are coalesced, and exhausted capacity returns an explicit error. Desktop frames reuse the cached ZIP. Explicit remote verification bypasses cache. The cache quota excludes at most two temporary desktop ZIPs, which retain existing recording-size bounds and are removed when the worker operation finishes.

Packing/download failure and eviction remove only files created by this instance. Close cancels and joins uploads, verification, removal and downloads, then closes cache leases and removes ciphertext copies; repeated reader close is safe. Active startup cleans only known `.replay-cipher-digits`/`.replay-pack-digits` files inside the cache directory, refuses links and preserves other files. Offline preflight never performs cleanup. Git/Docker ignore runtime state, ciphertext cache and interrupted atomic writes.

## Management, replay and local removal

The page is `/console/replay-storage`. Permissions are `replay_storage.view/manage`, `.archive` for historical enqueue/retry, `.verify`, `.evict` and `.audit`. SFTP configuration additionally requires `assets.manage` and `assets.sftp_all`, plus `login_review.bypass` for review-required targets. The server recomputes the target binding rather than trusting a client value. Retargeting the managed asset's host, route, workspace or login-review requirement refuses its old binding; restore the original asset binding to read those historical objects. Old locations are never guessed or automatically migrated.

Records, individual actions and session-referencing audit entries use existing own/all-replay authorization before pagination/counting. Storage permissions do not grant another operator's content. Existing replay routes prefer local files and fall back only when missing; corrupted local files are not silently replaced. No object URLs or presigned URLs are returned.

Local removal obtains a fresh fully verified remote copy, then checks that local ciphertext matches the archive. Mismatches refuse deletion. Only finalized recording ciphertext is removed; indexes, configuration, keys and remote objects remain. Partial desktop removal can retry, and request receipts prevent duplicate execution. This is neither remote deletion nor an automatic retention policy.

Standalone stopped exports preserve encrypted configuration, historical locators, receipts, keys, indexes and local originals while excluding root/organization `replay-cache/` directories. Existing archives retain their original manifest-validation semantics. External objects require independent storage backup/retention; whole PostgreSQL cluster backup remains E37 work.

## API / CLI / SDK

At `/api/v1/settings/replay-storage`, GET returns `{config, postgres_available}` and PUT accepts configuration, `revision` and `request_id`, returning a redacted configuration. `/records` and `/audit` accept `offset/limit` with at most 100 rows. `/records/{terminal|desktop}/{sessionID}` supports GET and POST suffixes `/archive`, `/retry`, `/verify`, `/evict`, accepting `{"request_id":"reusable-unique-request-ID"}`. Retries preserve request IDs/parameters; new intentions use new IDs.

```sh
jms replay-storage settings
jms replay-storage save --file -
jms replay-storage records --offset 0 --limit 20
jms replay-storage get terminal SESSION_ID
jms replay-storage archive terminal SESSION_ID --request-id REQUEST_ID
jms replay-storage verify terminal SESSION_ID --request-id REQUEST_ID
jms replay-storage evict terminal SESSION_ID --request-id REQUEST_ID
jms replay-storage retry terminal SESSION_ID --request-id REQUEST_ID
jms replay-storage audit --limit 20
```

CLI reuses `JMS_SERVER_URL`, platform Token/AccessKey and organization selection without reading target SSH passwords. Submit configuration JSON on stdin; SDK output additionally strips secrets/tokens. Go SDK methods are `ReplayStorage`, `SaveReplayStorage`, `ReplayStorageRecords`, `ReplayStorageRecord`, `ReplayStorageAction` and `ReplayStorageAudit`, retaining existing authentication/organization headers.

## Cases awaiting unified acceptance

Authored Testify cases cover signing/HTTPS, SFTP exclusive cleanup, database transactions/isolation, receipts/historical credentials, lost responses, concurrent notifications, draining, restart, corruption refusal, encrypted terminal/desktop formats, partial removal retries, cache teardown, API authority/hidden counts, CLI redaction and backup recovery. `replay-storage.spec.ts` authors actual SSH/SFTP, Web configuration, replay, local removal, receipt replay and bilingual 390px flows. `scripts/replay-storage-qa.mjs` reuses existing native-package OpenSSH/certificate fixtures and one restart, including actual password rotation without changing storage locators, historical backends and Web SSH output retained in remote playback. Linux race includes archive, objects, database, API, CLI and desktop teardown cases.

All await unified execution after full implementation. No passing, performance or size results were added, and [accepted progress](./PROGRESS.en.md) is unchanged.
