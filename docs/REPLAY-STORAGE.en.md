# External replay storage

> [中文](./REPLAY-STORAGE.md) | English

## Current status

E35 is **partial and unverified**. Object transports, PostgreSQL chunks, encrypted archive state, retry workers, recording authentication, ciphertext caching and Testify cases are authored. Runtime/session completion, HTTP permissions, Web/CLI/SDK, backup exclusions and real-environment acceptance remain unwired. The running application still uses existing local recordings; authored source does not enable external archival.

The user requires all 42 groups, cases and bilingual docs before unified tests, builds, browser and Docker verification. This document provides no new passing results, performance measurements or cloud compatibility guarantees.

## Authored backends

| Storage | Source design |
|---|---|
| S3 | SigV4, HTTPS and conditional object creation; path-style endpoints supported. |
| Alibaba Cloud OSS | Native V4 signing and forbid-overwrite header. |
| Tencent Cloud COS | Native HMAC-SHA1 signing and forbid-overwrite header. |
| Huawei Cloud OBS | Native OBS header signing and forbid-overwrite header. |
| SFTP | Existing SSH/SFTP transport, exclusive temporary files, digest validation, no-overwrite rename and linked-parent refusal. Runtime target/route/workspace binding remains unwired. |
| PostgreSQL | Optional shared-state pool, organization-isolated metadata and 1 MiB ciphertext chunks committed in one transaction. Standalone defaults gain no database dependency. |

HTTP signers reference [AWS S3 SigV4](https://docs.aws.amazon.com/AmazonS3/latest/developerguide/sig-v4-header-based-auth.html), [Alibaba's official OSS V4 implementation](https://github.com/aliyun/alibabacloud-oss-python-sdk-v2/blob/master/alibabacloud_oss_v2/signer/v4.py), [Tencent COS signatures](https://www.tencentcloud.com/document/product/436/7778) and [Huawei OBS header authentication](https://support.huaweicloud.com/intl/en-us/api-obs/obs_04_0010.html). Providers have separate signers without new cloud SDK dependencies. Signature cases and local HTTPS fixtures have not run; no real cloud account has been connected.

Cloud endpoints are HTTPS origins without URL user information, query, fragment or path prefix; HTTP is limited to loopback fixtures. Redirects are refused, explicit root certificates and temporary tokens are supported, and operations have deadlines. Error/audit data omits provider response bodies and credentials. Conditional creation depends on provider and bucket versioning behavior; completion always requires full readback validation.

## Configuration and jobs

- Vault-key AES-GCM protects `replay-archive.json`; PostgreSQL holds the same encrypted document. Public result types omit secrets/tokens and provide presence flags.
- Configuration uses revisions and request receipts. Historical locators remain available; unchanged locations use newer credentials without redirecting old objects to new buckets. Blank secrets retain current values only for the same location and AccessKeyID. Token removal is explicit.
- Opening defaults to disabled external storage with provider `local`, without directory creation, worker startup or network access. Runtime must explicitly call `Start`; configuration changes cancel uploads in flight.
- Completion notifications enqueue idempotently by recording kind/session ID. Object identities contain a namespace derived from the organization key, a session digest and ciphertext SHA-256. Persisting the manifest before upload makes lost-response retries reuse the same object identity.
- Successful upload and an existing object both require full GET/length/SHA-256 verification before `stored`. Automatic retries stop after 10 attempts pending explicit retry; failures retain fixed error codes. Local originals are never automatically deleted.
- Per organization: at most 20,000 manifests, 1,000 configuration revisions, 4,000 management receipts and 2,000 rolling management audit entries; state plaintext is limited to 32 MiB. Limits refuse new work explicitly rather than silently losing historical locators.

## Formats and cache

Terminal ciphertext retains `JMSREC1`; preparation requires a local ended audit event and authenticates the complete asciinema gzip stream. Desktop preparation requires an ended index, authenticates each encrypted frame and packs `.png.enc` files into a deterministic uncompressed ZIP, without plaintext screenshots or an index. The archive does not change session WebSocket frames or the authorized replay format.

Objects are limited to 1 GiB, terminal validation expansion to 8 GiB, and desktops retain existing frame/recording limits. Downloads enter `replay-cache/`, undergo whole-object verification and then reach the recording decoder. The cache reserves at most four objects and 1 GiB total; active leases are not evicted, downloads are coalesced, and exhausted capacity returns an explicit error. Desktop frames reuse the cached ZIP. Explicit remote verification bypasses cache.

Packing/download failure, eviction and normal close remove only files created by this instance. Active leases clean up after the last reader closes; repeated close is safe and unrelated files remain. Git/Docker ignore runtime state, ciphertext cache and interrupted atomic writes. Crash-residue cleanup and backup exclusions await runtime integration, so complete temporary-data cleanup is not yet claimed.

## Remaining delivery chain

1. Process/organization lifecycle, active-node-only workers, completion notifications and historical enqueue; pinned SFTP target/gateway/workspace binding.
2. Existing own/all-session authorization before archiving or reading; separate configuration/retry/verify permissions, without raw object URLs or credentials.
3. Bilingual Web settings/status, CLI/SDK, controlled local removal, backup recovery and crash-cache cleanup.
4. After full implementation, unified real SSH/SFTP, PostgreSQL takeover, browser, cloud compatibility fixtures, performance/size and idempotent cleanup acceptance.

Authored cases cover independent signing references, HTTPS/certificate/redirect refusal, SFTP exclusive writes/cleanup, database transactions and organization isolation, configuration receipts/credential rotation, lost responses, concurrent notifications, restart, corruption refusal, actual encrypted terminal/desktop formats and cache leases. They have not run and add no [accepted progress](./PROGRESS.en.md).
