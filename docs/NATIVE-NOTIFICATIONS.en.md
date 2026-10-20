# Native cloud SMS and enterprise bots

> English | [中文](./NATIVE-NOTIFICATIONS.md)

E22 native SMS and group bot code, bilingual Web, existing CLI/SDK extensions and cases are authored, **unverified**. The complete 42-group implementation gate remains. Contact verification is not E06 SMS login MFA.

## Configuration

Choose a provider in organization or platform notification settings. These scopes retain separate configuration, contacts, subscriptions and deliveries, disabled by default. Management requires scope-appropriate `notifications.manage`. Existing SMTP, custom HTTPS gateways and clients remain compatible.

| Provider | Settings and native protocol |
|---|---|
| Alibaba Cloud | AccessKey ID, write-only SMS secret, signature and two templates; `SendSms` 2017-05-25 with ACS3-HMAC-SHA256, mainland China numbers. |
| Tencent Cloud | SecretId, write-only SMS secret, region, SDK AppId, signature and two templates; 2021-01-11 with TC3-HMAC-SHA256, E.164. |
| Huawei Cloud | Application key/write-only secret, official application endpoint, sender, signature and two templates; `batchSendSms/v1` with SDK-HMAC-SHA256. |
| CMPP | Six-digit source ID, write-only shared secret, TLS gateway, sender/service ID, signature and two text templates; CMPP 2.0 mutual authentication and SUBMIT receipts. |
| WeCom | Select WeCom on the Webhook channel; enter the bot key as Bearer token. |
| DingTalk | Enter the bot access token as Bearer and its required signing secret; timestamp HMAC-SHA256. |
| Feishu/Lark | Enter the hook ID as Bearer and the enabled signing secret; fixed China/global domains respectively. |

Native bot tokens/hook IDs never enter the public URL field. Secrets retain organization AES-GCM encryption and write-only fields. Changing providers clears old credentials and requires the new provider's credentials. Bots send to the administrator's configured group with subscriber opt-in. Messages contain event metadata and native detail links, excluding commands, outputs, target passwords and login codes.

Obtain approved verification and notification templates. Ordered parameter names are `code` for verification, or `title state id time link` for notifications. Alibaba receives named JSON; Tencent/Huawei receive ordered arrays. Verification and notification data cannot mix. Notification phones retain existing one-time contact verification; API, CLI and audit never return codes.

CMPP requires a hostname- and certificate-verified TLS gateway, minimum TLS 1.2. It supports mainland China `+86` destinations and one UCS-2 message of at most 70 characters including signature, without automatic splitting or retransmission. Carrier-specific extensions are outside this adapter. Text uses declared `{code}`, `{state}` and similar placeholders. Connections, complete frame reads, sequence and receipt validation are bounded. Failed mutual authentication prevents submission; receipt loss after submission becomes uncertain.

## Security, retries and API

Native HTTP endpoints are fixed by vendor. Huawei application addresses are restricted to official `smsapi.*.myhuaweicloud.com` HTTPS hosts. Servers construct bot credential URLs without returning them. Redirects, compressed receipts, duplicate JSON keys and receipts over 64 KiB are rejected; response headers are limited to 16 KiB and HTTP calls to 15 seconds. WeCom text is limited to 2048 bytes, other bots conservatively to 3500 bytes; oversize messages fail explicitly.

Adapters reuse fixed delivery IDs, queues, current authorization, configuration revisions, contact binding, limits, backoff, uncertain states and audit. Provider acceptance does not prove terminal delivery. Missing receipts and HTTP 5xx never trigger automatic replay. This version does not consume asynchronous carrier delivery reports.

Settings endpoints remain `/api/v1/notifications/settings` and `/api/v1/platform-notifications/settings`. Channels gain `provider`; SMS gains `native_sms`. Omitted providers preserve custom-gateway behavior. Optional `request_id` enables idempotent settings saves: the same actor/content returns its original receipt; changed content returns 409. Up to 2000 encrypted receipts are retained. Older calls without IDs retain revision checks. CLI remains `jms notifications settings-save --file -`, reading secrets from stdin.

## Unified verification preparation

Authored cases cover native HTTPS signatures/receipts, certificate rejection, duplicate/oversize/redirect rejection, CMPP mutual authentication/sequence/disconnection, settings idempotency and secret isolation, provider changes, contact verification, queue deduplication, API permissions, SDK redaction and PostgreSQL reopen.

`native-notifications.spec.ts` uses a temporary organization for three cloud SMS providers, four bots, settings/message idempotency, phone verification and bilingual 390px UI. It reuses the OAuth process's TLS/CONNECT fixture without new containers and retains two screenshots after clearing secrets. Cleanup disables channels, clears secrets and repeats organization archiving. Existing QA lifecycle removes fixture memory and instance data. Actual template approval, billing, carrier connectivity and enterprise group receipt remain unverified.

## Official contracts

- [Alibaba SendSms](https://help.aliyun.com/zh/sms/developer-reference/api-dysmsapi-2017-05-25-sendsms), [ACS3 signing](https://help.aliyun.com/en/sdk/product-overview/v3-request-structure-and-signature).
- [Tencent official 2021-01-11 models](https://github.com/tencentcloud/tencentcloud-sdk-go/blob/master/tencentcloud/sms/v20210111/models.go).
- [Huawei SMS API](https://support.huaweicloud.com/intl/en-us/api-msgsms/sms_05_0001.html), [official signer](https://github.com/huaweicloud/huaweicloud-sdk-go-v3/blob/master/core/auth/signer/signer.go).
- [DingTalk bot security](https://open.dingtalk.com/document/robots/customize-robot-security-settings), [Feishu bots](https://open.feishu.cn/document/client-docs/bot-v3/add-custom-bot), [WeCom bots](https://developer.work.weixin.qq.com/document/path/91770). WeCom page retrieval was restricted; actual tenants remain unverified.

Contracts were checked on 2026-10-20. Implemented with Go standard libraries without full vendor SDK dependencies.
