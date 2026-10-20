# WeCom, DingTalk and Feishu/Lark sign-in

> English | [中文](./ENTERPRISE-LOGIN.md)

E05 native Go transports, identity sources/API, bilingual Web, CLI/SDK and cases are authored, **unverified**. Providers display their official QR/authorization pages; this installation does not fabricate provider QR codes. Synthetic pages and HTTPS fixtures support future unified acceptance and cannot prove actual tenants, app approval or mobile scanning.

## Configuration and use

Create a `wecom`, `dingtalk` or `feishu` identity source and open Provider settings. Every source has its own file/database namespace, derived key, callback, flow cookies, identities and suspension generation. Source IDs and provider kinds cannot be interchanged. Existing default LDAP/OIDC/CAS/SAML endpoints remain compatible.

Provider sign-in and first-login provisioning default off. Create an internal application, configure visibility and necessary read permissions, and register its complete callback and trusted domain. Production requires the installation's public HTTPS origin; literal loopback HTTP callbacks require explicit local-development permission. Application secrets are write-only; blank keeps the current secret. Clearing and replacing are mutually exclusive, and enabled configurations require a secret.

| Provider | Application fields | Enterprise boundary | Stable subject |
|---|---|---|---|
| WeCom | Corp ID, Agent ID, application Secret | CorpApp application token plus a readable active member; external identities returning only openid are rejected | `userid` |
| DingTalk | App Key, App Secret, Corp ID | A returned `corpId` must match; the application's token must resolve `unionId` to an active internal member | `unionId` |
| Feishu/Lark | App ID, App Secret, `tenant_key`, region | Exact user_info tenant match followed by directory identity/status checks using the application's token | `open_id` |

WeCom checks activation/enabled state. DingTalk rejects visitors, external contacts and inactive members. Feishu/Lark requires explicit activated, non-frozen, non-resigned, non-exited and joined state. Missing required fields or permissions reject authentication. Application credentials determine directory scope; DingTalk responses without `corpId` still require the application's internal-member lookup.

Feishu China and international Lark use separate official domains, with region included in the identity namespace. OAuth v3 is the default, with an explicit v2 compatibility option. Both use S256 PKCE. Administrators may configure up to 16 additional scopes appropriate to the application; `offline_access` is rejected and user refresh tokens are not stored. Feishu/Lark applications need sufficient rights to read stable IDs, tenant identity and member status. A successful credential check proves neither member permissions nor actual QR sign-in.

Controlled pre-provisioning accepts a stable subject and optional platform username. Optional first-login provisioning creates operators. Provider admin claims, nicknames, email and phone numbers never link identities or grant privileges. Use existing groups/RBAC for permissions. Successful primary identity continues through platform MFA, RADIUS additional factors, source policies and login review. A platform session is returned after all requirements pass. Profiles do not offer local password changes. Existing platform AccessKey/CLI access checks the current source and permissions without returning target SSH passwords.

## Network, secrets and lifecycle

Authorization, token, user-info and member endpoints are fixed by provider/region. Custom token/user-info URLs are unsupported. Additional CA certificates extend TLS trust without disabling hostname verification. HTTP redirects, plaintext fallback and uncontrolled compressed responses are rejected. Responses are capped at 128 KiB, headers at 16 KiB, and JSON depth/field count are bounded. Duplicate JSON keys are rejected. Fixed error codes keep raw provider responses, codes, credential-bearing URLs and tokens out of logs.

State, browser proof and the Feishu PKCE verifier use independent random values. Flows last at most 10 minutes and are consumed once; MFA pending tickets last 5 minutes. Cookies use HttpOnly, Lax, the source path and a source-generation HMAC, with Secure for HTTPS installations. Callbacks accept one state and authorization code; DingTalk supports either one `code` or one `authCode`. Failure clears flow cookies, while cancellation/replay cannot issue sessions. Configuration revisions invalidate in-flight results and pending state. Re-enabling a source cannot restore old credentials or cookies.

The shared client admits 16 network operations, coordinates up to 32 app-token fetches and retains at most 256 application tokens. A source admits 4 identity exchanges and 1,000 authorization flows. Application cache keys bind secrets, application, tenant, region and CA configuration. Tokens refresh before the provider's expiry, with concurrent fetch coalescing. User tokens exist only during the current exchange; app tokens remain in memory. HTTP requests have a 15-second limit and complete identity exchanges a 25-second limit. Sign-in/check work participates in `enterprise_login` draining. Closing cancels and joins active operations. Offline data checks read encrypted state without network work.

Configuration uses revisions and actor-bound `request_id` receipts. Identical retries return the original receipt; altered requests or stale revisions conflict. Failed persistence does not publish configuration. Storage retains up to 2,000 human configuration receipts and the latest 1,000 audit entries, capped at 8 MiB. Exhaustion preserves existing state and rejects writes. Successful changes clear old flows; audit records actor, revision and whether the secret changed.

Standalone deployment adds no external database, Redis, provider SDK or persistent authentication process. PostgreSQL reuses existing document storage. Configuration lives under `identity-sources/<id>/<kind>.json` or scoped database documents. Site backups protect the encrypted files and root key; incomplete online/cluster backup coverage remains tracked under E37/E39.

## API and CLI

The following routes have the prefix `/api/v1/identity-sources/{id}`:

```text
GET/PUT /api/v1/settings/security/{wecom|dingtalk|feishu}
GET     /api/v1/settings/security/{kind}/audit
POST    /api/v1/settings/security/{kind}/check
POST    /api/v1/settings/security/{kind}/users
GET     /api/v1/authentication/{kind}/start
GET     /api/v1/authentication/{kind}/callback
GET     /api/v1/authentication/{kind}/pending
POST    /api/v1/authentication/{kind}/complete
DELETE  /api/v1/authentication/{kind}/pending
```

Management requires system `security.manage`. Public `/api/v1/authentication/sources` lists only available source names, IDs, kinds and start paths. Provider settings remain private. Existing REST authentication methods, full-URI HTTP Signatures, organization authorization, login audit and review are preserved.

```text
jms identity-sources provider <id> wecom settings
jms identity-sources provider <id> dingtalk save --file -
jms identity-sources provider <id> feishu check
jms identity-sources provider <id> feishu audit
jms identity-sources provider <id> wecom prepare --file -
```

Pass secrets as JSON through standard input and keep them out of command arguments. Separate SDK transport types discard undeclared secret/token fields without linking server provider runtimes into the CLI.

## Unified verification and external boundaries

Authored testify cases cover actual provider-shaped HTTPS, Feishu/Lark v2/v3, PKCE, tenant/member rejection, duplicate JSON/redirect/size rejection, concurrent app-token refresh, authorization-code/flow/MFA replay, idempotent settings/revisions, secret isolation, close/drain, PostgreSQL reopen, API login audit and CLI redaction.

`enterprise-login.spec.ts` reuses the existing OAuth fixture process. Clearly labeled synthetic pages intercept browser authorization domains. The server still requests fixed official HTTPS domains through the disposable instance's CONNECT proxy to fixtures with valid matching host certificates. Coverage includes WeCom, DingTalk, Feishu China, Lark international, MFA, profiles, session revocation and bilingual 390px settings. No Docker container is added. Only settings pages with cleared secrets are captured; automatic failure screenshots and traces are disabled. The existing lifecycle cleans fixture connections, processes and disposable data; source archival cleanup is repeatable.

These cases have not run. Actual enterprise accounts, provider approval/callback registration, permission visibility, mobile scanning and public TLS need separate confirmation during final unified acceptance. Local fixtures and app-credential checks do not establish those results.

## Contract references

- [WeCom Web login](https://developer.work.weixin.qq.com/document/path/98152), [login identity](https://developer.work.weixin.qq.com/document/path/98176): official setup references; fetching these pages was restricted, and actual tenant integration remains unverified.
- [DingTalk OAuth SDK](https://github.com/alibabacloud-go/dingtalk/blob/master/oauth2_1_0/client.go), [user SDK](https://github.com/alibabacloud-go/dingtalk/blob/master/contact_1_0/client.go), [unionid membership lookup](https://developer.alibaba.com/docs/api.htm?apiId=52234): native fields and internal-member boundary.
- [Official Feishu token implementation](https://github.com/larksuite/oapi-sdk-go/blob/v3_main/core/accesstoken/access_token.go), [user model](https://github.com/larksuite/oapi-sdk-go/blob/v3_main/service/authen/v1/model.go), [member status model](https://github.com/larksuite/oapi-sdk-go/blob/v3_main/service/contact/v3/model.go): v3, PKCE, tenant and status fields, consulted 2026-10-20 without adding the full SDK dependency.
