# SMS MFA for sign-in

> [中文](./SMS-MFA.md) | English

E06 native SMS factors, personal bindings, policy management, bilingual Web, CLI/SDK and cases are authored, **without verification**. Unified acceptance starts after all 42 groups are implementation-ready. Vendor approval of signatures/templates, actual carrier delivery and production takeover still require real-environment evidence.

## Configuration and sign-in order

Enable [native SMS](./NATIVE-NOTIFICATIONS.en.md) in platform notifications first: Aliyun, Tencent, Huawei or CMPP 2.0. SMS MFA uses the platform SMS channel and defaults to disabled. Organization channels, custom gateways, bots and notification-contact verification do not provide this sign-in factor. Provider phone, signature, template and content restrictions still apply.

Settings → SMS MFA requires global `security.manage`. Policies are `opt_in` (bound users), `admins` (administrators and identities with delegated global permissions), `all` or `selected` (user IDs). Voluntarily bound users also require the factor. Enforcement applies to new sign-ins; saving policy does not revoke all existing platform/API sessions. Binding or removing a phone increments that user's security generation and revokes old sessions, permanent tokens, AccessKeys and pending sign-ins.

Order: primary authentication/Passkey/enterprise SSO → required local TOTP/enrollment → RADIUS factor → SMS MFA → restricted password change → platform login review → final session. Primary success without required SMS completion yields no asset-capable session. Chained steps preserve the original primary authentication time and absolute proof deadline; SMS or review cannot extend it.

First enforced sign-in verifies primary authentication and existing factors before registering an E.164 phone and checking a six-digit code. Personal settings can bind, change or remove a phone: local identities reenter their password; external identities need a provider-authenticated session from the last five minutes. Existing TOTP requires a fresh TOTP/recovery code, and already-bound SMS identities need a currently SMS-verified session. Enforced policies prohibit personal removal.

Administrators recover other identities through Reset MFA, requiring `users.manage`, `users.credentials.manage` and `roles.manage` for administrator targets. It clears TOTP, recovery codes and SMS binding while retaining Passkeys. Enforcement remains active for the next enrollment. Administrative self-reset is rejected. Existing protected administrator API credentials can repair an incorrect policy during recovery.

## Capabilities, limits and persistence

- Browser capabilities use an HttpOnly, SameSite=Lax cookie scoped to `/api/v1/authentication/sms`, with Secure on HTTPS. Responses expose no capability or platform token. CLI/SDK capabilities use body `factor_token`, never URLs.
- Flows bind source IP, identity generation/credential stamp, verified primary proof, policy revision and platform-notification revision. Archive, disablement, source revocation, credential or configuration changes invalidate pending flows. RADIUS and SMS stamps remain independent and are checked across password change/review.
- Lifetime is at most five minutes and clamped to the primary proof deadline. Only a nonce-bound SHA-256 code digest persists. Malformed codes also consume the five-attempt budget. Explicit resend replaces the code without extending the flow or automatically retrying delivery.
- Each user/phone allows six sends per hour with at least 60 seconds between sends; source IP permits 120 per hour. Send concurrency is four, total flows 1000 and receipts 32 per flow. Repeating a request ID/content returns its result; changing phone/action conflicts. Settings use revision CAS and at most 2000 idempotency receipts.
- Persist send intent before network access. Restart marks unfinished sends `uncertain` without repeating provider requests; received codes can still verify and users may explicitly resend. Provider acceptance is distinct from delivery to a phone.
- Persist one-time consumption before binding a phone or restoring a session. Failed consumption writes never invoke the callback. Later failures revoke newly issued sessions. A successfully saved binding may remain and requires a fresh sign-in for forward recovery; old capabilities cannot replay.
- `sms-mfa.json` / PostgreSQL document `sms-mfa` uses platform Vault-key AES-GCM. User phones are separately encrypted in the user document. Codes never enter notification inboxes/queues. Audit retains at most 1000 entries of identity IDs, revision, action and time; public state displays only the final four phone digits.

Maintenance uses the `sms_mfa` activity count. Close cancels and joins active sends; construction/offline preflight neither contacts providers nor opens ports. Standalone remains preferred; PostgreSQL follows the existing single-active document boundary and does not establish production multi-active acceptance.

## API, SDK and CLI

| Endpoint | Purpose |
|---|---|
| `GET/PUT /api/v1/settings/security/sms-mfa` | Read/save enabled/policy/user_ids/revision; writes require request_id |
| `GET …/sms-mfa/audit` | Protected policy/factor audit |
| `GET /api/v1/users/me/sms-mfa` | available/enabled/forced/masked_phone |
| `POST …/users/me/sms-mfa/enroll` | phone/password/otp; empty phone requests removal |
| `GET/POST /api/v1/authentication/sms/pending` | Resume with cookie/body capability |
| `POST …/sms/bind` | First sign-in phone/request_id |
| `POST …/sms/resend` | request_id; explicit resend |
| `POST …/sms/complete` | code; consume once, then continue sign-in |
| `POST …/sms/cancel` | Idempotent cancellation |

SDK methods: `SMSMFASettings`, `SaveSMSMFASettings`, `SMSMFAAudit`, `SMSProfile`, `BeginSMSBinding`; `Authentication` supports sms-pending/bind/resend/complete/cancel. CLI management uses `jms auth sms-settings|sms-save|sms-audit|sms-profile`; personal binding uses `sms-enroll --state-file PATH --file -`. Supply passwords/phones/codes as JSON on stdin. `auth login|continue|status|sms-resend|sms-cancel` uses protected state files and prints only next steps, masked phones and expiry. First enrollment proceeds through sms-bind and sms-complete; personal binding completion requires fresh sign-in. Platform identity is used throughout without returning target SSH credentials.

## Upgrade and authored cases

User writes now use **envelope 4**. New readers accept legacy arrays and v2/v3/v4; SMS flags/phones in older formats are rejected. Enabling policy persists the v4 reader boundary before enforcing SMS so old programs cannot silently ignore the factor. Old readers cannot open v4. Downgrade requires the pre-upgrade snapshot; deleting new fields to bypass it is unsupported. Maintain the [compatibility matrix](./UPGRADE-COMPATIBILITY.en.md) and [password security](./PASSWORD-SECURITY.en.md) together. New shared-session fields retain original authentication, fresh issuance and the proof deadline; valid older sessions remain readable.

Auth, core, failure-injection, PostgreSQL reopen, API, CLI/SDK cases cover encryption, revision/idempotency, one-time replay, malformed-code budgets, rate limits, policy/channel changes, close/drain, persist-before-callback and slow chained-factor deadlines. `sms-mfa.spec.ts` reuses existing HTTPS/CONNECT fixtures for local and enterprise SSO, initial phone binding, wrong codes, replay, personal status and bilingual narrow screens. It retains two sanitized screenshots, restores settings and cleans synthetic identities twice. **These cases are authored only; no tests, builds, browser or Docker verification has run.**
