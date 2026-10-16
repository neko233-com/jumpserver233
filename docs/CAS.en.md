# CAS Single Sign-on

> [中文](./CAS.md) | English

`/console/cas` configures one CAS 2.0/3.0 provider. Browsers redirect to CAS; the server validates a one-time service ticket against the exact service URL, enforces local MFA, and issues only an HttpOnly platform session. CAS and first-login provisioning are disabled by default; local administrators remain a recovery entry point.

## Configuration and identity

Management requires `security.manage`. Provide the CAS base URL, such as `https://identity.example.com/cas`, protocol, and exact `/api/v1/authentication/cas/callback` URL. Production sets `JMS_PUBLIC_URL=https://console.example.com`, matching the callback origin. CAS service registration must allow this path and generated `state` query; validation uses precisely the same service URL as ticket issuance.

CAS 2.0 calls `/serviceValidate`; 3.0 calls `/p3/serviceValidate`, requesting XML. Login and validation always send `renew=true`, requesting primary authentication again. Gateway, proxy tickets, and proxy authorization are not used.

Production endpoints require HTTPS with certificate/hostname verification. Optional private CA PEM is supported without disabling verification. Development HTTP must be explicitly enabled and uses literal loopback IPs only. Upstream requests have a ten-second timeout, roughly 1 MiB response limit, and no redirect following. Endpoint checks establish reachability, not ticket or actual sign-in acceptance.

Administrators prepare operators using the exact CAS `user` value and optional unused platform username, or explicitly enable first-login provisioning. New accounts have no asset grants or automatic system roles. Identity binds the CAS base URL and case-sensitive original user identifier; email, display names, and role attributes never link local accounts. Identifiers reject surrounding whitespace/control characters and are limited to 1,024 bytes. External provisioning respects the 10,000 total-user limit.

Accounts expose `source: "cas"` and reject local password login/change. Platform AccessKeys/permanent tokens support the existing Agent CLI; browsers and CLI never receive SSH passwords. Disabling CAS or changing its base URL blocks its sessions, AccessKeys, and permanent tokens at their next authentication check; identities are not migrated/merged automatically. CAS, OIDC, and LDAP identity/disablement checks remain independent.

## Browser and MFA

Each start creates random state and a separate HttpOnly browser-proof cookie. The complete service includes state. Callback requires the corresponding browser, configuration revision, and one-time flow within ten minutes. Tickets are validated server-side; callback then redirects to a login page containing only `cas=continue`, with `Referrer-Policy: no-referrer`.

XML must contain the correct CAS namespace, one successful authentication outcome, and one direct `user`. Mixed outcomes, duplicate/nested users, DTDs, unknown entities, extra documents, proxy authorization, and excessive document size/depth are rejected. Attributes do not grant platform permissions. The CAS server remains responsible for ticket expiry, one-time use, service binding, and `renew` semantics.

After validation, a five-minute HttpOnly pending cookie allows completion. Local TOTP, recovery codes, and mandatory enrollment remain enforced. Setup challenges require the corresponding pending ticket and cannot complete through the local MFA endpoint. Each ticket allows five requests; second-factor failures also accumulate per user across flows, with five failures limiting sign-in for fifteen minutes. Start/completion additionally allow 30 requests per source IP per minute. Cancel consumes the current ticket.

Success returns only `browser_session`, user, and expiry, without bearer tokens. MFA management requires a platform CAS session issued within five minutes and a fresh code. Logout currently revokes the platform session; CAS-wide logout, single logout notifications, and proxy chains are not implemented.

## Storage and HA

Configuration and up to 1,000 non-secret change audits are AES-GCM encrypted with the Vault key in standalone `cas.json` or PostgreSQL `cas-config`. The page shows 50 audits and the API returns all. `revision` prevents concurrent overwrites, and saves invalidate incomplete flows.

Standalone comes first. PostgreSQL can restore configuration, identity mappings, and completed shared platform sessions. State, browser proof, pending tickets, and rate limits are process-local; incomplete sign-in restarts after process restart/single-active takeover. Nodes share the same public origin and Vault key. Active SSH sessions do not migrate; see [CLUSTER-HA.en.md](./CLUSTER-HA.en.md).

## API and verification

- `GET/PUT /api/v1/settings/security/cas`, `GET .../audit`: configuration/audit. `POST .../check`: login endpoint check.
- `POST .../users`: `subject` and optional `username` prepare an external operator.
- `GET /api/v1/authentication/cas/status`, `GET .../start`, `GET .../callback`: status/start/callback.
- `GET .../pending`, `POST .../complete` (`otp`, any `setup_token`), `DELETE .../pending`: inspect, complete, or cancel browser sign-in.

Testify covers HTTPS trust, CAS 2/3, service/renew/one-time tickets, strict XML, browser proof, expiry/revisions, controlled provisioning, privilege boundaries, shared MFA/recovery boundaries, cross-flow failure budgets, source isolation, and PostgreSQL/HA recovery. Playwright follows a real synthetic CAS authorization page and verifies cancellation, mandatory MFA, HttpOnly sessions, no default asset grants, and disablement. Synthetic evidence does not establish production CAS acceptance. Multiple CAS providers, group/organization attribute mapping, federated logout, and production service registration remain outstanding. See [TESTING.en.md](./TESTING.en.md).

Protocol references: [Apereo CAS 2.0 specification](https://apereo.github.io/cas/8.0.x/protocol/CAS-Protocol-V2-Specification.html) and [CAS 3.0 overview](https://apereo.github.io/cas/development/protocol/CAS-Protocol.html).
