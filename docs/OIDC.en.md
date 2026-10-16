# OIDC Single Sign-on

> [中文](./OIDC.md) | English

Passkey registration, device-verified sign-in, local MFA, revocation, and HA recovery: [Passkey](./PASSKEY.en.md).

`/console/identity` configures OpenID Connect Authorization Code login. The sign-in page offers SSO; the server exchanges/verifies the ID token and issues only an HttpOnly platform session after local MFA. Browsers and the Agent CLI never receive SSH passwords. OIDC and first-login provisioning are disabled by default.

## Configuration

1. Retain a local administrator for recovery and initialize the platform first. An external identity cannot create the first administrator.
2. Set `JMS_PUBLIC_URL=https://console.example.com` for production and use that HTTPS origin. The reverse proxy carries requests/cookies; the server trusts the explicit public origin instead of arbitrary `X-Forwarded-Proto`. Ordinary login cookies also become `Secure`.
3. Register the exact callback `https://console.example.com/api/v1/authentication/oidc/callback` at the IdP. Enable code flow, PKCE S256, and `auth_time`. Requests use `max_age=300` and require recent primary authentication.
4. Enter the discovery issuer, Client ID, callback, and secret. Supported methods are `client_secret_basic`, `client_secret_post`, and PKCE public clients (`none`). Secrets are write-only: empty preserves the existing value; clearing requires an explicit checkbox.
5. Development HTTP is opt-in and restricted to literal loopback IPs such as `127.0.0.1` or `::1`. Production endpoints require HTTPS and certificate verification cannot be disabled. Callback origin must match `JMS_PUBLIC_URL`; without it, only local callbacks are accepted.
6. Saved discovery/endpoints can be checked. That check does not establish actual sign-in acceptance.

Management APIs require `security.manage`. Revisions reject concurrent overwrites. Vault-key AES-GCM encrypts local `oidc.json` or the PostgreSQL `oidc-config` document. Configuration audits contain the authenticated actor, time, and non-secret snapshot, never secrets, provider tokens, or authorization codes. History holds 1000 changes. Configuration changes invalidate incomplete OIDC flows.

## Accounts and authorization

- External accounts bind only to the exact `issuer + sub` pair, storing a subject digest. Email, display name, `preferred_username`, and provider roles never link or elevate local accounts.
- Administrators prepare accounts by default using an exact subject and optional unused username (existing 3–64 character ASCII rules). Explicit first-login provisioning generates a stable `oidc.<digest>` username.
- New accounts are always operators, without asset grants, administrator roles, or automatic group membership. Existing grants/RBAC manage access afterward. ID-token claims cannot obtain management capabilities. External provisioning stops at 10000 total users.
- External accounts cannot use or change a local primary password. With an enabled matching issuer, they can create platform AccessKeys/permanent tokens for the existing Agent CLI. SSH credentials remain server-side.
- Disabling the provider or changing issuer blocks its sessions, permanent tokens, and AccessKeys at the next authentication check. Checked invalid short-lived sessions are removed. Re-enabling the same issuer can restore unrevoked API credentials. An issuer change does not migrate accounts or grants.

## Browser flow and MFA

The server uses random state, nonce, a PKCE verifier, and an HttpOnly browser-proof cookie. A callback must match a one-use flow for that browser. State expires after ten minutes. OAuth tokens, ID tokens, and client secrets never reach frontend storage.

A verified callback creates a five-minute HttpOnly pending ticket and redirects with only a flow marker. “Complete sign-in” still enforces local TOTP/recovery codes and mandatory enrollment. External setup challenges require their pending ticket and cannot bypass it through the ordinary local enrollment-completion endpoint. A ticket permits at most five requests. Second-factor failures also accumulate per user across flows; five failures trigger a 15-minute limit.

Recovery-code management or MFA disable requires a platform SSO session issued within five minutes plus a fresh second factor. Authentication time persists with shared sessions for HA checks. Permanent tokens and AccessKeys do not substitute for a recent login. Platform sign-out only revokes the platform session; IdP federated/back-channel logout is not implemented yet.

## Validation and failures

The implementation uses [go-oidc](https://pkg.go.dev/github.com/coreos/go-oidc/v3/oidc) and [OAuth2 PKCE](https://pkg.go.dev/golang.org/x/oauth2), following [OIDC Core](https://openid.net/specs/openid-connect-core-1_0.html). Checks cover signature algorithms, JWKS, issuer, audience/azp, expiry, issue time, nonce, recent `auth_time`, and `at_hash` when present. RSA/ECDSA/EdDSA asymmetric signatures are supported; HMAC/none identity assertions are rejected. JWKS signing-key rotation is supported.

Upstream requests time out after ten seconds, read approximately 1 MiB at most, and do not follow discovery/token/JWKS redirects. Fixed errors never echo provider bodies. State, PKCE, and pending tickets are process-local, so incomplete SSO restarts after server restart/single-active HA takeover. Completed platform sessions, mappings, and encrypted configuration can reload from shared state. One OIDC provider is currently supported; multiple providers, organization/group claim mapping, and federated logout remain outstanding.

## Automated verification

Testify covers all three client-auth methods, PKCE/state/browser binding, signature/claim rejection, JWKS rotation, account-link/elevation prevention, encrypted write-only secrets, one-use tickets, mandatory local MFA, cross-flow failure budgets, recent-session proof, provider-disable checks across authentication methods, and PostgreSQL reload. Playwright follows a real synthetic IdP redirect/authorization page, completes local MFA, checks HttpOnly sessions and absent asset grants, and verifies disable-time denial. The synthetic IdP is loopback test infrastructure, not a production identity service. See [TESTING.en.md](./TESTING.en.md).

Separate [LDAP/AD directory sign-in](./LDAP.en.md) is also available; identities from different sources are never merged.

SAML sign-in is implemented separately; see [SAML.en.md](./SAML.en.md) for its accepted profile and limits.
