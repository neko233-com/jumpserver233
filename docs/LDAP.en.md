# LDAP / Active Directory Sign-in

> [中文](./LDAP.md) | English

Directory sign-in authenticates separately from local accounts and OIDC. Administrators configure one directory at `/console/directory`; users select LDAP / Active Directory on the sign-in page. Standalone comes first; PostgreSQL single-active HA shares configuration, identity mappings, and completed login sessions. Directory sign-in and first-login provisioning are disabled by default.

## Configuration

Management requires `security.manage`. Retain a local administrator for recovery, then provide the directory URL, user search Base DN, read-only search-account DN/password, user filter, and stable identity attribute.

- `ldaps://host:636` uses TLS. `ldap://host:389` must upgrade successfully with StartTLS before any bind. There is no plaintext downgrade; certificate chains and hostnames are always verified. System CAs are trusted, with optional private CA PEM certificates.
- Typical OpenLDAP settings are `(uid={username})` and `entryUUID`; AD uses `(sAMAccountName={username})` and `objectGUID`. Exactly one `{username}` placeholder is required and its value is LDAP-filter escaped. Binary AD `objectGUID` bytes are preserved rather than converted from display text.
- Searches stay in the Base DN subtree without following aliases/referrals. Exactly one entry with one nonempty stable attribute value is required; the returned DN must belong to the subtree. A returned `userAccountControl` disabled flag is rejected. The final user bind still delegates password, lockout, and account policy to the directory.
- The search account must read the stable attribute. The user password is verified by a second bind using the resolved DN, never saved as a local password, configuration, audit, or browser storage. Empty passwords are rejected to avoid accepting an unauthenticated LDAP bind.
- Each connection has a ten-second absolute deadline, cancellation, and roughly 1 MiB read budget. Searches allow two results and five seconds. At most four primary directory authentications run concurrently; passwords are not cached.

The search-account password is write-only: empty preserves it; clearing requires an explicit option. Configuration and non-secret change audits are AES-GCM encrypted with the Vault key in standalone `ldap.json` or PostgreSQL `ldap-config`. `revision` prevents concurrent overwrites; saving invalidates pending logins. Up to 1,000 configuration audits are retained; the page shows 50 and the API returns all. A TLS/bind check establishes search-account availability; actual user sign-in is verified separately.

## Identity and permissions

By default, an administrator resolves a directory username to its stable ID and prepares an external operator, optionally with an unused local display username. First-login provisioning can be explicitly enabled. Identities bind the directory search scope and stable ID; names, emails, and groups never link local administrators. New accounts are operators with no asset grants. Assign permissions through existing grants/RBAC; external provisioning respects the 10,000 total-user limit.

Directory scope comprises URL, Base DN, search-account DN, filter, and identity attribute. Changing these creates a new identity scope; old accounts are not migrated or merged automatically. CA/password updates preserve scope. Disabling the source or changing scope rejects its short sessions, permanent tokens, and AccessKeys on their next authentication check. Directory-side deletion, disablement, password changes, and filters are checked at the next primary login. Background synchronization and immediate directory checks on every API call are not implemented.

Accounts expose `source: "ldap"` and cannot authenticate/change passwords locally. Users can create platform AccessKeys/permanent tokens in Profile for the Agent CLI; browsers and CLI never receive SSH passwords. OIDC and LDAP scopes and disablement checks remain independent.

## Browser and MFA

The browser submits directory credentials by same-origin POST, clearing its password field after successful primary authentication. When TOTP, recovery, or mandatory enrollment is needed, the server issues a five-minute HttpOnly, SameSite=Lax pending cookie with at most five requests. Enrollment challenges bind that ticket and cannot bypass it through the ordinary local MFA endpoint. Completion issues only an HttpOnly platform session, without returning bearer tokens to the frontend. Cancel invalidates the ticket.

Each source IP/directory username allows at most 30 primary attempts per minute and five failures per 15 minutes. Second-factor failures accumulate separately per platform user across flows; submitting the correct password again cannot reset them. Tickets and rate limits are process-local; incomplete sign-in must restart after process restart/HA takeover. Completed shared session authentication timestamps recover. MFA management requires a directory login session issued within five minutes and a fresh code. Production uses an HTTPS `JMS_PUBLIC_URL` for Secure platform/pending cookies.

## API and verification

- `GET/PUT /api/v1/settings/security/ldap`, `GET .../audit`: configuration/audits.
- `POST .../check`: TLS/search-account bind. `POST .../users`: resolve `directory_username` and prepare an operator with optional `username`.
- `GET /api/v1/authentication/ldap/status`: entry-point availability.
- `POST /api/v1/authentication/ldap/login`: `username/password`; `POST .../complete`: `otp` and any `setup_token` with the corresponding cookie; `DELETE .../pending`: cancel.

Testify cases cover actual synthetic LDAPS/StartTLS, rejected certificates, binds, filter injection boundaries, ambiguous/missing/out-of-scope identities, disabled AD flags, encrypted configuration/revisions/recovery, source isolation, MFA, replay, and failure budgets. Playwright configures a private CA, prepares an account, completes local MFA after a real synthetic LDAPS bind, then verifies access loss on disablement. PostgreSQL/HA covers encrypted configuration recovery. Synthetic directory evidence does not establish production AD/OpenLDAP acceptance. Synchronization, automatic groups, multiple directories, SASL/Kerberos, directory password changes, and production integration remain outstanding. See [TESTING.en.md](./TESTING.en.md).

Implementation uses [go-ldap](https://pkg.go.dev/github.com/go-ldap/ldap/v3); transport and nonempty-password requirements follow [LDAP Authentication Methods (RFC 4513)](https://www.rfc-editor.org/rfc/rfc4513.html).
