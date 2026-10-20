# SAML 2.0 sign-in

> English | [中文](./SAML.md)

New [multiple identity-source and directory synchronization](./IDENTITY-SOURCES.en.md) source keeps named sources separate from default endpoints. Complete LDAP synchronization and owned group/organization mapping preserve manual precedence. This batch is unverified; historical default-provider acceptance below does not cover new source.

Connect one trusted SAML 2.0 IdP using SP-initiated HTTP-Redirect AuthnRequests, HTTP-POST assertions, and local MFA. Disabled by default, with automatic provisioning off. The competitor baseline remains [JumpServer Enterprise](https://www.jumpserver.org/enterprise.html); overall parity is incomplete.

## Configuration

1. Set `JMS_PUBLIC_URL` to the actual public console origin. Open “SAML sign-in”; `security.manage` is required.
2. Enter a stable SP entity ID, the same-origin consumer URL `/api/v1/authentication/saml/acs`, and a single IdP `EntityDescriptor` obtained through a trusted channel. Only its HTTP-Redirect SSO endpoint and RSA signing certificates of at least 2048 bits are used. Production endpoints require HTTPS; HTTP needs explicit opt-in and literal loopback addresses.
3. Save and import SP metadata from `/api/v1/authentication/saml/metadata` into the IdP. Require persistent NameIDs, signed assertions, and fresh authentication. Requests use RSA-SHA256. The SP private key and configuration are AES-GCM encrypted with the Vault Key; APIs and metadata never expose the private key.
4. Prefer preparing the exact persistent NameID. The identity namespace includes IdP entity, SP entity, and NameID format. Email, display names, and role claims cannot link local administrators. Explicitly enabled automatic provisioning creates operators without asset grants; asset and system permissions are assigned separately.

## Validation and sessions

- `crewjam/saml` validates XML signatures and assertions; the XML signature dependency is pinned to patched `goxmldsig v1.6.1`. Require one signed plaintext assertion, RSA-SHA256/384/512, and SHA256/384/512 digests. Reject weak algorithms, multiple assertions, duplicate IDs, DTDs, unsupported conditions, and oversized XML.
- Validate trusted certificates, exact issuer, request ID, Destination, Recipient, every audience restriction, validity, persistent NameID, and qualifiers. Assertion windows are at most 10 minutes, authentication at most 5 minutes old, and clock skew at most 1 minute. Replay storage has bounded size and lifetime.
- RelayState binds the request and configuration revision. The cross-site ACS creates no account or session. A 303 redirect to same-origin finalization must include the originating browser’s HttpOnly / SameSite=Lax proof, followed by a single-use local pending ticket. Local MFA/recovery and global MFA policy still apply.
- No platform Bearer Token is returned in URLs, localStorage, or login JSON. Configuration changes invalidate incomplete flows. Disabling the source blocks its short sessions, permanent tokens, and AccessKeys. Primary external passwords cannot be changed locally.

## Standalone and HA

Standalone comes first. Encrypted `saml.json`, identity mappings, and completed sessions can be restored from backups. PostgreSQL uses shared document `saml-config`, the same Vault Key, and single-active HA. The SP private key survives restart and takeover. Incomplete requests, callbacks, replay caches, and MFA tickets are process-local and must restart after takeover. Old responses lack an outstanding request and are rejected. Backups must include the Vault Key.

## Verification and limits

Testify covers valid/request signatures, forged/expired/wrong-audience assertions, browser binding, single-use tickets, revisions, encrypted keys, local MFA, source isolation, and disablement. Playwright uses the isolated synthetic IdP on `12235` to exercise real form POSTs, cancellation, and MFA. Synthetic evidence does not establish production IdP acceptance.

IdP-initiated sign-in, encrypted assertions, artifacts, SLO/federated logout, multiple IdPs, and organization/group mapping are unavailable. SP certificates last three years. Select certificate regeneration when saving to rotate the SP identity, then reimport metadata into the IdP. Rotation invalidates incomplete flows. Only RSA IdP signing certificates are supported. These capabilities and the remaining Enterprise features stay in the overall goal.

Expired trust material disables SAML entry points while preserving local administrator access for configuration repair.
