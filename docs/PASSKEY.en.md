# Passkey sign-in

> English | [中文](./PASSKEY.md)

Local and configured external accounts support WebAuthn Passkey registration, discoverable sign-in, renaming, and removal. Account source, roles, and asset grants come from server records; device names cannot create or link identities. The competitor remains [JumpServer Enterprise](https://www.jumpserver.org/enterprise.html), and overall parity is incomplete.

## Enable and use

1. Set `JMS_PUBLIC_URL` to the console’s trusted HTTPS domain origin, identically on every HA node. Production needs browser-trusted TLS; IP addresses cannot be WebAuthn RP IDs. An isolated development instance may use `http://localhost:<port>`. Existing identity-provider callbacks must remain consistent with their public-origin settings.
2. Enable “Passkey sign-in” with `security.manage`. It is off by default and cannot be enabled without a supported public origin. The RP ID comes from the public hostname. Origin validation includes scheme, host, and port and does not trust arbitrary request headers.
3. Register a named credential in Profile using a WebAuthn browser and device PIN, biometrics, or a security key supporting discoverable credentials and user verification. The server receives public keys and authentication data; the authenticator manages private keys and its own backup/synchronization.
4. Local registration/removal requires the current password, plus a fresh local authenticator/recovery code when MFA is enabled. External accounts require a new sign-in through their original source within five minutes; a Passkey session cannot replace this SSO proof.
5. Select Passkey on the login page. Device verification is followed by local MFA/recovery and global enrollment policy. Until completion, only a single-use HttpOnly pending ticket exists. Login JSON returns no platform Bearer Token; credentials are not placed in URLs or localStorage.

## Validation, revocation, and audit

- `go-webauthn/webauthn v0.18.2` validates attestation/assertion messages. Registration requires a discoverable credential and user verification; assertions require verification and presence. Validate the trusted origin, RP ID hash, purpose, challenge, user handle, credential ID, and signature. Cross-origin use is rejected.
- Challenges expire within five minutes, are single-use, and bind the ceremony type and configuration revision. Registration also binds the current platform session, server user, and primary-credential/MFA fingerprint; security-state changes invalidate old ceremonies. Limits: 64 KiB input, four concurrent validations, 4096 flows, ten credentials per user, 10,000 total. Second-factor verification has host/user budgets and five single-use attempts.
- Signature counters persist with optimistic update checks. A reported counter warning rejects sign-in and disables that credential. Standards-compliant zero counters are accepted and do not alone prove cloning. No remote metadata retrieval or custom signature algorithm implementation is used.
- Sessions bind the configuration generation and random credential-record ID. Saving configuration, including disable/re-enable, invalidates old Passkey sessions. Re-registering the same raw credential ID after removal cannot revive old sessions. Password/SSO sessions and independent user API credentials are not automatically revoked by Passkey configuration changes.
- Disabling an external identity source also blocks its Passkey logins and existing sessions. Passkeys grant no asset/system permissions. Users manage only their own credentials; foreign credentials return 404.
- Keep the most recent 1000 configuration, registration, verification, rename, removal, and counter-warning events; the UI shows 50. Private keys, passwords, second factors, and raw assertions are not logged.

## Storage and HA

Credentials, counters, settings, and events are AES-GCM encrypted with the Vault Key in `passkeys.json`, or PostgreSQL shared document `passkeys`. Shared login sessions retain credential-generation binding and token digests. Single-active takeover restores credentials, counters, and completed sessions; incomplete ceremonies/MFA tickets remain process-local and restart after takeover. Backups need the database/data directory and the same Vault Key.

## Automated verification

Testify uses ephemeral ES256 keys to generate real CBOR attestations and signed assertions. Cases cover wrong origin/port/RP/challenge/handle, missing UV/UP, cross-origin requests, forged signatures, browser/user binding, MFA/recovery, replay, non-resurrecting revocation, counter warnings, and encrypted reload. PostgreSQL and two-node takeover cases cover credentials and completed Passkey sessions.

Playwright uses an isolated temporary instance on `localhost:15178` / API `127.0.0.1:18185` and Chromium’s virtual authenticator. It exercises native `navigator.credentials.create/get`, cancellation, registration, renaming, MFA enrollment, recovery codes, global disablement, and removal. This establishes the browser protocol path, not acceptance on physical Windows Hello devices, phone synchronization, or every hardware security key.

## Current limits

Only explicitly started, same-origin discoverable sign-in is supported. Conditional autofill, cross-RP/Related Origins, enterprise attestation allowlists, and an administrator UI for deleting other users’ credentials remain open. Passkeys do not replace local MFA or create accounts without other recovery paths. Recover a lost device through the password, original identity source, and local recovery codes. Remaining capabilities stay in the overall goal.

References: [JumpServer Passkey settings](https://docs.jumpserver.org/zh/latest/guide/system/authentication/passkey/), [WebAuthn Level 3](https://www.w3.org/TR/webauthn-3/), [Go WebAuthn](https://github.com/go-webauthn/webauthn).

2026-10-15: all described Go/PostgreSQL/HA/race checks and 14 browser cases passed. In-app browser UI was checked in both languages.
