# SSH private-key credentials

> English | [中文](./SSHKEYS.md)

SSH key installation, verified rotation, opt-in seven-day scheduling and persistent staged recovery are described in [SSH key rotation](./SSH-KEY-ROTATION.en.md).

Targets and gateways can use server-managed SSH private keys. Administrators import keys; operators use existing target grants for Web SSH, CLI, SFTP, monitoring and jobs without receiving keys or import passphrases. Standalone deployment comes first; credentials, types and history support PostgreSQL single-active HA. The competitor and full scope remain [JumpServer Enterprise](https://www.jumpserver.org/enterprise.html); see [PLAN](./PLAN.en.md).

## Import and edit

Choose “SSH private key” in the asset form and paste a PEM/OpenSSH key, supplying its import passphrase when encrypted. Supported algorithms are RSA 2048–8192 bits, ECDSA P-256/P-384/P-521 and Ed25519. DSA, SSH certificates and public-key text are rejected. Parsing uses `x/crypto/ssh`; OpenSSH bcrypt work is capped at 64 rounds. Private-key parsing is limited to 64 KiB and the entire JSON request also has a 64 KiB limit. Oversized inputs, wrong passphrases and unsupported formats fail without returning key material in diagnostics.

The server normalizes the key into unencrypted OpenSSH PEM and encrypts it with the vault's AES-GCM key. **The import passphrase is not stored.** Additional authenticated data binds asset/history identity and credential type. APIs return only `credential_type` and public `key_fingerprint`; the independent `host_key_fingerprint` continues to pin every SSH hop.

Empty key and passphrase fields preserve the current key on edit. A passphrase cannot be updated alone; key replacement requires the full new key and its passphrase. Switching between password and key authentication requires complete replacement credentials and rejects mixed types. Saving or closing clears form inputs; credentials are not written to browser persistent storage.

## History, restore and rotation

History retains up to ten encrypted versions, with type and public fingerprint in metadata. Key restore verifies the target host key and candidate SSH authentication through the selected route before atomically selecting the vault credential. A changed verification snapshot rejects the commit; failure preserves the active credential. The platform does not modify remote `authorized_keys`, so restoring a revoked or invalid key cannot reauthorize it remotely.

Seven-day password rotation schedules password assets only. Key assets expose no password-rotation action. Keys can be installed/rotated manually, with a separate opt-in seven-day key schedule. A password backup can be restored using current key authentication for `chpasswd`, with the same root or noninteractive sudo requirements. The pending new password is verified before promotion; recovery can retain the old key and continues after restart/takeover. Historical passwords travel over SSH stdin, are limited to 4096 bytes and cannot contain CR/LF/NUL. Automatic rotation retains its existing generated-password policy.

## Verification and boundaries

Testify covers encrypted/plain formats, passphrases and algorithm policy, KDF work limits, encryption at rest, ambiguous types, metadata-only edits, per-hop key authentication, metrics/commands/PTY/SFTP, verified atomic backup restore, password restore under key authentication and HA takeover. Playwright obtains a public synthetic fixture key from its CLI, imports it through English/Chinese forms and exercises gateways, monitoring, Web SSH, CLI and backup restore. See [TESTING](./TESTING.en.md).

SSH CAs/certificates, hardware signers, external Vault/KMS and operator personal-public-key login remain open. This feature manages host credentials and does not establish those capabilities. Synthetic fixture keys are local-test identities and must never be installed on real hosts.
