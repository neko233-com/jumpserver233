# SSH user certificates and signing authorities

> [中文](./SSH-CERTIFICATES.md) | English

## Implementation status

E36 built-in CA, OpenBao signing, account policies, connection integration, Web, CLI/SDK, cases and bilingual docs are authored: **implementation awaiting verification**. No tests, builds, browser or Docker verification ran. Unified verification follows implementation of all 42 groups. An API, authored case or historical SSH pass does not prove this new certificate path.

## Connections and account policies

Open `/console/ssh-certificates`. The built-in Ed25519 CA needs no extra service. Alternatively configure an OpenBao SSH mount/role, write-only token, pinned signing CA public key and optional TLS root CA. Requests follow the [official signing API](https://openbao.org/docs/secrets/ssh/signed-ssh-certificates/). Authorities are organization-scoped; `X-JMS-ORG` isolates keys, tokens, policies, cache and audit.

Register an SSH asset/managed account, then select its issuer. Existing Vault credentials remain available for explicit recovery. While an issuer policy is selected, ordinary connections use it exclusively. Issuance failures, disabled authorities, CA mismatches and changed endpoints deny authentication. Clearing the policy explicitly restores stored credentials. This entrypoint does not offer initial asset creation without bootstrap credentials or export signing/ephemeral private keys.

The common SSH route resolver applies policies to Web SSH, platform-identity CLI, SFTP, monitoring, native Agent operations and every gateway hop. Certificates bind one principal matching the selected username and an ephemeral key; signature, lifetime and extensions are checked. Only PTY and port-forwarding extensions are allowed. Private keys remain in server memory, while platform permissions control allowed operations. Pinned host-key validation remains enforced.

Lifetime defaults to 300 seconds, bounded to 60–600. Cache expires 15 seconds early and reuses valid credentials per account. Cache is not persisted; restart issues fresh credentials and built-in serial counters remain durable. Lifetime limits new handshakes; established sessions retain platform authorization/duration rules. Account/CA revisions enter connection authorization bindings so old approvals cannot continue redeeming/executing after policy changes; live terminals use ongoing authorization checks. Assets without certificate policies preserve their previous binding format.

Password/key rotation is refused for certificate-bound accounts; automatic rotation skips them. Aliases of the same remote account participate in rotation checks. Complete pending credential recovery before binding a policy. Authentication checks use the account's current effective method.

## Target trust and CA rotation

1. Create an issuer and obtain its `trust_bundle` public text.
2. Install it in a protected target-server public-key file referenced by `TrustedUserCAKeys`; validate with `sshd -t`, then reload through the target's normal operations process.
3. Enable the account policy and use existing connection, monitoring or CLI workflows.

Built-in rotation is two-phase. `rotate` prepares a pending CA while the active CA keeps signing. Distribute the full active/pending trust bundle to every affected server before `activate`. Exported bundles retain the previous public key for 11 minutes after activation, covering maximum certificate lifetime. Operators must redistribute/clean target trust files; the platform does not automatically change production sshd. Manage OpenBao CA rotation in OpenBao, then update the pinned public key and distribute trust material here.

This entrypoint issues SSH user certificates. Host certificates, arbitrary client-private-key downloads and automatic target trust-file management are separate capabilities.

## Permissions and API

- `ssh_certificates.view`: read issuers/public keys. Non-managers do not receive OpenBao addresses, roles, namespaces or TLS configuration.
- `ssh_certificates.manage`: manage authorities, prepare/activate built-in rotation and delete.
- `ssh_certificates.assign` plus `assets.manage`: bind currently visible SSH accounts. Binding reads also recheck exact-account visibility.
- `ssh_certificates.audit`: read organization change/issuance metadata.

All support organization roles. CA management does not grant target-account access, and callers cannot request arbitrary principals or signing private keys. Deleting an issuer with live account references conflicts. Proven-deleted resources' stale bindings can be removed during issuer deletion; uncertain inventory reads conservatively preserve references.

API prefix: `/api/v1/settings/ssh-certificates`.

| Method/path | Purpose |
|---|---|
| `GET /issuers` | Authorities, public keys, trust bundles, revisions and pending keys |
| `POST /issuers`, `PUT /issuers/{id}` | Create/edit; empty token retains saved token |
| `POST /issuers/{id}/rotate` | Prepare built-in CA rotation |
| `POST /issuers/{id}/activate` | Explicitly activate the pending CA |
| `DELETE /issuers/{id}` | Delete an authority without live references |
| `GET /bindings/{assetOrAccountID}` | Current account policy/endpoint |
| `PUT /bindings/{assetOrAccountID}` | Replace policy; empty issuer_id clears it |
| `GET /audit?offset=0&limit=20` | Paginated audit, maximum limit 100 |

Management writes use the current `revision` and an 8–100 character alphanumeric, `_` or `-` request ID. The same actor/request/normalized content returns the original receipt. Changed content and stale revisions conflict. Repeating preparation, activation, deletion or clearing does not repeat mutation; old binding receipts never restore a subsequently cleared policy. Every API retry checks current authority first.

```sh
jms ssh-certificates list
jms ssh-certificates save --file issuer.json
jms ssh-certificates binding ASSET_OR_ACCOUNT_ID
jms ssh-certificates bind ASSET_OR_ACCOUNT_ID --file binding.json
jms ssh-certificates rotate ISSUER_ID --revision 1 --request-id prepare-ca-001
jms ssh-certificates activate ISSUER_ID --revision 2 --request-id activate-ca-001
jms ssh-certificates audit
```

Built-in `issuer.json`:

```json
{"name":"Operations CA","provider":"builtin","enabled":true,"ttl_seconds":300,"revision":0,"request_id":"create-ca-001"}
```

`binding.json`:

```json
{"issuer_id":"sshca-0123456789abcdef0123456789abcdef","revision":0,"request_id":"bind-ca-001"}
```

CLI supports `--file -` and rejects unknown fields. SDK methods: `SSHIssuers`, `SaveSSHIssuer`, `RotateSSHIssuer`, `ActivateSSHIssuer`, `DeleteSSHIssuer`, `SSHCertificateBinding`, `BindSSHCertificate`, `SSHCertificateAudit`. Existing `jms ssh`/`jms exec` and Web connections apply server-side policy without exposing target credentials.

## Persistence, performance and verification boundaries

Each organization's `ssh-certificates.json` or PostgreSQL `ssh-certificates` document uses Vault-derived AES-GCM envelope v1. It encrypts CA private keys, OpenBao tokens, configuration, management receipts and audit. Startup/offline preflight reject unknown formats; stopped-state full backups include the document and keys. Audit records actor, action, account/CA IDs, revision, serial, ephemeral public-key fingerprint and expiry, without private keys, tokens or commands.

Limits: 100 authorities, 20000 account bindings, 4000 immutable management receipts, latest 2000 audit entries, ten retained old CAs and 32 MiB plaintext. Full receipts reject new management changes without evicting idempotency history. OpenBao requires HTTPS/server certificate validation, with HTTP limited to loopback fixtures. Redirects are refused; responses are capped at 64 KiB and calls at five seconds. Concurrent cold requests for one account share issuance. OpenBao calls release the configuration lock and recheck policy afterward; warm connections reuse cache. Large cold-start performance and production OpenBao integration await final verification.

Authored cases cover Testify core/cache expiry/two-phase rotation/format refusal/TLS signing fixtures/PostgreSQL takeover, API permissions, CLI, organization-runtime reopen, encrypted backups and bilingual 390px browser flows. Native QA reuses its existing OpenSSH container/restart for certificate-only accounts, wrong-bootstrap negative controls, monitoring, CLI, SFTP, trust distribution/activation, failure refusal, Web SSH and live revocation. The final unified run will execute these paths and retain/clean evidence under existing idempotent rules. This batch adds no passing evidence.
