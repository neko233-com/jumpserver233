# Website, game, and service account vault

> English | [中文](./PASSWORD-VAULT.md)

The vault stores website, game, and service logins isolated by organization, with private and organization-shared items. The server encrypts data with AES-GCM using its Vault key; the server can decrypt it, and deployment administrators must protect the key and data. This is neither end-to-end encryption nor a 1Password client-compatible implementation. Existing stopped-writer data directory backups include the vault; recovery requires the same Vault key.

Vault APIs accept direct TLS, a local loopback connection, or HTTPS through a trusted reverse proxy. Set `JMS_PUBLIC_URL` to the full HTTPS origin and `JMS_TRUSTED_PROXIES` to the proxy network. The proxy must overwrite `X-Forwarded-Proto` and `Host`. The intranet HTTP address cannot directly transport vault data. Use the Mac's loopback address locally or, where the network permits, a controlled SSH tunnel to local loopback.

To retain an existing HTTP entrance, set `JMS_ADDITIONAL_HTTPS_ORIGIN` to the full HTTPS origin and trust only a proxy that checks Host and Origin and overwrites forwarding headers. Sign-in cookies on that entrance are Secure; the existing entrance keeps its behavior. No additional origin is trusted when the option is unset.

Choose Account vault in the console to add a website, game, or service login. Items are shared with the organization by default; clear the sharing option to keep an item private. Current organization members can view, edit, delete, and authorize Agents for shared items; private items belong only to their creator. Share only within a trusted organization. Editing requires a new password; saving a new revision invalidates prior grants. Deleting an account revokes its grants. Viewing, saving, deleting, granting, revoking, and reading are recorded in activity; the page shows the latest 100 events.

## Agent access

An Agent authenticates with an existing platform session or AccessKey, following [authentication](./AUTH.en.md) for organization selection and credential protection. Create an item with `POST /api/v1/password-vault/items` and JSON fields `kind` (`website`, `game`, or `service`), `title`, `site`, `username`, `password`, and `request_id`. The request ID is a random 16-byte value encoded as lowercase hexadecimal. An identical retry by the same user returns the original item; different content with the same request ID returns 409. Responses and lists exclude passwords. Keep passwords and tokens out of command lines, logs, prompts, and shared conversation records.

In the browser, the user selects Authorize Agent on a specific account to obtain a grant ID and token valid for 10 minutes. Share them through a secure channel with an Agent using the same platform identity. The Agent sends `{"token":"..."}` to `POST /api/v1/password-vault/grants/{id}/consume` with platform authentication. A grant can read only that account's current revision once. It cannot be reused after consumption, deletion, revocation, expiry, or service restart; a lost read response requires a new grant. Active grants can be revoked in the console. Grant issuance requires a browser session; a platform API token or AccessKey cannot issue a grant in place of the user.

Clients must use HTTPS or local loopback, and must not place passwords or grant tokens in URLs. When a user or organization loses access, platform authentication or organization authorization rejects subsequent requests.

## Controlled import

`scripts/password-vault-import.py` reads a JSON array from standard input and uses a platform token from a private file to write into the selected organization. It prints counts only, never account details or passwords. Each item contains `request_id`, `kind`, `title`, `site`, `username`, `password`, and boolean `shared`. Confirm the authoritative source before import and generate stable unique request IDs. Identical input can be retried; changed contents require a new ID and reconciliation with existing entries. The script accepts system-verified HTTPS or local loopback HTTP and rejects redirects. Keep real data out of this public repository and command lines.

A local administrator with the node's service token can provide `owner_id` per item to assign imported records to an existing active organization member. The server accepts this only on direct loopback without forwarding headers and records the actual importing principal. Normal platform tokens and remote proxies cannot assign another owner.

Use `--dry-run` to validate the complete input first. This mode does not read a token, connect to the service, or store passwords.
