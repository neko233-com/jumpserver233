# Multiple identity sources and directory synchronization

> English | [中文](./IDENTITY-SOURCES.md)

Go, API, bilingual Web, CLI/SDK and cases are authored, **unverified**. The complete 42-group implementation gate remains in force. Synthetic providers cannot establish production IdP acceptance.

## Entry points and deployment

Standalone installations use encrypted local files without another database or background service. PostgreSQL deployments reuse document storage with a separate namespace and derived encryption key per source. Identity sources are installation-wide; resource authorization remains organization-scoped.

Create LDAP, OIDC, CAS or SAML sources at `/console/identity-sources`, configure the provider, then enable it. Existing default provider URLs remain compatible. A source does not merge with another source or its default provider. The same issuer/subject in two sources produces different operator identities. Display names, email addresses and role claims never link local accounts or promote users.

New sources use `/api/v1/identity-sources/<source_id>` followed by the existing provider suffix:

```text
/api/v1/identity-sources/idp-<32 lowercase hex digits>/api/v1/authentication/oidc/callback
/api/v1/identity-sources/idp-<32 lowercase hex digits>/api/v1/authentication/cas/callback
/api/v1/identity-sources/idp-<32 lowercase hex digits>/api/v1/authentication/saml/acs
```

OIDC/CAS callbacks, SAML ACS/metadata, flow cookies and one-time capabilities are source-bound. An independent HMAC key also binds flow cookies to the source generation and cookie name. Disable/re-enable or synchronization abort invalidates old callbacks/cookies; a browser cannot relabel an old proof. Identity creation rechecks the request generation. Browsers return to `/login?identity_source=...` for local MFA. The final platform session cookie keeps path `/`. Existing REST authentication methods retain their behavior; HTTP Signatures for named sources bind the original complete URI. Public choices expose only source ID, name, kind and start path, without endpoints or passwords.

Disabling or archiving a source increments its users' authentication generations and revokes AccessKeys, permanent tokens and pending capabilities. Re-enabling cannot revive old credentials. Archiving preserves identity provenance and history; administrators can restore configuration and require fresh sign-in. Provider secrets retain their existing write-only and blank-to-keep behavior.

## Complete LDAP collection

For a named LDAP source, configure a user filter, username attribute, group base DN and group filter in Directory synchronization. Stable identity uses the login provider's `entryUUID` or binary `objectGUID`; display usernames never match platform accounts. The collection filter is separate from the login filter and cannot contain `{username}`.

Collection requires certificate- and hostname-verified LDAPS or StartTLS without plaintext fallback. RFC 2696 pages contain 500 entries, with an absolute 60-second deadline and 32 MiB read budget. Limits are 10,000 users, 2,000 groups, 100,000 member edges and expanded memberships, and 16 nesting levels. `member`, `uniqueMember` and `memberUid` are supported. Parsed DNs and Unicode simple folding handle equivalent spellings.

Missing paging controls, repeated cookies, referrals, server truncation, excessive results, duplicate identities, group cycles and unexpanded AD `member;range=` attributes reject the entire collection. Narrow filters or extend and accept the implementation boundary for larger directories; partial results are never considered complete. AD's disabled bit in `userAccountControl` produces a source suspension.

## Mapping, retries and recovery

Mappings connect directory groups to existing platform groups and organization roles. Configuration and application require system `security.manage`, `groups.manage`, `roles.manage` and `organizations.manage`. Directory claims cannot create a system administrator. Existing RBAC may grant permissions to a global group; select mapped groups deliberately. Organization `admin` is an explicit configuration choice.

Automatic memberships are stored in separate encrypted synchronization state and published through immutable authorization indexes. Manual platform memberships form a union. Manual organization roles, including explicit `none`, take precedence. Directory recovery cannot undo manual disablement, archival or expiry. Creating a user batch persists the user collection once.

Collect a preview, then apply it within 10 minutes. Application checks source, provider and configuration revisions, persists the intent, and blocks source authentication. Authentication resumes after identity state and the membership snapshot are both durable. Failure or restart retains the original request; retry cannot create duplicate identities or repeat a missing-user count. Configuration changes and new previews cannot overwrite a pending transaction. Its original actor can retry. Another administrator with all required permissions can abort, removing automatic memberships and suspending every source user until a successful synchronization restores directory state.

Missing-user policy defaults to `keep`. `remove` removes automatic memberships. `disable` removes them and suspends the user after two independent complete snapshots report absence. LDAP-disabled users are suspended immediately. Source suspension is separate from manual disablement. A failed collection changes neither missing counts nor memberships.

Interval `0` means manual operation; scheduled intervals are 15–10080 minutes and disabled by default. The scheduler starts explicitly after activation, participates in `directory_sync` draining, and performs no network work during offline data checks. Closing cancels collection and joins active work. Each source retains its latest 20 terminal scheduled runs and related scheduler receipts. Human receipts, pending intents and audit have independent bounded capacity; exhaustion preserves data and rejects new changes.

## API and CLI

```text
GET/POST /api/v1/identity-sources
GET/PUT  /api/v1/identity-sources/{id}
GET      /api/v1/identity-sources/audit
GET      /api/v1/authentication/sources
GET/PUT  /api/v1/identity-sources/{id}/sync
GET      /api/v1/identity-sources/{id}/sync/entries|runs|audit
POST     /api/v1/identity-sources/{id}/sync/preview|apply|abort
```

Mutations include revisions and `request_id`. Retrying identical content for the same actor returns the original receipt; altered content conflicts. Lists support `offset` / `limit`, capped at 200 entries. Provider settings use the source prefix followed by the existing `/api/v1/settings/security/<kind>` path.

```text
jms identity-sources list
jms identity-sources save --file -
jms identity-sources get <id>
jms identity-sources audit
jms identity-sources sync <id> settings
jms identity-sources sync <id> save --file -
jms identity-sources sync <id> preview --file -
jms identity-sources sync <id> apply --file -
jms identity-sources sync <id> entries --offset 0 --limit 100
jms identity-sources sync <id> runs
jms identity-sources sync <id> abort --file -
```

Pass JSON through standard input and keep secrets out of command arguments. CLI/SDK transport DTOs avoid linking server IdP runtimes. After browser identity authentication, existing platform identity CLI/AccessKey access remains available without exposing target SSH passwords.

## Pending unified acceptance

Authored testify cases cover named/default-source isolation, MFA and one-time replay, original HTTP Signature URIs, disable/re-enable, encryption-key isolation, batch persistence, TLS paging failures, interrupted restart/abort, manual assignment precedence and missing policies. Browser cases reuse the existing LDAPS fixture for actual directory login, synchronization, mappings, idempotency and bilingual 390px UI. Only essential screenshots are retained; the existing QA lifecycle removes disposable instance data. Actual enterprise LDAP/OIDC/CAS/SAML tenants, capacity boundaries and PostgreSQL restart coverage still require final unified acceptance.
