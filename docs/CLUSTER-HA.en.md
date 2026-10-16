# Cluster high availability

> [中文](./CLUSTER-HA.md) | English

Host plugins use existing encrypted job storage. Takeover marks unfinished jobs interrupted and does not replay installations or starts. Remote agents survive platform nodes; detect and act explicitly after takeover. Verified artifacts can be fetched again by their pinned hashes. See [host tools and agents](./HOST-PLUGINS.en.md).

RDP desktops join organization/process shutdown. Historical frames require shared storage and matching keys; takeover requires reconnection and never replays input. RDP production takeover drills remain unverified; see [RDP](./RDP.en.md).

Kubernetes and Telnet configuration/audit also support single-active takeover, without migrating live terminals or one-use tickets. Integration tests verify output on a real active connection before cancelling the leader, then check closure, retained audit and reconnect after takeover. See [Kubernetes](./KUBERNETES.en.md) and [Telnet](./TELNET.en.md) for boundaries.

Native PostgreSQL assets and encrypted query audit also support active/standby operation. Logical sessions and result rows do not migrate; unfinished queries are not replayed. Reconnect after takeover. See [PostgreSQL](./POSTGRESQL.en.md).

Organizations isolate resources, roles and operational audit through `X-JMS-ORG`, browser switching and Agent CLI selection. Standalone storage and PostgreSQL single-active HA are supported. See [Organizations](./ORGANIZATIONS.en.md). Full Enterprise parity remains in progress.

Platform sign-in approval and console notifications use verified identities, original-source one-use completion, encrypted persistence and PostgreSQL single-active HA. See [Platform sign-in reviews](./PLATFORM-LOGIN-REVIEWS.en.md). Full Enterprise parity remains in progress.

Source, weekly-hour and execution-channel restrictions support standalone and single-active HA. See [Access policies](./ACCESS-POLICIES.en.md). Full Enterprise parity remains in progress.

SSH key installation, verified rotation, opt-in seven-day scheduling and persistent staged recovery are described in [SSH key rotation](./SSH-KEY-ROTATION.en.md).

Targets and gateways support imported SSH private keys with write-only input, vault encryption, public fingerprints and verified history restore. Password rotation remains password-specific. See [SSH private keys](./SSHKEYS.en.md).

SSH gateway routing supports up to three pinned hops across monitoring, Web SSH, CLI, SFTP, jobs and password rotation. Configuration and encrypted credentials support standalone and PostgreSQL single-active HA; see [SSH gateways](./GATEWAYS.en.md). Full Enterprise parity remains in progress.

Passkey registration, device-verified sign-in, local MFA, revocation, and HA recovery: [Passkey](./PASSKEY.en.md).

SAML signed assertions, browser binding, local MFA, encrypted SP identity, and configuration audits: [SAML](./SAML.en.md). Remaining profiles and production IdP integration are open.

Encrypted CAS `cas-config`, mappings, and completed shared sessions recover; incomplete flows are process-local. See [CAS.en.md](./CAS.en.md).

Encrypted LDAP `ldap-config`, external mappings, and completed platform sessions also recover. Pending login tickets and failure budgets remain process-local. See [LDAP.en.md](./LDAP.en.md).

System roles, user/group bindings, and change audits also use the PostgreSQL `rbac` document and reload on active-node takeover. See [RBAC.en.md](./RBAC.en.md).

## Current mode

The service supports **single-active hot standby** coordinated by PostgreSQL. Nodes compete for the same PostgreSQL session advisory lock. The lock holder loads shared state and serves the API; other nodes stay on standby. An external load balancer should send application traffic only to nodes whose `/readyz` endpoint returns `200`.

This is single-active hot standby, not active/active. PostgreSQL coordinates election and shared asset, asset-node, user, user-group, grant, and login-session state. Assets, nodes, users, user groups, and grants are stored as JSONB documents (the node document is named `asset-nodes`); login sessions store only SHA-256 token digests. Asset credentials remain encrypted with the shared Vault key. On first startup, each legacy JSON file is imported only if its database document does not yet exist; the database becomes authoritative after import.

Session audit indexes, the file-transfer audit index at `file-transfers/index.jsonl`, recordings, credential-rotation logs, and other files remain under `JMS_DATA_DIR`, which every node must mount as shared read/write storage with reliable atomic rename behavior. During failover, the old node closes its API and active SSH sessions. The new node loads shared state from PostgreSQL, so unexpired login sessions remain valid; active SSH sessions and in-memory monitoring snapshots do not migrate.

## Node configuration

Encrypted OIDC `oidc-config`, user identity mappings, and completed session authentication timestamps also recover from PostgreSQL. State, PKCE, and pending-login tickets are process-local, so incomplete sign-in must restart after takeover. Set the same `JMS_PUBLIC_URL` on every node, matching the HTTPS load balancer's public origin and the provider callback; arbitrary forwarded headers do not determine cookie security. See [OIDC.en.md](./OIDC.en.md).

All nodes use the same `JMS_CLUSTER_MODE=true`, `JMS_CLUSTER_ID`, `JMS_DATABASE_URL`, `JMS_VAULT_KEY`, `JMS_ADMIN_TOKEN`, and shared `JMS_DATA_DIR`. The database URL must connect to the same PostgreSQL database because advisory locks are scoped to a database session and database. Connect directly to PostgreSQL or use a connection mode that preserves the same server session; PgBouncer transaction pooling cannot be used for this election connection.

Each node's `JMS_ADDR` must be reachable by the load balancer. `JMS_CLUSTER_HEALTH_ADDR` uses a separate port (default `0.0.0.0:8081`). `JMS_ADMIN_TOKEN` must contain at least 32 bytes and match on every node. Every node must use the same base64-encoded 32-byte Vault key. Cluster mode does not generate a key or infer a shared data directory.

```text
JMS_CLUSTER_MODE=true
JMS_CLUSTER_ID=jumpserver233-prod
JMS_DATABASE_URL=<connection string for the same PostgreSQL database>
JMS_DATA_DIR=/srv/jumpserver233/shared
JMS_VAULT_KEY=<base64-encoded 32-byte key>
JMS_ADDR=0.0.0.0:8080
JMS_CLUSTER_HEALTH_ADDR=0.0.0.0:8081
JMS_ADMIN_TOKEN=<same admin token on every node, at least 32 bytes>
```

Do not put keys or tokens in images, the repository, or logs. Inject the same values into each node through a secret manager. PostgreSQL and shared file storage need their own availability plan; application-node standby does not make them highly available.

## Probes and failover

- `GET /livez`: returns `200` while the process is alive, including on standby nodes.
- `GET /readyz`: returns `200` only while the node holds the election lock and its application API is listening; standby nodes return `503`.
- If the PostgreSQL session fails, the active node withdraws readiness and closes the API before participating in another election.
- After the active node exits or releases its lock, a standby polls and tries to take over. The external load balancer moves traffic to the new ready node.

The lock is checked every two seconds. Failure detection and load-balancer removal time depend on the database network, operating-system TCP keepalive, and load-balancer settings. This mode does not promise lossless session migration or zero interruption.

## Acceptance boundary

The current implementation provides PostgreSQL-coordinated single-active hot standby, readiness probes, and shared asset/asset-node/user/user-group/grant/login-session documents. PostgreSQL integration tests cover election, failover, and session continuity. Session and file-transfer audit indexes, recordings, and credential-rotation logs still depend on shared file storage; active WebSocket/SSH sessions and monitoring snapshots do not migrate between nodes. PostgreSQL outages, shared-storage outages, strict network-partition fencing, active/active load balancing, Kubernetes orchestration, and production failover drills remain incomplete. Preventing split-brain writes during a network partition still requires external fencing or a write path with fencing tokens.
