# SSH gateways

> English | [中文](./GATEWAYS.md)

SSH key installation, verified rotation, opt-in seven-day scheduling and persistent staged recovery are described in [SSH key rotation](./SSH-KEY-ROTATION.en.md).

Targets and gateways support imported SSH private keys with write-only input, vault encryption, public fingerprints and verified history restore. Password rotation remains password-specific. See [SSH private keys](./SSHKEYS.en.md).

Administrators can route an SSH asset through another registered SSH asset. Standalone deployment comes first; gateway references and encrypted credentials use the existing asset store with PostgreSQL single-active HA support. The competitor is [JumpServer Enterprise](https://www.jumpserver.org/enterprise.html); full parity remains in progress in [PLAN](./PLAN.en.md).

## Configuration and connections

Register the outer gateway address, account, password and SHA256 host fingerprint verified through a trusted channel. Then select it in the target asset's “SSH gateway” field. The final gateway resolves the target address; the platform does not need direct access to it. Gateway SSH services must allow `direct-tcpip` forwarding to the next hop. The platform requests no interactive gateway shell or SSH agent forwarding.

Each asset may reference one gateway, with at most three gateway hops, ordered outer → inner → target. Creation, updates and loading reject missing references, cycles and excessive depth, including upstream changes that invalidate existing descendants. Referenced gateways cannot be deleted (`409 ssh_gateway_in_use`). Omitting API `gateway_id` preserves it on update; an empty string clears it.

Every hop authenticates independently using vault credentials and verifies its own pinned host key. Asset responses contain no passwords, private keys or internal credential routes. Handshake failure or timeout closes the entire transport; closing a terminal, file session or job also closes its gateway connections.

## Authorization and audit

Route configuration requires asset-management permission. An administrator-selected gateway is platform connection infrastructure: operators need the corresponding target `view`, `connect` or `sftp` grant, without direct gateway login permission. Target login reviews, command policies and dispatch-time authorization still apply. Gateway login-review settings govern direct gateway login and do not add a second review for downstream routing. Restrict gateway configuration to trusted administrators.

Monitoring, Web SSH, Agent CLI, SFTP, command/batch/scheduled jobs, seven-day password rotation and credential recovery share this connector. Session indexes record the actual `gateway_ids` at connection time, outermost first, without gateway secrets. Target grants do not reveal the gateway inventory or credentials.

## Rotation and HA boundaries

Pending gateway password rotation/recovery blocks new downstream connections. Recover the gateway first, then retry downstream operations. Established sessions do not migrate; restart or HA takeover requires reconnection. Recovering configuration and encrypted credentials does not provide uninterrupted sessions or multi-active HA. Separate network-domain objects, automatic gateway selection, custom authorization files and production network failure drills remain open.

## Verification

Testify covers actual one-to-three-hop forwarding, per-hop host keys and authentication, metrics and commands, PTY/resize, SFTP, password rotation and new-credential verification, timeout cleanup, graph validation, persistence and API errors. HA integration covers route references and deletion protection after takeover. Playwright uses `private.synthetic.invalid`, mapped only inside the gateway fixture, for the form, monitoring, target-only grants, Web SSH, session audit and Agent CLI. Synthetic verification does not establish production-host acceptance. See [TESTING](./TESTING.en.md) for the unified entry point.
