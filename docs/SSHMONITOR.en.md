# SSH Host Monitoring

> [中文](./SSHMONITOR.md) | English

SSH key installation, verified rotation, opt-in seven-day scheduling and persistent staged recovery are described in [SSH key rotation](./SSH-KEY-ROTATION.en.md).

Targets and gateways support imported SSH private keys with write-only input, vault encryption, public fingerprints and verified history restore. Password rotation remains password-specific. See [SSH private keys](./SSHKEYS.en.md).

SSH gateway routing supports up to three pinned hops across monitoring, Web SSH, CLI, SFTP, jobs and password rotation. Configuration and encrypted credentials support standalone and PostgreSQL single-active HA; see [SSH gateways](./GATEWAYS.en.md). Full Enterprise parity remains in progress.

`assets.view_all` grants read-only global inventory/monitoring without SSH access. Probe and asset management have separate system permissions. See [RBAC.en.md](./RBAC.en.md).

The current monitoring panel targets registered Linux SSH hosts. It shows reachability and latency, CPU usage and core count, memory usage, root filesystem usage, and network throughput. Each asset occupies one row; CPU/memory bars sit on the left of the monitoring column, with upload/download rates and a disk bar on the right, matching the supplied reference layout.

## Collection

- The server connects with the SSH credential stored in the encrypted asset vault. The host key must match the pinned SHA256 fingerprint. The browser never receives the SSH password.
- CPU usage comes from a one-second delta between two `/proc/stat` samples. Memory uses `/proc/meminfo`; network counters use `/proc/net/dev` with loopback excluded; disk capacity and usage cover the `/` filesystem.
- Each SSH probe measures connection latency. Network rates are calculated from byte-counter deltas between samples; the first sample, a host reboot, or a counter reset produces a zero rate.
- The default collection interval is 60 seconds. `JMS_MONITOR_INTERVAL` can change it, with a 15-second minimum. The inventory page refreshes every 15 seconds, so new values arrive at the collection interval.
- Hosts without a sample show **Pending**. Failed probes show offline status and a localized error. At most eight hosts are probed concurrently.

## Authorization

- Administrators can add assets, probe them manually, edit them, and delete them.
- Operators see only assets covered by an active user/group–asset/node–SSH-account–action–time grant. Node grants apply to assets assigned to that node and all descendants. `view` allows access to inventory and monitoring data; `connect` includes `view` and allows creating a Web SSH session.
- User, group, asset, and node grants can be managed in Settings → Access Control. Operators see only the node paths containing assets they are allowed to view, plus their ancestors. Administrators can view all sessions; operators can view, stop, and replay only their own sessions.

## Current boundaries

- Monitoring supports hosts with common Linux `/proc` files and POSIX command-line tools. It does not install an agent.
- Only the latest in-memory snapshot is retained. Historical charts, alert rules, and persistent time-series storage are not available. Collection starts again after a server restart.
- Standalone is the default deployment. Cluster mode uses single-active hot standby, so only the lock holder collects metrics. The new active node resumes collection after failover, but the latest in-memory snapshot is not shared across nodes.
