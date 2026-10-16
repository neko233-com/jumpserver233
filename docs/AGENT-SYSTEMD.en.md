# Native Agent supervision with systemd

[中文](./AGENT-SYSTEMD.md) | [Documentation index](./README.en.md)

On Linux hosts with existing systemd, the platform can create a managed service using the SSH account. Persistent Go `jms-agent` version 3 verifies and periodically runs the fixed launcher. Systemd owns the supervisor and all child processes and restores the service after boot. No new listener, platform token or target-host Go installation is needed.

## Use

Open Tools & agents → Diagnostics & details → systemd service to inspect, enable or disable it. The CLI uses existing platform identity and audit:

```sh
jms plugin ASSET banhack233 systemd_status
jms plugin ASSET banhack233 systemd_enable
jms plugin ASSET banhack233 systemd_disable
```

`systemd_status` requires `plugins.inspect`; enable/disable require `plugins.manage`. All actions still require current target-account `connect` access and pass access policies and login/command reviews. Existing cron supervision remains available. Disable cron before enabling systemd to avoid duplicate starts. The platform does not install systemd, invoke sudo or enable linger automatically.

- Root uses system units under `/etc/systemd/system`.
- Other accounts use an existing user manager and `~/.config/systemd/user`; linger and the user bus must already be available.
- Unit names contain the plugin ID and canonical managed-directory digest. Clients cannot supply a unit name or arbitrary command.

## Lifecycle

The Go component executes only a SHA-256-matching managed `systemd-launcher.sh`. It reads a snapshot without following symlinks, verifies it, and sends those exact bytes to fixed `/bin/sh` stdin. The launcher rechecks pinned artifacts, configuration and process identity. Bounded local status records errors and last checks.

Upgrade, rollback, policy changes and component updates pause systemd first. After committing managed state, the platform rebuilds the fixed unit/launcher and restores service. Unknown units, overrides, drop-ins and malformed metadata are refused. Existing launchers are backed up before replacement. Failures surface a paused/degraded state and need explicit recovery; unknown programs are never executed.

Disabling systemd stops its managed service. An agent that was running is validated and restarted as a manual process, causing a brief restart. Stopping an agent disables supervision too. Uninstall removes only its verified unit and retains configuration, logs, ban state and event history. Reinspect remote state after cancelling a platform job.

The Go supervisor checks every 10 seconds. Crashes and lost kernel ban state use the existing recovery flow with remaining ban timeouts. Temporary kernel-inspection errors do not deliberately terminate an existing monitor. Centralized events use [Agent event audit](./AGENT-EVENTS.en.md).

## Validation boundary

Automation uses a software-emulated Debian QEMU VM without privileged mode or host network/filesystem mounts. It verifies actual PID 1 systemd, root/user units, process-group ownership and reboot. The Debian cloud bookworm image has a pinned SHA-512; credentials are public synthetic fixture data. Service semantics follow the [official systemd v252 manual source](https://github.com/systemd/systemd/blob/v252/man/systemd.service.xml). See [acceptance records](./TESTING.en.md) for actual outcomes. This does not establish acceptance on other Linux distributions, ARM64 or production HA.
