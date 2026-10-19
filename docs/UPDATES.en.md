# Release checks and native artifacts

> [中文](./UPDATES.md) | English

System settings → Security → Software updates shows the running version, published stable releases, optional automatic checks, native packages/checksums and recent activity. External checks are disabled by default. Enable a 1–168-hour interval, default 24 hours. Checks/downloads never install software or replace business data. Controlled installation, migration, health checks and automatic failure rollback remain pending; this is not the complete general updater.

## Source and permissions

Only the [official GitHub Releases](https://github.com/neko233-com/jumpserver233/releases) feed is used. Unpublished tags, drafts and prereleases are excluded; stable tags use `vX.Y.Z`. Development builds and source SHAs explicitly report that comparison is unavailable. No published release produces a clear no-release state.

Web/API/platform CLI share global `security.manage`, existing four authentication methods and login-access policies. Organization administrators do not automatically gain this permission. `X-JMS-ORG` format remains validated while update configuration is global. Automatic checks belong to the active node lifecycle. Policy, results, error codes, audit and the latest 100 request receipts support local persistence and PostgreSQL active/standby takeover. Unchanged settings do not increment revisions/audit; stale revisions conflict. Repeated check IDs return their original receipt, and new manual checks have a one-minute minimum interval.

Network failures retain the last successful result. Only fixed error codes are stored, excluding response bodies, credentials and signed redirect URLs. Disabling automatic checks prevents new jobs without canceling an already-issued manual check. Native packages inject version, source commit and build time; existing deployments can still override `JMS_VERSION` explicitly.

## CLI

```sh
jms --version
jms update check
jms update status
jms update audit
jms update policy --revision 1 --automatic=true --interval-hours 24
jms update check-server --revision 2 --request-id update-check-unique-001
jms update download --version v1.2.3 --out /srv/packages/jumpserver233.tar.gz
jms update verify --file /srv/packages/jumpserver233.tar.gz --sha256 EXPECTED_SHA256
```

`check`, `download` and `verify` run locally; other commands use the existing platform login. Downloads/verification accept `--os linux|darwin|windows --arch amd64|arm64`. Destinations must not exist. A private temporary file is atomically published after full length/SHA-256 validation, and failed downloads remove their temporary file. Downloads are bounded to 256 MiB/five minutes; metadata requests to 20 seconds. Archived programs are never executed.

`verify` checks the entire archive digest, platform/architecture, format version, source commit, stable version, exact file set and per-file hashes without extraction. It rejects traversal, links, Windows device names, case duplicates, file/parent conflicts, missing manifests, corrupt gzip and trailing data. Packages contain two executables, static web output and a manifest, excluding databases, Vault keys, runtime configuration and business data. The manifest version does not establish application data migration compatibility.

## Publication

Local QA entrypoints: `node scripts/update-race-qa.mjs` checks takeover/race using an isolated network and in-memory PostgreSQL. After committing sources, `node scripts/native-package-qa.mjs` builds all six targets and executes the host CLI and a Linux single-port server. Native QA uses a separate web output without overwriting an active `web/dist` verification. Repeated cleanup removes owned containers, temporary archives and runtime data, retaining compact reports. Archive verification on other targets does not prove real-device execution.

release-please maintains changelogs only at formal release time. `release-artifacts.yml` builds six Go packages for Linux/macOS/Windows × amd64/arm64 on a published stable release. Web output is built once; embedded helpers use the generation chain. A reusable `workflow_call` connects release-please without relying on a `GITHUB_TOKEN` event to trigger another workflow. Manually published stable releases also trigger packaging. Ordinary pushes/tags do not create releases.

```sh
cd server
go generate ./internal/agentbundle
go run ./cmd/jms-package --version v1.2.3 --commit FULL_SOURCE_SHA --built-at RFC3339_TIME --target linux/amd64
```

First run `cd web && pnpm build`. Output goes to ignored `dist/`, with a `.sha256` sidecar per archive. Publication targets an existing official stable release only. Retries compare remote size/digest: identical assets remain unchanged; different bytes refuse overwrite. The publisher creates no release/tag or handwritten changelog. Trust currently rests on official GitHub HTTPS metadata and asset digests, not an independent signature or offline trust root. [Release API](https://docs.github.com/en/rest/releases/releases), [asset API](https://docs.github.com/en/rest/releases/assets).

Stop the service normally and complete an [encrypted full-site backup](./BACKUP.en.md) before upgrading. Standalone restoration does not prove PostgreSQL whole-cluster backup or remote-password rollback. Automatic installation and active SSH session handling remain in the [SSH-first scope](./SSH-FIRST.en.md).
