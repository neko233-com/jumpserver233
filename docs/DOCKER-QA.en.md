# Docker isolation and parallel debugging

[中文](./DOCKER-QA.md) | [Documentation](./README.en.md)

Docker builds the production API and web application from source, with separate networks, named data volumes and localhost ports. Builds do not read host Go, Node, `node_modules` or generated native helpers. Runtime images contain only executables and web output. The API and Nginx run as ordinary users with read-only root filesystems.

## Fast verification

Requires Docker Compose and Node 24:

```sh
node scripts/docker-qa.mjs verify
```

Each run creates a random project, empty data volume and two free localhost ports. It checks health, unauthenticated rejection, default login, session identity, production JavaScript, gzip and caching, then removes its containers/network/volume. Named debug environments are never reused or deleted. Logs stay in ignored `.cache/docker-qa/` without login credentials or session tokens.

With existing `web` dependencies and Playwright Chromium, add real browser checks:

```sh
node scripts/docker-qa.mjs verify --browser
```

Browser checks cover English/Chinese inventory and account-risk pages, lazy scripts and page errors. Only the random clean volume runs an empty-account scan and verifies its successful receipt. Retained `up` environments only read risk pages, avoiding interference with existing periodic policies. Real SSH rotation and periodic risk checks run in the full `pnpm test:e2e` suite.

The browser checks production login, Chinese/English switching, page exceptions and that an authenticated console does not load login animation code. Local warm-cache measurements on 2026-10-16: build 3.14 seconds, isolated startup 12.05 seconds, HTTP/parallel-browser checks 3.42 seconds, approximately 18.6 seconds total. Initial image/dependency downloads take additional time. Full SSH/database/real-systemd regression is recorded in [verification records](./TESTING.en.md).

## Retained debug environments

```sh
node scripts/docker-qa.mjs up --project jms233-debug-a --web-port 15173 --api-port 18080 --browser
node scripts/docker-qa.mjs up --project jms233-debug-b --host 127.0.0.3 --web-port 15174 --api-port 18081
```

Web URLs are `http://127.0.0.2:15173` and `http://127.0.0.3:15174`; APIs use `http://127.0.0.2:18080` and `http://127.0.0.3:18081`. Empty stores use the project default administrator; existing data and passwords are preserved. Each project has separate networks, image names and volumes. Published ports bind only to a dedicated loopback address (`127.0.0.2` by default), preserving existing development instances such as 5173.

```sh
node scripts/docker-qa.mjs down --project jms233-debug-a
```

`down` retains the data volume. Docker-only startup is `docker compose -f compose.qa.yml -p jms233-debug up --build --detach --wait`. Default web/API ports are 15173/18080; override with `JMS_QA_WEB_PORT`, `JMS_QA_API_PORT` and `JMS_QA_HOST`. Use different loopback addresses to isolate cookies.

After starting both environments, verify that login does not overwrite the other session in a shared browser context: `node scripts/docker-qa.mjs up --project jms233-debug-a --browser --peer-url http://127.0.0.3:15174`. This passed on 2026-10-16; checking existing environments took approximately 6.5 seconds.

## Caching and scope

BuildKit caches Go modules, compiled Go packages, the pnpm store and incremental TypeScript state. Lockfiles/dependency manifests are copied first, so source edits do not download all dependencies again. `.dockerignore` excludes dependencies, generated programs, runtime data, documentation images and local tool configuration. Cache organization follows [Docker documentation](https://docs.docker.com/build/cache/optimize/).

Acceptance covers Linux amd64 standalone production images and localhost forwarding. Use service names or `host.docker.internal` to reach debug targets; container `127.0.0.1` refers to that container. This entry does not create protocol fixtures or prove cluster HA/production deployment. The default proxy declares no trusted source; configure actual proxies for production source-IP rules as described in [access policies](./ACCESS-POLICIES.en.md).

Actual in-app browser screenshot from the separate Docker port on 2026-10-16. The empty inventory belongs to a fresh data volume:

![Docker English production console](./images/docker-qa.en.png)
