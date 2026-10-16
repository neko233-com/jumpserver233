.PHONY: prepare-agents test test-content test-fixtures test-server test-e2e lint lint-server lint-web build build-server build-cli build-web verify run-server run-web

prepare-agents:
	cd server && go generate ./internal/agentbundle

test: test-content test-fixtures test-server test-e2e

test-content:
	node scripts/check-content.mjs

test-fixtures:
	node --test server/testsupport/docker-qa.test.mjs
	node --test scripts/docker-qa.test.mjs

test-server: prepare-agents
	cd server && go test -timeout 20m ./... github.com/microsoft/go-mssqldb github.com/adfnekc/grdp/protocol/sec github.com/adfnekc/grdp/emission

test-e2e:
	cd web && pnpm test:e2e

lint: lint-server lint-web

lint-server:
	cd server && go vet ./... github.com/microsoft/go-mssqldb github.com/adfnekc/grdp/protocol/sec github.com/adfnekc/grdp/emission

lint-web:
	cd web && pnpm lint

build: build-server build-cli build-web

build-server: prepare-agents
	cd server && go build -trimpath -ldflags="-s -w" -o bin/jms233-server ./cmd/server

build-cli:
	cd server && go build -trimpath -ldflags="-s -w" -o bin/jms ./cmd/jms

build-web:
	cd web && pnpm build

verify: test lint build

run-server: prepare-agents
	cd server && go run ./cmd/server

run-web:
	cd web && pnpm dev
