# SQL Server driver maintenance

> English | [中文](./UPSTREAM.md)

Runtime sources come from [Microsoft go-mssqldb v1.11.2](https://github.com/microsoft/go-mssqldb/tree/v1.11.2), preserving its original `LICENSE.txt`. This copy includes non-test Go sources for the connector/related packages and module files. Examples, CI, docs, optional Azure/named-pipe/shared-memory entry points and upstream integration tests are excluded. `UPSTREAM.sha256` records original runtime file hashes.

Allocation guards modify `types.go` and add `readlimit.go`: declared PLP lengths, accumulated PLP chunks, legacy text/image and SQL variant sizes are capped at 4 MiB before allocation, raising identifiable `ErrReadLimit`. The upstream decoder can preallocate a very large but valid LOB size, which a network byte limit cannot constrain. Display and connection traffic limits remain separate.

`readlimit_test.go` supplies 2 GiB declarations without payloads to prove rejection before allocation, covering known/unknown PLP, text, variant, accumulation overflow and ordinary values. The main module selects this copy with `go mod replace`; `go test ./... github.com/microsoft/go-mssqldb` includes the patch tests, as do CI and Makefile. Upgrades must compare runtime files with the new official tag, replay this small patch and retain real TLS/TDS, gateway, SQL and HA regressions.

The close path in `mssql.go` also fixes buffer lifetime: it closes the transport first and returns buffers to the pool only when the response reader has finished. Active readers retain their allocation until GC can reclaim it. `connection_close_test.go` verifies active-buffer retention and idle-buffer close ordering. Real TLS limit/reconnect tests and Linux race cover the observed cross-connection reuse race.
