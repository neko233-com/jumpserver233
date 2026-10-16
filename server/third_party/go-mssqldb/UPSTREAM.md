# SQL Server 驱动维护说明

> 中文 | [English](./UPSTREAM.en.md)

运行时源码来自 [Microsoft go-mssqldb v1.11.2](https://github.com/microsoft/go-mssqldb/tree/v1.11.2)，保留原始 `LICENSE.txt`。仅复制实际连接器及相关包的非测试 Go 源码、模块文件；未复制示例、CI、文档、可选 Azure/命名管道/共享内存入口与上游集成测试。原始运行时文件 SHA-256 保存在 `UPSTREAM.sha256`。

分配保护修改位于 `types.go` 和新增的 `readlimit.go`：在 PLP 声明长度/每块累计长度、旧 text/image 长度、SQL variant 长度被用于内存分配前限制为 4 MiB，并返回可识别的 `ErrReadLimit`。原驱动可按合法但极大的 LOB 长度预分配内存；仅限制网络字节无法约束该分配。SQL 控制台的显示与连接流量限制另行保留。

`readlimit_test.go` 用没有大字段正文的 2 GiB 声明验证分配前拒绝，覆盖已知/未知 PLP、text、variant、累计溢出及普通字段。主模块通过 `go mod replace` 使用本副本，`go test ./... github.com/microsoft/go-mssqldb` 同时执行本地补丁测试；CI 与 Makefile 使用该入口。升级时从新官方 tag 重新核对运行时文件并重放这份小补丁，保留真实 TLS/TDS、网关、SQL 及 HA 回归。

`mssql.go` 的关闭路径另修正缓冲区生命周期：先关闭传输，仅在响应读取协程已经结束时归还池；活动读取保留自己的分配，结束后由 GC 回收。`connection_close_test.go` 验证活动缓冲区不回池及空闲缓冲区的关闭顺序；真实 TLS 超限/重新连接用例和 Linux race 覆盖原先观察到的跨连接复用竞态。
