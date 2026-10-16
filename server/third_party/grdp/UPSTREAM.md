# Go RDP 协议运行库来源

> 中文 | [English](./UPSTREAM.en.md)

源：[adfnekc/grdp v0.9.0](https://github.com/adfnekc/grdp/tree/v0.9.0)，MIT，Go 模块校验和 `h1:9Aqm/H56H2nYjwQv7ZI0l5vvoE+2PlKS7HTAfrIpGwY=`。保留 LICENSE。仅引入 core/emission/glog/orders/protocol/codec 的 54 个运行时 Go 文件及模块元数据，共 57 个原始文件，原始 SHA-256 见 `UPSTREAM.sha256`。

本项目通过 go.mod replace 使用此目录，未更改全局模块缓存。未引入上游桌面客户端、宿主机剪贴板、文件/驱动器插件或原生 Windows API。

原始文件的修改限定为：

- `emission/emitter.go`：在任何回调前同时取得 On/Once 监听器快照，防止重新激活监听器被当前消息提前消费。
- `protocol/t125/mcs.go`：用常量解除对平台插件的导入；响应处理器在发送请求前注册；规范化静态通道名称，未知通道禁止回退到全局通道。
- `protocol/sec/sec.go`：许可交换使用专用的 RDP 小端 RSA，补齐许可消息头。
- `protocol/pdu/pdu.go`：图形分片累积限制为 16 MiB。

新增 `protocol/sec/license_rsa.go` 及对应测试，`emission/reactivation_test.go`、`protocol/pdu/frame_ack.go`、`protocol/pdu/refresh.go`、`protocol/pdu/bitmap_only.go`。当前连接仅协商标准位图，关闭未实现的高级编解码、绘图缓存和帧窗口能力；保留帧结束确认处理与有界启动刷新。许可 RSA 仅用于已通过独立 TLS 验证后的许可交换；不改变 TLS 的密钥强度和证书要求。

协议依据：[Microsoft MS-RDPELE](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpele/c57e4890-9049-421e-9fe8-9a6f9519675a)。实际 Windows NLA 验收仍待完成，不能继承上游的生产验证结论。
