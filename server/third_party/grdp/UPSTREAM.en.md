# Go RDP runtime provenance

> [中文](./UPSTREAM.md) | English

Source: [adfnekc/grdp v0.9.0](https://github.com/adfnekc/grdp/tree/v0.9.0), MIT, module checksum `h1:9Aqm/H56H2nYjwQv7ZI0l5vvoE+2PlKS7HTAfrIpGwY=`. LICENSE is retained. Only 54 runtime Go files from core/emission/glog/orders/protocol/codec plus module metadata are included, totaling 57 original files. Original SHA-256 values are in `UPSTREAM.sha256`.

The root module replaces the dependency with this directory. The global module cache is untouched. The upstream desktop client, host clipboard, file/drive plugins and native Windows APIs are excluded.

Changes to original files are limited to:

- `emission/emitter.go`: snapshot On/Once listeners before callbacks so reactivation listeners wait for the next message.
- `protocol/t125/mcs.go`: channel constants remove platform plugin imports; handlers register before request writes; static names are normalized and unknown channels cannot fall back to the global channel.
- `protocol/sec/sec.go`: licensing uses dedicated little-endian RDP RSA and includes licensing message headers.
- `protocol/pdu/pdu.go`: graphical fragment accumulation is bounded to 16 MiB.

Added `protocol/sec/license_rsa.go` and its tests, `emission/reactivation_test.go`, `protocol/pdu/frame_ack.go`, `protocol/pdu/refresh.go` and `protocol/pdu/bitmap_only.go`. Connections negotiate standard bitmap output and decline unsupported advanced codecs, drawing caches and frame windows; frame-end acknowledgement handling and bounded startup refreshes remain available. Licensing RSA operates only inside the independently verified TLS transport, without changing TLS key strength or certificate requirements.

Protocol reference: [Microsoft MS-RDPELE](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpele/c57e4890-9049-421e-9fe8-9a6f9519675a). Actual Windows NLA acceptance remains open; upstream production claims do not establish acceptance here.
