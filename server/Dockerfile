# syntax=docker/dockerfile:1
FROM golang:1.27-bookworm@sha256:5cf287a799e6b94384bad13d16b14904c531f51ba65792237e122ce42b392f61 AS build
WORKDIR /src
ENV CGO_ENABLED=0 GOFLAGS=-buildvcs=false
COPY server/go.mod server/go.sum ./
COPY server/third_party ./third_party
RUN --mount=type=cache,id=jms233-go-mod,target=/go/pkg/mod go mod download
COPY server/ ./
RUN --mount=type=cache,id=jms233-go-mod,target=/go/pkg/mod --mount=type=cache,id=jms233-go-build,target=/root/.cache/go-build \
    go generate ./internal/agentbundle && \
    go build -trimpath -ldflags="-s -w" -o /out/server ./cmd/server && \
    go build -trimpath -ldflags="-s -w" -o /out/jms ./cmd/jms

FROM alpine:3.23@sha256:85fe1e81d6758c208f3e1eed4338a1997e19d4be002d4dd32d3100c9a8c010a0
RUN apk add --no-cache ca-certificates && addgroup -S -g 10001 jms && adduser -S -D -H -u 10001 -G jms jms && mkdir /data && chown jms:jms /data
COPY --from=build /out/server /app/server
COPY --from=build /out/jms /usr/local/bin/jms
COPY server/docker-entrypoint.sh /app/entrypoint.sh
RUN chmod 755 /app/entrypoint.sh
USER 10001:10001
ENV JMS_ADDR=0.0.0.0:8080 JMS_DATA_DIR=/data JMS_VERSION=docker-qa HOME=/data
EXPOSE 8080
HEALTHCHECK --interval=1s --timeout=2s --start-period=1s --retries=20 CMD wget -q -O /dev/null http://127.0.0.1:8080/api/health || exit 1
ENTRYPOINT ["/app/entrypoint.sh"]
