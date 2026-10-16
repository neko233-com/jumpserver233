FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends busybox-static socat passwd ca-certificates && rm -rf /var/lib/apt/lists/*
COPY start.sh /usr/local/bin/start-telnet-qa
RUN sed -i 's/\r$//' /usr/local/bin/start-telnet-qa && chmod 0755 /usr/local/bin/start-telnet-qa
EXPOSE 23 992
ENTRYPOINT ["/usr/local/bin/start-telnet-qa"]
