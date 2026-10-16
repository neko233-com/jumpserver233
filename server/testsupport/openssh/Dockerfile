FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends openssh-server ca-certificates sudo cron nftables iproute2 netcat-openbsd && rm -rf /var/lib/apt/lists/*
COPY sshd_config /etc/ssh/sshd_config_fixture
COPY start.sh /usr/local/bin/start-keyhost
RUN sed -i 's/\r$//' /usr/local/bin/start-keyhost /etc/ssh/sshd_config_fixture && chmod 0755 /usr/local/bin/start-keyhost
EXPOSE 22
ENTRYPOINT ["/usr/local/bin/start-keyhost"]
