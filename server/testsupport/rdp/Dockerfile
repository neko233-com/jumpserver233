FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends xrdp xorgxrdp xserver-xorg-core openbox python3-tk dbus dbus-x11 fonts-dejavu-core ca-certificates && rm -rf /var/lib/apt/lists/*
COPY start.sh desktop.py /opt/qa/
RUN sed -i 's/\r$//' /opt/qa/start.sh && chmod 0755 /opt/qa/start.sh
EXPOSE 3389
ENTRYPOINT ["/opt/qa/start.sh"]
