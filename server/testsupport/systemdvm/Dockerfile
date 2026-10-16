FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends qemu-system-x86 qemu-utils cloud-image-utils openssh-client curl ca-certificates && rm -rf /var/lib/apt/lists/*
# Official Debian cloud image, pinned to the digest checked on 2026-10-16.
RUN mkdir /opt/qa && curl --fail --location --retry 2 https://cloud.debian.org/images/cloud/bookworm/20261015-2632/debian-12-genericcloud-amd64-20261015-2632.qcow2 --output /opt/qa/base.qcow2 && echo '56c0bd55b6623f2739f377e983d2872e7b208d0cb9c3ba4e93d3f72929026da03637c598b3bd472b29998c31c8a4c17d8e6ae1c556852a8b83a66a09bf5c2b37  /opt/qa/base.qcow2' | sha512sum --check
COPY start.sh /usr/local/bin/start-systemdvm
RUN sed -i 's/\r$//' /usr/local/bin/start-systemdvm && chmod 755 /usr/local/bin/start-systemdvm
EXPOSE 2222
ENTRYPOINT ["/usr/local/bin/start-systemdvm"]
