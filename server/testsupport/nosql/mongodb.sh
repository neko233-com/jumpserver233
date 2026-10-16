#!/bin/sh
set -eu
mkdir -p /run/qa-tls
cp /qa-input/server.crt /run/qa-tls/server.crt
cp /qa-input/server.pem /run/qa-tls/server.pem
chmod 600 /run/qa-tls/server.pem
chown -R mongodb:mongodb /run/qa-tls
exec /usr/local/bin/docker-entrypoint.sh mongod --bind_ip_all --auth --tlsMode requireTLS --tlsCertificateKeyFile /run/qa-tls/server.pem --tlsCAFile /run/qa-tls/server.crt --tlsAllowConnectionsWithoutCertificates --wiredTigerCacheSizeGB 0.25 --quiet
