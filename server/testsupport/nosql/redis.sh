#!/bin/sh
set -eu
mkdir -p /run/qa-tls
cp /qa-input/server.crt /run/qa-tls/server.crt
cp /qa-input/server.key /run/qa-tls/server.key
cat >/run/qa-tls/redis.conf <<'EOF'
bind 0.0.0.0
port 0
tls-port 6379
tls-cert-file /run/qa-tls/server.crt
tls-key-file /run/qa-tls/server.key
tls-ca-cert-file /run/qa-tls/server.crt
tls-auth-clients no
save ""
appendonly no
user default off
user qadb on >synthetic-redis-query-233 ~* &* +@all
EOF
chmod 600 /run/qa-tls/server.key /run/qa-tls/redis.conf
chown -R redis:redis /run/qa-tls
exec /usr/local/bin/docker-entrypoint.sh redis-server /run/qa-tls/redis.conf
