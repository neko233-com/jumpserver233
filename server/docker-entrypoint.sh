#!/bin/sh
set -eu
# A non-loopback container listener requires a bootstrap token. Generate one
# locally without publishing or persisting it; normal platform login is used.
if [ -z "${JMS_ADMIN_TOKEN:-}" ]; then
  JMS_ADMIN_TOKEN=$(head -c 48 /dev/urandom | base64 | tr -d '\n')
  export JMS_ADMIN_TOKEN
fi
exec /app/server
