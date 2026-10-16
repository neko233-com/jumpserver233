#!/bin/sh
set -eu
mkdir -p /run/qa-tls
cp /qa-input/server.crt /run/qa-tls/server.crt
cp /qa-input/server.key /run/qa-tls/server.key
chown mysql:mysql /run/qa-tls/server.*
chmod 600 /run/qa-tls/server.key
exec docker-entrypoint.sh "$@" --ssl-ca=/run/qa-tls/server.crt --ssl-cert=/run/qa-tls/server.crt --ssl-key=/run/qa-tls/server.key --local-infile=0 --max-allowed-packet=4M
