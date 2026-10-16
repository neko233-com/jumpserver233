#!/bin/sh
set -eu
mkdir -p /run/qa-tls
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -keyout /run/qa-tls/server.key -out /run/qa-tls/server.crt -subj /CN=postgres.synthetic.invalid -addext 'subjectAltName=DNS:postgres.synthetic.invalid,IP:127.0.0.1' >/dev/null 2>&1
chown postgres:postgres /run/qa-tls/server.*
chmod 600 /run/qa-tls/server.key
exec /usr/local/bin/docker-entrypoint.sh postgres -c ssl=on -c ssl_cert_file=/run/qa-tls/server.crt -c ssl_key_file=/run/qa-tls/server.key
