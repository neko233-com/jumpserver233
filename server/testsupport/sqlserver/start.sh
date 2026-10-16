#!/bin/sh
set -eu
mkdir -p /run/qa-tls /var/opt/mssql
cp /qa-input/server.crt /run/qa-tls/server.crt
cp /qa-input/server.key /run/qa-tls/server.key
chmod 600 /run/qa-tls/server.key
cp /qa-input/server.crt /usr/local/share/ca-certificates/jms233-qa.crt
update-ca-certificates >/dev/null 2>&1
cat > /var/opt/mssql/mssql.conf <<'EOF'
[network]
tlscert = /run/qa-tls/server.crt
tlskey = /run/qa-tls/server.key
forceencryption = 1
tlsprotocols = 1.2
[memory]
memorylimitmb = 1024
[telemetry]
customerfeedback = false
EOF
chown -R mssql:mssql /run/qa-tls /var/opt/mssql
exec su -s /bin/sh mssql -c /opt/mssql/bin/sqlservr
