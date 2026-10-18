#!/bin/sh
set -eu
umask 077
mkdir -p /run/qa-tls
cd /run/qa-tls
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=JMS233-RADIUS-QA -keyout ca.key -out ca.crt >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -subj /CN=radius.synthetic.invalid -keyout server.key -out server.csr >/dev/null 2>&1
printf 'subjectAltName=DNS:radius.synthetic.invalid,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n' > server.ext
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 2 -extfile server.ext -out server.crt >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -subj /CN=jms233-radius-client -keyout client.key -out client.csr >/dev/null 2>&1
printf 'extendedKeyUsage=clientAuth\n' > client.ext
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 2 -extfile client.ext -out client.crt >/dev/null 2>&1
chmod 755 /run/qa-tls
chown freerad:freerad server.key server.crt ca.crt
exec freeradius -f -l stdout
