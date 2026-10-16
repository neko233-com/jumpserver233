#!/bin/sh
set -eu
if ! id -u telnetqa >/dev/null 2>&1; then
    useradd --create-home --user-group --shell /bin/sh telnetqa
    printf '%s\n' 'telnetqa:synthetic-telnet-password-233' | chpasswd
fi
printf '\n' > /etc/issue.net
mkdir -p /run/telnet
cp /qa-input/server.pem /run/telnet/server.pem
chmod 0600 /run/telnet/server.pem
busybox telnetd -F -p 23 -l /bin/login &
exec socat OPENSSL-LISTEN:992,reuseaddr,fork,cert=/run/telnet/server.pem,verify=0 TCP:127.0.0.1:23
