#!/bin/sh
set -eu
if ! id -u rdpqa >/dev/null 2>&1; then
    useradd --create-home --shell /bin/bash rdpqa
    printf '%s\n' 'rdpqa:synthetic-rdp-password-233' | chpasswd
fi
install -d -m 0755 /run/xrdp /run/dbus
cp /qa-input/server.crt /etc/xrdp/qa.crt
cp /qa-input/server.key /etc/xrdp/qa.key
chown root:xrdp /etc/xrdp/qa.key
chmod 0640 /etc/xrdp/qa.key
sed -i -e 's/^security_layer=.*/security_layer=tls/' -e 's/^certificate=.*/certificate=\/etc\/xrdp\/qa.crt/' -e 's/^key_file=.*/key_file=\/etc\/xrdp\/qa.key/' -e 's/^ssl_protocols=.*/ssl_protocols=TLSv1.2, TLSv1.3/' /etc/xrdp/xrdp.ini
printf '%s\n' '#!/bin/sh' 'exec openbox --startup "python3 /opt/qa/desktop.py"' > /etc/xrdp/startwm.sh
chmod 0755 /etc/xrdp/startwm.sh
rm -f /run/dbus/pid /run/xrdp/xrdp.pid /run/xrdp/xrdp-sesman.pid
dbus-daemon --system --fork
/usr/sbin/xrdp-sesman --nodaemon &
exec /usr/sbin/xrdp --nodaemon
