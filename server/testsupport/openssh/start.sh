#!/bin/sh
set -eu
# Public synthetic credentials for a disposable loopback-only QA container.
mkdir -p /run/sshd /etc/sudoers.d
if [ ! -f /run/keyhost-ed25519 ]; then
    ssh-keygen -q -t ed25519 -N '' -f /run/keyhost-ed25519
fi
printf '%s\n' 'rotationqa ALL=(root) NOPASSWD: /usr/sbin/chpasswd' 'rotationha ALL=(root) NOPASSWD: /usr/sbin/chpasswd' > /etc/sudoers.d/qa-password-rotation
chmod 0440 /etc/sudoers.d/qa-password-rotation
for fixture_user in keyqa keyha rotationqa rotationha sharedkeyqa sharedkeyha pluginqa; do
    if id -u "$fixture_user" >/dev/null 2>&1; then continue; fi
    useradd --create-home --user-group --shell /bin/bash "$fixture_user"
    printf '%s\n' "$fixture_user:synthetic-keyhost-password-233" | chpasswd
    install -d -m 0700 -o "$fixture_user" -g "$fixture_user" "/home/$fixture_user/.ssh"
    printf '%s\n' '# jumpserver233 disposable OpenSSH fixture' > "/home/$fixture_user/.ssh/authorized_keys"
    chmod 0600 "/home/$fixture_user/.ssh/authorized_keys"
    chown "$fixture_user:$fixture_user" "/home/$fixture_user/.ssh/authorized_keys"
done
# Simulate a host boot: cron's @reboot jobs and the recovery tick must work
# independently of the platform API. Docker restart retains the managed home.
rm -f /run/crond.reboot /run/crond.pid
/usr/sbin/cron
if [ "${JMS_QA_PROTECTION:-false}" = true ]; then
    # Optional, isolated network-namespace firewall QA; never a host mount.
    printf '%s\n' 'root:synthetic-protection-root-password-233' | chpasswd
    touch /var/log/auth.log
    cp /etc/ssh/sshd_config_fixture /run/sshd_config_protection
    sed -i 's/^PermitRootLogin no$/PermitRootLogin yes/; s/^AllowUsers /AllowUsers root /' /run/sshd_config_protection
    exec /usr/sbin/sshd -D -e -f /run/sshd_config_protection
fi
exec /usr/sbin/sshd -D -e -f /etc/ssh/sshd_config_fixture
