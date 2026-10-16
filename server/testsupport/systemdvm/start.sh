#!/bin/sh
set -eu
umask 077
mkdir -p /qa
if [ ! -f /qa/disk.qcow2 ]; then
 ssh-keygen -q -t ed25519 -N '' -f /qa/access
 ssh-keygen -q -t ed25519 -N '' -f /qa/host
 key=$(cat /qa/access.pub)
 {
  printf '%s\n' '#cloud-config' 'hostname: jms233-systemd-qa' 'manage_etc_hosts: true' 'disable_root: false' 'ssh_pwauth: true' 'ssh_deletekeys: false' 'ssh_genkeytypes: []' 'ssh_keys:' '  ed25519_private: |'
  sed 's/^/    /' /qa/host
  printf '  ed25519_public: %s\n' "$(cat /qa/host.pub)"
  printf '%s\n' 'users:' '  - name: root' '    lock_passwd: false' '    ssh_authorized_keys:' "      - $key" '  - name: systemdqa' '    lock_passwd: false' '    shell: /bin/bash' 'chpasswd:' '  expire: false' '  users:' '    - {name: root, password: synthetic-protection-root-password-233, type: text}' '    - {name: systemdqa, password: synthetic-keyhost-password-233, type: text}' 'write_files:' '  - path: /etc/ssh/sshd_config.d/90-jms233-qa.conf' '    permissions: "0600"' '    content: |' '      PermitRootLogin yes' '      PasswordAuthentication yes' 'runcmd:' '  - [sh, -c, "apt-get update && apt-get install -y nftables netcat-openbsd iproute2 dbus-user-session"]' '  - [systemctl, reload, ssh]' '  - [sh, -c, "touch /var/log/auth.log; loginctl enable-linger systemdqa; touch /var/lib/jms233-systemd-qa.ready"]'
 } > /qa/user-data
 printf '%s\n' 'instance-id: jms233-systemd-qa' 'local-hostname: jms233-systemd-qa' > /qa/meta-data
 cloud-localds /qa/seed.img /qa/user-data /qa/meta-data
 qemu-img create -f qcow2 -F qcow2 -b /opt/qa/base.qcow2 /qa/disk.qcow2 6G
 printf '[127.0.0.1]:2222 %s\n' "$(cat /qa/host.pub)" > /qa/known_hosts
fi
exec qemu-system-x86_64 -machine q35 -accel tcg,tb-size=64 -cpu max -smp 2 -m 512 -display none -serial file:/qa/serial.log -monitor none -drive file=/qa/disk.qcow2,if=virtio,format=qcow2 -drive file=/qa/seed.img,if=virtio,format=raw -netdev user,id=net0,hostfwd=tcp:0.0.0.0:2222-:22 -device virtio-net-pci,netdev=net0
