#!/bin/bash
# Stands in for the legacy VPN: password-only remote access to the flat internal network, no MFA.
set -euo pipefail
useradd -m -s /bin/bash coordenadora 2>/dev/null || true
echo "coordenadora:${LEGACY_VPN_PASSWORD}" | chpasswd
ssh-keygen -A >/dev/null
mkdir -p /var/log/vaurora /central
touch /var/log/vaurora/auth.log /central/legacy-vpn-auth.log
chmod 666 /var/log/vaurora/auth.log
# Lab instrumentation: this mirror models the off-host copy the original network did not have.
# sshd -E writes no timestamp, so the mirror stamps each line as it arrives.
tail -F /var/log/vaurora/auth.log 2>/dev/null | while IFS= read -r line; do
  printf '%s legacy-vpn sshd[1]: %s\n' "$(date '+%b %e %H:%M:%S')" "$line"
done >> /central/legacy-vpn-auth.log &
exec /usr/sbin/sshd -D -E /var/log/vaurora/auth.log -o PasswordAuthentication=yes -o AllowTcpForwarding=yes \
  -o LogLevel=VERBOSE -o UsePAM=no
