#!/bin/bash
# VPN hub: the only service on the external segments, exposing nothing except 51820/udp.
set -euo pipefail
mkdir -p /var/log/vaurora

cat > /etc/ulogd.conf <<'CONF'
[global]
logfile="/var/log/vaurora/ulogd-hub.log"
loglevel=5
plugin="/usr/lib/x86_64-linux-gnu/ulogd/ulogd_inppkt_NFLOG.so"
plugin="/usr/lib/x86_64-linux-gnu/ulogd/ulogd_raw2packet_BASE.so"
plugin="/usr/lib/x86_64-linux-gnu/ulogd/ulogd_filter_IFINDEX.so"
plugin="/usr/lib/x86_64-linux-gnu/ulogd/ulogd_filter_IP2STR.so"
plugin="/usr/lib/x86_64-linux-gnu/ulogd/ulogd_filter_PRINTPKT.so"
plugin="/usr/lib/x86_64-linux-gnu/ulogd/ulogd_output_LOGEMU.so"
stack=log1:NFLOG,base1:BASE,ifi1:IFINDEX,ip2str1:IP2STR,print1:PRINTPKT,emu1:LOGEMU
[log1]
group=1
[emu1]
file="/var/log/vaurora/hub-firewall.log"
sync=1
CONF
ulogd -d -c /etc/ulogd.conf

nft -f /app/ruleset.nft

ip link add wg0 type wireguard
wg set wg0 listen-port 51820 private-key /secrets/hub/wg.key
ip addr add 10.50.0.1/24 dev wg0
ip addr add 10.70.0.1/24 dev wg0
ip link set wg0 up
while read -r name address key; do
  [[ -n "$name" ]] && wg set wg0 peer "$key" allowed-ips "$address/32"
done < /secrets/hub/peers.conf

# Serves the host-synchronised clock to the edges; -x because containers cannot set the clock.
cat > /etc/chrony/chrony.conf <<'CONF'
local stratum 8
allow 10.50.0.0/24
bindaddress 10.50.0.1
driftfile /var/lib/chrony/drift
CONF
chronyd -x -f /etc/chrony/chrony.conf

exec python -u /app/hub.py
