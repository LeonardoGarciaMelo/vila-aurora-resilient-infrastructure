#!/bin/bash
# Boots one autonomous edge node: firewall, tunnel, local broker, control service.
set -euo pipefail
: "${SPACE:?}" "${EDGE_IP:?}" "${WG_IP:?}"
# Logs live on the persistent volume: forensic records must survive a container being replaced.
mkdir -p /var/lib/vaurora/log
rm -rf /var/log/vaurora
ln -s /var/lib/vaurora/log /var/log/vaurora

SECRETS=/secrets/edge
PUBLIC=/secrets/public

# ─── Firewall: default deny between segments (RT-07) ───
cat > /etc/ulogd.conf <<'CONF'
[global]
logfile="/var/log/vaurora/ulogd.log"
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
file="/var/log/vaurora/firewall.log"
sync=1
CONF
ulogd -d -c /etc/ulogd.conf

nft -f - <<NFT
flush ruleset
table inet filter {
  set isolated {
    type ipv4_addr
  }
  chain input {
    type filter hook input priority 0; policy drop;
    iifname "lo" accept
    ip saddr @isolated log group 1 prefix "ISOLATED " drop
    ct state established,related accept
    ip saddr 10.10.${SITE_ID}.0/24 tcp dport 8883 accept
    log group 1 prefix "SEG-DROP " drop
  }
  chain forward {
    type filter hook forward priority 0; policy drop;
    log group 1 prefix "SEG-DROP " drop
  }
}
NFT

# ─── WireGuard tunnel to the hub (RT-06) ───
ip link add wg0 type wireguard
wg set wg0 private-key "$SECRETS/wg.key" \
  peer "$(cat "$PUBLIC/wg_hub.pub")" endpoint "${HUB_FIBER_IP}:51820" \
  allowed-ips 10.50.0.0/24,10.60.0.0/24 persistent-keepalive 25
ip addr add "${WG_IP}/32" dev wg0
ip link set wg0 up
ip route add 10.50.0.0/24 dev wg0
ip route add 10.60.0.0/24 dev wg0

# ─── Local broker: mTLS, CRL and per-identity ACL (RT-04) ───
mkdir -p /etc/mosquitto/vaurora
cat > /etc/mosquitto/vaurora/mosquitto.conf <<CONF
per_listener_settings false
persistence false
log_dest file /var/log/vaurora/mosquitto.log
log_timestamp_format %b %d %H:%M:%S
log_type error
log_type warning
log_type notice
log_type information
connection_messages true
user root
allow_anonymous false
acl_file /etc/mosquitto/vaurora/acl
listener 8883
cafile $PUBLIC/ca-chain.crt
certfile $SECRETS/server.crt
keyfile $SECRETS/server.key
crlfile $PUBLIC/crl.pem
require_certificate true
use_identity_as_username true
tls_version tlsv1.3
CONF
cat > /etc/mosquitto/vaurora/acl <<CONF
# Each device writes only its own telemetry and reads only its own commands.
pattern write vilaaurora/${SPACE}/%u/telemetry
pattern read vilaaurora/${SPACE}/%u/command

user ${SPACE}-edge-01
topic read vilaaurora/${SPACE}/+/telemetry
topic write vilaaurora/${SPACE}/+/command
CONF
mosquitto -c /etc/mosquitto/vaurora/mosquitto.conf -d

exec python -u /app/main.py
