#!/usr/bin/env bash
# Generates every secret the lab needs (idempotent). Nothing here is ever committed.
set -euo pipefail
cd "$(dirname "$0")/.."

SPACES=(centro escola ubs horta abrigo)
declare -A DEVICES=(
  [centro]="energy-01 lock-01"
  [escola]="level-01 pump-01 quality-01"
  [ubs]="coldchamber-01 lock-01"
  [horta]="energy-01 level-01"
  [abrigo]="flood-01 generator-01 air-01"
)

rand() { openssl rand -base64 32 | tr -dc 'A-Za-z0-9' | head -c 32; }
b32() { python3 -c "import base64,os;print(base64.b32encode(os.urandom(20)).decode())"; }

if [[ ! -f .env ]]; then
  sed -e "s|^TZ=.*|TZ=America/Sao_Paulo|" .env.example > .env
  for var in POSTGRES_PASSWORD INGEST_DB_PASSWORD PANEL_DB_PASSWORD AUTH_DB_PASSWORD LEGACY_DB_PASSWORD \
             LEGACY_VPN_PASSWORD PANEL_SESSION_SECRET BADGE_HMAC_KEY HUB_API_TOKEN AI_DB_PASSWORD; do
    sed -i "s|^$var=.*|$var=$(rand)|" .env
  done
  sed -i "s|^ZTNA_OPERATOR_TOTP=.*|ZTNA_OPERATOR_TOTP=$(b32)|" .env
  chmod 600 .env
  echo "created .env"
fi

umask 077
mkdir -p secrets
pki/pki.sh init

issue_once() { # cn out_dir san file_name
  [[ -f "$2/$4.crt" ]] || pki/pki.sh issue "$1" "$2" "$3" "$4"
}

wg_keypair() { # path_without_extension
  [[ -f "$1.key" ]] && return
  openssl genpkey -algorithm x25519 -outform DER -out "$1.der" 2>/dev/null
  tail -c 32 "$1.der" | base64 > "$1.key"
  openssl pkey -inform DER -in "$1.der" -pubout -outform DER | tail -c 32 | base64 > "$1.pub"
  rm -f "$1.der"
}

site_id=0
for space in "${SPACES[@]}"; do
  site_id=$((site_id + 1))
  dir="secrets/edges/$space"; mkdir -p "$dir" "secrets/devices/$space"
  issue_once "edge-$space" "$dir" "DNS:localhost,IP:127.0.0.1,IP:10.10.$site_id.2" server
  issue_once "$space-edge-01" "$dir" "" client
  wg_keypair "$dir/wg"
  for device in ${DEVICES[$space]}; do
    issue_once "$space-$device" "secrets/devices/$space" "" "$space-$device"
  done
done

mkdir -p secrets/cloud/broker secrets/cloud/ingest secrets/cloud/panel secrets/hub secrets/operator
issue_once cloud-broker secrets/cloud/broker "IP:10.60.0.30" server
issue_once ingest-01 secrets/cloud/ingest "" client
issue_once panel-01 secrets/cloud/panel "" client
mkdir -p secrets/cloud/waf secrets/lab
issue_once painel.vilaaurora.example secrets/cloud/waf "IP:10.60.0.20,DNS:localhost,IP:127.0.0.1" server
wg_keypair secrets/hub/wg
wg_keypair secrets/operator/wg
cp secrets/hub/wg.pub secrets/public/wg_hub.pub

if [[ ! -f secrets/cloud/panel/command_signing.key ]]; then
  openssl genpkey -algorithm ed25519 -out secrets/cloud/panel/command_signing.key
  openssl pkey -in secrets/cloud/panel/command_signing.key -pubout -out secrets/public/command_signing.pub
fi

mkdir -p secrets/cloud/soar
issue_once soar-01 secrets/cloud/soar "" client
if [[ ! -f secrets/cloud/soar/command_signing.key ]]; then
  openssl genpkey -algorithm ed25519 -out secrets/cloud/soar/command_signing.key
  openssl pkey -in secrets/cloud/soar/command_signing.key -pubout -out secrets/public/soar_signing.pub
fi

# Lab mail domain: the DKIM private key stays in secrets, the zone only carries public data.
mkdir -p secrets/mail
[[ -f secrets/mail/dkim.key ]] || openssl genrsa -out secrets/mail/dkim.key 2048 2>/dev/null
dkim_pub="$(openssl rsa -in secrets/mail/dkim.key -pubout -outform DER 2>/dev/null | base64 -w0)"
cat > services/mail-auth/dns/vilaaurora.example.zone <<ZONE
\$ORIGIN vilaaurora.example.
\$TTL 300
@ IN SOA ns1 hostmaster 2026110501 3600 600 86400 300
@ IN NS ns1
ns1 IN A 172.27.0.53
@ IN A 172.27.0.10
@ IN MX 10 mail
mail IN A 172.27.0.10
@ IN TXT "v=spf1 ip4:172.27.0.10 -all"
mail._domainkey IN TXT "v=DKIM1; k=rsa; p=$dkim_pub"
_dmarc IN TXT "v=DMARC1; p=quarantine; pct=100; adkim=s; aspf=s; rua=mailto:dmarc@vilaaurora.example"
ZONE
chmod 644 services/mail-auth/dns/vilaaurora.example.zone

# Peer table consumed by the hub: name, tunnel IP, public key
{
  n=1
  for space in "${SPACES[@]}"; do
    echo "edge-$space 10.50.0.$((10 + n)) $(cat "secrets/edges/$space/wg.pub")"
    n=$((n + 1))
  done
  echo "operator-01 10.70.0.10 $(cat secrets/operator/wg.pub)"
} > secrets/hub/peers.conf

# Public material must stay readable from containers; private keys stay in scoped mounts.
chmod -R a+rX secrets/public
echo "bootstrap complete"
