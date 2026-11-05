#!/usr/bin/env bash
# Project PKI (RT-04/RT-05): offline root, online intermediate, one X.509 per device.
# Usage: pki.sh init | issue <cn> <out_dir> [server_san] | revoke <cn> | crl | list
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
CA_DIR="$ROOT_DIR/secrets/ca"
PUBLIC_DIR="$ROOT_DIR/secrets/public"
DAYS_DEVICE="${DAYS_DEVICE:-30}"
export PKI_CA_DIR="$CA_DIR"

openssl_conf() {
  cat > "$CA_DIR/openssl.cnf" <<CONF
[ ca ]
default_ca = intermediate
[ intermediate ]
dir = \$ENV::PKI_CA_DIR/intermediate
certs = \$dir/certs
new_certs_dir = \$dir/newcerts
database = \$dir/index.txt
serial = \$dir/serial
crlnumber = \$dir/crlnumber
private_key = \$dir/intermediate.key
certificate = \$dir/intermediate.crt
default_md = sha256
default_crl_days = 7
policy = policy_any
unique_subject = no
copy_extensions = copy
[ policy_any ]
commonName = supplied
organizationName = optional
[ req ]
distinguished_name = dn
[ dn ]
[ v3_root ]
basicConstraints = critical, CA:true
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
[ v3_intermediate ]
basicConstraints = critical, CA:true, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
[ v3_leaf ]
basicConstraints = critical, CA:false
keyUsage = critical, digitalSignature
extendedKeyUsage = clientAuth, serverAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
CONF
}

cmd_init() {
  [[ -f "$CA_DIR/root/root.key" ]] && { echo "PKI already initialised"; return; }
  mkdir -p "$CA_DIR"/root "$CA_DIR"/intermediate/{certs,newcerts} "$PUBLIC_DIR"
  chmod 700 "$CA_DIR"
  touch "$CA_DIR/intermediate/index.txt"
  echo 1000 > "$CA_DIR/intermediate/serial"
  echo 1000 > "$CA_DIR/intermediate/crlnumber"
  openssl_conf

  openssl ecparam -name prime256v1 -genkey -noout -out "$CA_DIR/root/root.key"
  openssl req -x509 -new -key "$CA_DIR/root/root.key" -sha256 -days 3650 \
    -subj "/O=Vila Aurora Lab/CN=Vila Aurora Offline Root" \
    -config "$CA_DIR/openssl.cnf" -extensions v3_root -out "$CA_DIR/root/root.crt"

  openssl ecparam -name prime256v1 -genkey -noout -out "$CA_DIR/intermediate/intermediate.key"
  openssl req -new -key "$CA_DIR/intermediate/intermediate.key" \
    -subj "/O=Vila Aurora Lab/CN=Vila Aurora Intermediate" \
    -config "$CA_DIR/openssl.cnf" -out "$CA_DIR/intermediate/intermediate.csr"
  openssl x509 -req -in "$CA_DIR/intermediate/intermediate.csr" -sha256 -days 1825 \
    -CA "$CA_DIR/root/root.crt" -CAkey "$CA_DIR/root/root.key" -CAcreateserial \
    -extfile "$CA_DIR/openssl.cnf" -extensions v3_intermediate \
    -out "$CA_DIR/intermediate/intermediate.crt" 2>/dev/null

  cat "$CA_DIR/intermediate/intermediate.crt" "$CA_DIR/root/root.crt" > "$PUBLIC_DIR/ca-chain.crt"
  cmd_crl
  echo "PKI initialised"
}

cmd_issue() {
  local cn="$1" out="$2" san="${3:-}" name="${4:-$1}"
  mkdir -p "$out"
  local ext; ext="$(mktemp)"
  { echo "subjectAltName = DNS:$cn${san:+,$san}"; } > "$ext"
  openssl ecparam -name prime256v1 -genkey -noout -out "$out/$name.key"
  chmod 600 "$out/$name.key"
  openssl req -new -key "$out/$name.key" -subj "/O=Vila Aurora Lab/CN=$cn" \
    -config "$CA_DIR/openssl.cnf" -out "$out/$name.csr"
  { cat "$CA_DIR/openssl.cnf"; echo "[ leaf_ext ]"; grep -A5 '^\[ v3_leaf \]' "$CA_DIR/openssl.cnf" | tail -n +2; cat "$ext"; } > "$ext.cnf"
  openssl ca -batch -notext -config "$ext.cnf" -extensions leaf_ext -days "$DAYS_DEVICE" \
    -in "$out/$name.csr" -out "$out/$name.crt" 2>/dev/null
  rm -f "$out/$name.csr" "$ext" "$ext.cnf"
  echo "issued $cn serial=$(openssl x509 -in "$out/$name.crt" -noout -serial | cut -d= -f2)"
}

cmd_revoke() {
  local cn="$1" serials
  # awk, not `read`: tab is IFS whitespace there and the empty revocation column would collapse.
  serials="$(awk -F'\t' -v cn="CN=$cn" '$1 == "V" && index($6, cn) { print $4 }' "$CA_DIR/intermediate/index.txt")"
  [[ -n "$serials" ]] || { echo "no valid certificate for $cn" >&2; exit 1; }
  for serial in $serials; do
    openssl ca -config "$CA_DIR/openssl.cnf" -revoke "$CA_DIR/intermediate/newcerts/$serial.pem" 2>/dev/null
    echo "revoked $cn serial=$serial"
  done
  cmd_crl
}

cmd_crl() {
  openssl ca -config "$CA_DIR/openssl.cnf" -gencrl -out "$CA_DIR/intermediate/intermediate.crl" 2>/dev/null
  # Mosquitto needs a CRL for every CA in the chain when check_all is active.
  openssl ca -config "$CA_DIR/openssl.cnf" -gencrl -out "$PUBLIC_DIR/crl.pem" 2>/dev/null
  chmod 644 "$PUBLIC_DIR/crl.pem"
  # The SOAR container runs this as root: keep files usable by the operator on the host.
  if [[ $EUID -eq 0 ]]; then chown -R --reference="$CA_DIR" "$CA_DIR" "$PUBLIC_DIR"; fi
}

cmd_list() {
  awk -F'\t' '{printf "%s serial=%s %s\n", $1, $4, $6}' "$CA_DIR/intermediate/index.txt"
}

[[ -d "$CA_DIR/intermediate" ]] && openssl_conf

case "${1:-}" in
  init) cmd_init ;;
  issue) shift; cmd_issue "$@" ;;
  revoke) shift; cmd_revoke "$@" ;;
  crl) cmd_crl ;;
  list) cmd_list ;;
  *) echo "usage: $0 init|issue <cn> <out_dir> [san] [file_name]|revoke <cn>|crl|list" >&2; exit 2 ;;
esac
