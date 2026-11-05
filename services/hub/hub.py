"""Hub control plane: VPN handshake logging, ZTNA MFA portal and the SOAR management API."""
import hmac
import ipaddress
import json
import os
import subprocess
import threading
import time
from datetime import datetime
from pathlib import Path

import pyotp
from flask import Flask, abort, jsonify, request

from vlog import log

PEERS = {}
for line in Path("/secrets/hub/peers.conf").read_text().splitlines():
    name, address, key = line.split()
    PEERS[key] = (name, address)
# Each peer may only connect from the addresses it is known to use (fiber and, if it has one, 4G).
EXPECTED_ENDPOINTS = {}
for line in Path("/app/expected_endpoints.conf").read_text().splitlines():
    if line.strip() and not line.startswith("#"):
        name, *addresses = line.split()
        EXPECTED_ENDPOINTS[name] = set(addresses)
BUSINESS = tuple(int(h) for h in os.environ.get("VPN_BUSINESS_HOURS", "06-22").split("-"))
OPERATOR_TOTP = pyotp.TOTP(os.environ["ZTNA_OPERATOR_TOTP"])
API_TOKEN = os.environ["HUB_API_TOKEN"]
SESSION_TIMEOUT = "8h"


def sh(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(args, capture_output=True, text=True, check=False)


def after_hours() -> bool:
    return not BUSINESS[0] <= datetime.now().hour < BUSINESS[1]


def monitor_handshakes() -> None:
    """WireGuard has no native log: we emit one line per new handshake for the SIEM (rules 100100/1)."""
    seen: dict[str, int] = {}
    while True:
        for row in sh("wg", "show", "wg0", "dump").stdout.splitlines()[1:]:
            fields = row.split("\t")
            key, endpoint, handshake = fields[0], fields[2], int(fields[4])
            if handshake and handshake != seen.get(key):
                seen[key] = handshake
                peer, _ = PEERS.get(key, ("unknown", ""))
                src = endpoint.rsplit(":", 1)[0]
                known = "yes" if src in EXPECTED_ENDPOINTS.get(peer, ()) else "no"
                log("wireguard-handshake", f"peer={peer} srcip={src} after_hours={'yes' if after_hours() else 'no'} known_ip={known}", "vpn.log")
        time.sleep(3)


portal = Flask("ztna")


@portal.post("/login")
def ztna_login():
    source = request.remote_addr
    if ipaddress.ip_address(source) not in ipaddress.ip_network("10.70.0.0/24"):
        abort(403)
    code = (request.get_json(silent=True) or {}).get("totp", "")
    if not OPERATOR_TOTP.verify(code, valid_window=1):
        log("vilaaurora-ztna", f"event=mfa_failed srcip={source}", "ztna.log")
        return jsonify(result="denied"), 401
    sh("nft", "add", "element", "inet", "filter", "ztna_ok", f"{{ {source} timeout {SESSION_TIMEOUT} }}")
    log("vilaaurora-ztna", f"event=mfa_ok srcip={source} session={SESSION_TIMEOUT}", "ztna.log")
    return jsonify(result="granted", session=SESSION_TIMEOUT)


api = Flask("hubapi")


def authorised() -> None:
    if not hmac.compare_digest(request.headers.get("X-Token", ""), API_TOKEN):
        abort(401)


@api.post("/block-ip")
def block_ip():
    authorised()
    ip = str(ipaddress.ip_address(request.json["ip"]))
    sh("nft", "add", "element", "inet", "filter", "blocked", f"{{ {ip} timeout 1h }}")
    log("vilaaurora-soar", f"action=block_ip ip={ip}", "soar-hub.log")
    return jsonify(ok=True)


@api.post("/kick-peer")
def kick_peer():
    authorised()
    name = request.json["peer"]
    for key, (peer, address) in PEERS.items():
        if peer == name:
            sh("wg", "set", "wg0", "peer", key, "remove")
            sh("nft", "delete", "element", "inet", "filter", "ztna_ok", f"{{ {address} }}")
            log("vilaaurora-soar", f"action=kick_peer peer={name}", "soar-hub.log")
            return jsonify(ok=True)
    abort(404)


@api.post("/restore-peer")
def restore_peer():
    authorised()
    name = request.json["peer"]
    for key, (peer, address) in PEERS.items():
        if peer == name:
            sh("wg", "set", "wg0", "peer", key, "allowed-ips", f"{address}/32")
            log("vilaaurora-soar", f"action=restore_peer peer={name}", "soar-hub.log")
            return jsonify(ok=True)
    abort(404)


threading.Thread(target=monitor_handshakes, daemon=True).start()
threading.Thread(target=lambda: portal.run(host="10.70.0.1", port=8443), daemon=True).start()
api.run(host="10.60.0.1", port=9100)
