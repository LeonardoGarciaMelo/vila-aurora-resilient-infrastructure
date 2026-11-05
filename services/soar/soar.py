"""Low-risk playbooks driven by SIEM alerts (RT-15). High-impact actions are not reachable from here:
the SOAR signing key is only accepted by edges for safe_mode and isolate_device.
AI anomalies stay out of this table on purpose: a false positive on the vaccine sensor must not
silence it, so they go to human triage and revocation is the confirmed scripts/revoke_device.sh."""
import base64
import json
import os
import ssl
import time
import uuid
from datetime import datetime
from pathlib import Path

import paho.mqtt.client as mqtt
import requests
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from vlog import log

ALERTS = Path("/wazuh/logs/alerts/alerts.json")
HUB = "http://10.60.0.1:9100"
HEADERS = {"X-Token": os.environ["HUB_API_TOKEN"]}
SIGNING_KEY = load_pem_private_key(Path("/secrets/client/command_signing.key").read_bytes(), None)

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.minimum_version = ssl.TLSVersion.TLSv1_3
ctx.load_verify_locations("/secrets/public/ca-chain.crt")
ctx.load_cert_chain("/secrets/client/client.crt", "/secrets/client/client.key")
broker = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="soar-01")
broker.tls_set_context(ctx)
broker.reconnect_delay_set(1, 10)
broker.connect_async("10.60.0.30", 8883, keepalive=30)
broker.loop_start()


def signed_command(site: str, action: str, **extra) -> None:
    body = json.dumps({"id": str(uuid.uuid4()), "site": site, "actuator": "edge", "action": action,
                       "user": "soar", "issued_at": time.time(), **extra})
    envelope = json.dumps({"body": body, "sig": base64.b64encode(SIGNING_KEY.sign(body.encode())).decode(), "key": "soar"})
    broker.publish(f"vilaaurora/{site}/command/soar", envelope, qos=1)


def hub(path: str, **payload) -> None:
    requests.post(f"{HUB}{path}", json=payload, headers=HEADERS, timeout=5).raise_for_status()


def kick_vpn_peer(alert: dict) -> str:
    peer = alert["data"]["peer"]
    # Cutting an edge stops a whole community space's uplink, which is not low risk: a person decides.
    if not peer.startswith("operator"):
        return f"none peer={peer} escalated_to_human"
    hub("/kick-peer", peer=peer)
    return f"kick_peer peer={peer}"


def block_source_ip(alert: dict) -> str:
    ip = alert["data"]["srcip"]
    hub("/block-ip", ip=ip)
    return f"block_ip ip={ip}"


def safe_mode(alert: dict) -> str:
    site = alert["data"]["site"]
    signed_command(site, "safe_mode", enabled=True)
    return f"safe_mode site={site}"


def isolate_device(alert: dict) -> str:
    site, ip = alert["data"]["site"], alert["data"]["srcip"]
    signed_command(site, "isolate_device", ip=ip)
    return f"isolate_device site={site} ip={ip}"


PLAYBOOKS = {
    "100100": kick_vpn_peer, "100101": kick_vpn_peer,
    "100110": block_source_ip,
    "100120": isolate_device,
    "100130": safe_mode, "100131": safe_mode,
}


def handle(alert: dict) -> None:
    rule = alert["rule"]["id"]
    playbook = PLAYBOOKS.get(rule)
    if playbook is None:
        return
    fired = datetime.strptime(alert["timestamp"], "%Y-%m-%dT%H:%M:%S.%f%z").timestamp()
    try:
        outcome = playbook(alert)
    except (requests.RequestException, KeyError, OSError) as exc:
        log("vilaaurora-soar", f"rule={rule} result=failed error={type(exc).__name__}")
        return
    log("vilaaurora-soar", f"rule={rule} result=done action={outcome} latency_s={time.time() - fired:.2f}")


def main() -> None:
    while not ALERTS.exists():
        time.sleep(2)
    with open(ALERTS, encoding="utf-8") as handle_file:
        handle_file.seek(0, os.SEEK_END)
        while True:
            line = handle_file.readline()
            if not line:
                time.sleep(0.5)
                continue
            try:
                handle(json.loads(line))
            except ValueError:
                continue


if __name__ == "__main__":
    main()
