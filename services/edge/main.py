"""Edge node control service: local rules, command validation, store-and-forward, log shipping."""
import base64
import ipaddress
import json
import re
import os
import socket
import sqlite3
import ssl
import subprocess
import threading
import time
from datetime import datetime
from pathlib import Path

import ntplib
import paho.mqtt.client as mqtt
import psutil
import requests
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from vlog import log

SPACE = os.environ["SPACE"]
CLOUD_HOST = os.environ.get("CLOUD_HOST", "10.60.0.30")
SIEM_HOST = os.environ.get("SIEM_HOST", "10.60.0.40")
HUB_WG_IP = os.environ.get("HUB_WG_IP", "10.50.0.1")
HUB_FIBER_IP = os.environ["HUB_FIBER_IP"]
HUB_4G_IP = os.environ.get("HUB_4G_IP", "")
SMS_URL = os.environ.get("SMS_URL", "")
COLD_ALARM_SECONDS = int(os.environ.get("COLD_ALARM_SECONDS", "300"))
PUMP_WINDOW = (5, 22)
LEVEL_MIN = 20.0
COLD_RANGE = (2.0, 8.0)
COMMAND_MAX_AGE = 120
SOAR_ACTIONS = {"safe_mode", "isolate_device"}
TLS_REJECT = re.compile(r"certificate revoked|certificate verify failed|peer did not return a certificate|unknown ca", re.I)
NEW_CONNECTION = re.compile(r"New connection from ([\d.]+)")
SYNC_BATCH = 200
FAILOVER_RETRY_SECONDS = 60
FAILBACK_SECONDS = int(os.environ.get("FAILBACK_SECONDS", "900"))
RETENTION_DAYS = 7
SECRETS = "/secrets/edge"
PUBLIC = "/secrets/public"
DB_PATH = "/var/lib/vaurora/buffer.db"
METRICS_PATH = Path("/var/lib/vaurora/metrics.json")
# Critical actuators require human approval upstream; the edge still validates all of them.
ACTUATORS = {"pump": f"{SPACE}-pump-01", "generator": f"{SPACE}-generator-01", "lock": f"{SPACE}-lock-01"}


def tls_context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_verify_locations(f"{PUBLIC}/ca-chain.crt")
    ctx.load_cert_chain(f"{SECRETS}/client.crt", f"{SECRETS}/client.key")
    return ctx


class Buffer:
    """SQLite store-and-forward (RT-02). Reconciliation is idempotent on (device_id, seq)."""

    def __init__(self) -> None:
        self.db = sqlite3.connect(DB_PATH, check_same_thread=False)
        self.lock = threading.Lock()
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS buffer(device_id TEXT, seq INTEGER, ts TEXT, payload TEXT, "
            "sent INTEGER DEFAULT 0, PRIMARY KEY(device_id, seq))"
        )
        self.db.execute("CREATE INDEX IF NOT EXISTS buffer_sent ON buffer(sent, ts)")
        self.db.commit()

    def store(self, reading: dict) -> None:
        with self.lock:
            self.db.execute(
                "INSERT OR IGNORE INTO buffer(device_id, seq, ts, payload, sent) VALUES (?, ?, ?, ?, 0)",
                (reading["device_id"], reading["seq"], reading["ts"], json.dumps(reading)),
            )
            self.db.commit()

    def pending(self, limit: int) -> list[tuple]:
        with self.lock:
            return self.db.execute(
                "SELECT rowid, payload FROM buffer WHERE sent = 0 ORDER BY ts LIMIT ?", (limit,)
            ).fetchall()

    def mark_sent(self, rowids: list[int]) -> None:
        with self.lock:
            self.db.executemany("UPDATE buffer SET sent = 1 WHERE rowid = ?", [(r,) for r in rowids])
            self.db.commit()

    def backlog(self) -> int:
        with self.lock:
            return self.db.execute("SELECT count(*) FROM buffer WHERE sent = 0").fetchone()[0]

    def purge(self) -> None:
        with self.lock:
            self.db.execute(
                "DELETE FROM buffer WHERE sent = 1 AND ts < datetime('now', ?)", (f"-{RETENTION_DAYS} days",)
            )
            self.db.commit()


class Edge:
    def __init__(self) -> None:
        self.buffer = Buffer()
        self.command_key = load_pem_public_key(Path(f"{PUBLIC}/command_signing.pub").read_bytes())
        self.soar_key = load_pem_public_key(Path(f"{PUBLIC}/soar_signing.pub").read_bytes())
        self.seen_commands: dict[str, float] = {}
        self.safe_mode = False
        self.state: dict[str, float] = {}
        self.cold_since: float | None = None
        self.cold_alarm_active = False
        self.flood_active = False
        self.pump_locked = False
        self.cloud_up = threading.Event()
        self.online = None
        self.link = "fiber"

        self.local = self._client(f"{SPACE}-edge-01")
        self.local.tls_set_context(tls_context())
        self.local.on_connect = self._on_local_connect
        self.local.on_message = self._on_local_message

        self.cloud = self._client(f"{SPACE}-edge-uplink", clean=False)
        self.cloud.tls_set_context(tls_context())
        self.cloud.on_connect = self._on_cloud_connect
        self.cloud.on_disconnect = self._on_cloud_disconnect
        self.cloud.on_message = self._on_cloud_message
        self.cloud.reconnect_delay_set(2, 15)

    @staticmethod
    def _client(client_id: str, clean: bool = True) -> mqtt.Client:
        return mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=client_id, clean_session=clean)

    # ─── Local broker ───
    def _on_local_connect(self, client, _userdata, _flags, reason, _props):
        log("vilaaurora-edge", f"site={SPACE} event=local_broker_connected reason={reason}")
        client.subscribe(f"vilaaurora/{SPACE}/+/telemetry", qos=1)

    def _on_local_message(self, _client, _userdata, msg):
        try:
            device_from_topic = msg.topic.split("/")[2]
            reading = json.loads(msg.payload)
            if reading.get("device_id") != device_from_topic:
                log("vilaaurora-edge", f"site={SPACE} event=identity_mismatch topic={device_from_topic}")
                return
            self.buffer.store(reading)
            self.apply_rules(reading)
        except (ValueError, KeyError) as exc:
            log("vilaaurora-edge", f"site={SPACE} event=bad_payload error={type(exc).__name__}")

    # ─── Local control rules: work with or without internet (RT-02) ───
    def apply_rules(self, reading: dict) -> None:
        metric, value = reading["metric"], reading["value"]
        self.state[metric] = value
        if metric == "cold_temp_c":
            self._rule_cold_chamber(value)
        elif metric == "tank_level_pct":
            self._rule_tank_level(value)
        elif metric == "flood_active":
            self._rule_flood(value)

    def _rule_cold_chamber(self, value: float) -> None:
        if COLD_RANGE[0] <= value <= COLD_RANGE[1]:
            if self.cold_alarm_active:
                log("vilaaurora-alarm", f"site={SPACE} alarm=cold_chamber state=cleared temp={value}")
            self.cold_since, self.cold_alarm_active = None, False
            return
        self.cold_since = self.cold_since or time.time()
        if not self.cold_alarm_active and time.time() - self.cold_since >= COLD_ALARM_SECONDS:
            self.cold_alarm_active = True
            self._raise_alarm("cold_chamber", f"temp={value}", "A geladeira das vacinas esta fora da temperatura segura")

    def _rule_tank_level(self, value: float) -> None:
        if value < LEVEL_MIN and not self.pump_locked:
            self.pump_locked = True
            self._raise_alarm("low_tank", f"level={value}", "Reservatorio baixo: bomba bloqueada")
            self._actuate("pump", "off", "edge-rule")
        elif value >= LEVEL_MIN + 5 and self.pump_locked:
            self.pump_locked = False
            log("vilaaurora-alarm", f"site={SPACE} alarm=low_tank state=cleared level={value}")

    def _rule_flood(self, value: float) -> None:
        active = bool(value)
        if active and not self.flood_active:
            self._raise_alarm("flood", "sensor=active", "Alagamento detectado no abrigo")
            if not self.state.get("grid_power", 1):
                self._actuate("generator", "on", "edge-rule")
        self.flood_active = active

    def _raise_alarm(self, name: str, detail: str, text: str) -> None:
        # Buzzer/LED are simulated by this log line. The uplink copy waits in the buffer if WAN is down.
        log("vilaaurora-alarm", f"site={SPACE} alarm={name} state=raised {detail} local_alarm=buzzer+led")
        self.buffer.store({"device_id": f"{SPACE}-edge-01", "seq": int(time.time() * 1000), "site": SPACE,
                           "metric": "alarm", "value": 1, "ts": datetime.now().astimezone().isoformat(),
                           "alarm": name, "text": text})
        sent = self._send_sms(text)
        log("vilaaurora-alarm", f"site={SPACE} alarm={name} sms_sent={str(sent).lower()}")

    def _send_sms(self, text: str) -> bool:
        if not SMS_URL:
            return False
        try:
            return requests.post(SMS_URL, json={"site": SPACE, "text": text}, timeout=5).ok
        except requests.RequestException:
            return False

    def _actuate(self, actuator: str, action: str, origin: str) -> None:
        device = ACTUATORS[actuator]
        payload = json.dumps({"action": action, "origin": origin, "ts": datetime.now().isoformat()})
        self.local.publish(f"vilaaurora/{SPACE}/{device}/command", payload, qos=1)
        log("vilaaurora-atuador", f"site={SPACE} atuador={actuator} action={action} user={origin} result=executed reason=ok")

    # ─── Remote commands: signature, freshness, replay, window and safety limits ───
    def _on_cloud_connect(self, client, _userdata, _flags, reason, _props):
        if reason.is_failure:
            return
        client.subscribe(f"vilaaurora/{SPACE}/command/#", qos=1)
        self.cloud_up.set()
        self._set_online(True)

    def _on_cloud_disconnect(self, _client, _userdata, _flags, reason, _props):
        self.cloud_up.clear()
        self._set_online(False, str(reason))

    def _set_online(self, online: bool, reason: str = "") -> None:
        if self.online == online:
            return
        self.online = online
        event = "wan_restored" if online else "wan_lost_islanded"
        log("vilaaurora-edge", f"site={SPACE} event={event} backlog={self.buffer.backlog()} reason={reason or 'ok'}")

    def _on_cloud_message(self, _client, _userdata, msg):
        try:
            self.handle_command(json.loads(msg.payload))
        except (ValueError, KeyError) as exc:
            log("vilaaurora-atuador", f"site={SPACE} atuador=unknown action=unknown user=unknown result=rejected reason=malformed_{type(exc).__name__}")

    def handle_command(self, cmd: dict) -> None:
        body, signature = cmd["body"], cmd["sig"]
        # The SOAR identity holds a separate key limited to low-risk containment actions.
        key = self.soar_key if cmd.get("key") == "soar" else self.command_key
        data = json.loads(body)
        actuator, action, user = data["actuator"], data["action"], data["user"]

        def reject(reason: str) -> None:
            log("vilaaurora-atuador", f"site={SPACE} atuador={actuator} action={action} user={user} result=rejected reason={reason}")

        try:
            key.verify(base64.b64decode(signature), body.encode())
        except (InvalidSignature, ValueError):
            return reject("bad_signature")
        if data["site"] != SPACE:
            return reject("wrong_site")
        if abs(time.time() - data["issued_at"]) > COMMAND_MAX_AGE:
            return reject("stale")
        if data["id"] in self.seen_commands:
            return reject("replay")
        self.seen_commands[data["id"]] = time.time()

        if key is self.soar_key and action not in SOAR_ACTIONS:
            return reject("not_allowed_for_key")
        if action == "isolate_device":
            ip = str(ipaddress.ip_address(data["ip"]))
            subprocess.run(["nft", "add", "element", "inet", "filter", "isolated", f"{{ {ip} }}"], check=False)
            log("vilaaurora-edge", f"site={SPACE} event=device_isolated ip={ip} by={user}")
            return
        if action == "safe_mode":
            self.safe_mode = bool(data.get("enabled", True))
            log("vilaaurora-edge", f"site={SPACE} event=safe_mode enabled={str(self.safe_mode).lower()} by={user}")
            return
        if self.safe_mode:
            return reject("safe_mode")
        if actuator not in ACTUATORS:
            return reject("unknown_actuator")
        if actuator == "pump":
            hour = datetime.fromtimestamp(data.get("execute_at", time.time())).hour
            if not PUMP_WINDOW[0] <= hour < PUMP_WINDOW[1]:
                return reject("out_of_window")
            if action == "on" and self.pump_locked:
                return reject("tank_below_minimum")
        self._actuate(actuator, action, user)

    # ─── Store-and-forward uplink ───
    def sync_loop(self) -> None:
        topic = f"vilaaurora/{SPACE}/uplink"
        while True:
            if not self.cloud_up.is_set():
                time.sleep(2)
                continue
            rows = self.buffer.pending(SYNC_BATCH)
            if not rows:
                time.sleep(2)
                continue
            payload = json.dumps([json.loads(p) for _, p in rows])
            info = self.cloud.publish(topic, payload, qos=1)
            try:
                info.wait_for_publish(timeout=15)
            except (RuntimeError, ValueError):
                time.sleep(2)
                continue
            if info.is_published():
                self.buffer.mark_sent([r for r, _ in rows])

    # ─── 4G failover for spaces with a backup link (RT-03) ───
    def failover_loop(self) -> None:
        if not HUB_4G_IP:
            return
        peer = Path(f"{PUBLIC}/wg_hub.pub").read_text().strip()
        next_switch = 0.0
        on_4g_since = None
        while True:
            time.sleep(15)
            out = subprocess.run(["wg", "show", "wg0", "latest-handshakes"], capture_output=True, text=True).stdout
            parts = out.split()
            age = time.time() - int(parts[1]) if len(parts) == 2 and parts[1] != "0" else 9999
            # During a total outage this keeps probing both paths, but only once a minute.
            if age > 150 and time.time() >= next_switch:
                next_switch = time.time() + FAILOVER_RETRY_SECONDS
                self._switch_link(peer, "fiber" if self.link == "4g" else "4g", f"handshake_age={int(age)}")
                on_4g_since = time.time() if self.link == "4g" else None
            # 4G is a paid backup: try the fiber again from time to time. If it is still down,
            # the rule above returns to 4G, and the buffer covers the gap with no data loss.
            elif self.link == "4g" and on_4g_since and time.time() - on_4g_since > FAILBACK_SECONDS:
                self._switch_link(peer, "fiber", "failback_attempt")
                next_switch = time.time() + 150
                on_4g_since = None

    def _switch_link(self, peer: str, link: str, reason: str) -> None:
        self.link = link
        target = HUB_4G_IP if link == "4g" else HUB_FIBER_IP
        subprocess.run(["wg", "set", "wg0", "peer", peer, "endpoint", f"{target}:51820"], check=False)
        log("vilaaurora-edge", f"site={SPACE} event=link_failover link={link} {reason}")

    # ─── Ships local logs to the SIEM over the tunnel, resuming from a saved offset ───
    def ship_logs_loop(self) -> None:
        cursor_file = Path("/var/lib/vaurora/ship_cursor.json")
        cursor = json.loads(cursor_file.read_text()) if cursor_file.exists() else {}
        sources = ["vilaaurora-edge.log", "vilaaurora-alarm.log", "vilaaurora-atuador.log",
                   "mosquitto.log", "firewall.log", "vilaaurora-time.log"]
        sock = None
        while True:
            try:
                if sock is None:
                    sock = socket.create_connection((SIEM_HOST, 514), timeout=5)
                for name in sources:
                    path = Path("/var/log/vaurora") / name
                    if not path.exists():
                        continue
                    # A file shorter than the saved offset was replaced, so it is read from the start.
                    if path.stat().st_size < cursor.get(name, 0):
                        cursor[name] = 0
                    with open(path, "rb") as handle:
                        handle.seek(cursor.get(name, 0))
                        for raw in handle:
                            sock.sendall(self._syslog_frame(name, raw))
                            cursor[name] = handle.tell()
                cursor_file.write_text(json.dumps(cursor))
            except OSError:
                if sock:
                    sock.close()
                sock = None
            time.sleep(3)

    @staticmethod
    def _syslog_frame(name: str, raw: bytes) -> bytes:
        line = raw.decode("utf-8", "replace").rstrip("\n")
        if name.startswith("vilaaurora-"):
            return (line + "\n").encode()
        stamp = time.strftime("%b %e %H:%M:%S")
        program = "mosquitto" if name == "mosquitto.log" else "edge-firewall"
        return f"{stamp} edge-{SPACE} {program}: {line}\n".encode()

    # ─── Turns broker TLS failures into attributable events and applies new CRLs ───
    def broker_watch_loop(self) -> None:
        path = Path("/var/log/vaurora/mosquitto.log")
        crl = Path(f"{PUBLIC}/crl.pem")
        crl_mtime = crl.stat().st_mtime
        last_ip = "unknown"
        while not path.exists():
            time.sleep(1)
        with open(path, encoding="utf-8", errors="replace") as handle:
            handle.seek(0, os.SEEK_END)
            while True:
                line = handle.readline()
                if line:
                    if match := NEW_CONNECTION.search(line):
                        last_ip = match.group(1)
                    elif match := TLS_REJECT.search(line):
                        detail = match.group(0).replace(" ", "_").lower()
                        log("vilaaurora-edge", f"site={SPACE} event=tls_reject srcip={last_ip} detail={detail}")
                    continue
                if crl.stat().st_mtime != crl_mtime:
                    crl_mtime = crl.stat().st_mtime
                    # A restart also drops live sessions of the revoked device; the rest reconnect on their own.
                    subprocess.run(["pkill", "-x", "mosquitto"], check=False)
                    time.sleep(1)
                    subprocess.run(["mosquitto", "-c", "/etc/mosquitto/vaurora/mosquitto.conf", "-d"], check=False)
                    log("vilaaurora-edge", f"site={SPACE} event=crl_applied")
                time.sleep(0.5)

    # ─── Time sync check and resource metrics (RT-12, RT-22) ───
    def housekeeping_loop(self) -> None:
        ntp = ntplib.NTPClient()
        process = psutil.Process()
        tick = 0
        while True:
            metrics = {
                "at": datetime.now().isoformat(), "site": SPACE, "backlog": self.buffer.backlog(),
                "rss_mb": round(process.memory_info().rss / 1e6, 1),
                "online": bool(self.online), "link": self.link, "safe_mode": self.safe_mode,
            }
            METRICS_PATH.write_text(json.dumps(metrics))
            if tick % 60 == 0:
                try:
                    offset = ntp.request(HUB_WG_IP, version=4, timeout=3).offset
                    log("vilaaurora-time", f"site={SPACE} event=ntp_check offset_ms={offset * 1000:.1f}")
                except (ntplib.NTPException, OSError):
                    log("vilaaurora-time", f"site={SPACE} event=ntp_unreachable")
                self.buffer.purge()
            tick += 1
            time.sleep(5)

    def run(self) -> None:
        self.local.connect_async("localhost", 8883, keepalive=30)
        self.local.loop_start()
        self.cloud.connect_async(CLOUD_HOST, 8883, keepalive=20)
        self.cloud.loop_start()
        for target in (self.sync_loop, self.failover_loop, self.ship_logs_loop, self.broker_watch_loop, self.housekeeping_loop):
            threading.Thread(target=target, daemon=True).start()
        self._set_online(False, "booting")
        while True:
            time.sleep(60)


if __name__ == "__main__":
    Edge().run()
