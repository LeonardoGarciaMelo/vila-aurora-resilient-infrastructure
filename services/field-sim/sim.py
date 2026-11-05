"""Simulated field devices. Each device authenticates with its own certificate over MQTT/mTLS."""
import json
import os
import random
import ssl
import threading
import time
from datetime import datetime
from pathlib import Path

import paho.mqtt.client as mqtt

SPACE = os.environ["SPACE"]
BROKER = os.environ["BROKER_IP"]
INTERVAL = float(os.environ.get("READ_INTERVAL_SECONDS", "5"))
CERTS = Path("/secrets/devices")
STATE = Path("/var/lib/field")
FAULTS = Path("/tmp/faults")  # `touch /tmp/faults/<name>` injects a physical event
FAULTS.mkdir(exist_ok=True)
STATE.mkdir(parents=True, exist_ok=True)

SPACE_DEVICES = {
    "centro": {"energy-01": ["load_kw"], "lock-01": ["door_open"]},
    "escola": {"level-01": ["tank_level_pct"], "pump-01": ["pump_on"], "quality-01": ["turbidity_ntu", "chlorine_mgl"]},
    "ubs": {"coldchamber-01": ["cold_temp_c"], "lock-01": ["door_open"]},
    "horta": {"energy-01": ["battery_pct"], "level-01": ["tank_level_pct"]},
    "abrigo": {"flood-01": ["flood_active"], "generator-01": ["generator_on", "grid_power"], "air-01": ["air_quality_aqi", "humidity_pct"]},
}


class Physics:
    """Shared physical state for one space, so actuators visibly change sensors."""

    def __init__(self) -> None:
        self.tank = 80.0
        self.pump_on = False
        self.generator_on = False
        self.temp = 4.5

    def step(self) -> None:
        self.tank = max(0.0, self.tank - 0.5) if self.pump_on else min(100.0, self.tank + 0.02)
        target = 12.0 if (FAULTS / "cold").exists() else 4.5
        self.temp += (target - self.temp) * 0.2

    def read(self, metric: str) -> float:
        fault_freeze = (FAULTS / "freeze").exists()
        noise = 0 if fault_freeze else random.gauss(0, 1)
        values = {
            "load_kw": 3.2 + 0.2 * noise,
            "battery_pct": 72 + 0.5 * noise,
            "door_open": float(random.random() < 0.02),
            "tank_level_pct": self.tank + 0.1 * noise,
            "pump_on": float(self.pump_on),
            "turbidity_ntu": 0.8 + 0.05 * noise,
            "chlorine_mgl": 1.1 + 0.03 * noise,
            "cold_temp_c": self.temp + 0.1 * noise,
            "flood_active": float((FAULTS / "flood").exists()),
            "generator_on": float(self.generator_on),
            "grid_power": 0.0 if (FAULTS / "grid").exists() else 1.0,
            "air_quality_aqi": 42 + 3 * noise,
            "humidity_pct": 61 + 1.5 * noise,
        }
        return round(values[metric], 3)


class Device(threading.Thread):
    def __init__(self, name: str, metrics: list[str], physics: Physics) -> None:
        super().__init__(daemon=True)
        self.cn, self.metrics, self.physics = f"{SPACE}-{name}", metrics, physics
        self.seq_file = STATE / f"{self.cn}.seq"
        self.seq = int(self.seq_file.read_text()) if self.seq_file.exists() else 0
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.load_verify_locations("/secrets/public/ca-chain.crt")
        ctx.load_cert_chain(CERTS / f"{self.cn}.crt", CERTS / f"{self.cn}.key")
        self.client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=self.cn)
        self.client.tls_set_context(ctx)
        self.client.reconnect_delay_set(1, 10)
        self.client.on_connect = self._on_connect
        self.client.on_message = self._on_command
        self.client.connect_async(BROKER, 8883, keepalive=30)
        self.client.loop_start()

    def _on_connect(self, client, _userdata, _flags, reason, _props):
        print(f"{self.cn} connected: {reason}", flush=True)
        if not reason.is_failure:
            client.subscribe(f"vilaaurora/{SPACE}/{self.cn}/command", qos=1)

    def _on_command(self, _client, _userdata, msg):
        action = json.loads(msg.payload).get("action")
        if "pump" in self.cn:
            self.physics.pump_on = action == "on"
        elif "generator" in self.cn:
            self.physics.generator_on = action == "on"
        print(f"{self.cn} actuated: {action}", flush=True)

    def run(self) -> None:
        while True:
            for metric in self.metrics:
                self.seq += 1
                payload = {
                    "device_id": self.cn, "seq": self.seq, "site": SPACE, "metric": metric,
                    "value": self.physics.read(metric), "ts": datetime.now().astimezone().isoformat(),
                }
                self.client.publish(f"vilaaurora/{SPACE}/{self.cn}/telemetry", json.dumps(payload), qos=1)
            self.seq_file.write_text(str(self.seq))
            time.sleep(INTERVAL)


def main() -> None:
    physics = Physics()
    for name, metrics in SPACE_DEVICES[SPACE].items():
        Device(name, metrics, physics).start()
    while True:
        physics.step()
        time.sleep(INTERVAL)


if __name__ == "__main__":
    main()
