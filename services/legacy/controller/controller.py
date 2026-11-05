"""Legacy field controller: obeys the database schedule blindly and depends on the cloud for alerts."""
import os
import time
from pathlib import Path

import psycopg

from vlog import log

DSN = f"host=db-legacy dbname=legacy user=postgres password={os.environ['LEGACY_DB_PASSWORD']}"
FIBER_DOWN = Path("/tmp/fiber_down")
tank, temp = 80.0, 4.5


def schedule() -> bool:
    with psycopg.connect(DSN, connect_timeout=3) as conn:
        row = conn.execute("SELECT hora_inicio, hora_fim, ligada FROM agendamento_bomba WHERE id = 1").fetchone()
    return bool(row[2]) or row[0] <= time.localtime().tm_hour < row[1]


was_on = False
while True:
    try:
        pump_on = schedule()
    except psycopg.Error:
        time.sleep(2)
        continue
    if pump_on != was_on:
        log("legacy-controller", f"pump_state={'on' if pump_on else 'off'} origin=db_schedule validation=none")
        was_on = pump_on
    tank = max(0.0, tank - 2.0) if pump_on else min(100.0, tank + 0.02)
    fiber = not FIBER_DOWN.exists()
    temp += ((12.0 if not fiber else 4.5) - temp) * 0.1
    state = f"tank_pct={tank:.1f} cold_temp_c={temp:.1f} fiber={'up' if fiber else 'down'}"
    if fiber:
        alert = "cloud_alert=sent" if not 2 <= temp <= 8 else "cloud_alert=none"
    else:
        alert = "cloud_alert=unavailable local_alarm=none"  # the original design flaw
    log("legacy-controller", f"{state} {alert}")
    time.sleep(5)
