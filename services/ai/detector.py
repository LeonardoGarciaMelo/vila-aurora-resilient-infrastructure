"""Live anomaly detection. Advisory only: it logs to the SIEM and has no path to any actuator."""
import os
import time
from datetime import datetime

import joblib
import numpy as np
import psycopg

from features import window_features
from vlog import log

DSN = f"host=10.60.0.10 dbname=vaurora user=ai_app password={os.environ['AI_DB_PASSWORD']}"
MODEL = joblib.load("/tmp/model.joblib")
QUERY = ("SELECT value FROM readings WHERE device_id = %s AND metric = %s "
         "AND read_at > now() - interval '5 minutes' ORDER BY read_at")
# The model correlates water and cold chain, which sit in different spaces, so it scores paired streams.
LEVEL, PUMP, TEMP = ("escola-level-01", "tank_level_pct"), ("escola-pump-01", "pump_on"), ("ubs-coldchamber-01", "cold_temp_c")
MIN_POINTS = 30


def series(conn: psycopg.Connection, stream: tuple[str, str]) -> np.ndarray:
    return np.array([r[0] for r in conn.execute(QUERY, stream).fetchall()], dtype=float)


def main() -> None:
    while True:
        try:
            with psycopg.connect(DSN) as conn:
                level, pump, temp = (series(conn, s) for s in (LEVEL, PUMP, TEMP))
            if min(len(level), len(pump), len(temp)) >= MIN_POINTS:
                now = datetime.now()
                features = [window_features(level, pump, temp, now.hour + now.minute / 60)]
                score = float(MODEL.decision_function(features)[0])
                if MODEL.predict(features)[0] == -1:
                    device = "ubs-coldchamber-01" if abs(temp.mean() - 4.5) > 0.5 or temp.std() < 0.02 else "escola-level-01"
                    site = device.split("-")[0]
                    log("vilaaurora-ai", f"event=anomaly site={site} device={device} score={score:.3f}")
        except psycopg.Error as exc:
            log("vilaaurora-ai", f"event=db_error error={type(exc).__name__}")
        time.sleep(60)


if __name__ == "__main__":
    main()
