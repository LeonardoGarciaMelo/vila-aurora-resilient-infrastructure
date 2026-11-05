"""Cloud ingestion: acknowledges an uplink batch only after an idempotent commit."""
import json
import os
import ssl
import time

import paho.mqtt.client as mqtt
import psycopg

from vlog import log

DSN = (f"host=10.60.0.10 dbname=vaurora user=ingest_app password={os.environ['INGEST_DB_PASSWORD']}")
UPSERT = ("INSERT INTO readings (device_id, seq, site, metric, value, read_at) "
          "VALUES (%(device_id)s, %(seq)s, %(site)s, %(metric)s, %(value)s, %(ts)s) "
          "ON CONFLICT (device_id, seq) DO NOTHING")
ALERT = "INSERT INTO alerts (site, severity, message, raised_at) VALUES (%(site)s, 'alto', %(text)s, %(ts)s)"


def connect_db() -> psycopg.Connection:
    while True:
        try:
            return psycopg.connect(DSN)
        except psycopg.OperationalError:
            time.sleep(2)


db = connect_db()


def on_connect(client, _userdata, _flags, reason, _props):
    log("vilaaurora-ingest", f"event=broker_connected reason={reason}")
    client.subscribe("vilaaurora/+/uplink", qos=1)


def on_message(client, _userdata, msg):
    global db
    site = msg.topic.split("/")[1]
    try:
        rows = [row for row in json.loads(msg.payload) if row.get("site") == site]
        with db.cursor() as cur:
            for row in rows:
                cur.execute(UPSERT, row)
                # Alarm copies arrive through the buffer; only the first delivery raises the alert.
                if row.get("metric") == "alarm" and cur.rowcount == 1:
                    cur.execute(ALERT, row)
        db.commit()
        client.ack(msg.mid, msg.qos)
        log("vilaaurora-ingest", f"event=batch_committed site={site} rows={len(rows)}")
    except psycopg.Error as exc:
        log("vilaaurora-ingest", f"event=db_error site={site} error={type(exc).__name__}")
        db = connect_db()
    except ValueError:
        client.ack(msg.mid, msg.qos)
        log("vilaaurora-ingest", f"event=bad_batch site={site}")


ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.minimum_version = ssl.TLSVersion.TLSv1_3
ctx.load_verify_locations("/secrets/public/ca-chain.crt")
ctx.load_cert_chain("/secrets/client/client.crt", "/secrets/client/client.key")

client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="ingest-01", clean_session=False, manual_ack=True)
client.tls_set_context(ctx)
client.on_connect = on_connect
client.on_message = on_message
client.reconnect_delay_set(1, 10)
client.connect_async("10.60.0.30", 8883, keepalive=30)
client.loop_forever()
