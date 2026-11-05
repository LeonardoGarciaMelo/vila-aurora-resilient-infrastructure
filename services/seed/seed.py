"""Seeds synthetic users and access logs (Faker pt_BR). No real personal data exists in the lab."""
import hashlib
import hmac
import json
import os
import random
import time
from datetime import datetime, timedelta, timezone

import psycopg
import pyotp
from argon2 import PasswordHasher
from faker import Faker

fake = Faker("pt_BR")
Faker.seed(712)
random.seed(712)
HASHER = PasswordHasher()
HMAC_KEY = os.environ["BADGE_HMAC_KEY"].encode()
LOCATIONS = ["Escola Municipal", "UBS", "Centro Comunitário", "Horta Solidária", "Abrigo de Emergência"]
DEMO_ACCOUNTS = [("operador.demo", "operator"), ("tecnico.demo", "technician"), ("coordenacao.demo", "coordination"),
                 ("coordenacao2.demo", "coordination"), ("auditor.demo", "auditor")]
OUTPUT = "/secrets/out/demo_users.json"


def badge_hash(badge: str) -> str:
    return hmac.new(HMAC_KEY, badge.encode(), hashlib.sha256).hexdigest()


def main() -> None:
    dsn = f"host=10.60.0.10 dbname=vaurora user=postgres password={os.environ['POSTGRES_PASSWORD']}"
    for _ in range(30):
        try:
            conn = psycopg.connect(dsn)
            break
        except psycopg.OperationalError:
            time.sleep(2)
    else:
        raise SystemExit("database unavailable")
    with conn, conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM users")
        if cur.fetchone()[0]:
            print("already seeded")
            return
        demo = {}
        for username, role in DEMO_ACCOUNTS:
            password, secret = fake.password(length=16), pyotp.random_base32()
            demo[username] = {"password": password, "totp_secret": secret, "role": role}
            cur.execute("INSERT INTO users (username, display_name, email, role, password_hash, totp_secret) VALUES (%s,%s,%s,%s,%s,%s)",
                        (username, fake.name(), f"{username}@vilaaurora.example", role, HASHER.hash(password), secret))
        for i in range(40):
            name = fake.unique.user_name()
            cur.execute("INSERT INTO users (username, display_name, email, role, password_hash, totp_secret) VALUES (%s,%s,%s,%s,%s,%s)",
                        (name, fake.name(), f"voluntario{i}@vilaaurora.example", "operator", HASHER.hash(fake.password()), pyotp.random_base32()))
        now = datetime.now(timezone.utc)
        badges = [f"BADGE-{n:04d}" for n in range(40)]
        cur.executemany("INSERT INTO access_logs (happened_at, location, badge_hash, result) VALUES (%s,%s,%s,%s)", [
            (now - timedelta(minutes=random.randint(1, 60 * 24 * 30)), random.choice(LOCATIONS),
             badge_hash(random.choice(badges)), random.choice(["liberado"] * 9 + ["negado"]))
            for _ in range(3000)
        ])
    with open(OUTPUT, "w", encoding="utf-8") as handle:
        json.dump(demo, handle, indent=2)
    print("seeded")


if __name__ == "__main__":
    main()
