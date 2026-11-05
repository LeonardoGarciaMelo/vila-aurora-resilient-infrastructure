"""Panel v1: INTENTIONALLY VULNERABLE reproduction of INC-VA-0712. Runs only on the isolated legacy network."""
import hashlib
import os
import random
import time
import traceback
from datetime import datetime, timedelta, timezone

import psycopg
from faker import Faker
from flask import Flask, redirect, render_template_string, request, session

from vlog import log

app = Flask(__name__)
app.secret_key = os.environ["LEGACY_SESSION_SECRET"]
DSN = f"host=db-legacy dbname=legacy user=postgres password={os.environ['LEGACY_DB_PASSWORD']}"
COORDINATOR_PASSWORD = os.environ["LEGACY_COORDINATOR_PASSWORD"]


def db():
    return psycopg.connect(DSN, autocommit=True)


def seed() -> None:
    for _ in range(30):
        try:
            conn = db()
            break
        except psycopg.OperationalError:
            time.sleep(2)
    fake = Faker("pt_BR")
    with conn, conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM usuarios")
        if cur.fetchone()[0]:
            return
        cur.execute("INSERT INTO usuarios (username, nome, email, telefone, senha_md5, perfil) VALUES (%s,%s,%s,%s,%s,%s)",
                    ("coordenadora", fake.name(), "coordenadora@vilaaurora.example", fake.phone_number(),
                     hashlib.md5(COORDINATOR_PASSWORD.encode()).hexdigest(), "admin"))
        for i in range(39):
            cur.execute("INSERT INTO usuarios (username, nome, email, telefone, senha_md5, perfil) VALUES (%s,%s,%s,%s,%s,%s)",
                        (fake.unique.user_name(), fake.name(), f"voluntario{i}@vilaaurora.example", fake.phone_number(),
                         hashlib.md5(fake.password().encode()).hexdigest(), "operador"))
        now = datetime.now(timezone.utc)
        for _ in range(500):
            cur.execute("INSERT INTO acessos (data, local, cracha) VALUES (%s,%s,%s)",
                        (now - timedelta(hours=random.randint(1, 500)),
                         random.choice(["escola", "ubs", "centro", "horta", "abrigo"]), f"BADGE-{random.randint(0, 39):04d}"))


PAGE = """<!doctype html><title>Painel legado</title><h1>Histórico de acessos</h1>
<form><input name=q value="{{ q }}"><button>Buscar</button></form>
<table>{% for r in rows %}<tr>{% for c in r %}<td>{{ c }}</td>{% endfor %}</tr>{% endfor %}</table>"""


@app.after_request
def access_log(response):
    log("legacy-panel", f'{request.remote_addr} "{request.method} {request.full_path}" {response.status_code}', "legacy-panel-access.log")
    return response


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if request.form.get("username") == "coordenadora" and request.form.get("password") == COORDINATOR_PASSWORD:
            session["user"] = "coordenadora"
            log("legacy-panel", f"login_ok user=coordenadora src={request.remote_addr}", "legacy-panel-app.log")
            return redirect("/history")
        return "login invalido", 401
    return '<form method=post><input name=username><input name=password type=password><button>Entrar</button></form>'


@app.route("/history")
def history():
    if "user" not in session:
        return redirect("/login")
    term = request.args.get("q", "")
    # VULNERABLE ON PURPOSE: string concatenation, privileged user, multi-statement simple protocol.
    sql = f"SELECT data, local, cracha FROM acessos WHERE local LIKE '%{term}%'"
    log("legacy-panel", f"sql={sql!r}", "legacy-panel-app.log")
    try:
        with db() as conn:
            rows = conn.execute(sql).fetchall()
        return render_template_string(PAGE, rows=rows, q=term)
    except Exception:
        return f"<pre>{traceback.format_exc()}</pre>", 500  # VULNERABLE ON PURPOSE: leaks details


if __name__ == "__main__":
    seed()
    app.run(host="0.0.0.0", port=5000)
