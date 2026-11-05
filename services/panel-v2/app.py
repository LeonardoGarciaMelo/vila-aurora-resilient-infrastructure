"""Supervision panel v2 (RT-08, RT-09, RT-21). User-facing text is pt-BR by requirement RT-21."""
import base64
import json
import os
import re
import secrets
import ssl
import time
import uuid
from datetime import timedelta
from functools import wraps

import paho.mqtt.client as mqtt
import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from flask import Flask, abort, flash, g, redirect, render_template, request, session, url_for
from sqlalchemy import create_engine, text
from werkzeug.exceptions import HTTPException
from werkzeug.middleware.proxy_fix import ProxyFix

from vlog import log

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)
app.config.update(
    SECRET_KEY=os.environ["PANEL_SESSION_SECRET"],
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
)

# Two least-privilege database identities: only auth_app can read the users table.
DATA = create_engine(f"postgresql+psycopg://panel_app:{os.environ['PANEL_DB_PASSWORD']}@10.60.0.10/vaurora", pool_pre_ping=True)
AUTH = create_engine(f"postgresql+psycopg://auth_app:{os.environ['AUTH_DB_PASSWORD']}@10.60.0.10/vaurora", pool_pre_ping=True)
HASHER = PasswordHasher()
SIGNING_KEY = load_pem_private_key(open("/secrets/client/command_signing.key", "rb").read(), None)

SEARCH_TERM = re.compile(r"^[\w\s\-]{0,40}$")
SITE_ID = re.compile(r"^(centro|escola|ubs|horta|abrigo)$")
ROLE_LABELS = {"operator": "Operador", "technician": "Técnico", "coordination": "Coordenação", "auditor": "Auditor"}
# Anything that can harm people if wrong goes through the human approval queue (RT-15).
HIGH_IMPACT = {("pump", "off"), ("generator", "off"), ("lock", "open_all")}
ALLOWED_COMMANDS = {("pump", "on"), ("pump", "off"), ("generator", "on"), ("generator", "off"), ("lock", "open"), ("lock", "open_all")}
LOGIN_FAILURES: dict[str, list[float]] = {}
MAX_FAILURES, FAILURE_WINDOW = 5, 300


def audit(action: str, detail: str, username: str | None = None) -> None:
    who = username or session.get("user", "anonimo")
    with DATA.begin() as conn:
        conn.execute(
            text("INSERT INTO audit_log (username, action, detail, source_ip) VALUES (:u, :a, :d, :ip)"),
            {"u": who, "a": action, "d": detail, "ip": request.remote_addr},
        )
    log("vilaaurora-panel", f"user={who} action={action} srcip={request.remote_addr} detail={detail}")


def login_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if "user" not in session:
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapper


def requires_role(*roles):
    """RBAC enforced on the server, never only in the interface."""
    def decorator(view):
        @wraps(view)
        def wrapper(*args, **kwargs):
            if session.get("role") not in roles:
                audit("rbac_denied", f"path={request.path}")
                abort(403)
            return view(*args, **kwargs)
        return wrapper
    return decorator


@app.before_request
def csrf_protect():
    if request.method == "POST":
        token = session.get("csrf")
        if not token or not secrets.compare_digest(token, request.form.get("csrf", "")):
            abort(400)


@app.context_processor
def inject_globals():
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(24)
    return {"csrf": session["csrf"], "role_labels": ROLE_LABELS}


@app.after_request
def security_headers(response):
    response.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Strict-Transport-Security"] = "max-age=31536000"
    return response


@app.errorhandler(Exception)
def handle_error(exc):
    # Details stay in the log; the visitor only ever sees a generic message.
    if isinstance(exc, HTTPException):
        messages = {400: "Não entendemos o que foi digitado. Confira e tente de novo.",
                    403: "Você não tem permissão para esta ação.",
                    404: "Página não encontrada."}
        return render_template("error.html", message=messages.get(exc.code, "Algo deu errado.")), exc.code
    app.logger.exception("internal error")
    log("vilaaurora-panel", f"event=internal_error type={type(exc).__name__} path={request.path}")
    return render_template("error.html", message="Algo deu errado. Tente novamente."), 500


@app.route("/healthz")
def healthz():
    return "ok"


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")
    username = request.form.get("username", "")[:60]
    now = time.time()
    failures = [t for t in LOGIN_FAILURES.get(username, []) if now - t < FAILURE_WINDOW]
    if len(failures) >= MAX_FAILURES:
        audit("login_locked", "too_many_attempts", username)
        flash("Muitas tentativas. Aguarde 5 minutos.")
        return render_template("login.html"), 429
    with AUTH.connect() as conn:
        user = conn.execute(
            text("SELECT username, role, password_hash, totp_secret, active FROM users WHERE username = :u"),
            {"u": username},
        ).first()
    valid = False
    if user is not None and user.active:
        try:
            HASHER.verify(user.password_hash, request.form.get("password", ""))
            valid = pyotp.TOTP(user.totp_secret).verify(request.form.get("totp", ""), valid_window=1)
        except VerifyMismatchError:
            valid = False
    if not valid:
        LOGIN_FAILURES[username] = [*failures, now]
        audit("login_failed", "bad_credentials_or_totp", username)
        flash("Usuário, senha ou código incorretos.")
        return render_template("login.html"), 401
    session.clear()
    session.permanent = True
    session.update(user=user.username, role=user.role, csrf=secrets.token_urlsafe(24))
    audit("login_ok", f"role={user.role}")
    return redirect(url_for("dashboard"))


@app.post("/logout")
@login_required
def logout():
    audit("logout", "user_request")
    session.clear()
    return redirect(url_for("login"))


def latest_status() -> list[dict]:
    with DATA.connect() as conn:
        sites = conn.execute(text("SELECT id, name FROM sites ORDER BY name")).fetchall()
        rows = conn.execute(text(
            "SELECT DISTINCT ON (site, metric) site, metric, value, read_at FROM readings "
            "WHERE metric <> 'alarm' ORDER BY site, metric, read_at DESC")).fetchall()
    by_site: dict[str, dict] = {}
    for row in rows:
        by_site.setdefault(row.site, {})[row.metric] = row
    return [describe_site(site, by_site.get(site.id, {})) for site in sites]


def decimal(value: float) -> str:
    return f"{value:.1f}".replace(".", ",")


def describe_site(site, metrics: dict) -> dict:
    """Plain-language status: state is always text plus icon, never colour alone (WCAG 1.4.1)."""
    state, notes = "Normal", []
    temp = metrics.get("cold_temp_c")
    if temp is not None:
        if not 2 <= temp.value <= 8:
            state = "Perigo"
            notes.append(f"A geladeira das vacinas está fora da temperatura segura ({decimal(temp.value)} °C).")
        else:
            notes.append(f"A geladeira das vacinas está em {decimal(temp.value)} °C.")
    tank = metrics.get("tank_level_pct")
    if tank is not None:
        if tank.value < 20:
            state = "Perigo"
            notes.append(f"O reservatório está quase vazio ({tank.value:.0f}%).")
        else:
            notes.append(f"O reservatório está com {tank.value:.0f}% de água.")
    pump = metrics.get("pump_on")
    if pump is not None:
        notes.append("A bomba está ligada." if pump.value else "A bomba está desligada.")
    flood = metrics.get("flood_active")
    if flood is not None:
        if flood.value:
            state = "Perigo"
            notes.append("Há água no piso do abrigo.")
        else:
            notes.append("Sem alagamento.")
    newest = max((m.read_at for m in metrics.values()), default=None)
    if newest is None or time.time() - newest.timestamp() > 120:
        state = "Atenção" if state == "Normal" else state
        notes.append("Sem notícias deste espaço há mais de 2 minutos. O espaço continua operando sozinho.")
    return {"id": site.id, "name": site.name, "state": state, "notes": notes,
            "icon": {"Normal": "✔", "Atenção": "⚠", "Perigo": "⛔"}[state]}


@app.route("/")
@login_required
def dashboard():
    return render_template("dashboard.html", sites=latest_status())


@app.route("/history")
@login_required
@requires_role("coordination", "auditor")
def history():
    term = request.args.get("q", "")
    if not SEARCH_TERM.fullmatch(term):
        abort(400)
    stmt = text("SELECT happened_at, location, badge_hash, result FROM access_logs "
                "WHERE location ILIKE :term ORDER BY happened_at DESC LIMIT 200")
    with DATA.connect() as conn:
        rows = conn.execute(stmt, {"term": f"%{term}%"}).fetchall()
    return render_template("history.html", rows=rows, term=term)


@app.route("/alerts")
@login_required
def alerts():
    with DATA.connect() as conn:
        rows = conn.execute(text("SELECT id, site, severity, message, raised_at, acked_by FROM alerts "
                                 "ORDER BY raised_at DESC LIMIT 100")).fetchall()
    return render_template("alerts.html", rows=rows)


@app.post("/alerts/<int:alert_id>/ack")
@login_required
@requires_role("operator", "technician", "coordination")
def ack_alert(alert_id: int):
    with DATA.begin() as conn:
        conn.execute(text("UPDATE alerts SET acked_by = :u, acked_at = now() WHERE id = :i AND acked_by IS NULL"),
                     {"u": session["user"], "i": alert_id})
    audit("alert_ack", f"alert={alert_id}")
    return redirect(url_for("alerts"))


def send_command(site: str, actuator: str, action: str, user: str) -> None:
    body = json.dumps({"id": str(uuid.uuid4()), "site": site, "actuator": actuator, "action": action,
                       "user": user, "issued_at": time.time()})
    envelope = json.dumps({"body": body, "sig": base64.b64encode(SIGNING_KEY.sign(body.encode())).decode()})
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_verify_locations("/secrets/public/ca-chain.crt")
    ctx.load_cert_chain("/secrets/client/client.crt", "/secrets/client/client.key")
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=f"panel-{uuid.uuid4().hex[:8]}")
    client.tls_set_context(ctx)
    client.connect("10.60.0.30", 8883, keepalive=10)
    client.loop_start()
    client.publish(f"vilaaurora/{site}/command/{actuator}", envelope, qos=1).wait_for_publish(timeout=5)
    client.loop_stop()
    client.disconnect()


@app.route("/commands")
@login_required
@requires_role("technician", "coordination")
def commands():
    with DATA.connect() as conn:
        pending = conn.execute(text("SELECT id, site, actuator, action, requested_by, requested_at FROM pending_actions "
                                    "WHERE status = 'pending' ORDER BY requested_at")).fetchall()
    return render_template("commands.html", pending=pending)


@app.post("/commands")
@login_required
@requires_role("technician", "coordination")
def request_command():
    site, actuator, action = request.form.get("site", ""), request.form.get("actuator", ""), request.form.get("action", "")
    if not SITE_ID.fullmatch(site) or (actuator, action) not in ALLOWED_COMMANDS:
        abort(400)
    if (actuator, action) in HIGH_IMPACT:
        with DATA.begin() as conn:
            conn.execute(text("INSERT INTO pending_actions (site, actuator, action, requested_by) VALUES (:s, :t, :a, :u)"),
                         {"s": site, "t": actuator, "a": action, "u": session["user"]})
        audit("high_impact_requested", f"site={site} actuator={actuator} action={action}")
        flash("Pedido enviado. Esta ação precisa da aprovação da coordenação.")
    else:
        send_command(site, actuator, action, session["user"])
        audit("command_sent", f"site={site} actuator={actuator} action={action}")
        flash("Comando enviado. O espaço ainda confere se é seguro executar.")
    return redirect(url_for("commands"))


@app.post("/commands/<int:action_id>/<any(approve,reject):decision>")
@login_required
@requires_role("coordination")
def decide_command(action_id: int, decision: str):
    with DATA.begin() as conn:
        row = conn.execute(text("SELECT site, actuator, action, requested_by FROM pending_actions "
                                "WHERE id = :i AND status = 'pending' FOR UPDATE"), {"i": action_id}).first()
        if row is None:
            abort(404)
        if row.requested_by == session["user"]:
            audit("approval_denied", f"action={action_id} reason=self_approval")
            flash("Outra pessoa da coordenação precisa aprovar este pedido.")
            return redirect(url_for("commands"))
        status = "approved" if decision == "approve" else "rejected"
        conn.execute(text("UPDATE pending_actions SET status = :s, approved_by = :u, decided_at = now() WHERE id = :i"),
                     {"s": status, "u": session["user"], "i": action_id})
    if decision == "approve":
        send_command(row.site, row.actuator, row.action, session["user"])
    audit("high_impact_decided", f"action={action_id} decision={status}")
    flash("Decisão registrada.")
    return redirect(url_for("commands"))


@app.route("/audit")
@login_required
@requires_role("coordination", "auditor")
def audit_view():
    with DATA.connect() as conn:
        rows = conn.execute(text("SELECT at, username, action, detail, source_ip FROM audit_log ORDER BY at DESC LIMIT 200")).fetchall()
    return render_template("audit.html", rows=rows)


@app.route("/users")
@login_required
@requires_role("coordination")
def users():
    with AUTH.connect() as conn:
        rows = conn.execute(text("SELECT id, username, display_name, role, active FROM users ORDER BY username LIMIT 200")).fetchall()
    return render_template("users.html", rows=rows)


@app.post("/users/<int:user_id>/toggle")
@login_required
@requires_role("coordination")
def toggle_user(user_id: int):
    with AUTH.begin() as conn:
        conn.execute(text("UPDATE users SET active = NOT active WHERE id = :i"), {"i": user_id})
    audit("user_toggled", f"user_id={user_id}")
    return redirect(url_for("users"))
