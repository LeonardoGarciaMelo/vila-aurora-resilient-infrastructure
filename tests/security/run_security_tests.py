#!/usr/bin/env python3
"""Runs the E3 security test suite against the live lab and stores raw evidence.

Usage: python3 tests/security/run_security_tests.py
Output: evidence/raw/security/*.txt and docs/results/security_results.json
Every offensive step targets this lab's isolated Docker networks only.
"""
import json
import os
import re
import subprocess
import time
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RAW = ROOT / "evidence/raw/security"
RAW.mkdir(parents=True, exist_ok=True)
RESULTS_FILE = ROOT / "docs/results/security_results.json"
RESULTS_FILE.parent.mkdir(parents=True, exist_ok=True)
ATTACKER_IMAGE = "vaurora/attacker:1.0"
PUBLIC = f"{ROOT}/secrets/public"
results: dict = {"started_at": datetime.now().isoformat()}


def run(cmd: list[str], timeout: int = 180, name: str | None = None) -> subprocess.CompletedProcess:
    try:
        done = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=ROOT)
    except subprocess.TimeoutExpired as exc:
        out = (exc.stdout or b"").decode() if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        done = subprocess.CompletedProcess(cmd, 124, out, "TIMEOUT")
    if name:
        (RAW / f"{name}.txt").write_text(f"$ {' '.join(cmd)}\n[exit {done.returncode}]\n{done.stdout}\n{done.stderr}\n", encoding="utf-8")
    return done


def compose(*args: str, **kwargs) -> subprocess.CompletedProcess:
    return run(["docker", "compose", *args], **kwargs)


def sandbox(network: str, ip: str | None, script: str, *docker_args: str, name: str | None = None, timeout: int = 180):
    cmd = ["docker", "run", "--rm", "--network", network]
    if ip:
        cmd += ["--ip", ip]
    cmd += [*docker_args, "--entrypoint", "sh", ATTACKER_IMAGE, "-c", script]
    return run(cmd, timeout=timeout, name=name)


def record(test: str, passed: bool, detail) -> None:
    results[test] = {"pass": bool(passed), "detail": detail}
    print(f"[{'PASS' if passed else 'FAIL'}] {test}: {detail}", flush=True)


def alerts_since(start: float, rule_id: str) -> list[dict]:
    out = compose("exec", "-T", "wazuh", "cat", "/var/ossec/logs/alerts/alerts.json").stdout
    found = []
    for line in out.splitlines():
        if f'"id":"{rule_id}"' not in line:
            continue
        alert = json.loads(line)
        if datetime.strptime(alert["timestamp"], "%Y-%m-%dT%H:%M:%S.%f%z").timestamp() >= start:
            found.append(alert)
    return found


def wait_alert(start: float, rule_id: str, timeout: int = 60, must_contain: str = "") -> dict | None:
    """`must_contain` ties an alert to this test, so an earlier test's alert cannot satisfy it."""
    limit = time.time() + timeout
    while time.time() < limit:
        found = [a for a in alerts_since(start, rule_id) if must_contain in a.get("full_log", "")]
        if found:
            return found[0]
        time.sleep(1)
    return None


def soar_line_after(start: float, rule_id: str, timeout: int = 30) -> str | None:
    limit = time.time() + timeout
    while time.time() < limit:
        out = compose("logs", "--since", datetime.fromtimestamp(start).isoformat(), "--no-log-prefix", "soar").stdout
        for line in out.splitlines():
            if f"rule={rule_id} " in line:
                return line
        time.sleep(1)
    return None


def alert_time(alert: dict) -> float:
    return datetime.strptime(alert["timestamp"], "%Y-%m-%dT%H:%M:%S.%f%z").timestamp()


MQTT_BASE = "mosquitto_pub -h 10.10.3.2 -p 8883 --cafile /p/ca-chain.crt --tls-version tlsv1.3"


def test_mtls() -> None:
    # T1: no client certificate
    start = time.time()
    done = sandbox("vaurora_iot_ubs", "10.10.3.9", f"{MQTT_BASE} -t test -m x", "-v", f"{PUBLIC}:/p:ro", name="T1_no_certificate", timeout=40)
    record("T1_connection_without_certificate_refused", done.returncode != 0, (done.stderr or done.stdout).strip()[:160])
    alert = wait_alert(start, "100120", 40, "srcip=10.10.3.9 ")
    record("T1_rule_100120_alert", alert is not None, alert["rule"]["description"] if alert else "no alert")

    # T1b: certificate from a foreign CA
    script = ("openssl ecparam -name prime256v1 -genkey -noout -out /tmp/r.key && "
              "openssl req -x509 -new -key /tmp/r.key -days 1 -subj /CN=ubs-rogue-01 -out /tmp/r.crt && "
              f"{MQTT_BASE} --cert /tmp/r.crt --key /tmp/r.key -t vilaaurora/ubs/ubs-rogue-01/telemetry -m x")
    done = sandbox("vaurora_iot_ubs", "10.10.3.11", script, "-v", f"{PUBLIC}:/p:ro", name="T1b_foreign_ca", timeout=40)
    record("T1b_foreign_ca_refused", done.returncode != 0, (done.stderr or done.stdout).strip()[-160:])

    # T2: valid certificate, foreign topic (MQTT v5 surfaces the ACL reason code)
    device = f"{ROOT}/secrets/devices/ubs"
    script = (f"{MQTT_BASE} -V mqttv5 -q 1 -d --cert /d/ubs-lock-01.crt --key /d/ubs-lock-01.key "
              "-i t2-probe -t vilaaurora/ubs/ubs-coldchamber-01/telemetry -m spoof")
    done = sandbox("vaurora_iot_ubs", "10.10.3.12", script, "-v", f"{PUBLIC}:/p:ro", "-v", f"{device}:/d:ro", name="T2_foreign_topic", timeout=40)
    text = done.stdout + done.stderr
    record("T2_valid_cert_foreign_topic_denied", "not authorized" in text.lower() or "rc135" in text.lower() or "(135" in text, text.strip()[-200:])

    # T3: revocation demonstrated with a disposable device identity
    # A fresh identity each run, so the suite can be repeated after a previous revocation.
    tmp = ROOT / "secrets/devices/ubs"
    test_cn = f"ubs-testrevoke-{int(time.time())}"
    run(["pki/pki.sh", "issue", test_cn, str(tmp), "", test_cn], name="T3_issue")
    probe = (f"{MQTT_BASE} -q 1 --cert /d/{test_cn}.crt --key /d/{test_cn}.key "
             f"-t vilaaurora/ubs/{test_cn}/telemetry -m '{{}}'")
    before = sandbox("vaurora_iot_ubs", "10.10.3.13", probe, "-v", f"{PUBLIC}:/p:ro", "-v", f"{device}:/d:ro", name="T3_before_revoke", timeout=40)
    record("T3_valid_device_connects_before_revocation", before.returncode == 0, f"exit {before.returncode}")
    revoke = run(["pki/pki.sh", "revoke", test_cn], name="T3_revoke")
    record("T3_revocation_command", revoke.returncode == 0, revoke.stdout.strip())
    start = time.time()
    time.sleep(5)  # the edge notices the new CRL and reloads the broker
    after = sandbox("vaurora_iot_ubs", "10.10.3.14", probe, "-v", f"{PUBLIC}:/p:ro", "-v", f"{device}:/d:ro", name="T3_after_revoke", timeout=40)
    record("T3_revoked_device_refused", after.returncode != 0, (after.stderr or after.stdout).strip()[-160:])
    # The broker logs a revoked certificate as "certificate verify failed"; this address connected fine before.
    alert = wait_alert(start, "100120", 40, "srcip=10.10.3.14 ")
    record("T3_rule_100120_after_revocation", alert is not None, alert["full_log"][:160] if alert else "no alert")

    # T4: unique identity per device
    listing = run(["pki/pki.sh", "list"], name="T4_certificates").stdout
    serials = re.findall(r"serial=(\S+)", listing)
    record("T4_unique_serial_per_certificate", len(serials) == len(set(serials)) > 20, f"{len(serials)} certificates, {len(set(serials))} serials")


def test_vpn_segmentation() -> None:
    # T5: external scan of the hub
    tcp = sandbox("vaurora_wan_fiber", "172.30.0.67", "nmap -Pn -sT -p- --max-retries 0 --min-rate 3000 172.30.0.2", "--cap-add", "NET_RAW", name="T5_nmap_tcp", timeout=300)
    udp = sandbox("vaurora_wan_fiber", "172.30.0.67", "nmap -Pn -sU -p 51820,53,123,161,500,1194,4500 172.30.0.2", "--cap-add", "NET_RAW", name="T5_nmap_udp", timeout=120)
    open_tcp = re.findall(r"(\d+)/tcp\s+open", tcp.stdout)
    open_udp = re.findall(r"(\d+)/udp\s+open\s", udp.stdout)
    record("T5_no_tcp_port_exposed_on_hub", tcp.returncode == 0 and not open_tcp, f"open tcp={open_tcp}")
    record("T5_no_other_udp_service_answers", not open_udp, f"answering udp={open_udp}; 51820 is silent by WireGuard design")

    # T6: tunnel state
    show = compose("exec", "-T", "hub", "wg", "show", "wg0", name="T6_wg_show")
    handshakes = show.stdout.count("latest handshake")
    record("T6_all_edge_tunnels_up", handshakes >= 5, f"{handshakes} peers with handshake; cipher fixed by WireGuard")
    edge_kicks = [l for l in compose("logs", "--no-log-prefix", "soar").stdout.splitlines() if "action=kick_peer peer=edge-" in l]
    record("T6_no_edge_was_ever_disconnected_by_soar", not edge_kicks, edge_kicks[:2] or "no automatic kick of any edge")

    # T7: operator tunnel without MFA can reach only the portal
    compose("--profile", "tools", "up", "-d", "operator-ws")
    compose("exec", "-T", "hub", "nft", "flush", "set", "inet", "filter", "ztna_ok")
    setup = ("ip link show wg0 >/dev/null 2>&1 || { ip link add wg0 type wireguard && "
             "wg set wg0 private-key /secrets/operator/wg.key peer \"$HUB\" endpoint 172.30.0.2:51820 allowed-ips 10.70.0.1/32,10.60.0.20/32 persistent-keepalive 25 && "
             "ip addr add 10.70.0.10/24 dev wg0 && ip link set wg0 up && ip route add 10.60.0.20/32 dev wg0; }; sleep 3")
    hub_key = (ROOT / "secrets/public/wg_hub.pub").read_text().strip()
    exec_op = lambda script, **kw: compose("--profile", "tools", "exec", "-T", "-e", f"HUB={hub_key}", "operator-ws", "sh", "-c", script, **kw)
    exec_op(setup, name="T7_operator_tunnel")
    blocked = exec_op("curl -sk -m 8 -o /dev/null -w '%{http_code}' https://10.60.0.20:8443/login", name="T7_panel_before_mfa")
    record("T7_panel_unreachable_before_mfa", blocked.stdout.strip() in ("000", ""), f"http_code={blocked.stdout.strip()}, curl exit {blocked.returncode}")
    wrong = exec_op("curl -s -m 8 -o /dev/null -w '%{http_code}' -H 'Content-Type: application/json' -d '{\"totp\":\"000000\"}' http://10.70.0.1:8443/login", name="T7_wrong_totp")
    record("T7_wrong_second_factor_denied", wrong.stdout.strip() == "401", f"http_code={wrong.stdout.strip()}")
    login = ("code=$(python3 -c \"import os,pyotp;print(pyotp.TOTP(os.environ['ZTNA_OPERATOR_TOTP']).now())\"); "
             "curl -s -m 8 -H 'Content-Type: application/json' -d \"{\\\"totp\\\":\\\"$code\\\"}\" http://10.70.0.1:8443/login; "
             "curl -sk -m 8 -o /dev/null -w ' panel=%{http_code}' https://10.60.0.20:8443/login")
    good = exec_op(login, name="T7_valid_totp")
    record("T7_panel_reachable_after_mfa", "granted" in good.stdout and "panel=200" in good.stdout, good.stdout.strip().replace("\n", " ")[:120])

    # T8: IoT segment cannot reach the database or the panel
    field = "vaurora-field-ubs-1"
    probe = ("ip route replace 10.60.0.0/24 via 10.10.3.2; nc -z -w 4 10.60.0.10 5432; echo nc_db_exit=$?; "
             "nc -z -w 4 10.60.0.20 8443; echo nc_panel_exit=$?; ip route del 10.60.0.0/24")
    done = run(["docker", "run", "--rm", f"--network=container:{field}", "--cap-add", "NET_ADMIN", "--entrypoint", "sh", ATTACKER_IMAGE, "-c", probe], name="T8_iot_to_admin", timeout=30)
    record("T8_iot_to_database_blocked", "nc_db_exit=1" in done.stdout and "nc_panel_exit=1" in done.stdout, done.stdout.strip().replace("\n", " "))
    time.sleep(1)
    firewall = compose("exec", "-T", "edge-ubs", "sh", "-c", "grep -a SEG-DROP /var/log/vaurora/firewall.log | grep 10.60.0 | tail -2", name="T8_firewall_log")
    record("T8_drop_logged_as_seg_drop", "SEG-DROP" in firewall.stdout, firewall.stdout.strip()[:170])


def hub_endpoint_of_ubs() -> str:
    dump = compose("exec", "-T", "hub", "wg", "show", "wg0", "endpoints").stdout
    return next((l.split()[1] for l in dump.splitlines() if "172.31.0.13" in l or "172.30.0.13" in l), "")


def wait_for_endpoint(prefix: str, timeout: int) -> float | None:
    started = time.time()
    while time.time() - started < timeout:
        if hub_endpoint_of_ubs().startswith(prefix):
            return round(time.time() - started, 1)
        time.sleep(5)
    return None


def test_failover() -> None:
    """RT-03: cutting only the fiber moves the UBS tunnel to 4G, and it returns once the fiber is back."""
    # A short failback timer for the test only. Recreating the edge also guarantees it starts on fiber.
    env = {**os.environ, "FAILBACK_SECONDS": "120"}
    subprocess.run(["docker", "compose", "up", "-d", "edge-ubs"], env=env, cwd=ROOT, capture_output=True, check=False)
    on_fiber = wait_for_endpoint("172.30.0.13", 60)
    record("T9_starts_on_fiber", on_fiber is not None, hub_endpoint_of_ubs())

    started = time.time()
    compose("exec", "-T", "edge-ubs", "wan", "fiber-down", name="T9_fiber_down")
    moved = wait_for_endpoint("172.31.0.13", 330)
    record("T9_tunnel_moved_to_4g", moved is not None, {"endpoint": hub_endpoint_of_ubs(), "seconds_after_fiber_cut": moved})
    time.sleep(20)
    newest = compose("exec", "-T", "db", "psql", "-U", "postgres", "-d", "vaurora", "-tAc",
                     "SELECT extract(epoch FROM now() - max(received_at)) FROM readings WHERE site='ubs'", name="T9_data_over_4g").stdout.strip()
    record("T9_data_flows_over_4g", bool(newest) and float(newest) < 30, f"newest reading received {newest} s ago")

    compose("exec", "-T", "edge-ubs", "wan", "up")
    back = wait_for_endpoint("172.30.0.13", 330)
    record("T9_returns_to_fiber", back is not None, {"endpoint": hub_endpoint_of_ubs(), "seconds_after_fiber_restored": back})
    log = compose("logs", "--since", datetime.fromtimestamp(started).isoformat(), "--no-log-prefix", "edge-ubs", name="T9_edge_log").stdout
    record("T9_failover_logged", "link_failover link=4g" in log and "failback_attempt" in log,
           [l[16:90] for l in log.splitlines() if "link_failover" in l][:3])
    subprocess.run(["docker", "compose", "up", "-d", "edge-ubs"], cwd=ROOT, capture_output=True, check=False)
    time.sleep(15)


def test_sql_injection() -> None:
    demo = f"{ROOT}/secrets/lab/demo_users.json"
    app = sandbox("vaurora_cloud", None, "python3 /t/app_checks.py", "-v", f"{ROOT}/tests/security:/t:ro", "-v", f"{demo}:/lab/demo_users.json:ro", name="APP_panel_v2_checks", timeout=120)
    try:
        for name, value in json.loads(app.stdout).items():
            record(f"APP_{name}", value["pass"], value["detail"])
    except ValueError:
        record("APP_checks_executed", False, (app.stderr or app.stdout)[-300:])

    # Which CRS rule answered the manual payload through the WAF.
    audit = compose("exec", "-T", "waf", "cat", "/var/log/vaurora/waf-audit.log").stdout
    rules = sorted(set(re.findall(r'"ruleId":"(9\d{5})"', audit) + re.findall(r'\[id "(9\d{5})"\]', audit)))
    (RAW / "waf_rule.txt").write_text("CRS " + ", ".join(r for r in rules if r.startswith("942")))

    # sqlmap against v2 directly (no WAF), with a real session: the fix itself must hold.
    cookie_script = """
import json,re,pyotp,requests
u=json.load(open('/lab/demo_users.json'))['auditor.demo']
b='http://10.60.0.21:8000';h={'X-Forwarded-Proto':'https'}
first=requests.get(b+'/login',headers=h)
t=re.search(r'name="csrf" value="([^"]+)"',first.text).group(1)
# Plain HTTP inside the cloud segment: the Secure cookie is passed by hand.
r=requests.post(b+'/login',data=dict(csrf=t,username='auditor.demo',password=u['password'],totp=pyotp.TOTP(u['totp_secret']).now()),cookies={'session':first.cookies['session']},headers=h,allow_redirects=False)
print(r.cookies['session'])
"""
    script = (f"python3 - <<'PY' > /tmp/c\n{cookie_script}\nPY\n"
              "echo baseline_http=$(curl -s -o /tmp/b -w '%{http_code}' -H \"Cookie: session=$(cat /tmp/c)\" 'http://10.60.0.21:8000/history?q=escola') "
              "baseline_auth=$(grep -c 'Últimos' /tmp/b); "
              "sqlmap -u 'http://10.60.0.21:8000/history?q=escola' --cookie \"session=$(cat /tmp/c)\" -p q "
              "--headers='X-Forwarded-Proto: https' --batch --level 5 --risk 3 --technique=BEUST --flush-session "
              "--output-dir=/tmp/s 2>&1 | tail -25")
    done = sandbox("vaurora_cloud", None, script, "-v", f"{demo}:/lab/demo_users.json:ro", name="SQLI_v2_sqlmap_level5", timeout=580)
    authenticated = "baseline_http=200" in done.stdout and "baseline_auth=1" in done.stdout
    record("SQLI_v2_sqlmap_ran_authenticated", authenticated, done.stdout.splitlines()[0] if done.stdout else "no output")
    clean = "do not appear to be injectable" in done.stdout or "does not seem to be injectable" in done.stdout
    record("SQLI_v2_sqlmap_finds_nothing", authenticated and clean, done.stdout.strip()[-200:])


def detection_scenarios() -> None:
    """MTTD = first SIEM alert minus attack start. MTTR = containment action minus alert."""
    scenarios = []

    def scored(name: str, rule: str, started: float) -> None:
        alert = wait_alert(started, rule, 90)
        line = soar_line_after(started, rule, 30) if alert else None
        latency = float(re.search(r"latency_s=([\d.]+)", line).group(1)) if line and "latency_s" in line else None
        entry = {"scenario": name, "rule": rule, "detected": alert is not None,
                 "mttd_s": round(alert_time(alert) - started, 2) if alert else None,
                 "mttr_s": latency, "action": line.split("result=")[-1][:80] if line else None}
        scenarios.append(entry)
        record(f"DET_{name}", alert is not None and line is not None and "result=done" in line, entry)

    # Stolen operator key used from an unknown address.
    started = time.time()
    hub_key = (ROOT / "secrets/public/wg_hub.pub").read_text().strip()
    script = ("ip link add wg0 type wireguard && "
              f"wg set wg0 private-key /k/wg.key peer {hub_key} endpoint 172.30.0.2:51820 allowed-ips 10.70.0.1/32 && "
              "ip addr add 10.70.0.10/24 dev wg0 && ip link set wg0 up && (echo probe | nc -u -w 2 10.70.0.1 9; sleep 8); wg show wg0 | tail -4")
    sandbox("vaurora_wan_fiber", "172.30.0.66", script, "--cap-add", "NET_ADMIN", "-v", f"{ROOT}/secrets/operator:/k:ro", name="DET_stolen_vpn_key", timeout=60)
    scored("stolen_vpn_key_from_unknown_ip", "100101", started)
    token = next(l.split("=", 1)[1] for l in (ROOT / ".env").read_text().splitlines() if l.startswith("HUB_API_TOKEN="))
    compose("exec", "-T", "-e", f"T={token}", "soar", "python", "-c",
            "import os,requests;print(requests.post('http://10.60.0.1:9100/restore-peer',json={'peer':'operator-01'},headers={'X-Token':os.environ['T']}).text)")

    # SQL Injection against the panel through the operator tunnel.
    compose("--profile", "tools", "restart", "operator-ws")
    time.sleep(2)
    compose("exec", "-T", "hub", "nft", "flush", "set", "inet", "filter", "blocked")
    setup = ("ip link add wg0 type wireguard && wg set wg0 private-key /secrets/operator/wg.key "
             f"peer {hub_key} endpoint 172.30.0.2:51820 allowed-ips 10.70.0.1/32,10.60.0.20/32 persistent-keepalive 25 && "
             "ip addr add 10.70.0.10/24 dev wg0 && ip link set wg0 up && ip route add 10.60.0.20/32 dev wg0; sleep 2; "
             "code=$(python3 -c \"import os,pyotp;print(pyotp.TOTP(os.environ['ZTNA_OPERATOR_TOTP']).now())\"); "
             "curl -s -m 8 -H 'Content-Type: application/json' -d \"{\\\"totp\\\":\\\"$code\\\"}\" http://10.70.0.1:8443/login")
    compose("--profile", "tools", "exec", "-T", "operator-ws", "sh", "-c", setup, name="DET_operator_tunnel")
    started = time.time()
    compose("--profile", "tools", "exec", "-T", "operator-ws", "sh", "-c",
            "curl -sk -m 8 -o /dev/null -w '%{http_code}\\n' 'https://10.60.0.20:8443/history?q=x%27%20UNION%20ALL%20SELECT%20NULL--%20-'", name="DET_sqli_via_tunnel")
    scored("sql_injection_through_tunnel", "100110", started)
    time.sleep(2)
    after = compose("--profile", "tools", "exec", "-T", "operator-ws", "sh", "-c", "curl -sk -m 6 -o /dev/null -w '%{http_code}' https://10.60.0.20:8443/login", name="DET_after_ip_block")
    record("DET_source_ip_blocked_after_sqli", after.stdout.strip() in ("000", ""), f"http_code={after.stdout.strip()}")
    compose("exec", "-T", "hub", "nft", "flush", "set", "inet", "filter", "blocked")

    # Rogue device without a certificate.
    started = time.time()
    sandbox("vaurora_iot_escola", "10.10.2.9", "mosquitto_pub -h 10.10.2.2 -p 8883 --cafile /p/ca-chain.crt --tls-version tlsv1.3 -t x -m y", "-v", f"{PUBLIC}:/p:ro", name="DET_rogue_device", timeout=30)
    scored("rogue_device_without_certificate", "100120", started)
    time.sleep(3)
    isolated = compose("exec", "-T", "edge-escola", "nft", "list", "set", "inet", "filter", "isolated", name="DET_isolated_set").stdout
    record("DET_rogue_device_isolated", "10.10.2.9" in isolated, "10.10.2.9 in isolated set" if "10.10.2.9" in isolated else isolated[:120])

    # Correctly signed pump command that targets 02:40, as in the incident.
    command = """
import base64,json,time,uuid,ssl
from datetime import datetime
import paho.mqtt.client as mqtt
from cryptography.hazmat.primitives.serialization import load_pem_private_key
key=load_pem_private_key(open('/secrets/client/command_signing.key','rb').read(),None)
when=datetime.now().replace(hour=2,minute=40).timestamp()
body=json.dumps(dict(id=str(uuid.uuid4()),site='escola',actuator='pump',action='on',user='coordenacao.demo',issued_at=time.time(),execute_at=when))
env=json.dumps(dict(body=body,sig=base64.b64encode(key.sign(body.encode())).decode()))
ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT);ctx.load_verify_locations('/secrets/public/ca-chain.crt');ctx.load_cert_chain('/secrets/client/client.crt','/secrets/client/client.key')
c=mqtt.Client(mqtt.CallbackAPIVersion.VERSION2,client_id='panel-test');c.tls_set_context(ctx);c.connect('10.60.0.30',8883);c.loop_start()
c.publish('vilaaurora/escola/command/pump',env,qos=1).wait_for_publish(5);c.loop_stop();c.disconnect()
"""
    started = time.time()
    compose("exec", "-T", "panel", "python", "-c", command, name="DET_pump_0240")
    scored("pump_command_at_0240", "100130", started)
    time.sleep(3)
    edge = compose("logs", "--since", "90s", "--no-log-prefix", "edge-escola", name="DET_pump_edge_log").stdout
    record("DET_pump_command_rejected_by_edge", "reason=out_of_window" in edge, next((l for l in edge.splitlines() if "out_of_window" in l), "none")[:150])
    record("DET_edge_entered_safe_mode", "event=safe_mode enabled=true" in edge, next((l for l in edge.splitlines() if "safe_mode" in l), "none")[:150])

    # Forged signature must be refused even from an authenticated broker client.
    forged = command.replace("sig=base64.b64encode(key.sign(body.encode())).decode()", "sig=base64.b64encode(b'0'*64).decode()").replace("hour=2", "hour=10")
    started = time.time()
    compose("exec", "-T", "panel", "python", "-c", forged, name="DET_forged_signature")
    alert = wait_alert(started, "100131", 40)
    record("DET_forged_signature_rejected", alert is not None, alert["full_log"][-90:] if alert else "no alert")

    # A handshake from an unexpected address on an EDGE must alert a person and not cut the site off.
    edge_peers_before = compose("exec", "-T", "hub", "wg", "show", "wg0", "peers").stdout.count("=")
    probe = "from vlog import log; log('wireguard-handshake', 'peer=edge-horta srcip=172.30.0.99 after_hours=no known_ip=no', 'vpn.log')"
    started = time.time()
    compose("exec", "-T", "hub", "python", "-c", probe)
    alert = wait_alert(started, "100101", 40, "peer=edge-horta srcip=172.30.0.99")
    line = soar_line_after(started, "100101", 20)
    time.sleep(2)
    edge_peers_after = compose("exec", "-T", "hub", "wg", "show", "wg0", "peers").stdout.count("=")
    record("DET_edge_anomaly_escalated_not_disconnected", alert is not None and line is not None and "escalated_to_human" in line and edge_peers_after == edge_peers_before,
           {"action": line.split("result=")[-1][:70] if line else None, "peers_before": edge_peers_before, "peers_after": edge_peers_after})

    # Leave the lab as found: remove safe mode through a signed command and clear containment sets.
    release = command.replace("action='on'", "action='safe_mode',enabled=False").replace("execute_at=when", "execute_at=time.time()")
    compose("exec", "-T", "panel", "python", "-c", release)
    compose("exec", "-T", "edge-escola", "nft", "flush", "set", "inet", "filter", "isolated")
    compose("exec", "-T", "edge-ubs", "nft", "flush", "set", "inet", "filter", "isolated")

    detected = [s for s in scenarios if s["mttd_s"] is not None]
    responded = [s for s in scenarios if s["mttr_s"] is not None]
    results["detection_summary"] = {
        "scenarios": scenarios,
        "mttd_mean_s": round(sum(s["mttd_s"] for s in detected) / len(detected), 2) if detected else None,
        "mttr_mean_s": round(sum(s["mttr_s"] for s in responded) / len(responded), 2) if responded else None,
    }
    print(results["detection_summary"], flush=True)


def main() -> None:
    test_mtls()
    test_vpn_segmentation()
    test_failover()
    test_sql_injection()
    detection_scenarios()
    tests = {k: v for k, v in results.items() if isinstance(v, dict) and "pass" in v}
    results["totals"] = {"passed": sum(v["pass"] for v in tests.values()), "failed": sum(not v["pass"] for v in tests.values())}
    results["finished_at"] = datetime.now().isoformat()
    RESULTS_FILE.write_text(json.dumps(results, indent=2, ensure_ascii=False), encoding="utf-8")
    print(results["totals"])


if __name__ == "__main__":
    main()
