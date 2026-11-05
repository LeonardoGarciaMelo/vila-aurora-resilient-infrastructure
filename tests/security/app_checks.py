"""Application-level checks executed from the cloud segment against panel v2 (via WAF and directly)."""
import json
import re
import sys

import pyotp
import requests
import urllib3

urllib3.disable_warnings()
WAF = "https://10.60.0.20:8443"
DIRECT = "http://10.60.0.21:8000"
USERS = json.load(open("/lab/demo_users.json"))
results = {}


class LabSession(requests.Session):
    """The direct check uses plain HTTP inside the cloud segment, so the Secure cookie must still be sent."""

    def request(self, *args, **kwargs):
        for cookie in self.cookies:
            cookie.secure = False
        return super().request(*args, **kwargs)


def csrf(session: requests.Session, url: str) -> str:
    return re.search(r'name="csrf" value="([^"]+)"', session.get(url, verify=False).text).group(1)


def login(username: str, totp: bool = True, base: str = WAF) -> requests.Session:
    session = LabSession()
    session.headers["X-Forwarded-Proto"] = "https"
    data = {"csrf": csrf(session, f"{base}/login"), "username": username, "password": USERS[username]["password"],
            "totp": pyotp.TOTP(USERS[username]["totp_secret"]).now() if totp else "000000"}
    session.last_login = session.post(f"{base}/login", data=data, verify=False, allow_redirects=False)
    return session


def record(name: str, ok: bool, detail) -> None:
    results[name] = {"pass": bool(ok), "detail": detail}


no_mfa = login("coordenacao.demo", totp=False)
record("login_without_valid_totp_rejected", no_mfa.last_login.status_code == 401, no_mfa.last_login.status_code)

operator = login("operador.demo")
record("operator_login_with_totp", operator.last_login.status_code == 302, operator.last_login.status_code)
status = operator.get(f"{WAF}/history?q=escola", verify=False).status_code
record("operator_cannot_read_access_history", status == 403, status)
status = operator.get(f"{WAF}/commands", verify=False).status_code
record("operator_cannot_send_commands", status == 403, status)

auditor = login("auditor.demo")
status = auditor.get(f"{WAF}/history?q=escola", verify=False).status_code
record("auditor_reads_history", status == 200, status)
page = auditor.get(f"{WAF}/history?q=", verify=False).text
record("auditor_sees_only_pseudonyms", "BADGE-" not in page, "no BADGE- identifiers in page")
status = auditor.get(f"{WAF}/users", verify=False).status_code
record("auditor_cannot_manage_users", status == 403, status)

coord = login("coordenacao.demo")
record("sqli_manual_blocked_by_waf",
       coord.get(f"{WAF}/history", params={"q": "' OR '1'='1"}, verify=False).status_code == 403, "HTTP 403 expected from WAF")

# Direct to the app, skipping the WAF: the root-cause fix must hold on its own.
direct = login("coordenacao.demo", base=DIRECT)
baseline = direct.get(f"{DIRECT}/history", params={"q": "escola"}, allow_redirects=False)
record("sqli_direct_session_is_authenticated", baseline.status_code == 200 and "Histórico de acessos" in baseline.text, baseline.status_code)
for name, payload in {"or_tautology": "' OR '1'='1", "union": "x' UNION SELECT 1,2,3,4--", "stacked": "x'; UPDATE users SET role='x'--"}.items():
    response = direct.get(f"{DIRECT}/history", params={"q": payload}, allow_redirects=False)
    record(f"sqli_direct_{name}_rejected_400", response.status_code == 400, response.status_code)
    record(f"sqli_direct_{name}_generic_message", "psycopg" not in response.text and "Traceback" not in response.text and "SELECT" not in response.text, "no DB detail in body")

# Human approval queue for high-impact actions.
tech = login("tecnico.demo")
token = csrf(tech, f"{WAF}/commands")
response = tech.post(f"{WAF}/commands", data={"csrf": token, "site": "abrigo", "actuator": "generator", "action": "off"}, verify=False)
pending = coord.get(f"{WAF}/commands", verify=False).text
action_ids = re.findall(r"/commands/(\d+)/approve", pending)
record("high_impact_enters_queue", bool(action_ids) and response.status_code == 200, f"queue ids={action_ids}")
action_id = action_ids[-1]

status = tech.post(f"{WAF}/commands/{action_id}/approve", data={"csrf": csrf(tech, f'{WAF}/commands')}, verify=False).status_code
record("technician_cannot_approve", status == 403, status)

requester = login("coordenacao.demo")
token = csrf(requester, f"{WAF}/commands")
requester.post(f"{WAF}/commands", data={"csrf": token, "site": "abrigo", "actuator": "lock", "action": "open_all"}, verify=False)
own_ids = re.findall(r"/commands/(\d+)/approve", requester.get(f"{WAF}/commands", verify=False).text)
own = requester.post(f"{WAF}/commands/{own_ids[-1]}/approve", data={"csrf": csrf(requester, f'{WAF}/commands')}, verify=False)
record("self_approval_refused", "Outra pessoa da coordenação" in own.text, "message shown")

second = login("coordenacao2.demo")
done = second.post(f"{WAF}/commands/{action_id}/approve", data={"csrf": csrf(second, f'{WAF}/commands')}, verify=False)
record("other_coordinator_approves", "Decisão registrada" in done.text, done.status_code)
second.post(f"{WAF}/commands/{own_ids[-1]}/reject", data={"csrf": csrf(second, f'{WAF}/commands')}, verify=False)

record("post_without_csrf_rejected", coord.post(f"{WAF}/commands", data={"site": "ubs"}, verify=False).status_code == 400, 400)
audit_page = coord.get(f"{WAF}/audit", verify=False).text
record("audit_trail_has_decisions", "high_impact_decided" in audit_page, "audit page lists decisions")

json.dump(results, sys.stdout, indent=2, ensure_ascii=False)
