#!/usr/bin/env python3
"""RT-11: phishing simulation with Gophish, against fictitious accounts created by the team only.

The landing page never stores what is typed: capture_credentials and capture_passwords are off, so
Gophish records only that a submission happened.

Modes:
  --manual   creates the campaign and stops, so team members can act on their test accounts in Mailpit.
  --personas scripted accounts follow fixed probabilities. This validates the pipeline. Its rates reflect
             the configured probabilities, NOT human behaviour, and the export says so.
  --export   writes results of every campaign to docs/results/phishing_results.json.
"""
import argparse
import json
import random
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import requests

API = "http://172.26.0.10:3333/api"
PHISH_URL = "http://172.26.0.10:8080"
MAILPIT = "http://172.26.0.25:8025/api/v1"
RESULTS = Path("/results/phishing_results.json")
ACCOUNTS = 20
TEMPLATE_HTML = """<html><body>
<p>Prezada equipe,</p>
<p>Por determinacao da Prefeitura de Serra Clara, o acesso ao painel da Rede Vila Aurora deve ser atualizado hoje.</p>
<p><a href="{{.URL}}">Atualizar acesso</a></p>
<p>Secretaria Municipal (FICTICIA) - simulacao de laboratorio</p>{{.Tracker}}
</body></html>"""
LANDING_HTML = """<html><body><h1>Atualizacao de acesso</h1>
<form method="post"><label>Usuario <input name="u"></label><label>Senha <input name="p" type="password"></label><button>Enviar</button></form>
</body></html>"""
# (open, click given open, submit given click, report given open): illustrative inputs, not findings.
PERSONA_PROBABILITIES = {"before_training": (0.9, 0.6, 0.6, 0.1), "after_training": (0.9, 0.25, 0.3, 0.55)}


class Gophish:
    def __init__(self, key: str) -> None:
        self.headers = {"Authorization": key}

    def post(self, path: str, body: dict) -> dict:
        response = requests.post(f"{API}{path}", json=body, headers=self.headers, timeout=30)
        if response.status_code not in (200, 201):
            raise SystemExit(f"{path}: {response.status_code} {response.text[:200]}")
        return response.json()

    def get(self, path: str):
        return requests.get(f"{API}{path}", headers=self.headers, timeout=30).json()


def create_campaign(api: Gophish, name: str) -> dict:
    suffix = f"{name}-{int(time.time())}"
    profile = api.post("/smtp/", {"name": f"lab-{suffix}", "host": "172.26.0.25:1025", "from_address": "secretaria@serra-clara-portal.test", "ignore_cert_errors": True, "interface_type": "SMTP"})
    template = api.post("/templates/", {"name": f"tpl-{suffix}", "subject": "Atualizacao obrigatoria do acesso ao painel", "html": TEMPLATE_HTML})
    page = api.post("/pages/", {"name": f"page-{suffix}", "html": LANDING_HTML, "capture_credentials": False, "capture_passwords": False, "redirect_url": ""})
    targets = [{"first_name": "Conta", "last_name": f"Teste{i:02d}", "email": f"conta.teste{i:02d}@vilaaurora.example", "position": "Conta ficticia"} for i in range(ACCOUNTS)]
    group = api.post("/groups/", {"name": f"grp-{suffix}", "targets": targets})
    return api.post("/campaigns/", {
        "name": name, "template": {"name": template["name"]}, "page": {"name": page["name"]}, "smtp": {"name": profile["name"]},
        "url": PHISH_URL, "groups": [{"name": group["name"]}], "launch_date": datetime.now(timezone.utc).isoformat(),
    })


def wait_for_delivery(expected: int) -> None:
    for _ in range(60):
        if requests.get(f"{MAILPIT}/messages", params={"limit": 1}, timeout=10).json().get("total", 0) >= expected:
            return
        time.sleep(2)
    raise SystemExit("mail was not delivered to Mailpit")


def play_personas(label: str, seed: int) -> None:
    rng = random.Random(seed)
    p_open, p_click, p_submit, p_report = PERSONA_PROBABILITIES[label]
    messages = requests.get(f"{MAILPIT}/messages", params={"limit": ACCOUNTS}, timeout=10).json()["messages"]
    for summary in messages:
        body = requests.get(f"{MAILPIT}/message/{summary['ID']}", timeout=10).json()["HTML"]
        rid = re.search(r"rid=([A-Za-z0-9]+)", body).group(1)
        if rng.random() > p_open:
            continue
        requests.get(f"{PHISH_URL}/track", params={"rid": rid}, timeout=10)
        time.sleep(rng.uniform(0.05, 0.3))
        if rng.random() < p_report:
            requests.get(f"{PHISH_URL}/report", params={"rid": rid}, timeout=10)
        if rng.random() < p_click:
            requests.get(PHISH_URL, params={"rid": rid}, timeout=10)
            if rng.random() < p_submit:
                # Fixed placeholder text: nothing resembling a credential ever exists in this flow.
                requests.post(PHISH_URL, params={"rid": rid}, data={"u": "placeholder", "p": "placeholder"}, timeout=10)


def summarise(campaign: dict) -> dict:
    results = campaign["results"]
    total = len(results)
    timeline = campaign["timeline"]
    rate = lambda messages: round(100 * len({e["email"] for e in timeline if e["message"] in messages}) / total, 1) if total else 0
    launched = datetime.fromisoformat(campaign["launch_date"].replace("Z", "+00:00"))
    reports = [e for e in results if e.get("reported")]
    report_times = [datetime.fromisoformat(e["modified_date"].replace("Z", "+00:00")) for e in reports]
    return {
        "name": campaign["name"], "accounts": total,
        "open_rate": rate({"Email Opened", "Clicked Link", "Submitted Data"}),
        "click_rate": rate({"Clicked Link", "Submitted Data"}),
        "submit_rate": rate({"Submitted Data"}),
        "report_rate": round(100 * len(reports) / total, 1) if total else 0,
        "seconds_to_first_report": round((min(report_times) - launched).total_seconds(), 1) if report_times else None,
    }


def export(api: Gophish, behaviour: str) -> None:
    campaigns = [api.get(f"/campaigns/{c['id']}") for c in api.get("/campaigns/")]
    payload = {"generated_at": datetime.now().isoformat(), "behaviour_source": behaviour, "credentials_stored": False,
               "targets": "fictitious accounts created by the team", "campaigns": [summarise(c) for c in campaigns]}
    stored = any(e.get("details") and '"payload"' in e["details"] and "placeholder" in e["details"] for c in campaigns for e in c["timeline"])
    payload["submitted_values_recorded_by_gophish"] = stored
    RESULTS.write_text(json.dumps(payload, indent=2, ensure_ascii=False))
    print(json.dumps(payload, indent=2, ensure_ascii=False))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--key", required=True)
    parser.add_argument("--manual", metavar="NAME")
    parser.add_argument("--personas", action="store_true")
    parser.add_argument("--export", metavar="BEHAVIOUR_SOURCE")
    args = parser.parse_args()
    api = Gophish(args.key)
    if args.manual:
        create_campaign(api, args.manual)
        print("campaign launched; act on the test accounts in Mailpit, then run --export")
    if args.personas:
        for offset, label in enumerate(PERSONA_PROBABILITIES):
            requests.delete(f"{MAILPIT}/messages", timeout=10)
            create_campaign(api, label)
            wait_for_delivery(ACCOUNTS)
            play_personas(label, 712 + offset)
            time.sleep(5)
        export(api, "SCRIPTED PERSONAS with fixed probabilities: validates the pipeline, these are not human results")
    if args.export:
        export(api, args.export)
    sys.exit(0)


if __name__ == "__main__":
    main()
