#!/usr/bin/env python3
"""Builds the consolidated incident timeline from the hashed evidence.

Reads only the bundles in evidence/forensics/images, after re-verifying their hashes, and works on
extracted copies, so the originals stay untouched.
"""
import csv
import json
import re
import subprocess
import tarfile
import tempfile
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "evidence/forensics"
IMAGES = OUT / "images"
YEAR = datetime.now().year
RESULTS = ROOT / "docs/results"


def parse_syslog(line: str) -> datetime | None:
    try:
        return datetime.strptime(f"{YEAR} {line[:15]}", "%Y %b %d %H:%M:%S")
    except ValueError:
        return None


def extract(bundle: str, into: Path) -> None:
    with tarfile.open(IMAGES / bundle) as tar:
        tar.extractall(into, filter="data")


def main() -> None:
    check = subprocess.run(["sha256sum", "-c", "hashes_at_collection.txt"], cwd=OUT, capture_output=True, text=True)
    if check.returncode != 0:
        raise SystemExit(f"integrity check failed, refusing to analyse:\n{check.stdout}")
    events: list[tuple[datetime, str, str, str]] = []
    facts: dict = {}
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        for bundle in ("EV-03_vpn_logs.tar", "EV-04_panel_logs.tar", "EV-05_postgres_logs.tar", "EV-06_controller_logs.tar"):
            extract(bundle, work)

        # VPN: sshd -E lines start with a pid or date depending on the build, so both forms are handled.
        central = (work / "vpn_central_mirror_auth.log").read_text(errors="replace").splitlines()
        local = (work / "vpn_local_auth.log").read_text(errors="replace").splitlines()
        facts["vpn_central_lines"], facts["vpn_local_lines_after_tampering"] = len(central), len(local)
        for line in central:
            if "Accepted password" in line:
                source = re.search(r"from (\S+)", line).group(1)
                events.append((parse_syslog(line), "EV-03", f"VPN login with password only, user coordenadora, source {source}", "T1133, T1078"))

        access = (work / "legacy-panel-access.log").read_text(errors="replace").splitlines()
        sqli = [l for l in access if re.search(r"(?i)union|select|sleep|%27|'", l)]
        facts["panel_requests_total"], facts["panel_requests_with_sqli_pattern"] = len(access), len(sqli)
        if sqli:
            events.append((parse_syslog(sqli[0]), "EV-04", f"First SQL Injection payload on /history ({len(sqli)} suspicious requests in total)", "T1190"))
            events.append((parse_syslog(sqli[-1]), "EV-04", "Last SQL Injection payload on /history", "T1190"))

        database = (work / "legacy-postgresql.log").read_text(errors="replace").splitlines()
        # UNION separates the injected extraction from the panel's own start-up queries on this table.
        dump = [l for l in database if "usuarios" in l and re.search(r"\bunion\b", l, re.I)]
        update = [l for l in database if "UPDATE agendamento_bomba" in l]
        facts["database_statements_touching_usuarios"], facts["database_schedule_updates"] = len(dump), len(update)
        pg_time = lambda l: datetime.strptime(l[:19], "%Y-%m-%d %H:%M:%S")
        if dump:
            events.append((pg_time(dump[0]), "EV-05", f"UNION extraction from table usuarios ({len(dump)} statements)", "T1213"))
        if update:
            events.append((pg_time(update[-1]), "EV-05", "UPDATE on agendamento_bomba through stacked query", "T0836"))

        controller = (work / "legacy-controller.log").read_text(errors="replace").splitlines()
        pump = next((l for l in controller if "pump_state=on" in l), None)
        if pump:
            events.append((parse_syslog(pump), "EV-06", "Pump turned on by database schedule, no validation; tank level starts falling", "T0831"))
        levels = [(parse_syslog(l), float(m.group(1))) for l in controller if (m := re.search(r"tank_pct=([\d.]+)", l))]
        empty = next((t for t, v in levels if v <= 0), None)
        if levels:
            facts["tank_start_pct"], facts["tank_end_pct"] = levels[0][1], levels[-1][1]
        if empty:
            events.append((empty, "EV-06", "School tank reaches 0%", "T0831"))
        fiber = next((l for l in controller if "fiber=down" in l), None)
        if fiber:
            events.append((parse_syslog(fiber), "EV-06", "Fiber down: controller loses cloud alerts, no local alarm exists", "-"))
        out_of_range = [l for l in controller if "local_alarm=none" in l and (m := re.search(r"cold_temp_c=([\d.]+)", l)) and float(m.group(1)) > 8]
        if out_of_range:
            events.append((parse_syslog(out_of_range[0]), "EV-06", "Cold chamber above 8 C with no alert to anyone", "-"))
            facts["cold_chamber_unalerted_samples"] = len(out_of_range)

    dump_file = OUT.parent / "raw/attacker/sqlmap_dump.txt"
    if dump_file.exists():
        match = re.search(r"\[(\d+) entries\]", dump_file.read_text(errors="replace"))
        facts["records_extracted_by_attacker"] = int(match.group(1)) if match else None

    alerts = []
    for line in (IMAGES / "EV-07_wazuh_alerts.json").read_text(errors="replace").splitlines():
        try:
            alert = json.loads(line)
        except ValueError:
            continue
        if alert["rule"]["id"] in {"100111", "100170"}:
            alerts.append(alert)
    if alerts:
        # Wazuh stamps alerts in UTC; every other source here is local time.
        first = datetime.strptime(alerts[0]["timestamp"], "%Y-%m-%dT%H:%M:%S.%f%z").astimezone().replace(tzinfo=None)
        events.append((first, "EV-07", f"First SIEM alert for the chain: rule {alerts[0]['rule']['id']} ({len(alerts)} alerts in total)", "-"))
    facts["siem_alerts_for_chain"] = len(alerts)

    tampering = next((l for l in (OUT.parent / "raw/attacker/incident_steps.log").read_text().splitlines() if "log_tampering" in l), None)
    if tampering:
        events.append((datetime.fromisoformat(tampering.split()[0]).replace(tzinfo=None), "attacker ground truth", "Local VPN log truncated; central mirror keeps the records", "T1070"))

    events = sorted((e for e in events if e[0]), key=lambda e: e[0])
    with open(OUT / "timeline.csv", "w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["time", "source", "event", "attack"])
        for when, source, text, attack in events:
            writer.writerow([when.isoformat(sep=" "), source, text, attack])
    summary = {"facts": facts, "events": [{"time": e[0].isoformat(sep=" "), "source": e[1], "event": e[2], "attack": e[3]} for e in events],
               "integrity": check.stdout.strip().splitlines(),
               "hashes": json.loads((OUT / "hashes.json").read_text())}
    RESULTS.mkdir(parents=True, exist_ok=True)
    (RESULTS / "forensics_summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    for event in events:
        print(event[0], event[1], event[2], event[3], sep=" | ")
    print(json.dumps(facts, indent=2))


if __name__ == "__main__":
    main()
