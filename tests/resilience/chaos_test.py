#!/usr/bin/env python3
"""RT-22/RT-23: controlled WAN outage with real measurements.

Usage: chaos_test.py [--minutes 35] [--sites escola,ubs]
Cuts the tunnel at the chosen edges, injects a cold chamber fault at the UBS while it is cut, then restores
the link and measures reconciliation and data loss per device, by sequence number.
"""
import argparse
import json
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "docs/results/chaos_results.json"
SERIES = ROOT / "docs/results/chaos_timeseries.csv"
MAX_TICK_GAP_SECONDS = 120


def compose(*args: str, check: bool = False) -> str:
    return subprocess.run(["docker", "compose", *args], capture_output=True, text=True, cwd=ROOT, check=check).stdout


def sql(query: str) -> str:
    return compose("exec", "-T", "db", "psql", "-U", "postgres", "-d", "vaurora", "-tAc", query).strip()


def edge_metrics(site: str) -> dict:
    return json.loads(compose("exec", "-T", f"edge-{site}", "cat", "/var/lib/vaurora/metrics.json"))


def last_seq_generated(site: str) -> dict[str, int]:
    out = compose("exec", "-T", f"field-{site}", "sh", "-c", "cd /var/lib/field && for f in *.seq; do echo \"$f $(cat $f)\"; done")
    return {line.split()[0].removesuffix(".seq"): int(line.split()[1]) for line in out.splitlines()}


def received_between(device: str, low: int, high: int) -> tuple[int, int]:
    row = sql(f"SELECT count(*), count(DISTINCT seq) FROM readings WHERE device_id='{device}' AND seq > {low} AND seq <= {high}")
    total, distinct = row.split("|")
    return int(total), int(distinct)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--minutes", type=float, default=35)
    parser.add_argument("--sites", default="escola,ubs")
    args = parser.parse_args()
    sites = args.sites.split(",")
    series = open(SERIES, "w", encoding="utf-8")
    series.write("elapsed_s,phase," + ",".join(f"{s}_backlog,{s}_rss_mb" for s in sites) + "\n")

    def sample(start: float, phase: str) -> dict:
        values = {s: edge_metrics(s) for s in sites}
        series.write(f"{time.time() - start:.0f},{phase}," + ",".join(f"{values[s]['backlog']},{values[s]['rss_mb']}" for s in sites) + "\n")
        series.flush()
        return values

    before = {s: last_seq_generated(s) for s in sites}
    start = time.time()
    results = {"started_at": datetime.now().isoformat(), "planned_minutes": args.minutes, "sites": sites}
    for site in sites:
        compose("exec", "-T", f"edge-{site}", "wan", "down", check=True)
    results["wan_down_at"] = datetime.now().isoformat()
    print("WAN down", results["wan_down_at"], flush=True)

    samples, fault_at, fault_cleared = [], None, None
    outage = args.minutes * 60
    last_tick, max_gap = time.time(), 0.0
    while time.time() - start < outage:
        elapsed = time.time() - start
        # A long gap between 30-second ticks means the host slept, which would inflate the outage time.
        max_gap, last_tick = max(max_gap, time.time() - last_tick), time.time()
        if "ubs" in sites and fault_at is None and elapsed > 120:
            compose("exec", "-T", "field-ubs", "touch", "/tmp/faults/cold")
            fault_at = datetime.now().isoformat()
            print("cold chamber fault injected", fault_at, flush=True)
        if fault_at and fault_cleared is None and elapsed > 720:
            compose("exec", "-T", "field-ubs", "rm", "-f", "/tmp/faults/cold")
            fault_cleared = datetime.now().isoformat()
        samples.append(sample(start, "outage"))
        time.sleep(30)

    actual_outage = time.time() - start
    peak = {s: max(x[s]["backlog"] for x in samples) for s in sites}
    results["islanded_during_outage"] = {s: not samples[-1][s]["online"] for s in sites}
    for site in sites:
        compose("exec", "-T", f"edge-{site}", "wan", "up", check=True)
    restored = time.time()
    results["wan_restored_at"] = datetime.now().isoformat()
    print("WAN restored", results["wan_restored_at"], flush=True)

    reconciled = {}
    while len(reconciled) < len(sites) and time.time() - restored < 1200:
        values = sample(start, "reconcile")
        for site in sites:
            if site not in reconciled and values[site]["online"] and values[site]["backlog"] < 5:
                reconciled[site] = round(time.time() - restored, 1)
                print(f"{site} reconciled in {reconciled[site]} s", flush=True)
        time.sleep(3)
    time.sleep(20)  # let in-flight batches commit before counting
    series.close()

    # The last sequence comes from just before restoring, so counts cover the whole outage.
    after = {s: last_seq_generated(s) for s in sites}
    per_device, generated_total, received_total, duplicates = {}, 0, 0, 0
    for site in sites:
        for device, high in after[site].items():
            low = before[site].get(device, 0)
            total, distinct = received_between(device, low, high - 12)
            generated = max(high - 12 - low, 0)
            per_device[device] = {"generated": generated, "received": distinct, "duplicates": total - distinct}
            generated_total += generated
            received_total += distinct
            duplicates += total - distinct

    alarm_logs = compose("logs", "--since", results["started_at"], "--no-log-prefix", "edge-ubs")
    alarms = [l for l in alarm_logs.splitlines() if "alarm=cold_chamber" in l]
    sms = [l for l in compose("exec", "-T", "sms-gw", "cat", "/var/log/vaurora/vilaaurora-sms.log").splitlines() if "site=ubs" in l]
    wan_events = [l for l in alarm_logs.splitlines() if "wan_lost_islanded" in l or "wan_restored" in l]
    fault_epoch = datetime.fromisoformat(fault_at).timestamp() if fault_at else None
    alarm_time = None
    if alarms and fault_epoch:
        stamp = datetime.strptime(f"{datetime.now().year} {alarms[0][:15]}", "%Y %b %d %H:%M:%S")
        alarm_time = round(stamp.timestamp() - fault_epoch, 1)

    results.update({
        "max_sample_gap_seconds": round(max_gap, 1),
        "valid_no_host_pause": max_gap < MAX_TICK_GAP_SECONDS,
        "outage_minutes_measured": round(actual_outage / 60, 2),
        "peak_backlog_readings": peak,
        "reconciliation_seconds": reconciled,
        "generated_readings": generated_total, "received_readings": received_total, "duplicate_rows": duplicates,
        "loss_percent": round(100 * (1 - received_total / generated_total), 4) if generated_total else None,
        "per_device": per_device,
        "cold_fault_injected_at": fault_at, "cold_fault_cleared_at": fault_cleared,
        "alarm_seconds_after_fault": alarm_time, "local_alarm_lines": alarms[:4], "sms_lines": sms[-3:], "wan_events": wan_events[-4:],
        "finished_at": datetime.now().isoformat(),
    })
    OUT.write_text(json.dumps(results, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps({k: v for k, v in results.items() if k != "per_device"}, indent=2, ensure_ascii=False)[:2500])
    if not results["valid_no_host_pause"]:
        sys.exit(f"INVALID RUN: the host paused for about {max_gap:.0f} s, so these figures must not be reported")


if __name__ == "__main__":
    main()
