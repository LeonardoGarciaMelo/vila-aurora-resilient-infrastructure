#!/usr/bin/env python3
"""RT-22: per-container CPU and memory, tunnel bandwidth, and availability of panel and local brokers.

Usage: measure_edge.py [--minutes 10]
Availability samples every 60 s. Pass a long --minutes (for example 1440) for a meaningful availability figure.
"""
import argparse
import json
import re
import subprocess
import time
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "docs/results/edge_resources.json"
SPACES = {"centro": 1, "escola": 2, "ubs": 3, "horta": 4, "abrigo": 5}


def shell(*cmd: str) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, cwd=ROOT, check=False)


def bytes_of(value: str) -> float:
    number, unit = re.match(r"([\d.]+)\s*([A-Za-z]+)", value).groups()
    return float(number) * {"B": 1, "KiB": 1024, "MiB": 1024**2, "GiB": 1024**3, "kB": 1000, "MB": 1000**2, "GB": 1000**3}[unit]


def stats() -> dict:
    names = [f"vaurora-edge-{s}-1" for s in SPACES]
    out = shell("docker", "stats", "--no-stream", "--format", "{{.Name}};{{.CPUPerc}};{{.MemUsage}}", *names).stdout
    values = {}
    for line in out.splitlines():
        name, cpu, memory = line.split(";")
        values[name.split("-")[2]] = {"cpu": float(cpu.rstrip("%")), "mem_mb": bytes_of(memory.split("/")[0].strip()) / 1e6}
    return values


def tunnel_bytes(space: str) -> int:
    out = shell("docker", "compose", "exec", "-T", f"edge-{space}", "wg", "show", "wg0", "transfer").stdout.split()
    return int(out[1]) + int(out[2]) if len(out) == 3 else 0


def probe() -> dict[str, bool]:
    results = {}
    for space, site_id in SPACES.items():
        done = shell("docker", "compose", "exec", "-T", f"field-{space}", "nc", "-z", "-w", "3", f"10.10.{site_id}.2", "8883")
        results[f"broker_{space}"] = done.returncode == 0
    panel = shell("docker", "compose", "exec", "-T", "panel", "python", "-c",
                  "import urllib.request as u;u.urlopen('http://127.0.0.1:8000/healthz',timeout=3)")
    results["panel"] = panel.returncode == 0
    return results


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--minutes", type=float, default=10)
    args = parser.parse_args()
    started = time.time()
    first_bytes = {s: tunnel_bytes(s) for s in SPACES}
    samples: list[dict] = []
    checks: dict[str, list[bool]] = {}
    while time.time() - started < args.minutes * 60:
        samples.append(stats())
        for key, value in probe().items():
            checks.setdefault(key, []).append(value)
        time.sleep(60)
    elapsed = time.time() - started
    per_space = {}
    for space in SPACES:
        cpu = [s[space]["cpu"] for s in samples]
        mem = [s[space]["mem_mb"] for s in samples]
        per_space[space] = {
            "cpu_percent_of_one_core_mean": round(sum(cpu) / len(cpu), 2), "cpu_percent_peak": max(cpu),
            "memory_mb_mean": round(sum(mem) / len(mem), 1), "memory_mb_peak": round(max(mem), 1),
            "tunnel_kB_per_s": round((tunnel_bytes(space) - first_bytes[space]) / elapsed / 1000, 3),
        }
    output = {
        "generated_at": datetime.now().isoformat(), "duration_minutes": round(elapsed / 60, 1), "samples": len(samples),
        "per_space": per_space,
        "availability_percent": {k: round(100 * sum(v) / len(v), 2) for k, v in checks.items()},
        "environment": "containers on one developer workstation, not Raspberry Pi hardware",
        "energy": "NOT MEASURED: needs a USB-C power meter on real hardware",
    }
    OUT.write_text(json.dumps(output, indent=2))
    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
