#!/usr/bin/env python3
"""RT-14: acquires evidence in order of volatility, hashes at collection time, writes chain of custody.

Usage: collect_evidence.py "<examiner name>"
Memory scope: only the panel-v1 process is dumped. A full host RAM image would expose the examiner's
whole personal machine, since containers share its kernel, so it is deliberately out of scope.
"""
import csv
import hashlib
import json
import subprocess
import sys
import tarfile
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "evidence/forensics"
IMAGES = OUT / "images"
IMAGES.mkdir(parents=True, exist_ok=True)
EXAMINER = sys.argv[1] if len(sys.argv) > 1 else "Lab team"
COMPOSE = ["docker", "compose", "--profile", "legacy", "--profile", "tools"]
MEMORY_DUMP = r"""
import re,sys,os
pid=int(sys.argv[1])
with open(f'/proc/{pid}/maps') as m, open(f'/proc/{pid}/mem','rb',0) as mem, open(sys.argv[2],'wb') as out:
    for line in m:
        match=re.match(r'([0-9a-f]+)-([0-9a-f]+) r', line)
        if not match or '[vvar' in line or '[vsyscall' in line: continue
        start,end=int(match[1],16),int(match[2],16)
        try:
            mem.seek(start); out.write(mem.read(end-start))
        except (OSError,ValueError,OverflowError): pass
"""
hashes, custody = [], []


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def register(evidence_id: str, description: str, path: Path, tool: str) -> None:
    now = datetime.now().astimezone().isoformat(timespec="seconds")
    value = sha256(path)
    hashes.append({"id": evidence_id, "description": description, "file": path.name, "tool": tool,
                   "bytes": path.stat().st_size, "sha256": value, "collected_at": now, "examiner": EXAMINER})
    custody.append([evidence_id, now, "Collection", f"{tool} -> {path.relative_to(ROOT)}", EXAMINER, value])
    print(f"{evidence_id} {value} {path.name}", flush=True)


def exec_in(service: str, *cmd: str, **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run([*COMPOSE, "exec", "-T", service, *cmd], capture_output=True, cwd=ROOT, **kwargs)


def copy_out(service: str, source: str, name: str) -> Path:
    target = IMAGES / name
    subprocess.run([*COMPOSE, "cp", f"{service}:{source}", str(target)], check=True, capture_output=True, cwd=ROOT)
    return target


def bundle(name: str, files: list[Path]) -> Path:
    target = IMAGES / name
    with tarfile.open(target, "w") as tar:
        for path in files:
            tar.add(path, arcname=path.name)
            path.unlink()
    return target


def main() -> None:
    # 1. Most volatile first: process memory and live connections of the panel.
    script = IMAGES / "dump.py"
    script.write_text(MEMORY_DUMP)
    subprocess.run([*COMPOSE, "cp", str(script), "panel-v1:/tmp/dump.py"], check=True, capture_output=True, cwd=ROOT)
    pid = exec_in("panel-v1", "sh", "-c", "pgrep -f app.py | head -1 || cat /proc/1/stat | cut -d' ' -f1").stdout.decode().strip() or "1"
    exec_in("panel-v1", "python", "/tmp/dump.py", pid, "/tmp/mem.raw")
    script.unlink()
    register("EV-01", "Process memory of panel v1 (scope limited, see module docstring)", copy_out("panel-v1", "/tmp/mem.raw", "EV-01_panel_process_memory.raw"), "/proc/pid/mem reader")
    exec_in("panel-v1", "rm", "-f", "/tmp/mem.raw", "/tmp/dump.py")

    # 2. Filesystem of the compromised panel.
    disk = IMAGES / "EV-02_panel_filesystem.tar"
    with open(disk, "wb") as handle:
        subprocess.run(["docker", "export", "vaurora-panel-v1-1"], stdout=handle, check=True)
    register("EV-02", "Filesystem export of panel v1 container", disk, "docker export")

    # 3. Logs: VPN local copy (tampered) and its off-host mirror.
    vpn = [copy_out("legacy-vpn", "/var/log/vaurora/auth.log", "vpn_local_auth.log"),
           copy_out("legacy-vpn", "/central/legacy-vpn-auth.log", "vpn_central_mirror_auth.log")]
    register("EV-03", "Legacy VPN authentication logs: local (tampered) and central mirror", bundle("EV-03_vpn_logs.tar", vpn), "docker cp + tar")
    panel = [copy_out("panel-v1", "/central/legacy-panel-access.log", "legacy-panel-access.log"),
             copy_out("panel-v1", "/central/legacy-panel-app.log", "legacy-panel-app.log")]
    register("EV-04", "Panel v1 access and application logs", bundle("EV-04_panel_logs.tar", panel), "docker cp + tar")
    register("EV-05", "Legacy PostgreSQL statement log", bundle("EV-05_postgres_logs.tar", [copy_out("db-legacy", "/var/log/pg/legacy-postgresql.log", "legacy-postgresql.log")]), "docker cp + tar")
    register("EV-06", "Field controller log (pump, tank, cold chamber)", bundle("EV-06_controller_logs.tar", [copy_out("legacy-controller", "/central/legacy-controller.log", "legacy-controller.log")]), "docker cp + tar")

    # 4. SIEM alerts.
    alerts = IMAGES / "EV-07_wazuh_alerts.json"
    with open(alerts, "wb") as handle:
        subprocess.run([*COMPOSE, "exec", "-T", "wazuh", "cat", "/var/ossec/logs/alerts/alerts.json"], stdout=handle, check=True, cwd=ROOT)
    register("EV-07", "Wazuh alert export", alerts, "alerts.json export")

    # 5. Phishing message from the mail lab, when that lab was run.
    quarantine = sorted((ROOT / "evidence/raw/mail/quarantine").glob("*.eml"))
    if quarantine:
        target = IMAGES / "EV-08_phishing_message.eml"
        target.write_bytes(quarantine[-1].read_bytes())
        register("EV-08", "Forged e-mail with Authentication-Results headers", target, "lab MTA quarantine copy")

    with open(OUT / "hashes.json", "w", encoding="utf-8") as handle:
        json.dump(hashes, handle, indent=2)
    with open(OUT / "hashes_at_collection.txt", "w", encoding="utf-8") as handle:
        for item in hashes:
            handle.write(f"{item['sha256']}  images/{item['file']}\n")
    custody_file = OUT / "chain_of_custody.csv"
    with open(custody_file, "w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["evidence", "timestamp", "action", "source_or_destination", "responsible", "sha256"])
        writer.writerows(custody)
    verified = subprocess.run(["sha256sum", "-c", "hashes_at_collection.txt"], cwd=OUT, capture_output=True, text=True)
    (OUT / "verification_at_collection.txt").write_text(verified.stdout)
    print(verified.stdout)


if __name__ == "__main__":
    main()
