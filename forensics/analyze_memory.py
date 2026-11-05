#!/usr/bin/env python3
"""Searches the panel process memory (EV-01) for traces of the attack.

This is a string search over one process, not a Volatility analysis: Volatility needs a full RAM image,
which is out of scope here because it would expose the examiner's whole machine (see collect_evidence.py).
Hash is verified first, and only counts plus short redacted samples are written out.
"""
import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "evidence/forensics"
IMAGE = OUT / "images/EV-01_panel_process_memory.raw"
RESULT = ROOT / "docs/results/memory_analysis.json"
PATTERNS = {
    "stacked_update_on_pump_schedule": rb"UPDATE agendamento_bomba[ -~]{0,60}",
    "union_on_users_table": rb"UNION ALL SELECT[ -~]{0,200}usuarios",
    "sqlmap_user_agent": rb"sqlmap/[0-9][ -~]{0,20}",
    "attacker_tunnel_source": rb"172\.28\.0\.2\b",
    "concatenated_query_template": rb"SELECT data, local, cracha FROM acessos WHERE local LIKE '%[ -~]{0,50}",
}


def main() -> None:
    check = subprocess.run(["sha256sum", "-c", "hashes_at_collection.txt"], cwd=OUT, capture_output=True, text=True)
    if check.returncode != 0:
        raise SystemExit("integrity check failed, refusing to analyse")
    data = IMAGE.read_bytes()
    findings = {}
    for name, pattern in PATTERNS.items():
        matches = re.findall(pattern, data)
        findings[name] = {"count": len(matches), "sample": matches[0][:90].decode("ascii", "replace") if matches else None}
    result = {"evidence": "EV-01", "bytes": len(data), "method": "byte pattern search over one process's readable memory",
              "not_performed": "Volatility 3 (requires a full RAM image)", "findings": findings}
    RESULT.write_text(json.dumps(result, indent=2))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
