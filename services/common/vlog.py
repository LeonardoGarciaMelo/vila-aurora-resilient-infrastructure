"""Syslog-formatted logging shared by lab services so Wazuh decoders can parse every source."""
import os
import socket
import sys
import time
from pathlib import Path

HOST = os.environ.get("LOG_HOST") or socket.gethostname()
LOG_DIR = Path(os.environ.get("LOG_DIR", "/var/log/vaurora"))


def log(program: str, message: str, filename: str | None = None) -> None:
    stamp = time.strftime("%b %e %H:%M:%S")
    line = f"{stamp} {HOST} {program}: {message}"
    print(line, file=sys.stdout, flush=True)
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    with open(LOG_DIR / (filename or f"{program}.log"), "a", encoding="utf-8") as handle:
        handle.write(line + "\n")
