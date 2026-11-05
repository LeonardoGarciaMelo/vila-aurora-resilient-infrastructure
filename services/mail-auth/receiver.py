"""Receiving MTA for the lab: evaluates SPF, DKIM and DMARC for real and quarantines failures (RT-10)."""
import email
import os
import time
from email import policy
from pathlib import Path

import dkim
import dns.resolver
import spf
from aiosmtpd.controller import Controller

from vlog import log

LAB_DNS = os.environ["LAB_DNS"]
MAILBOX = Path("/mailbox")
resolver = dns.resolver.Resolver(configure=False)
resolver.nameservers = [LAB_DNS]
dns.resolver.default_resolver = resolver


def dns_txt(name, timeout=5):
    name = name.decode() if isinstance(name, bytes) else name
    try:
        return b"".join(b"".join(r.strings) for r in resolver.resolve(name.rstrip("."), "TXT"))
    except dns.exception.DNSException:
        return None


def dmarc_policy(domain: str) -> dict:
    try:
        answer = resolver.resolve(f"_dmarc.{domain}", "TXT")
    except dns.exception.DNSException:
        return {}
    record = b"".join(answer[0].strings).decode()
    return dict(part.strip().split("=", 1) for part in record.split(";") if "=" in part)


class Handler:
    async def handle_DATA(self, _server, session, envelope):
        raw = envelope.content
        message = email.message_from_bytes(raw, policy=policy.default)
        from_domain = message["From"].addresses[0].domain.lower()
        mail_from = envelope.mail_from
        spf_result, _ = spf.check2(i=session.peer[0], s=mail_from, h="lab-sender")
        dkim_ok = dkim.verify(raw, dnsfunc=dns_txt)
        signing_domain = ""
        if dkim_ok and message.get("DKIM-Signature"):
            tags = dict(p.strip().split("=", 1) for p in message["DKIM-Signature"].split(";") if "=" in p)
            signing_domain = tags.get("d", "").strip().lower()
        record = dmarc_policy(from_domain)
        # Strict alignment (adkim=s, aspf=s), as published in the record.
        spf_aligned = spf_result == "pass" and mail_from.split("@")[-1].lower() == from_domain
        dkim_aligned = bool(dkim_ok) and signing_domain == from_domain
        dmarc_ok = spf_aligned or dkim_aligned
        folder = "inbox" if dmarc_ok or not record else record.get("p", "none")
        results = (f"lab-mx; spf={spf_result} smtp.mailfrom={mail_from}; "
                   f"dkim={'pass' if dkim_ok else 'fail'} header.d={signing_domain or 'none'}; "
                   f"dmarc={'pass' if dmarc_ok else 'fail'} (p={record.get('p', 'none')}) header.from={from_domain}")
        target = MAILBOX / folder
        target.mkdir(parents=True, exist_ok=True)
        name = f"{int(time.time() * 1000)}.eml"
        (target / name).write_bytes(f"Authentication-Results: {results}\r\n".encode() + raw)
        log("vilaaurora-mail", f"from={from_domain} peer={session.peer[0]} folder={folder} {results}")
        return "250 OK"


controller = Controller(Handler(), hostname="0.0.0.0", port=25)
controller.start()
while True:
    time.sleep(3600)
