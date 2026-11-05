"""Sends one legitimate signed message and one forged message to the lab MTA, then prints the verdicts."""
import smtplib
import sys
from email.message import EmailMessage

import dkim

KEY = open("/keys/dkim.key", "rb").read()
SELECTOR, DOMAIN = b"mail", b"vilaaurora.example"


def build(sender: str, subject: str, body: str) -> EmailMessage:
    message = EmailMessage()
    message["From"], message["To"], message["Subject"] = sender, "coordenacao@vilaaurora.example", subject
    message.set_content(body)
    return message


mode = sys.argv[1]
if mode == "legit":
    message = build("avisos@vilaaurora.example", "Reuniao da associacao", "Reuniao na quinta as 19h. Mensagem de teste do laboratorio.")
    raw = message.as_bytes()
    signature = dkim.sign(raw, SELECTOR, DOMAIN, KEY, include_headers=[b"from", b"to", b"subject"])
    raw = signature + raw
    envelope_from = "avisos@vilaaurora.example"
else:
    # Spoofs the project's own domain from an address outside the SPF record, with no valid signature.
    message = build("avisos@vilaaurora.example", "Atualizacao obrigatoria do acesso ao painel", "SIMULACAO DE LABORATORIO. Dominio ficticio, nenhum link real.")
    raw = message.as_bytes()
    envelope_from = "avisos@vilaaurora.example"
with smtplib.SMTP("172.27.0.25", 25, timeout=20) as smtp:
    smtp.sendmail(envelope_from, ["coordenacao@vilaaurora.example"], raw)
print(f"{mode}: delivered to lab MTA")
