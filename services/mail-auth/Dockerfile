FROM python:3.12-slim-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends dnsutils tzdata && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir aiosmtpd==1.4.6 dnspython==2.7.0 dkimpy==1.1.8 pyspf==2.0.14 cryptography==43.0.3
COPY common/vlog.py /app/vlog.py
COPY mail-auth/ /app/
WORKDIR /app
