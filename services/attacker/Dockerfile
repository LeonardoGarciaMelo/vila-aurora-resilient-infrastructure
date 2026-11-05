# Offensive tooling for the team's own isolated lab only. Its networks have no internet route.
FROM python:3.12-slim-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends \
      nmap sshpass openssh-client mosquitto-clients wireguard-tools iproute2 curl netcat-openbsd \
      tzdata procps openssl \
    && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir sqlmap==1.8.11 requests==2.32.3 pysocks==1.7.1 pyotp==2.9.0
COPY attacker/ /attack/
WORKDIR /attack
CMD ["sleep", "infinity"]
