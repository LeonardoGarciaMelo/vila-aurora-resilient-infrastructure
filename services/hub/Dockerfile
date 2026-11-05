FROM python:3.12-slim-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends \
      wireguard-tools nftables iproute2 ulogd2 chrony tzdata procps iputils-ping \
    && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir flask==3.0.3 pyotp==2.9.0
COPY common/vlog.py /app/vlog.py
COPY hub/ /app/
RUN chmod +x /app/entrypoint.sh
WORKDIR /app
ENTRYPOINT ["/app/entrypoint.sh"]
