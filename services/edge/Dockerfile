FROM python:3.12-slim-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends \
      mosquitto mosquitto-clients wireguard-tools nftables iproute2 ulogd2 tzdata procps openssl \
    && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir paho-mqtt==2.1.0 cryptography==43.0.3 ntplib==0.4.0 psutil==6.1.0 requests==2.32.3
COPY common/vlog.py /app/vlog.py
COPY edge/ /app/
RUN chmod +x /app/entrypoint.sh /app/wan.sh && ln -s /app/wan.sh /usr/local/bin/wan
WORKDIR /app
ENTRYPOINT ["/app/entrypoint.sh"]
