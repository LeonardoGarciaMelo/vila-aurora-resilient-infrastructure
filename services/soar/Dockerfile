FROM python:3.12-slim-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends tzdata openssl && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir paho-mqtt==2.1.0 cryptography==43.0.3 requests==2.32.3
COPY common/vlog.py /app/vlog.py
COPY soar/soar.py /app/soar.py
WORKDIR /app
CMD ["python", "-u", "soar.py"]
