FROM python:3.12-slim-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends tzdata && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir paho-mqtt==2.1.0 "psycopg[binary]==3.2.3"
COPY common/vlog.py /app/vlog.py
COPY ingest/ingest.py /app/ingest.py
WORKDIR /app
CMD ["python", "-u", "ingest.py"]
