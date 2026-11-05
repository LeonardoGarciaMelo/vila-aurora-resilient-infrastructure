FROM python:3.12-slim-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends tzdata && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir flask==3.0.3 sqlalchemy==2.0.36 "psycopg[binary]==3.2.3" argon2-cffi==23.1.0 \
    pyotp==2.9.0 paho-mqtt==2.1.0 cryptography==43.0.3 gunicorn==23.0.0 werkzeug==3.0.6
COPY common/vlog.py /app/vlog.py
COPY panel-v2/ /app/
WORKDIR /app
USER 1000:1000
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "1", "--threads", "8", "app:app"]
