FROM python:3.12-slim-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends tzdata && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir flask==3.0.3 "psycopg[binary]==3.2.3" faker==30.8.2
COPY common/vlog.py /app/vlog.py
COPY legacy/panel/ /app/
WORKDIR /app
CMD ["python", "-u", "app.py"]
