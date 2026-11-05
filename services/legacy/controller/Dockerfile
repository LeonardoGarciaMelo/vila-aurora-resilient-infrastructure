FROM python:3.12-slim-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends tzdata && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir "psycopg[binary]==3.2.3"
COPY common/vlog.py /app/vlog.py
COPY legacy/controller/controller.py /app/controller.py
WORKDIR /app
CMD ["python", "-u", "controller.py"]
