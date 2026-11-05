FROM python:3.12-slim-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends tzdata && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir requests==2.32.3 jsonschema==4.23.0
COPY common/vlog.py /app/vlog.py
COPY llm-triage/ /app/
WORKDIR /app
CMD ["sleep", "infinity"]
