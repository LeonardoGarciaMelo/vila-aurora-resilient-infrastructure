FROM python:3.12-slim-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends tzdata && rm -rf /var/lib/apt/lists/*
COPY common/vlog.py /app/vlog.py
COPY sms-gw/sms_gw.py /app/sms_gw.py
WORKDIR /app
CMD ["python", "-u", "sms_gw.py"]
