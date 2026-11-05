FROM python:3.12-slim-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends iproute2 mosquitto-clients netcat-openbsd tzdata && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir paho-mqtt==2.1.0
COPY field-sim/sim.py /app/sim.py
WORKDIR /app
CMD ["python", "-u", "sim.py"]
