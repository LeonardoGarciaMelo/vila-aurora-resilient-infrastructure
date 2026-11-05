FROM python:3.12-slim-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends tzdata && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir numpy==2.1.3 scikit-learn==1.5.2 joblib==1.4.2 "psycopg[binary]==3.2.3"
COPY common/vlog.py /app/vlog.py
COPY ai/ /app/
WORKDIR /app
CMD ["sh", "-c", "python -u train_eval.py && exec python -u detector.py"]
