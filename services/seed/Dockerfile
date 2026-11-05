FROM python:3.12-slim-bookworm
RUN pip install --no-cache-dir "psycopg[binary]==3.2.3" faker==30.8.2 argon2-cffi==23.1.0 pyotp==2.9.0
COPY seed/seed.py /app/seed.py
WORKDIR /app
CMD ["python", "-u", "seed.py"]
