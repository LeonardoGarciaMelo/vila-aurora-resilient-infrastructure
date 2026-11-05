FROM mcr.microsoft.com/playwright/python:v1.48.0-jammy
RUN pip install --no-cache-dir playwright==1.48.0 axe-playwright-python==0.1.4 pyotp==2.9.0
COPY a11y.py /a11y.py
CMD ["python", "-u", "/a11y.py"]
