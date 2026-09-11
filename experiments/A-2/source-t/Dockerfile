FROM python:3.10-slim
WORKDIR /app
COPY send.py client.cert.pem client.key.pem /app/
CMD ["python", "-c", "import time; time.sleep(10**9)"]
