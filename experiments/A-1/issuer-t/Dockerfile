FROM python:3.10-slim
WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY issue_and_send.py private.pem /app/
CMD ["python", "-c", "import time; time.sleep(10**9)"]
