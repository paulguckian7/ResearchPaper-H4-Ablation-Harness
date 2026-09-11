FROM python:3.10-slim
WORKDIR /app
RUN pip install --no-cache-dir paho-mqtt==2.1.0
COPY subscribe_and_record.py /app/subscribe_and_record.py
CMD ["python", "-c", "import time; time.sleep(10**9)"]
