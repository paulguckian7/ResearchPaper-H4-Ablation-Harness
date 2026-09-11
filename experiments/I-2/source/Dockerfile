FROM python:3.10-slim
WORKDIR /app
RUN pip install --no-cache-dir paho-mqtt==2.1.0
COPY publish.py /app/publish.py
CMD ["python", "-c", "import time; time.sleep(10**9)"]
