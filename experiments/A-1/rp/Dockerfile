FROM python:3.10-slim
WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY rp.py internal_probe.py issuer-t.pub.pem issuer-c.pub.pem /app/
RUN mkdir -p /data /run/h4
EXPOSE 8080
CMD ["python", "/app/rp.py"]
