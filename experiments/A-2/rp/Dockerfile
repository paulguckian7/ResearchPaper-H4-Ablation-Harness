FROM python:3.10-slim
WORKDIR /app
COPY rp.py internal_probe.py server.cert.pem server.key.pem ca-bundle.pem /app/
RUN mkdir -p /data /run/h4
EXPOSE 8080 8443
CMD ["python", "/app/rp.py"]
