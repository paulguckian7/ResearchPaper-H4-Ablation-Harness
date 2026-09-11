FROM python:3.10-slim
WORKDIR /app
COPY client.py internal_probe.py /app/
RUN mkdir -p /run/h4
EXPOSE 8080
CMD ["python", "/app/client.py"]
