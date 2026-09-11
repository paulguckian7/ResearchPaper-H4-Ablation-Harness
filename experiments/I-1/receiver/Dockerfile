FROM python:3.10-slim

RUN useradd --uid 10001 --create-home h4
WORKDIR /app

COPY receiver.py /app/receiver.py
COPY internal_probe.py /app/internal_probe.py

RUN mkdir -p /data /run/h4 && chown -R h4:h4 /app /data /run/h4

USER h4
EXPOSE 8080

CMD ["python", "/app/receiver.py"]
