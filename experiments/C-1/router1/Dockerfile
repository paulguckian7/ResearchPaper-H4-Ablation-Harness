FROM python:3.10-slim
RUN useradd --uid 10002 --create-home h4
WORKDIR /app
COPY router.py internal_probe.py /app/
RUN mkdir -p /data /run/h4 && chown -R h4:h4 /app /data /run/h4
USER h4
EXPOSE 8080
CMD ["python", "/app/router.py"]
