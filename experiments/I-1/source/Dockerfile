FROM python:3.10-slim

RUN useradd --uid 10002 --create-home h4source
WORKDIR /app

COPY send.py /app/send.py
RUN chown -R h4source:h4source /app

USER h4source
