FROM python:3.12.8-slim
RUN pip install --no-cache-dir "psycopg[binary]==3.2.3" maxminddb==2.6.2 tzdata==2024.2
COPY --chmod=644 ingest.py /ingest.py
USER nobody
ENV PYTHONDONTWRITEBYTECODE=1
ENTRYPOINT ["python", "-I", "/ingest.py"]
