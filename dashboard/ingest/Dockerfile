# Pinned by digest; to update, pick a new python:3.12.x-slim tag and run
#   docker buildx imagetools inspect python:<tag>
FROM python:3.12.16-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir --require-hashes --only-binary=:all: -r /tmp/requirements.txt && rm /tmp/requirements.txt
COPY --chmod=644 ingest.py /ingest.py
# docker-compose.yml runs this as your own UID so it can read data/ (mode 700); nobody otherwise
USER nobody
ENV PYTHONDONTWRITEBYTECODE=1
ENTRYPOINT ["python", "-I", "/ingest.py"]
