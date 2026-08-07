# Pinned by digest (not just tag) so rebuilds reuse the local image instead of
# re-checking Docker Hub every time — avoids pull rate limits.
FROM python:3.12-slim@sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de

WORKDIR /app

# tzdata is needed for the TZ environment variable (set in docker-compose.yml)
# to have any effect on Python's local-time functions — the slim base image
# doesn't include a timezone database by default.
RUN apt-get update && apt-get install -y --no-install-recommends tzdata \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/

VOLUME ["/data"]
EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
