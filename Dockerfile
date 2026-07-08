# ── CyberWatch Dockerfile ──────────────────────────────────────────
# Serves the dashboard via nginx and optionally runs the fetcher via cron
# ────────────────────────────────────────────────────────────────────

ARG VERSION=latest

FROM nginx:alpine AS frontend
LABEL org.opencontainers.image.title="CyberWatch Dashboard" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.source="https://github.com/priyanshu965/Cyberwatch"
COPY . /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]

FROM python:3.11-slim AS fetcher
ARG VERSION=latest
LABEL org.opencontainers.image.title="CyberWatch Fetcher" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.source="https://github.com/priyanshu965/Cyberwatch"
WORKDIR /app
COPY scripts/ scripts/
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt  # runtime only; dev deps not needed in image
CMD ["python", "scripts/fetch_intel.py"]
