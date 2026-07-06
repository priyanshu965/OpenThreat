# ── CyberWatch Dockerfile ──────────────────────────────────────────
# Serves the dashboard via nginx and optionally runs the fetcher via cron
# ────────────────────────────────────────────────────────────────────

FROM nginx:alpine AS frontend
COPY . /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]

FROM python:3.11-slim AS fetcher
WORKDIR /app
COPY scripts/ scripts/
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
CMD ["python", "scripts/fetch_intel.py"]
