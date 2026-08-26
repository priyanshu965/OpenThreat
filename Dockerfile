# ── CyberWatch Dockerfile ──────────────────────────────────────────
# Serves the dashboard via nginx and optionally runs the fetcher via cron
# ────────────────────────────────────────────────────────────────────

ARG VERSION=latest

# ── Dashboard ──────────────────────────────────────────────────────
# Copies an EXPLICIT file list rather than `COPY .`. The context has to keep
# scripts/ and requirements.txt for the fetcher stage below, so allow-listing
# here is what keeps the pipeline source, and anything else, out of the public
# web root.
FROM nginx:alpine AS frontend
ARG VERSION=latest
LABEL org.opencontainers.image.title="CyberWatch Dashboard" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.source="https://github.com/priyanshu965/Cyberwatch"
WORKDIR /usr/share/nginx/html
COPY index.html app.js style.css service-worker.js manifest.json robots.txt ./
# js/ is not optional: index.html loads three sibling modules from it, and
# without them every view button throws a ReferenceError. The allow-list above
# is the reason this needs saying — a `COPY .` would have picked it up, and
# would also have served .git/ to the internet.
COPY js/ ./js/
COPY data/ ./data/
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]

# ── Fetcher ────────────────────────────────────────────────────────
FROM python:3.11-slim AS fetcher
ARG VERSION=latest
LABEL org.opencontainers.image.title="CyberWatch Fetcher" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.source="https://github.com/priyanshu965/Cyberwatch"
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt  # runtime only; dev deps not needed in image
COPY scripts/ scripts/
# Run as a non-root user; the image only ever needs to write into /app/data,
# which is a bind mount at runtime.
RUN useradd --create-home --uid 10001 cyberwatch && chown -R cyberwatch /app
USER cyberwatch
CMD ["python", "scripts/fetch_intel.py"]
