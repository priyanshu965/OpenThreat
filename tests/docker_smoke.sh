#!/usr/bin/env bash
# Builds both images and checks that they do what the Dockerfile says.
#
# Nothing else in the suite touches the images, so a base-image bump or a new
# js/ module missing from a COPY line would ship unnoticed. Run from the
# repository root:  bash tests/docker_smoke.sh
set -euo pipefail

PORT="${SMOKE_PORT:-18080}"
NAME="openthreat-smoke-$$"
BASE="http://127.0.0.1:${PORT}"

cleanup() { docker rm -f "${NAME}" >/dev/null 2>&1 || true; }
trap cleanup EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }

docker build --quiet --target frontend -t openthreat-frontend:smoke . >/dev/null
docker build --quiet --target fetcher  -t openthreat-fetcher:smoke  . >/dev/null

docker run -d --name "${NAME}" -p "127.0.0.1:${PORT}:80" openthreat-frontend:smoke >/dev/null
for _ in $(seq 1 30); do
  curl -fsS -o /dev/null "${BASE}/" 2>/dev/null && break
  sleep 0.5
done

status() { curl -s -o /dev/null -w '%{http_code}' "${BASE}$1" || true; }
header() { { curl -sI "${BASE}$1" || true; } | tr -d '\r' | { grep -i "^$2:" || true; }; }

# Every script the page loads has to be in the image.
for asset in / /app.js /style.css /service-worker.js /manifest.json \
    $(grep -oE 'js/[a-z]+\.js' index.html | sort -u | sed 's#^#/#'); do
  [ "$(status "${asset}")" = "200" ] || fail "${asset} returned $(status "${asset}")"
done

# The pipeline source and anything hidden must not be reachable.
for secret in /scripts/config.py /tests/test_security.py /.git/config /.env /requirements.txt /Dockerfile; do
  code="$(status "${secret}")"
  body="$(curl -s "${BASE}${secret}" | head -c 200)"
  case "${code}" in
    403|404) ;;
    # The SPA fallback answers unknown paths with index.html. That is fine as
    # long as it is the page and not the file that was asked for.
    200) echo "${body}" | grep -qi '<!doctype html' || fail "${secret} is being served" ;;
    *) fail "${secret} returned ${code}" ;;
  esac
done

# Security headers on the page AND on the nested locations, which nginx does
# not inherit once a location sets a header of its own.
for path in / /app.js /manifest.json; do
  header "${path}" "X-Frame-Options" | grep -qi 'DENY' || fail "no X-Frame-Options on ${path}"
  header "${path}" "X-Content-Type-Options" | grep -qi 'nosniff' || fail "no nosniff on ${path}"
  header "${path}" "Content-Security-Policy" | grep -qi "frame-ancestors 'none'" \
    || fail "no frame-ancestors on ${path}"
done

# The fetcher image: imports resolve, it does not run as root.
docker run --rm openthreat-fetcher:smoke python -c "
import sys
sys.path.insert(0, 'scripts')
import fetch_intel, sources
assert len(sources.RSS_SOURCES) > 50
" >/dev/null || fail "the fetcher image cannot import the pipeline"
[ "$(docker run --rm openthreat-fetcher:smoke id -u)" != "0" ] || fail "the fetcher runs as root"

echo "OK: both images build, the dashboard serves, and nothing private is exposed"
