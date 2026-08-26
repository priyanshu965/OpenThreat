"""
CYBERWATCH — fetchlib.py
=========================
The HTTP session and the on-disk cache, extracted so every module shares ONE
of each.

Why this exists. The satellite modules used to reach into fetch_intel for these:

    try:
        from fetch_intel import _SESSION, _cached_fetch, log
    except Exception:
        ...build a private session, set _cached_fetch = None...

That import can never succeed in production. fetch_intel imports darkweb at
line ~78 but defines _SESSION at line ~179, so during the import of fetch_intel
the name does not exist yet and the fallback always fires. Worse, when the
pipeline is run as `python scripts/fetch_intel.py` the module is `__main__`, so
`from fetch_intel import ...` imports a SECOND, independent copy of the whole
module — duplicate sessions, duplicate caches, duplicate globals.

The visible symptom was that dark-web fetches ran with `_cached_fetch = None`
and therefore re-downloaded RansomLook on all 24 daily runs.

fetchlib has no project imports beyond config, so anything may import it at any
point in its own module body without circularity.
"""

from __future__ import annotations

import gzip
import io
import json
import logging
import os
import re
import time
from pathlib import Path

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

try:
    from config import CONFIG
except ImportError:  # pragma: no cover - standalone use
    import importlib.util
    _spec = importlib.util.spec_from_file_location(
        "config", Path(__file__).parent / "config.py")
    _mod = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_mod)
    CONFIG = _mod.CONFIG


# ── Logging ───────────────────────────────────────────────────────────────────
class StructuredAdapter(logging.LoggerAdapter):
    """Minimal structured logging: extra kwargs become space-separated key=val."""

    def process(self, msg, kwargs):
        extra = kwargs.pop("extra", {})
        if extra:
            ctx = " ".join(f"{k}={v}" for k, v in sorted(extra.items()))
            msg = f"{msg}  [{ctx}]"
        return msg, kwargs


logging.basicConfig(
    level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = StructuredAdapter(logging.getLogger("cyberwatch"), {})

HEADERS = {"User-Agent": CONFIG.http_user_agent}

# ── Shared HTTP session ───────────────────────────────────────────────────────
# Every fetcher used to open a fresh TCP+TLS connection (~37 handshakes/run).
# One pooled session with a retry adapter removes that, and gives every source
# uniform backoff on 429/5xx instead of a hard failure.
SESSION = requests.Session()
SESSION.headers.update(HEADERS)
_ADAPTER = HTTPAdapter(
    pool_connections=16, pool_maxsize=16,
    max_retries=Retry(total=2, backoff_factor=0.6, respect_retry_after_header=True,
                      status_forcelist=[429, 500, 502, 503, 504],
                      allowed_methods=frozenset(["GET", "POST"])),
)
SESSION.mount("https://", _ADAPTER)
SESSION.mount("http://", _ADAPTER)

# ── On-disk cache ─────────────────────────────────────────────────────────────
CACHE_DIR = CONFIG.data_dir / ".cache"

# Cache filenames are partly built from values that arrive over the network
# (e.g. f"ssvc_{cve_id}.json", where cve_id can come straight from a third-party
# API response). A hostile or compromised upstream feed returning a cve_id of
# "CVE-../../../../etc/passwd" would otherwise escape the cache directory and
# turn cached_fetch into an arbitrary-file read. We ingest 45 third-party feeds,
# so "upstream returns something malicious" is squarely in scope.
#
# Sanitise at the chokepoint rather than at each call site: every caller is
# covered, and a future one cannot forget.
_SAFE_CACHE_NAME = re.compile(r"[^A-Za-z0-9._-]+")


def safe_cache_name(name: str) -> str:
    cleaned = _SAFE_CACHE_NAME.sub("_", str(name)).lstrip(".") or "cache"
    return cleaned[:120]


def cache_path(name: str) -> Path:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    safe = safe_cache_name(name)
    path = (CACHE_DIR / safe).resolve()
    # Belt and braces: even after sanitising, refuse anything that resolves
    # outside the cache directory.
    if not str(path).startswith(str(CACHE_DIR.resolve())):
        raise ValueError(f"unsafe cache path for {name!r}")
    return path


def cached_fetch(name: str, ttl_hours: float, fetcher) -> str | None:
    """Return cached content (decoded text) if fresh, else call ``fetcher()``
    and cache the result atomically (write to tmp, then rename). ``fetcher``
    must return ``(content_str, None)`` on success or ``(None, error_str)``
    on failure."""
    path = cache_path(name)
    if path.exists():
        age = time.time() - path.stat().st_mtime
        if age < ttl_hours * 3600:
            log.info(f"  Cache HIT for {name} ({(age / 3600):.1f}h old)")
            return path.read_text(encoding="utf-8")

    content, err = fetcher()
    if content is not None:
        tmp = path.with_suffix(f".{os.getpid()}.tmp")
        tmp.write_text(content, encoding="utf-8")
        tmp.replace(path)
        return content

    # Fetch failed; a stale answer beats no answer.
    if path.exists():
        log.warning(f"  Fetch failed for {name}, using stale cache: {err}")
        return path.read_text(encoding="utf-8")
    log.warning(f"  Fetch failed for {name} (no cache): {err}")
    return None


def http_text(url: str, timeout: int | None = None, headers: dict | None = None):
    """``(text, None)`` / ``(None, error)`` — the shape cached_fetch wants."""
    try:
        resp = SESSION.get(url, timeout=timeout or CONFIG.request_timeout,
                           headers=headers or None)
        resp.raise_for_status()
        return resp.text, None
    except Exception as e:  # noqa: BLE001 - a bad source must never abort a run
        return None, str(e)[:300]


def cached_json(name: str, url: str, ttl_hours: float, headers: dict | None = None):
    """Fetch JSON through the disk cache. Returns the parsed object or None."""
    text = cached_fetch(name, ttl_hours, lambda: http_text(url, headers=headers))
    if not text:
        return None
    try:
        return json.loads(text)
    except Exception as e:  # noqa: BLE001
        log.warning(f"  {name} did not parse as JSON: {e}")
        return None


def cached_derive(name: str, ttl_hours: float, producer):
    """
    Cache a DERIVED artifact rather than the bytes it came from.

    Some upstreams are far too large to keep on disk: MITRE's
    enterprise-attack.json is 48 MB, and the CI cache and the published state
    tarball both carry whatever lands in data/.cache. ``producer`` downloads
    and reduces in one step, and only the small result is stored.

    ``producer`` returns a JSON-serialisable object, or None on failure (in
    which case a stale cached copy is used if one exists).
    """
    path = cache_path(name)
    if path.exists():
        age = time.time() - path.stat().st_mtime
        if age < ttl_hours * 3600:
            try:
                return json.loads(path.read_text(encoding="utf-8"))
            except Exception:  # noqa: BLE001 - corrupt cache, rebuild it
                log.warning(f"  Cached {name} was unreadable; rebuilding")

    try:
        derived = producer()
    except Exception as e:  # noqa: BLE001
        log.warning(f"  Could not build {name}: {e}")
        derived = None

    if derived is not None:
        tmp = path.with_suffix(f".{os.getpid()}.tmp")
        tmp.write_text(json.dumps(derived, ensure_ascii=False, separators=(",", ":")),
                       encoding="utf-8")
        tmp.replace(path)
        return derived

    if path.exists():
        log.warning(f"  Using stale {name}")
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            return None
    return None


def stream_json(url: str, timeout: int | None = None, max_bytes: int = 120 * 1024 * 1024):
    """
    Download a large JSON document without holding the encoded bytes and the
    decoded object in memory at the same time, and refuse anything absurd.

    ``max_bytes`` is a guard, not a tuning knob: an upstream that suddenly
    serves a 4 GB body should fail the source, not the runner.
    """
    resp = SESSION.get(url, timeout=timeout or max(60, CONFIG.request_timeout), stream=True)
    resp.raise_for_status()
    buf = io.BytesIO()
    total = 0
    for chunk in resp.iter_content(chunk_size=1 << 16):
        if not chunk:
            continue
        total += len(chunk)
        if total > max_bytes:
            raise ValueError(f"response exceeded {max_bytes} bytes")
        buf.write(chunk)
    raw = buf.getvalue()
    if raw[:2] == b"\x1f\x8b":
        raw = gzip.decompress(raw)
    return json.loads(raw.decode("utf-8", "replace"))


def now_utc() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()
