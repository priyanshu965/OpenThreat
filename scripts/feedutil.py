"""
OPENTHREAT — feedutil.py
======================
Small helpers every fetcher uses: dates, HTML stripping and JSON/text GETs.

Moved out of fetch_intel.py unchanged; fetch_intel re-exports every name here,
so `fetch_intel.now_utc` and the like keep working.
"""

import json
import re
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

import requests

from fetchlib import (
    CONFIG,
    log,
)

HEADERS = {"User-Agent": CONFIG.http_user_agent}
REQUEST_TIMEOUT = CONFIG.request_timeout


# ── Helpers ───────────────────────────────────────────────────────────────────

def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()

def parse_date(date_str) -> str:
    if not date_str:
        return now_utc()
    try:
        if hasattr(date_str, 'tm_year'):
            return datetime(*date_str[:6], tzinfo=timezone.utc).isoformat()
        for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S%z",
                    "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S",
                    "%Y-%m-%d %H:%M:%S UTC", "%Y-%m-%d"):
            try:
                return datetime.strptime(date_str, fmt).replace(tzinfo=timezone.utc).isoformat()
            except ValueError:
                continue
    except Exception:
        pass
    return now_utc()

# Date strings feedparser gives up on. CrowdStrike's feed writes
# "Nov 10, 2026 00:00:00-0600", which is neither RFC 822 nor ISO 8601.
_LOOSE_DATE_FORMATS = ("%b %d, %Y %H:%M:%S%z", "%B %d, %Y %H:%M:%S%z",
                       "%b %d, %Y", "%B %d, %Y", "%d %b %Y", "%d %B %Y")


def entry_date(entry) -> str | None:
    """The publication time of one feed entry as ISO 8601 UTC, or None.

    None matters. parse_date() answers "now" for anything it cannot read, which
    is right for a single missing field and wrong for a whole feed: every item
    looks brand new on every run, it never ages out, and the staleness check
    can never fire. Callers that need a date regardless add the fallback
    themselves; the feed probe uses the None to reject the feed outright.

    feedparser exposes dc:date as `updated` (Debian's RDF does this), so both
    fields are tried, parsed form first and then the raw string.
    """
    for key in ("published_parsed", "updated_parsed"):
        stamp = entry.get(key)
        if stamp:
            try:
                return datetime(*stamp[:6], tzinfo=timezone.utc).isoformat()
            except (TypeError, ValueError):
                continue
    for key in ("published", "updated"):
        raw = str(entry.get(key) or "").strip()
        if not raw:
            continue
        parsed = None
        try:
            parsed = parsedate_to_datetime(raw)
        except (TypeError, ValueError):
            for fmt in _LOOSE_DATE_FORMATS:
                try:
                    parsed = datetime.strptime(raw, fmt)
                    break
                except ValueError:
                    continue
        if parsed:
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc).isoformat()
    return None


_TAG_RE = re.compile(r"</?[a-zA-Z][a-zA-Z0-9-]*(?:\s[^<>]*)?/?>|<!--.*?-->", re.DOTALL)

def clean_html(text: str) -> str:
    """Strip HTML tags without destroying prose that merely contains '<'.

    The previous `<[^>]+>` pattern deleted everything between a bare '<' in
    text (e.g. `if (a < b)`) and the next '>', silently truncating code
    snippets in advisory descriptions."""
    if not text:
        return ""
    text = _TAG_RE.sub(" ", text)
    text = (text.replace("&nbsp;", " ").replace("&amp;", "&")
                .replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", '"'))
    text = re.sub(r"\s+", " ", text).strip()
    return text[:999]

def make_request(url: str, headers: dict = None, params: dict = None) -> dict | None:
    try:
        resp = requests.get(url, headers=headers or HEADERS, params=params, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        return resp.json()
    except requests.exceptions.Timeout:
        log.warning(f"Timeout: {url}")
    except requests.exceptions.HTTPError as e:
        log.warning(f"HTTP {e.response.status_code}: {url}")
    except requests.exceptions.RequestException as e:
        log.warning(f"Request failed {url}: {e}")
    except json.JSONDecodeError:
        log.warning(f"Invalid JSON: {url}")
    return None

def make_request_text(url: str, headers: dict = None) -> str | None:
    try:
        resp = requests.get(url, headers=headers or HEADERS, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        return resp.text
    except Exception as e:
        log.warning(f"Text request failed {url}: {e}")
        return None
