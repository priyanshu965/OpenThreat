"""
CYBERWATCH — darkweb.py
=======================
Dark-web monitoring: ransomware leak-site activity.

WHAT THIS IS, PRECISELY. A GitHub Actions runner cannot reach .onion services,
so we do not crawl Tor and this module does not pretend to. What it consumes is
the CLEARNET MIRROR of projects that do the Tor crawling and publish results:
RansomLook tracks 600+ leak sites and republishes each post over HTTPS. The
observation is genuinely dark-web-sourced; the transport is not, and the UI says
so.

Leak-site posts are also the one class of item in this pipeline that is written
BY the adversary rather than about them, which is why they carry the
"adversary-authored" provenance tag - they are claims, not confirmed breaches.
A listing means the crew says they have the data.

Sources (both free, no key):
  RansomLook       https://www.ransomlook.io/api/recent   posts + descriptions
                   https://www.ransomlook.io/api/groups   tracked leak sites
  Ransomware.live  already wired into fetch_intel as a separate source
"""

from __future__ import annotations

import json
import re
from collections import Counter

from config import CONFIG

try:
    from fetch_intel import _SESSION, _cached_fetch, log, now_utc, parse_date
except Exception:  # pragma: no cover - standalone/tests
    import logging
    from datetime import datetime, timezone
    import requests
    log = logging.getLogger("cyberwatch.darkweb")
    _SESSION = requests.Session()
    _cached_fetch = None

    def now_utc() -> str:
        return datetime.now(timezone.utc).isoformat()

    def parse_date(v):
        return str(v or "")

_RANSOMLOOK_RECENT = "https://www.ransomlook.io/api/recent"
_RANSOMLOOK_GROUPS = "https://www.ransomlook.io/api/groups"

# RansomLook timestamps look like "2026-08-25 08:26:26.109019" (UTC, no zone).
_TS = re.compile(r"^(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})")


def _iso(ts: str) -> str:
    m = _TS.match(str(ts or "").strip())
    return f"{m.group(1)}T{m.group(2)}+00:00" if m else ""


def _fetch_json(name: str, url: str):
    def _raw():
        try:
            resp = _SESSION.get(url, timeout=CONFIG.request_timeout)
            resp.raise_for_status()
            return resp.text, None
        except Exception as e:
            return None, str(e)

    text = _cached_fetch(name, CONFIG.darkweb_ttl_hours, _raw) if _cached_fetch else _raw()[0]
    if not text:
        return None
    try:
        return json.loads(text)
    except Exception as e:
        log.warning(f"  darkweb: {name} did not parse: {e}")
        return None


def fetch_leak_site_posts() -> list[dict]:
    """Recent ransomware leak-site listings, as feed items.

    Registered in API_SOURCES, so it inherits run_source()'s failure isolation
    and freshness-aware health reporting like every other source.
    """
    if not CONFIG.enable_darkweb:
        log.info("Dark-web monitoring disabled (ENABLE_DARKWEB=0)")
        return []

    log.info("Fetching ransomware leak-site posts (RansomLook)...")
    data = _fetch_json("darkweb_recent.json", _RANSOMLOOK_RECENT)
    if not isinstance(data, list):
        log.warning("  RansomLook returned no usable post list")
        return []

    items: list[dict] = []
    for post in data[:CONFIG.max_items_per_source]:
        victim = str(post.get("post_title") or "").strip()
        group = str(post.get("group_name") or "").strip()
        if not victim:
            continue
        desc = str(post.get("description") or "").strip()
        published = _iso(post.get("discovered"))

        body = (f"Ransomware group '{group or 'unknown'}' has listed {victim} on its "
                f"leak site. This is the group's own claim, not a confirmed breach.")
        if desc:
            body += " Victim profile: " + desc[:400]

        link = post.get("link") or ""
        url = ("https://www.ransomlook.io" + link) if link.startswith("/") else \
              (link or "https://www.ransomlook.io/recent")

        items.append({
            "title": f"Leak site: {group or 'unknown group'} lists {victim[:80]}",
            "description": body,
            "url": url,
            "cve_id": None,
            "source": "RansomLook",
            "category": "incident",
            "severity": "high",
            "cvss_score": None,
            "published": parse_date(published) if published else now_utc(),
            "iocs": {},
            "threat_actors_hint": [group] if group else [],
            # Written by the adversary, so it is a claim. The provenance layer
            # surfaces this distinctly from vendor research or journalism.
            "provenance_hint": "adversary-authored",
        })

    log.info(f"  Got {len(items)} leak-site posts")
    return items


def build_darkweb_summary() -> dict | None:
    """Roll leak-site activity up for the dashboard panel.

    Aggregated server-side, like the attacker map: the dashboard gets counts,
    not a dump of every victim name ever posted.
    """
    if not CONFIG.enable_darkweb:
        return None

    posts = _fetch_json("darkweb_recent.json", _RANSOMLOOK_RECENT)
    groups = _fetch_json("darkweb_groups.json", _RANSOMLOOK_GROUPS)
    if not isinstance(posts, list) and not isinstance(groups, list):
        return None

    posts = posts if isinstance(posts, list) else []
    groups = groups if isinstance(groups, list) else []

    active = Counter()
    dated = []
    for p in posts:
        g = str(p.get("group_name") or "").strip()
        if g:
            active[g] += 1
        iso = _iso(p.get("discovered"))
        if iso:
            dated.append(iso[:10])

    return {
        "generated": now_utc(),
        "tracked_leak_sites": len(groups),
        "recent_posts": len(posts),
        "distinct_groups_active": len(active),
        "most_active": [{"group": g, "posts": n} for g, n in active.most_common(10)],
        "newest_post": max(dated) if dated else None,
        "oldest_in_window": min(dated) if dated else None,
        "source": "RansomLook (https://www.ransomlook.io)",
        "collection_note": (
            "Leak-site posts observed on Tor hidden services by RansomLook and "
            "republished over HTTPS. CyberWatch consumes that mirror; it does "
            "not crawl Tor itself. A listing is the group's claim, not a "
            "confirmed breach."
        ),
    }
