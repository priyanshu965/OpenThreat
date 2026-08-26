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

# Shared session + disk cache. See fetchlib for why this is not a
# `from fetch_intel import ...` any more: that import could never succeed here,
# so RansomLook was re-downloaded on every run with caching silently disabled.
from fetchlib import SESSION as _SESSION, cached_fetch as _cached_fetch, log, now_utc  # noqa: F401,E402


def parse_date(v):
    """Local, dependency-free: RansomLook stamps are normalised by _iso()."""
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


# ── Searchable exposure index (CASM-style) ────────────────────────────────────
# The dashboard is static, and ransomware.live rate-limits to 1 request/minute,
# so interactive search cannot call an API at view time. Instead the pipeline
# builds a compact index once per run and the browser searches it locally. That
# removes the rate limit from the interactive path entirely.

_RW_VICTIMS_YEAR = "https://api.ransomware.live/v2/victims/{year}"
_RANSOMLOOK_POSTS = "https://www.ransomlook.io/api/posts"

# What this index does and does NOT cover. Stated in the payload so the UI
# cannot quietly imply more coverage than exists: a company absent from these
# sources means "not in our leak-site corpus", NOT "no dark-web exposure".
COVERAGE = {
    "covers": [
        "Ransomware and extortion leak-site victim listings",
        "600+ leak sites tracked by RansomLook on Tor",
        "Victim, claiming group, date, and where published, country and sector",
    ],
    "does_not_cover": [
        "Criminal forums, marketplaces and Telegram channels",
        "Credential dumps, combolists and infostealer logs",
        "Paste sites and open buckets",
        "Anything not published to a ransomware leak site",
    ],
    "caveat": (
        "A listing is the crew's own claim, not a confirmed breach. Absence "
        "from this index is not evidence of safety - it only means the name "
        "does not appear in the leak-site sources we track."
    ),
}


def _norm(text) -> str:
    """Fold a name for matching: lowercase, collapse punctuation and spacing."""
    return re.sub(r"[^a-z0-9]+", " ", str(text or "").lower()).strip()


def build_darkweb_index() -> dict | None:
    """Merge the leak-site corpora into one compact, searchable index."""
    if not CONFIG.enable_darkweb:
        return None

    entries: dict[tuple, dict] = {}

    # ransomware.live: multi-year, and carries country + sector.
    from datetime import datetime, timezone
    year = datetime.now(timezone.utc).year
    for y in (year, year - 1):
        data = _fetch_json(f"darkweb_victims_{y}.json", _RW_VICTIMS_YEAR.format(year=y))
        if not isinstance(data, list):
            continue
        for v in data:
            victim = str(v.get("victim") or "").strip()
            group = str(v.get("group") or "").strip()
            if not victim:
                continue
            key = (_norm(victim), _norm(group))
            entries.setdefault(key, {
                "v": victim[:120], "g": group[:60],
                "d": (v.get("attackdate") or v.get("discovered") or "")[:10],
                "c": (v.get("country") or "")[:2],
                "s": (v.get("activity") or "")[:60],
                "src": "ransomware.live",
            })

    # RansomLook: different site coverage, last ~30 days.
    posts = _fetch_json("darkweb_posts.json", _RANSOMLOOK_POSTS)
    if isinstance(posts, dict):
        posts = posts.get("posts", [])
    if isinstance(posts, list):
        for p in posts:
            victim = str(p.get("post_title") or "").strip()
            group = str(p.get("group_name") or "").strip()
            if not victim:
                continue
            key = (_norm(victim), _norm(group))
            entries.setdefault(key, {
                "v": victim[:120], "g": group[:60],
                "d": _iso(p.get("discovered"))[:10],
                "c": "", "s": "", "src": "ransomlook",
            })

    if not entries:
        return None

    rows = sorted(entries.values(), key=lambda r: r.get("d") or "", reverse=True)
    total = len(rows)
    cap = CONFIG.darkweb_index_max
    if cap and total > cap:
        rows = rows[:cap]
    # "src" is provenance for our own bookkeeping, not something the search UI
    # renders, so it does not need to be shipped to every visitor.
    for r in rows:
        r.pop("src", None)
    dates = [r["d"] for r in rows if r.get("d")]
    return {
        "generated": now_utc(),
        "count": len(rows),
        "total_available": total,
        "capped": total > len(rows),
        "from": min(dates) if dates else None,
        "to": max(dates) if dates else None,
        "coverage": COVERAGE,
        "victims": rows,
    }


def search_index(index: dict, term: str, limit: int = 50) -> list[dict]:
    """Substring match over folded victim names. Shared by the pipeline
    watchlist and mirrored by the browser, so both agree on what a hit is."""
    q = _norm(term)
    if not q or not index:
        return []
    out = []
    for row in index.get("victims", []):
        if q in _norm(row.get("v")):
            out.append(row)
            if len(out) >= limit:
                break
    return out


def check_watchlist(index: dict) -> list[dict]:
    """CASM-style standing monitoring: check configured names every run.

    This is the continuous half of the feature. Interactive search answers
    "is this name listed right now"; the watchlist answers "tell me when it
    becomes listed", which is what actually matters for monitoring.
    """
    terms = [t.strip() for t in (CONFIG.darkweb_watch or "").split(",") if t.strip()]
    if not terms or not index:
        return []
    hits = []
    for term in terms:
        matches = search_index(index, term, limit=25)
        if matches:
            hits.append({"term": term, "count": len(matches), "matches": matches[:10]})
            log.warning(f"  DARK WEB WATCHLIST HIT: '{term}' — {len(matches)} listing(s)")
    return hits


# ── Sector benchmarking ───────────────────────────────────────────────────────
# The index already carries a sector on every listing, so quarter-over-quarter
# movement per sector costs one pass and no new source. "Healthcare listings are
# up 40%" is the question a defender in healthcare actually asks.

def build_sector_benchmark(index: dict, window_days: int = 90) -> dict | None:
    """Compare the most recent window against the one before it, per sector."""
    if not index or not index.get("victims"):
        return None
    from datetime import datetime, timedelta, timezone

    today = datetime.now(timezone.utc).date()
    cur_from = today - timedelta(days=window_days)
    prev_from = today - timedelta(days=window_days * 2)

    current: Counter = Counter()
    previous: Counter = Counter()
    countries: Counter = Counter()

    for row in index["victims"]:
        d = row.get("d") or ""
        if len(d) != 10:
            continue
        try:
            day = datetime.strptime(d, "%Y-%m-%d").date()
        except ValueError:
            continue
        sector = (row.get("s") or "").strip() or "Unspecified"
        if day > cur_from:
            current[sector] += 1
            if row.get("c"):
                countries[row["c"]] += 1
        elif prev_from < day <= cur_from:
            previous[sector] += 1

    if not current:
        return None

    rows = []
    for sector, now_n in current.most_common(14):
        then = previous.get(sector, 0)
        if then:
            change = round(((now_n - then) / then) * 100)
        else:
            change = None                       # no baseline; do not invent one
        rows.append({
            "sector": sector, "current": now_n, "previous": then,
            "change_pct": change,
            "direction": ("up" if change is not None and change > 5 else
                          "down" if change is not None and change < -5 else
                          "flat" if change is not None else "new"),
        })

    return {
        "generated": now_utc(),
        "window_days": window_days,
        "current_total": sum(current.values()),
        "previous_total": sum(previous.values()),
        "sectors": rows,
        "top_countries": [{"cc": c, "count": n} for c, n in countries.most_common(10)],
        "note": (f"Leak-site listings in the last {window_days} days against the "
                 f"{window_days} before. Sectors with no prior listings show as "
                 f"new rather than a percentage."),
    }
