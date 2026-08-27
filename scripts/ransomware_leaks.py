"""
CYBERWATCH — ransomware_leaks.py
=================================
Ransomware leak-site activity: the highest-signal "dark web" data that exists
in public form.

WHY AGGREGATORS AND NOT TOR
---------------------------
The obvious implementation is to run a Tor daemon in CI and scrape the onion
sites directly. That is the wrong call three times over:

  * Reliability. Leak sites are deliberately flaky, move constantly, and half
    of them sit behind a captcha. A scraper in an hourly job would spend most
    of its life timing out.
  * Terms. Routing GitHub Actions traffic through Tor to scrape criminal
    infrastructure is not a fight worth having with a CI provider.
  * Duplication. ransomware.live and ransomwatch already run that
    infrastructure, with better uptime than this project could manage, and
    publish the results as plain JSON.

So this reads the aggregators. It is not a compromise — it is the same data,
more reliably, without operating scraping infrastructure against criminal
hosts.

THE TWO SOURCES ARE COMPLEMENTARY
---------------------------------
    ransomwatch      the long history. ~16,000 posts, three fields each.
    ransomware.live  the current window, month by month, with sector and
                     country attached.

Using both gives multi-year group trends AND sector/geography on the current
window. Either alone gives half of it.

FRESHNESS IS MEASURED, NOT ASSUMED
----------------------------------
The first cut of this module read ransomwatch for history and ONE
`recentvictims` call (100 rows) for the present. The published view then showed
99 claims in a 120-day window over a corpus of 4,000 — which looked like a slow
quarter for ransomware and was actually an artefact: ransomwatch's newest post
was ten months old, so almost the entire history was stale and the current
window was whatever fitted in those 100 rows.

Two changes came out of that. The current window is now assembled from
`/v2/victims/{year}/{month}` across `leak_history_months`, which is complete
rather than truncated. And every source reports the age of its newest record in
the payload, so a feed that quietly stops updating shows up as a number on the
page instead of as a wrong conclusion about ransomware activity.

WHAT IS DELIBERATELY NOT PUBLISHED
----------------------------------
The victim `description` field is the crew's own extortion copy — "we will
upload 185gb, including SSNs for 130 employees". It is dropped.

The analytical value of a leak-site post is entirely in its structured fields:
who claimed it, when, what sector, which country. The prose adds nothing to
that and republishing it means a public dashboard restating criminal claims
about a named, frequently small, victim organisation. The victim names
themselves are kept because the aggregate is the point (and they are already
public on the aggregators), but this tool is not going to be another
amplification channel for the extortion note.

Where any attacker-authored string does survive (a group's self-chosen name,
say), it is DATA. It is rendered as text, never interpreted, and never used to
build a URL.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

from fetchlib import CONFIG, cached_derive, cached_json, log, now_utc

_RW_MONTH = "https://api.ransomware.live/v2/victims/{year}/{month}"
_RW_GROUPS = "https://api.ransomware.live/v2/groups"
_WATCH_POSTS = ("https://raw.githubusercontent.com/joshhighet/ransomwatch/"
                "main/posts.json")

_CACHE = "leak_sites.json"

_DATE = re.compile(r"^(\d{4}-\d{2}-\d{2})")
_NON_ALNUM = re.compile(r"[^a-z0-9]+")


def _day(value) -> str:
    m = _DATE.match(str(value or "").strip())
    return m.group(1) if m else ""


def _recent_months(count: int) -> list[tuple[int, int]]:
    """The last `count` (year, month) pairs, newest first."""
    now = datetime.now(timezone.utc)
    year, month = now.year, now.month
    out = []
    for _ in range(max(1, count)):
        out.append((year, month))
        month -= 1
        if month == 0:
            year, month = year - 1, 12
    return out


def _age_days(newest: str) -> int | None:
    """How old the freshest record in a source is. None when unparseable."""
    if not newest:
        return None
    try:
        when = datetime.strptime(newest, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except ValueError:
        return None
    return max(0, (datetime.now(timezone.utc) - when).days)


def _clean(value, limit: int) -> str:
    return " ".join(str(value or "").split())[:limit]


def _norm_group(name) -> str:
    """
    Group names arrive in several spellings across the two feeds.

    Everything that is not a letter or a digit is removed, rather than a
    hand-written list of separators. The first version stripped spaces, hyphens
    and underscores only, which left "LockBit 3.0" and "lockbit30" as two
    different groups -- the precise failure this function exists to prevent.
    """
    return _NON_ALNUM.sub("", _clean(name, 60).lower())


def _derive() -> dict | None:
    log.info("  Building ransomware leak-site view...")

    posts = cached_json("ransomwatch_posts.json", _WATCH_POSTS,
                        CONFIG.leak_sites_ttl_hours * 4) or []

    # The current window, month by month. One call per month is complete for
    # that month, where a single "recent" call is a truncated tail.
    recent: list = []
    months_ok = 0
    for year, month in _recent_months(CONFIG.leak_history_months):
        url = _RW_MONTH.format(year=year, month=month)
        rows = cached_json(f"ransomware_live_{year}_{month:02d}.json", url,
                           # Closed months never change again, so they are
                           # cached for a month rather than re-fetched 4x a day.
                           CONFIG.leak_sites_ttl_hours if month == datetime.now(
                               timezone.utc).month else 24 * 30)
        if isinstance(rows, list) and rows:
            recent.extend(rows)
            months_ok += 1

    groups_raw = cached_json("ransomware_live_groups.json", _RW_GROUPS,
                             CONFIG.leak_sites_ttl_hours * 4) or []

    if not posts and not recent:
        return None

    # ── Group profiles ────────────────────────────────────────────────────
    profiles: dict[str, dict] = {}
    for row in groups_raw if isinstance(groups_raw, list) else []:
        if not isinstance(row, dict):
            continue
        name = _clean(row.get("name"), 60)
        if not name:
            continue
        profiles[_norm_group(name)] = {
            "name": name,
            "altname": _clean(row.get("altname"), 60),
            "description": _clean(row.get("description"), 900),
            "first_seen": _day(row.get("added_date")),
            # The aggregator's own TTP/tool notes. Coarse, but it is the only
            # actor->technique signal that exists for crews too new for ATT&CK.
            "ttps": [_clean(t, 120) for t in (row.get("ttps") or [])][:12],
            "tools": [_clean(t, 60) for t in (row.get("tools") or [])][:16],
            "sites": len(row.get("locations") or []),
        }

    # ── Victims ───────────────────────────────────────────────────────────
    victims: dict[tuple, dict] = {}

    for row in posts if isinstance(posts, list) else []:
        if not isinstance(row, dict):
            continue
        victim = _clean(row.get("post_title"), 160)
        group = _clean(row.get("group_name"), 60)
        day = _day(row.get("discovered"))
        if not victim or not group or not day:
            continue
        victims[(_norm_group(group), victim.lower())] = {
            "victim": victim, "group": group, "date": day,
            "sector": "", "country": "", "source": "ransomwatch",
        }

    # ransomware.live rows carry sector and country, so they OVERWRITE the
    # ransomwatch row for the same claim rather than being deduplicated away.
    for row in recent if isinstance(recent, list) else []:
        if not isinstance(row, dict):
            continue
        victim = _clean(row.get("victim") or row.get("post_title"), 160)
        group = _clean(row.get("group"), 60)
        day = _day(row.get("discovered")) or _day(row.get("attackdate"))
        if not victim or not group or not day:
            continue
        victims[(_norm_group(group), victim.lower())] = {
            "victim": victim,
            "group": group,
            "date": day,
            "sector": _clean(row.get("activity"), 80),
            "country": _clean(row.get("country"), 8).upper(),
            "source": "ransomware.live",
            # NOTE: row["description"] is the extortion note and is not read.
        }

    if not victims:
        return None

    # Freshness per source, BEFORE anything is aggregated. A source that has
    # stopped updating still contributes history; what must not happen is the
    # page implying its silence is a quiet quarter.
    freshness = {}
    for label in ("ransomwatch", "ransomware.live"):
        dates = [r["date"] for r in victims.values() if r["source"] == label]
        newest = max(dates) if dates else ""
        freshness[label] = {"records": len(dates), "newest": newest,
                            "age_days": _age_days(newest)}
        age = freshness[label]["age_days"]
        if age is not None and age > 45:
            log.warning(f"  Leak source {label} looks stale: newest record is "
                        f"{age} days old ({newest})")

    rows = sorted(victims.values(), key=lambda r: r["date"], reverse=True)
    rows = rows[:CONFIG.leak_victims_max]

    cutoff = (datetime.now(timezone.utc)
              - timedelta(days=CONFIG.leak_recent_days)).strftime("%Y-%m-%d")
    window = [r for r in rows if r["date"] >= cutoff]

    by_group = Counter(r["group"] for r in window)
    by_sector = Counter(r["sector"] for r in window if r["sector"])
    by_country = Counter(r["country"] for r in window if r["country"])
    by_month: dict[str, int] = defaultdict(int)
    for r in rows:
        by_month[r["date"][:7]] += 1

    # Per-group activity, with the group's own profile attached where we have
    # one. This is the leaderboard the dark-web view is actually for.
    group_rows = []
    for group, count in by_group.most_common(60):
        profile = profiles.get(_norm_group(group), {})
        dates = [r["date"] for r in window if r["group"] == group]
        sectors = Counter(r["sector"] for r in window
                          if r["group"] == group and r["sector"])
        group_rows.append({
            "group": group,
            "victims": count,
            "first_in_window": min(dates) if dates else "",
            "last_in_window": max(dates) if dates else "",
            "top_sectors": [s for s, _ in sectors.most_common(4)],
            "description": profile.get("description", ""),
            "first_seen": profile.get("first_seen", ""),
            "ttps": profile.get("ttps", []),
            "tools": profile.get("tools", []),
            "sites": profile.get("sites", 0),
        })

    months = sorted(by_month)
    log.info(f"  Leak sites: {len(rows)} claims, {len(window)} in the last "
             f"{CONFIG.leak_recent_days}d, {len(by_group)} active groups "
             f"({months_ok}/{CONFIG.leak_history_months} months fetched)")

    return {
        "built": now_utc(),
        "sources": [_WATCH_POSTS, _RW_MONTH, _RW_GROUPS],
        "freshness": freshness,
        "months_fetched": months_ok,
        "window_days": CONFIG.leak_recent_days,
        "total_claims": len(rows),
        "window_claims": len(window),
        "active_groups": len(by_group),
        "groups": group_rows,
        "by_sector": [{"name": k, "count": v} for k, v in by_sector.most_common(20)],
        "by_country": [{"name": k, "count": v} for k, v in by_country.most_common(25)],
        "by_month": [{"month": m, "count": by_month[m]} for m in months[-36:]],
        "recent": window[:400],
        "group_profiles": len(profiles),
    }


def load_leak_sites(force: bool = False) -> dict | None:
    if not CONFIG.enable_leak_sites:
        return None
    ttl = 0 if force else CONFIG.leak_sites_ttl_hours
    return cached_derive(_CACHE, ttl, _derive)


def leak_activity_for(name: str, view: dict | None) -> dict | None:
    """
    A group's leak-site activity, for its entity page.

    Matched on the normalised name so "LockBit3", "lockbit3" and "LockBit 3.0"
    resolve together — the two feeds disagree on spelling constantly, and the
    v4 graph already learned what unnormalised name matching costs.
    """
    if not view or not name:
        return None
    target = _norm_group(name)
    for row in view.get("groups") or []:
        if _norm_group(row.get("group")) == target:
            return row
    return None
