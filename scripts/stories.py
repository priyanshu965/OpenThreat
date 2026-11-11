"""
OPENTHREAT — stories.py
=======================
One incident, reported by fifteen outlets, is one story.

deduplicate() removes copies: the same URL, the same CVE from the same source,
a title that normalises to the same words. It cannot see that "Hackers exploit
critical PHP flaw" and "PHP2Shell attacks hit unpatched servers" are the same
event, and with a hundred-odd sources the feed fills up with exactly that. On
one run a single pair of CVEs accounted for 35 separate cards.

This groups items into stories and marks one lead per story. Nothing is
removed: every member keeps its own card data, and the dashboard folds the
rest behind the lead. How many independent sources carried a story is
published too, because that count is the cheapest importance signal there is.

Two items join the same story when either holds:

  shared CVE     both name the same CVE id. Items naming more than
                 MAX_CVES_FOR_LINK are skipped - a Patch Tuesday roundup lists
                 sixty and would weld every one of those stories together.
  similar title  from DIFFERENT sources, published within WINDOW_DAYS of each
                 other, sharing at least MIN_SHARED significant words and a
                 Jaccard overlap of MIN_JACCARD. Same-source pairs are never
                 title-matched: a vendor's own advisories are templated
                 ("Multiple vulnerabilities in X") and are different stories.

Only human-written items are title-matched. Indicator feeds and leak-site
posts are rows, not stories.
"""

from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone

from dedup import _canonical_url, _source_rank, item_key

MAX_CVES_FOR_LINK = 3
WINDOW_DAYS = 5
MIN_SHARED = 3
MIN_JACCARD = 0.5

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)
_WORD_RE = re.compile(r"[a-z0-9][a-z0-9.+#-]*[a-z0-9+#]|[a-z0-9]")

# Words that say nothing about WHICH story this is. Security headlines are
# built almost entirely out of these, so leaving them in makes any two
# vulnerability headlines look alike.
_FILLER = frozenset("""
a an and are as at be been by for from has have how in into is it its of on or
that the their this to was were what when which who why will with you your
after again against all also amid among any before can could may more most new
now over says said than up via vs

attack attacks attacker attackers hack hacked hacker hackers hacking breach
breached breaches bug bugs critical cyber cyberattack cybersecurity exploit
exploited exploiting exploitation exploits flaw flaws high issue issues
malicious multiple patch patched patches released releases report reports
researchers security severity threat threats update updated updates users
vulnerabilities vulnerability warn warns warning advisory alert fix fixed fixes
actively active wild day zero 0-day zero-day rce remote code execution
""".split())

_BAND = {"urgent": 3, "elevated": 2, "moderate": 1, "low": 0}

# Provenance classes that are prose about an event rather than a data row.
_STORY_PROVENANCE = {"vendor-research", "independent-researcher", "journalism",
                     "government", "vendor-advisory"}


def title_tokens(title: str) -> frozenset[str]:
    words = _WORD_RE.findall((title or "").lower())
    return frozenset(w for w in words if w not in _FILLER and (len(w) > 2 or w.isdigit()))


def item_cves(item: dict) -> set[str]:
    text = f"{item.get('cve_id') or ''} {item.get('title') or ''} {item.get('description') or ''}"
    return {c.upper() for c in _CVE_RE.findall(text)}


def _when(item: dict) -> datetime | None:
    try:
        stamp = datetime.fromisoformat(str(item.get("published") or "").replace("Z", "+00:00"))
    except ValueError:
        return None
    return stamp if stamp.tzinfo else stamp.replace(tzinfo=timezone.utc)


def _lead_rank(item: dict) -> tuple:
    """Which member speaks for the story: the one with a verdict, then the most
    authoritative source, then the newest."""
    return (_BAND.get(item.get("priority_label") or "", -1),
            float(item.get("priority_score") or 0.0),
            _source_rank(item.get("source", "")),
            str(item.get("published") or ""))


def cluster_stories(items: list[dict]) -> dict:
    """Tag items in place with story_id / story_size / story_sources and mark
    one `story_lead` per story. Returns a small summary for the feed metadata.

    Items that belong to no multi-item story are left untouched.
    """
    for item in items:
        for field in ("story_id", "story_size", "story_sources", "story_lead"):
            item.pop(field, None)

    parent = list(range(len(items)))

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    def union(a: int, b: int) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[max(ra, rb)] = min(ra, rb)

    # ── Shared CVE ──────────────────────────────────────────────────────────
    by_cve: dict[str, int] = {}
    for idx, item in enumerate(items):
        cves = item_cves(item)
        if not cves or len(cves) > MAX_CVES_FOR_LINK:
            continue
        for cve in cves:
            if cve in by_cve:
                union(by_cve[cve], idx)
            else:
                by_cve[cve] = idx

    # ── Similar title ───────────────────────────────────────────────────────
    prose = []
    for idx, item in enumerate(items):
        if item.get("provenance") not in _STORY_PROVENANCE:
            continue
        tokens = title_tokens(item.get("title", ""))
        if len(tokens) >= MIN_SHARED:
            prose.append((idx, tokens, item.get("source", ""), _when(item)))

    window = WINDOW_DAYS * 86400
    for a in range(len(prose)):
        ia, ta, sa, wa = prose[a]
        for b in range(a + 1, len(prose)):
            ib, tb, sb, wb = prose[b]
            if sa == sb:
                continue
            shared = len(ta & tb)
            if shared < MIN_SHARED or shared / len(ta | tb) < MIN_JACCARD:
                continue
            if wa and wb and abs((wa - wb).total_seconds()) > window:
                continue
            union(ia, ib)

    groups: dict[int, list[int]] = {}
    for idx in range(len(items)):
        groups.setdefault(find(idx), []).append(idx)

    stories = 0
    folded = 0
    largest = 0
    for members in groups.values():
        if len(members) < 2:
            continue
        group = [items[i] for i in members]
        lead = max(group, key=_lead_rank)
        # Derived from the lead's identity, so the id survives a re-run as long
        # as the same item still leads.
        story_id = hashlib.sha1(item_key(lead).encode(), usedforsecurity=False).hexdigest()[:12]
        sources = len({(m.get("source") or _canonical_url(m.get("url", ""))) for m in group})
        for member in group:
            member["story_id"] = story_id
            member["story_size"] = len(group)
            member["story_sources"] = sources
        lead["story_lead"] = True
        stories += 1
        folded += len(group) - 1
        largest = max(largest, len(group))

    return {"stories": stories, "items_folded": folded, "largest": largest}
