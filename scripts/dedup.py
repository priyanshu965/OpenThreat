"""
OPENTHREAT — dedup.py
===================
Deduplication: one item per story, keeping the most authoritative copy.

Moved out of fetch_intel.py unchanged; fetch_intel re-exports every name here,
so `fetch_intel._STOPWORDS` and the like keep working.
"""

import re




_STOPWORDS = {
    "the", "a", "an", "of", "to", "in", "on", "for", "and", "with", "via",
    "new", "critical", "high", "cve", "vulnerability", "flaw", "bug", "attack",
}

def _normalize_title(title: str) -> str:
    """
    Collapse a title to a comparable fingerprint: lowercase, drop punctuation,
    strip common filler words, sort the remaining tokens. This makes near-dupes
    like "New Critical RCE in Foo" and "Foo RCE Vulnerability (Critical)" hash
    to the same key while keeping genuinely different stories apart.
    """
    t = re.sub(r"[^a-z0-9 ]+", " ", (title or "").lower())
    tokens = [w for w in t.split() if w and w not in _STOPWORDS]
    if not tokens:
        tokens = t.split()
    return " ".join(sorted(set(tokens)))[:120]

def _canonical_url(url: str) -> str:
    """Strip scheme, www, tracking params and trailing slash for URL dedup."""
    if not url:
        return ""
    u = url.strip().lower()
    u = re.sub(r"^https?://", "", u)
    u = re.sub(r"^www\.", "", u)
    u = u.split("?")[0].split("#")[0].rstrip("/")
    return u

# Higher rank wins a dedup collision. Primary vendor/government advisories
# beat aggregators, which beat news rewrites of the same story.
_SOURCE_AUTHORITY = {
    "NVD": 100, "CISA": 95, "MSRC": 90, "GitHub Advisories": 85, "ZDI": 85,
    "VMware": 80, "Fedora": 75, "Arch Linux": 75,
    "Fortinet PSIRT": 80, "Siemens ProductCERT": 80, "Synology": 80, "Splunk": 80,
    "Chrome Releases": 80, "CERT/CC": 85, "UK NCSC": 75, "HKCERT": 70, "CERT-In": 75,
    "Amazon Linux": 75, "CentOS": 70, "Mitre CWE": 70,
    "PoC-in-GitHub": 65, "Ransomware.live": 60, "AlienVault OTX": 60,
    "ThreatFox": 60, "URLhaus": 60, "Feodo Tracker": 60, "Spamhaus": 60,
}


def _source_rank(source: str) -> int:
    return _SOURCE_AUTHORITY.get(source, 10)


def sort_for_dedup(items: list[dict]) -> list[dict]:
    """Order items so that ``deduplicate()``'s "first occurrence wins" rule
    keeps the RIGHT copy: most authoritative source first, then newest.

    Sorts in place and returns the list. The key is deliberately un-negated —
    ``reverse=True`` already gives descending order, and negating the rank on
    top of that silently inverted the whole thing, so the least authoritative
    copy of a story survived dedup and the NVD/CISA record was discarded.
    """
    items.sort(key=lambda x: (_source_rank(x.get("source", "")),
                              x.get("published", "")), reverse=True)
    return items


def deduplicate(items: list[dict]) -> list[dict]:
    """
    Drop duplicates by (a) same CVE from the same source, (b) identical
    canonical URL, or (c) fuzzy-normalized title. First occurrence wins, so the
    published-desc sort upstream keeps the newest copy.
    """
    seen_titles, seen_urls, seen_cve_src = set(), set(), set()
    unique = []
    for item in items:
        title_key = _normalize_title(item.get("title", ""))
        url_key   = _canonical_url(item.get("url", ""))
        cve       = (item.get("cve_id") or "").upper()
        src       = item.get("source", "")
        cve_src_key = f"{cve}|{src}" if cve else None

        if title_key and title_key in seen_titles:
            continue
        if url_key and url_key in seen_urls:
            continue
        if cve_src_key and cve_src_key in seen_cve_src:
            continue

        if title_key:
            seen_titles.add(title_key)
        if url_key:
            seen_urls.add(url_key)
        if cve_src_key:
            seen_cve_src.add(cve_src_key)
        unique.append(item)
    return unique


def item_key(item: dict) -> str:
    """Stable identity for an item across runs — prefers CVE, then URL, then title."""
    cve = (item.get("cve_id") or "").upper()
    if cve:
        return f"cve:{cve}"
    url = _canonical_url(item.get("url", ""))
    if url:
        return f"url:{url}"
    return f"title:{_normalize_title(item.get('title', ''))}"
