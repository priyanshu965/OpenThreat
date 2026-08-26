"""
CYBERWATCH — attacker_feeds.py
==============================
Ingest free attacker-infrastructure feeds and aggregate them, server-side, into
a small country/category summary for the live attacker map.

Design constraint (the whole reason this is a separate module):
    The Tier-1 feeds carry ~400,000 IP addresses combined. Those IPs MUST NOT
    reach the browser. They are counted here into ~200 countries × 5 categories
    and the client receives kilobytes, regardless of how many feeds we add.

Category assignment is by FEED PROVENANCE, not by guessing from an address. Each
feed exists to publish one observed behaviour, so the mapping below is
declarative and auditable — the same discipline as source-gated IOC extraction
elsewhere in the pipeline.

    Web Attackers  ← blocklist.de apache, bots
    Intruders      ← blocklist.de ssh; dataplane sshpwauth, telnetlogin, vncrfb
    Scanners       ← dataplane sshclient, sipquery, dnsversion, smtpgreet
    DDoS           ← dataplane dnsrd, dnsrdany, proto41   (amplification)
    Anonymizers    ← Tor bulk exit list

IPsum and CI Army are aggregate reputation lists, not a single behaviour, so
they contribute a cross-feed CONFIDENCE signal rather than a category.
"""

from __future__ import annotations

import ipaddress
import re
from collections import defaultdict

from config import CONFIG

# The pooled session and the disk cache live in fetchlib so every module shares
# one of each. This used to be a `from fetch_intel import ...` inside a
# try/except that ALWAYS fell through in production (fetch_intel imports this
# module before it defines those names, and running the pipeline as a script
# makes it `__main__` anyway) — so the fallback ran with `_cached_fetch = None`
# and this module re-downloaded everything on all 24 daily runs.
from fetchlib import SESSION as _SESSION, cached_fetch as _cached_fetch, log, now_utc  # noqa: F401,E402

# Attack categories, in display order. Kept as constants so the frontend and the
# aggregator agree on spelling.
WEB, INTRUDER, SCANNER, DDOS, ANON = (
    "web_attackers", "intruders", "scanners", "ddos_attackers", "anonymizers")
CATEGORIES = [WEB, INTRUDER, SCANNER, DDOS, ANON]

CATEGORY_LABELS = {
    WEB: "Web Attackers", INTRUDER: "Intruders", SCANNER: "Scanners",
    DDOS: "DDoS Attackers", ANON: "Anonymizers",
}

# Each entry: (feed id, url, category, ttl_hours override or None).
# id is what appears in the "sources" provenance block on the map.
_FEEDS: list[tuple[str, str, str]] = [
    # Web Attackers
    ("blocklist.de/apache", "https://lists.blocklist.de/lists/apache.txt", WEB),
    ("blocklist.de/bots",   "https://lists.blocklist.de/lists/bots.txt",   WEB),
    # Intruders (brute-force / login abuse)
    ("blocklist.de/ssh",       "https://lists.blocklist.de/lists/ssh.txt",  INTRUDER),
    ("dataplane/sshpwauth",    "https://dataplane.org/sshpwauth.txt",       INTRUDER),
    ("dataplane/telnetlogin",  "https://dataplane.org/telnetlogin.txt",     INTRUDER),
    ("dataplane/vncrfb",       "https://dataplane.org/vncrfb.txt",          INTRUDER),
    # Scanners (recon)
    ("dataplane/sshclient",    "https://dataplane.org/sshclient.txt",       SCANNER),
    ("dataplane/sipquery",     "https://dataplane.org/sipquery.txt",        SCANNER),
    ("dataplane/dnsversion",   "https://dataplane.org/dnsversion.txt",      SCANNER),
    ("dataplane/smtpgreet",    "https://dataplane.org/smtpgreet.txt",       SCANNER),
    # DDoS (amplification participants)
    ("dataplane/dnsrd",        "https://dataplane.org/dnsrd.txt",           DDOS),
    ("dataplane/dnsrdany",     "https://dataplane.org/dnsrdany.txt",        DDOS),
    ("dataplane/proto41",      "https://dataplane.org/proto41.txt",         DDOS),
    # Anonymizers
    ("tor/exit", "https://check.torproject.org/torbulkexitlist", ANON),
]

# Aggregate reputation lists → cross-feed confidence, not a category of their own.
_CONFIDENCE_FEEDS: list[tuple[str, str]] = [
    ("ipsum",   "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt"),
    ("ciarmy",  "http://cinsscore.com/list/ci-badguys.txt"),
]

# An IPv4 dotted quad, optionally leading each line. dataplane rows are
# pipe-delimited (asn | asn-name | ip | ...); blocklist.de and tor are bare IPs.
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _extract_ips(text: str, max_rows: int = 0) -> list[str]:
    """Pull valid public IPv4 addresses out of a feed body, whatever its shape."""
    ips: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        m = _IPV4_RE.search(line)
        if not m:
            continue
        ip = m.group(0)
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if addr.is_private or addr.is_loopback or addr.is_reserved or addr.is_multicast:
            continue
        ips.append(ip)
        if max_rows and len(ips) >= max_rows:
            break
    return ips


def _fetch_feed_text(feed_id: str, url: str) -> str | None:
    ttl = CONFIG.attacker_feed_ttl_hours
    cache_name = "attacker_" + re.sub(r"[^a-z0-9]+", "_", feed_id.lower()) + ".txt"

    def _raw() -> tuple[str | None, str | None]:
        try:
            resp = _SESSION.get(url, timeout=CONFIG.request_timeout)
            resp.raise_for_status()
            return resp.text, None
        except Exception as e:
            return None, str(e)

    if _cached_fetch is not None:
        return _cached_fetch(cache_name, ttl, _raw)
    text, _ = _raw()
    return text


def collect_attacker_infrastructure(geo) -> dict | None:
    """Fetch every feed, geolocate each IP, and aggregate into the map summary.

    ``geo`` is a GeoIP instance (or None). Returns the summary dict, or None if
    the map is disabled or nothing could be fetched. Never raises — a broken
    feed is recorded and skipped, mirroring run_source().
    """
    if not CONFIG.enable_attacker_map:
        log.info("Attacker map disabled (ENABLE_ATTACKER_MAP=0)")
        return None

    max_rows = CONFIG.attacker_feed_max_rows

    # ip -> set of categories it was seen in; ip -> confidence hits
    ip_categories: dict[str, set[str]] = defaultdict(set)
    confidence: dict[str, int] = defaultdict(int)
    provenance: list[dict] = []

    for feed_id, url, category in _FEEDS:
        text = _fetch_feed_text(feed_id, url)
        if not text:
            provenance.append({"feed": feed_id, "category": category,
                               "rows": 0, "status": "error"})
            log.warning(f"  attacker feed {feed_id}: no data")
            continue
        ips = _extract_ips(text, max_rows)
        for ip in ips:
            ip_categories[ip].add(category)
        provenance.append({"feed": feed_id, "category": category,
                           "rows": len(ips), "status": "ok", "fetched": now_utc()})
        log.info(f"  attacker feed {feed_id}: {len(ips)} IPs → {category}")

    for feed_id, url in _CONFIDENCE_FEEDS:
        text = _fetch_feed_text(feed_id, url)
        if not text:
            provenance.append({"feed": feed_id, "category": "confidence",
                               "rows": 0, "status": "error"})
            continue
        ips = _extract_ips(text, max_rows)
        for ip in ips:
            confidence[ip] += 1
        provenance.append({"feed": feed_id, "category": "confidence",
                           "rows": len(ips), "status": "ok", "fetched": now_utc()})
        log.info(f"  confidence feed {feed_id}: {len(ips)} IPs")

    if not ip_categories:
        log.warning("Attacker map: no IPs collected from any feed")
        return None

    return _aggregate(ip_categories, confidence, provenance, geo)


def _aggregate(ip_categories: dict[str, set[str]], confidence: dict[str, int],
               provenance: list[dict], geo) -> dict:
    """Collapse per-IP data into per-country, per-category counts. This is the
    step that keeps the IPs off the wire — nothing below carries an address."""
    # country -> category -> count of distinct IPs
    by_country: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    totals: dict[str, int] = defaultdict(int)
    unknown_geo = 0
    high_confidence = 0

    for ip, cats in ip_categories.items():
        cc = geo.country(ip) if geo is not None else None
        if cc is None:
            unknown_geo += 1
        if confidence.get(ip, 0) >= 2:
            high_confidence += 1
        for cat in cats:
            totals[cat] += 1
            if cc is not None:
                by_country[cc][cat] += 1

    # Build the ranked country list.
    countries = []
    for cc, cats in by_country.items():
        total = sum(cats.values())
        countries.append({
            "cc": cc,
            "name": geo.country_name(cc) if geo is not None else cc,
            "by_category": {c: cats.get(c, 0) for c in CATEGORIES if cats.get(c)},
            "total": total,
        })
    countries.sort(key=lambda c: -c["total"])
    for rank, c in enumerate(countries, 1):
        c["rank"] = rank

    return {
        "generated": now_utc(),
        "distinct_ips": len(ip_categories),
        "geolocated": len(ip_categories) - unknown_geo,
        "high_confidence_ips": high_confidence,
        "totals": {c: totals.get(c, 0) for c in CATEGORIES},
        "category_labels": CATEGORY_LABELS,
        "countries": countries,
        "sources": provenance,
        "attribution": "IP Geolocation by DB-IP (https://db-ip.com)",
    }


if __name__ == "__main__":
    from geoip import GeoIP
    geo = GeoIP.load()
    summary = collect_attacker_infrastructure(geo)
    if not summary:
        print("no summary produced")
    else:
        import json
        print(f"distinct IPs      : {summary['distinct_ips']:,}")
        print(f"geolocated        : {summary['geolocated']:,}")
        print(f"totals            : {summary['totals']}")
        print("top 10 countries  :")
        for c in summary["countries"][:10]:
            print(f"  {c['rank']:>2}. {c['cc']} {c['name']:<18} {c['total']:>7,}  {c['by_category']}")
        payload = json.dumps(summary, ensure_ascii=False)
        print(f"\npayload size      : {len(payload) / 1024:.1f} KB")
