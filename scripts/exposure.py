"""
CYBERWATCH — exposure.py
========================
Credential and infostealer exposure for a domain you own, plus the public
breach catalogue. This is the half of CASM that leak-site monitoring cannot
reach: an organisation can have thousands of stolen credentials circulating
without ever appearing on a ransomware leak site.

Sources (both free, no key):

  Hudson Rock Cavalier OSINT tools
      https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain
      Counts of employee / user / third-party machines found in infostealer
      logs. Published by Hudson Rock specifically so defenders can check their
      own exposure. It returns COUNTS AND STATISTICS, not credentials - we
      neither receive nor store passwords.

  Have I Been Pwned breach catalogue
      https://haveibeenpwned.com/api/v3/breaches
      The public list of known breaches. Keyless. Per-account and per-domain
      lookups need a paid key, so this is the catalogue only: which breaches
      exist, when, how large, and what classes of data they exposed.

WHAT THIS IS NOT. Checking a domain here tells you about infostealer infections
and public breaches. It does not read criminal forums, marketplaces or Telegram
channels - see darkweb.COVERAGE for why those are out of reach and out of
scope.
"""

from __future__ import annotations

import json
import re

from config import CONFIG

try:
    from fetch_intel import _SESSION, _cached_fetch, log, now_utc
except Exception:  # pragma: no cover - standalone/tests
    import logging
    from datetime import datetime, timezone
    import requests
    log = logging.getLogger("cyberwatch.exposure")
    _SESSION = requests.Session()
    _cached_fetch = None

    def now_utc() -> str:
        return datetime.now(timezone.utc).isoformat()


_HUDSONROCK_DOMAIN = ("https://cavalier.hudsonrock.com/api/json/v2/"
                      "osint-tools/search-by-domain?domain={domain}")
_HIBP_BREACHES = "https://haveibeenpwned.com/api/v3/breaches"

# A domain we are willing to look up. Anything else is refused rather than
# pasted into a URL.
_DOMAIN_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$")


def valid_domain(value) -> str | None:
    d = str(value or "").strip().lower().rstrip(".")
    if d.startswith("http://") or d.startswith("https://"):
        d = d.split("//", 1)[1]
    d = d.split("/")[0].split("@")[-1]
    return d if d and len(d) <= 253 and _DOMAIN_RE.match(d) else None


def _fetch_json(name: str, url: str, ttl: int):
    def _raw():
        try:
            resp = _SESSION.get(url, timeout=max(CONFIG.request_timeout, 45))
            resp.raise_for_status()
            return resp.text, None
        except Exception as e:
            return None, str(e)

    text = _cached_fetch(name, ttl, _raw) if _cached_fetch else _raw()[0]
    if not text:
        return None
    try:
        return json.loads(text)
    except Exception as e:
        log.warning(f"  exposure: {name} did not parse: {e}")
        return None


def check_domain_exposure(domain: str) -> dict | None:
    """Infostealer exposure for one domain. Counts only, never credentials."""
    d = valid_domain(domain)
    if not d:
        log.warning(f"  exposure: refusing malformed domain {domain!r}")
        return None

    safe_name = "exposure_" + re.sub(r"[^a-z0-9]+", "_", d) + ".json"
    data = _fetch_json(safe_name, _HUDSONROCK_DOMAIN.format(domain=d),
                       CONFIG.exposure_ttl_hours)
    if not isinstance(data, dict):
        return None

    def _int(v):
        try:
            return int(v)
        except (TypeError, ValueError):
            return 0

    employees = _int(data.get("employees"))
    users = _int(data.get("users"))
    third = _int(data.get("third_parties"))
    total = _int(data.get("total")) or (employees + users + third)

    # Deliberately narrow: we take counts and dates, never the record bodies.
    return {
        "domain": d,
        "employees": employees,
        "users": users,
        "third_parties": third,
        "total": total,
        "total_urls": _int(data.get("totalUrls")),
        "last_employee_compromised": str(data.get("last_employee_compromised") or "")[:10] or None,
        "last_user_compromised": str(data.get("last_user_compromised") or "")[:10] or None,
        "source": "Hudson Rock Cavalier (free OSINT tools)",
        "note": ("Counts of machines found in infostealer logs. Credentials "
                 "themselves are neither requested nor stored by CyberWatch."),
    }


def build_exposure(domains: list[str]) -> dict | None:
    """Check every configured domain. Returns None when none are configured."""
    if not CONFIG.enable_exposure:
        return None
    checked = []
    for raw in domains:
        result = check_domain_exposure(raw)
        if result:
            checked.append(result)
            if result["employees"]:
                log.warning(f"  EXPOSURE: {result['domain']} — "
                            f"{result['employees']} employee machine(s) in stealer logs")
    if not checked:
        return None
    return {
        "generated": now_utc(),
        "domains": checked,
        "totals": {
            "employees": sum(c["employees"] for c in checked),
            "users": sum(c["users"] for c in checked),
            "third_parties": sum(c["third_parties"] for c in checked),
        },
    }


def build_breach_catalogue(limit: int = 40) -> dict | None:
    """Recent entries from the public HIBP breach catalogue."""
    if not CONFIG.enable_exposure:
        return None
    data = _fetch_json("hibp_breaches.json", _HIBP_BREACHES, CONFIG.exposure_ttl_hours)
    if not isinstance(data, list):
        return None

    rows = []
    for b in data:
        if not isinstance(b, dict):
            continue
        rows.append({
            "name": str(b.get("Title") or b.get("Name") or "")[:80],
            "domain": str(b.get("Domain") or "")[:80],
            "date": str(b.get("BreachDate") or "")[:10],
            "added": str(b.get("AddedDate") or "")[:10],
            "accounts": int(b.get("PwnCount") or 0),
            "classes": [str(c)[:40] for c in (b.get("DataClasses") or [])][:8],
            "verified": bool(b.get("IsVerified")),
        })
    rows.sort(key=lambda r: r.get("added") or "", reverse=True)
    recent = rows[:limit]
    return {
        "generated": now_utc(),
        "total_breaches": len(rows),
        "total_accounts": sum(r["accounts"] for r in rows),
        "recent": recent,
        "source": "Have I Been Pwned breach catalogue",
    }
