"""
CYBERWATCH — attack_surface.py
==============================
External attack surface discovery from Certificate Transparency.

Every publicly-trusted TLS certificate is logged to CT, so querying crt.sh for
a domain enumerates subdomains that certificates were issued for - including
the ones nobody told the security team about. That is the shadow-IT half of
EASM, and it needs no key and no scanning: we read a public log, we do not
touch the hosts.

NOTHING HERE PROBES ANYTHING. No port scan, no HTTP request to a discovered
host, no DNS brute force. CyberWatch reads the CT log and stops. Anyone wanting
liveness or service detail should take the list to a tool they are authorised
to point at that estate.

crt.sh is free but genuinely flaky (frequent 502s and timeouts under load), so
every call retries and degrades to the cached copy rather than failing the run.
"""

from __future__ import annotations

import json
import re
from collections import Counter

from config import CONFIG

try:
    from fetch_intel import _SESSION, _cached_fetch, log, now_utc
except Exception:  # pragma: no cover - standalone/tests
    import logging
    from datetime import datetime, timezone
    import requests
    log = logging.getLogger("cyberwatch.attack_surface")
    _SESSION = requests.Session()
    _cached_fetch = None

    def now_utc() -> str:
        return datetime.now(timezone.utc).isoformat()

_CRTSH = "https://crt.sh/?q=%25.{domain}&output=json"

_HOST_RE = re.compile(r"^(?!-)[a-z0-9*_-]{1,63}(?<!-)(\.(?!-)[a-z0-9_-]{1,63}(?<!-))+$")

# Hostname prefixes that usually mean "not production", which is exactly what
# shadow-IT review wants surfaced first.
_INTERESTING = (
    "dev", "test", "staging", "stage", "uat", "qa", "sandbox", "demo",
    "internal", "intranet", "vpn", "admin", "portal", "jenkins", "git",
    "jira", "confluence", "grafana", "kibana", "backup", "old", "legacy",
    "beta", "preprod", "mail", "remote", "citrix", "rdp", "ftp",
)


def _valid_host(h: str) -> bool:
    return bool(h) and len(h) <= 253 and bool(_HOST_RE.match(h))


def discover_subdomains(domain: str) -> dict | None:
    """Enumerate hostnames seen in Certificate Transparency for one domain."""
    from exposure import valid_domain          # shared, strict domain check
    d = valid_domain(domain)
    if not d:
        log.warning(f"  attack surface: refusing malformed domain {domain!r}")
        return None

    name = "ct_" + re.sub(r"[^a-z0-9]+", "_", d) + ".json"

    def _raw():
        last = None
        for _ in range(3):                      # crt.sh 502s often; retry
            try:
                resp = _SESSION.get(_CRTSH.format(domain=d),
                                    timeout=max(CONFIG.request_timeout, 60))
                resp.raise_for_status()
                if resp.text.strip().startswith(("[", "{")):
                    return resp.text, None
                last = "non-JSON response (crt.sh returned an error page)"
            except Exception as e:
                last = str(e)
        return None, last or "crt.sh unavailable"

    text = _cached_fetch(name, CONFIG.attack_surface_ttl_hours, _raw) if _cached_fetch else _raw()[0]
    if not text:
        return None
    try:
        records = json.loads(text)
    except Exception:
        return None
    if not isinstance(records, list):
        return None

    hosts: set[str] = set()
    issuers: Counter = Counter()
    for rec in records:
        if not isinstance(rec, dict):
            continue
        issuer = str(rec.get("issuer_name") or "")
        m = re.search(r"O=([^,]+)", issuer)
        if m:
            issuers[m.group(1).strip().strip('"')[:40]] += 1
        for raw in str(rec.get("name_value") or "").split("\n"):
            h = raw.strip().lower().lstrip("*.")
            if _valid_host(h) and (h == d or h.endswith("." + d)):
                hosts.add(h)

    ordered = sorted(hosts)
    flagged = [h for h in ordered
               if any(h.split(".")[0].startswith(p) for p in _INTERESTING)]

    return {
        "domain": d,
        "hostnames": len(ordered),
        "sample": ordered[:CONFIG.attack_surface_max_hosts],
        "truncated": len(ordered) > CONFIG.attack_surface_max_hosts,
        "noteworthy": flagged[:40],
        "issuers": [{"issuer": k, "certs": v} for k, v in issuers.most_common(6)],
        "source": "crt.sh Certificate Transparency logs",
    }


def build_attack_surface(domains: list[str]) -> dict | None:
    """Enumerate every configured domain."""
    if not CONFIG.enable_attack_surface or not domains:
        return None
    out = []
    for raw in domains:
        res = discover_subdomains(raw)
        if res:
            out.append(res)
            log.info(f"  attack surface: {res['domain']} — {res['hostnames']} hostname(s), "
                     f"{len(res['noteworthy'])} noteworthy")
    if not out:
        return None
    return {
        "generated": now_utc(),
        "domains": out,
        "total_hostnames": sum(d["hostnames"] for d in out),
        "note": ("Discovered from public Certificate Transparency logs. "
                 "CyberWatch does not probe, scan or resolve these hosts."),
    }
