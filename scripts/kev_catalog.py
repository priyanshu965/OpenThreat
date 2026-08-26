"""
CYBERWATCH — kev_catalog.py
============================
The CISA Known Exploited Vulnerabilities catalogue, with its dates kept.

The pipeline previously cached KEV as a bare list of CVE ids, because the only
question ever asked of it was "is this CVE in the catalogue". Three things now
need the rest of the record:

  backtest.py    needs dateAdded, to ask whether a CVE was scored highly
                 BEFORE it was listed — the whole point of the exercise.
  exploit_lag.py needs dateAdded to measure publication → KEV latency.
  source_reliability.py needs it to work out which sources were early.

Cached for a day like the old list was, and the loader still understands the
legacy list shape so a warm cache from the previous version is not a crash.
"""

from __future__ import annotations

import json

from fetchlib import CONFIG, SESSION, cached_fetch, log

_KEV_URL = ("https://www.cisa.gov/sites/default/files/feeds/"
            "known_exploited_vulnerabilities.json")
_CACHE = "cisa_kev.json"


def _fetch_raw() -> tuple[str | None, str | None]:
    try:
        resp = SESSION.get(_KEV_URL, timeout=CONFIG.request_timeout)
        resp.raise_for_status()
        data = resp.json()
        records = {}
        for entry in data.get("vulnerabilities", []) or []:
            cve = (entry.get("cveID") or "").upper()
            if not cve:
                continue
            records[cve] = {
                "added": entry.get("dateAdded", ""),
                "due": entry.get("dueDate", ""),
                "vendor": entry.get("vendorProject", ""),
                "product": entry.get("product", ""),
                "ransomware": entry.get("knownRansomwareCampaignUse", "") == "Known",
            }
        return json.dumps({"catalog_version": data.get("catalogVersion", ""),
                           "released": data.get("dateReleased", ""),
                           "records": records}), None
    except Exception as e:  # noqa: BLE001
        return None, str(e)[:300]


def load_kev(ttl_hours: float = 24) -> dict:
    """CVE id -> {added, due, vendor, product, ransomware}. {} when unavailable."""
    cached = cached_fetch(_CACHE, ttl_hours, _fetch_raw)
    if not cached:
        return {}
    try:
        parsed = json.loads(cached)
    except Exception as e:  # noqa: BLE001
        log.warning(f"CISA KEV cache parse failed: {e}")
        return {}

    # Legacy shape: a bare list of CVE ids, written by versions before dates
    # were kept. Honour it rather than crashing on a warm cache.
    if isinstance(parsed, list):
        return {str(c).upper(): {"added": "", "due": "", "vendor": "",
                                 "product": "", "ransomware": False}
                for c in parsed if c}
    return parsed.get("records", {}) if isinstance(parsed, dict) else {}


def kev_ids(ttl_hours: float = 24) -> set[str]:
    return set(load_kev(ttl_hours))
