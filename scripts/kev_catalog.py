"""
OPENTHREAT — kev_catalog.py
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
# Versioned filename. Adding a field to the record shape makes every warm
# cache incomplete, and an incomplete record is not detectably different from
# a complete one -- the KEV table would simply render blank names and
# descriptions for a full TTL, looking broken with nothing reporting an error.
# That is the same failure the legacy-shape guard below exists to prevent, so
# the fix is the same: a cache written by an older shape must be a MISS by
# construction, not by inspection.
_CACHE = "cisa_kev_v2.json"


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
                "name": entry.get("vulnerabilityName", ""),
                "desc": entry.get("shortDescription", ""),
                "action": entry.get("requiredAction", ""),
                "cwes": entry.get("cwes", []) or [],
            }
        return json.dumps({"catalog_version": data.get("catalogVersion", ""),
                           "released": data.get("dateReleased", ""),
                           "records": records}), None
    except Exception as e:  # noqa: BLE001
        return None, str(e)[:300]


def _parse(cached: str | None):
    """Records dict, or None when the cache is unusable/legacy."""
    if not cached:
        return None
    try:
        parsed = json.loads(cached)
    except Exception as e:  # noqa: BLE001
        log.warning(f"CISA KEV cache parse failed: {e}")
        return None
    # Legacy shape: a bare list of CVE ids, written by versions before dates
    # were kept. Unusable — see load_kev.
    if not isinstance(parsed, dict):
        return None
    return parsed.get("records") or None


def load_kev(ttl_hours: float = 24) -> dict:
    """CVE id -> {added, due, vendor, product, ransomware, name, desc,
    action, cwes}. {} when unavailable."""
    records = _parse(cached_fetch(_CACHE, ttl_hours, _fetch_raw))
    if records is not None:
        return records

    # A warm cache in the OLD shape is treated as a MISS, not as data.
    #
    # The first version of this returned dateless records for a legacy list so
    # nothing would crash. Nothing did — it just quietly produced wrong answers
    # for a full TTL. The first deploy restored a legacy cache from the Actions
    # cache and published a backtest reading "0 KEV additions in 564 CVEs" and
    # an exploitation-lag report claiming 0% date coverage across 1,675
    # entries. Both looked like real findings and neither was.
    #
    # Every caller of this module wants the dates. A cache entry without them
    # is not a cheaper answer, it is a different and wrong one, so re-fetch.
    log.info("  CISA KEV cache predates dateAdded — refetching")
    records = _parse(cached_fetch(_CACHE, 0, _fetch_raw))
    return records or {}


def kev_ids(ttl_hours: float = 24) -> set[str]:
    return set(load_kev(ttl_hours))
