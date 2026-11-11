"""
OPENTHREAT — orkl.py
=====================
ORKL: the open threat-report library, indexed by actor.

The Library can now say what APT41 is, which techniques it uses and which
malware it runs. What it could not do is the thing an analyst actually wants
next — read the primary sources. Every entity page in every tool ends with a
"References" list of three URLs somebody curated in 2019.

ORKL is a community archive of threat-intelligence reports (APTnotes, CyberMonitor
and others), normalised, deduplicated by SHA-1, and — crucially — tagged with the
threat actors each report covers, with alias resolution already applied. That
turns "everything about APT41" from a curated stub into an actual bibliography.

BANDWIDTH, HONESTLY
-------------------
The list endpoint returns each report's FULL extracted text: about 2.3 MB per
100 rows. Pulling the whole ~15k-report corpus would be several hundred MB a
week for data we discard immediately.

So this pages until `orkl_max_reports`, most-recently-added first, and reduces
each row to a citation (~200 bytes) as it goes. The published index is
therefore a RECENT-HEAVY sample, not the complete archive, and it says so in
its own payload — `complete: false` — so the UI can tell the reader that too.
A bibliography that silently omits half the literature is worse than one that
admits its own edges.
"""

from __future__ import annotations

from collections import defaultdict

from fetchlib import CONFIG, SESSION, cached_derive, log, now_utc

_API = "https://orkl.eu/api/v1/library/entries"
_ENTRY = "https://orkl.eu/library"
_CACHE = "orkl_reports.json"

_PAGE = 100


def _clean(value, limit: int) -> str:
    return " ".join(str(value or "").split())[:limit]


def _derive() -> dict | None:
    budget = max(0, int(CONFIG.orkl_max_reports))
    if not budget:
        return None
    log.info(f"  Building ORKL report index (up to {budget} reports, weekly)...")

    reports: list[dict] = []
    by_actor: dict[str, list] = defaultdict(list)
    alias_to_actor: dict[str, str] = {}
    offset = 0
    pages = 0

    while len(reports) < budget:
        try:
            resp = SESSION.get(
                _API,
                params={"limit": _PAGE, "offset": offset,
                        "order_by": "created_at", "order": "desc"},
                timeout=max(90, CONFIG.request_timeout * 2),
            )
            resp.raise_for_status()
            payload = resp.json()
        except Exception as e:  # noqa: BLE001 - partial index beats no index
            log.warning(f"  ORKL page at offset {offset} failed: {e}")
            break

        rows = (payload or {}).get("data") or []
        if not rows:
            break
        pages += 1

        for row in rows:
            if not isinstance(row, dict):
                continue
            title = _clean(row.get("title") or row.get("llm_title"), 240)
            rid = _clean(row.get("id"), 40)
            if not title or not rid:
                continue

            actors = []
            for actor in row.get("threat_actors") or []:
                if not isinstance(actor, dict):
                    continue
                main = _clean(actor.get("main_name"), 80)
                if not main:
                    continue
                actors.append(main)
                # ORKL has already done alias resolution across its sources.
                # Harvesting it costs nothing and materially widens the name
                # deconfliction index.
                for alias in actor.get("aliases") or []:
                    a = _clean(alias, 80)
                    if a and a.lower() != main.lower():
                        alias_to_actor.setdefault(a.lower(), main)

            entry = {
                "id": rid,
                "title": title,
                "authors": _clean(row.get("authors"), 160),
                "date": _clean(row.get("file_creation_date"), 10),
                "added": _clean(row.get("created_at"), 10),
                "language": _clean(row.get("language"), 8),
                "sources": [_clean(s, 40) for s in (row.get("sources") or []) if s][:4],
                "actors": sorted(set(actors))[:12],
                "url": f"{_ENTRY}/{rid}",
                # `plain_text` is read and discarded here on purpose: it is the
                # bulk of the payload and none of the value.
            }
            reports.append(entry)
            for actor in entry["actors"]:
                by_actor[actor].append(rid)
            if len(reports) >= budget:
                break

        if len(rows) < _PAGE:
            break              # end of the corpus
        offset += _PAGE

    if not reports:
        return None

    for actor in list(by_actor):
        by_actor[actor] = by_actor[actor][:60]

    log.info(f"  ORKL: {len(reports)} reports over {pages} pages, "
             f"{len(by_actor)} actors referenced, "
             f"{len(alias_to_actor)} aliases harvested")
    return {
        "built": now_utc(),
        "source": _API,
        "count": len(reports),
        # True only if the corpus ran out before the budget did.
        "complete": len(reports) < budget,
        "reports": {r["id"]: r for r in reports},
        "by_actor": dict(by_actor),
        "aliases": alias_to_actor,
    }


def load_orkl(force: bool = False) -> dict:
    if not CONFIG.enable_orkl:
        return {}
    ttl = 0 if force else CONFIG.orkl_ttl_hours
    return cached_derive(_CACHE, ttl, _derive) or {}


def reports_for(name: str, aliases, orkl: dict, limit: int = 12) -> list[dict]:
    """
    Reports covering an entity, matched on its name OR any of its aliases.

    Alias matching is what makes this work at all: ORKL tags a report with
    whatever name its author used, so a search for "APT29" that ignores
    "Cozy Bear" and "Nobelium" misses most of the literature about APT29.
    """
    if not orkl or not name:
        return []
    reports = orkl.get("reports") or {}
    by_actor = orkl.get("by_actor") or {}
    resolve = orkl.get("aliases") or {}

    wanted = {str(name).lower()}
    for alias in aliases or []:
        wanted.add(str(alias).lower())
    # Map each candidate through ORKL's own alias table too.
    canonical = {resolve.get(w, "") for w in wanted}
    canonical.discard("")

    ids: list[str] = []
    for actor, report_ids in by_actor.items():
        if actor.lower() in wanted or actor in canonical:
            ids.extend(report_ids)

    seen, out = set(), []
    for rid in ids:
        if rid in seen:
            continue
        seen.add(rid)
        row = reports.get(rid)
        if row:
            out.append(row)
    out.sort(key=lambda r: (r.get("date") or "", r.get("added") or ""), reverse=True)
    return out[:limit]
