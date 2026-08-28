"""
OPENTHREAT — misp_galaxy.py
============================
The MISP galaxy clusters: the best free machine-readable threat encyclopedia.

WHY THIS AND NOT SOMETHING ELSE
-------------------------------
The pipeline already had two entity corpora — ATT&CK (curated, narrow, ~160
actors) and Malpedia (broad on malware, thin on actors). Neither answers the
question an analyst actually asks first:

    "Midnight Blizzard — is that anyone I already know about?"

It is APT29, Cozy Bear, UNC2452, Nobelium, BlueBravo, The Dukes and about a
dozen more, because every vendor names actors independently and none of them
coordinate. Resolving that by hand is a daily tax. MISP galaxy is the corpus
that already did the work: ~700 actor clusters, each with the synonym list,
country attribution, references and — via the CFR tracker fields — suspected
sponsor and target categories.

It is plain JSON in a git repository. No key, no rate limit, no terms to
accept, and it is versioned so a bad day upstream is visible in the diff.

WHAT IS TAKEN
-------------
    threat-actor         actors, synonyms, country, sponsor, victimology
    ransomware           ransomware families and their leak-site names
    tool                 offensive tooling
    rat / banker /
    stealer / botnet     malware categories ATT&CK does not enumerate
    mitre-intrusion-set  the ATT&CK actor list as MISP mirrors it, which
                         carries synonyms ATT&CK's own objects sometimes lack

DELIBERATE OMISSION
-------------------
The galaxy also ships `mitre-attack-pattern` and friends. We do not read them:
ATT&CK is fetched from MITRE directly in entity_graph, and taking the same data
from two places is how two sources of truth start disagreeing.
"""

from __future__ import annotations

from fetchlib import CONFIG, cached_derive, log, now_utc, stream_json

_BASE = "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters"
_CACHE = "misp_galaxy.json"

# cluster file -> the entity kind it contributes.
_CLUSTERS = {
    "threat-actor": "actor",
    "mitre-intrusion-set": "actor",
    "ransomware": "malware",
    "rat": "malware",
    "banker": "malware",
    "stealer": "malware",
    "botnet": "malware",
    "backdoor": "malware",
    "tool": "tool",
}

# Synonyms that are worse than useless. A galaxy synonym list is written for
# humans reading a page, so it contains bare country names, generic vendor
# labels and single words that appear in ordinary prose. Matching on those is
# how "Global" ended up as a malware family in the v4 graph.
_JUNK_SYNONYMS = {
    "unknown", "unnamed", "unattributed", "n/a", "na", "none", "other",
    "china", "russia", "iran", "north korea", "korea", "usa", "united states",
    "government", "criminal", "state", "group", "team", "unit", "actor",
    "apt", "unknown actor", "ransomware", "malware", "trojan", "botnet",
    "stealer", "loader", "backdoor", "rat", "tool", "generic",
}

_MIN_SYNONYM_LEN = 3


def _clean_synonyms(value: str, raw) -> list[str]:
    out = []
    seen = {str(value).strip().lower()}
    for syn in raw or []:
        s = str(syn).strip()
        low = s.lower()
        if not s or low in seen or low in _JUNK_SYNONYMS:
            continue
        if len(s) < _MIN_SYNONYM_LEN:
            continue
        seen.add(low)
        out.append(s)
    return sorted(out)[:40]


def _refs(meta: dict, limit: int = 10) -> list[str]:
    return [str(r)[:400] for r in (meta.get("refs") or [])
            if str(r).startswith("http")][:limit]


def _derive() -> dict | None:
    log.info("  Building MISP galaxy corpus (9 clusters, weekly)...")
    entries: dict[str, dict] = {}
    clusters_ok = 0

    for cluster, kind in _CLUSTERS.items():
        url = f"{_BASE}/{cluster}.json"
        try:
            raw = stream_json(url, max_bytes=48 * 1024 * 1024)
        except Exception as e:  # noqa: BLE001 - one bad cluster is not a failed run
            log.warning(f"  MISP galaxy cluster {cluster} unavailable: {e}")
            continue
        values = (raw or {}).get("values") or []
        if not values:
            continue
        clusters_ok += 1

        for row in values:
            if not isinstance(row, dict):
                continue
            name = str(row.get("value") or "").strip()
            if not name:
                continue
            meta = row.get("meta") or {}
            if not isinstance(meta, dict):
                meta = {}

            key = name.lower()
            existing = entries.get(key)
            entry = {
                "name": name,
                "kind": kind,
                "cluster": cluster,
                "synonyms": _clean_synonyms(name, meta.get("synonyms")),
                "description": " ".join(str(row.get("description") or "").split())[:2500],
                "country": str(meta.get("country") or "").strip()[:8],
                # The CFR Cyber Operations Tracker fields, which MISP folds into
                # the actor cluster. This is the victimology the feed itself can
                # never supply, because it only sees one week at a time.
                "sponsor": str(meta.get("cfr-suspected-state-sponsor") or "").strip()[:120],
                "victims": [str(v)[:80] for v in
                            (meta.get("cfr-suspected-victims") or [])][:25],
                "target_categories": [str(v)[:80] for v in
                                      (meta.get("cfr-target-category") or [])][:10],
                "incident_type": str(meta.get("cfr-type-of-incident") or "").strip()[:120],
                "motive": str(meta.get("motive") or "").strip()[:120],
                "attribution_confidence": str(
                    meta.get("attribution-confidence") or "").strip()[:16],
                "references": _refs(meta),
                "uuid": str(row.get("uuid") or "")[:40],
            }
            # A name can appear in more than one cluster (ransomware families
            # are frequently also in `tool`). Keep the richest record rather
            # than whichever happened to load last.
            if existing is None or _richness(entry) > _richness(existing):
                entries[key] = entry
            elif existing is not None:
                # Even when the other record wins, its synonyms are still real.
                merged = sorted(set(existing["synonyms"]) | set(entry["synonyms"]))
                existing["synonyms"] = merged[:60]

    if not entries:
        return None

    actors = sum(1 for e in entries.values() if e["kind"] == "actor")
    synonyms = sum(len(e["synonyms"]) for e in entries.values())
    log.info(f"  MISP galaxy: {len(entries)} entities from {clusters_ok} clusters "
             f"({actors} actors, {synonyms} synonyms)")
    return {"built": now_utc(), "source": _BASE, "clusters": clusters_ok,
            "entries": entries}


def _richness(entry: dict) -> int:
    """How much a record actually says, for duplicate resolution."""
    return (len(entry.get("description") or "") // 40
            + len(entry.get("synonyms") or []) * 2
            + len(entry.get("references") or [])
            + (3 if entry.get("country") else 0)
            + (3 if entry.get("sponsor") else 0)
            + len(entry.get("victims") or []))


def load_galaxy(force: bool = False) -> dict:
    """name.lower() -> galaxy entry. {} when disabled or unavailable."""
    if not CONFIG.enable_misp_galaxy:
        return {}
    ttl = 0 if force else CONFIG.misp_galaxy_ttl_hours
    data = cached_derive(_CACHE, ttl, _derive)
    return (data or {}).get("entries", {})


def build_alias_index(galaxy: dict) -> dict:
    """
    alias.lower() -> canonical name. The name-deconfliction lookup.

    Collisions are real and are resolved by preferring the entity that owns the
    name outright: "Wizard Spider" is both a canonical actor and a synonym of
    several TrickBot-adjacent clusters, and the canonical claim must win.
    """
    index: dict[str, str] = {}
    for entry in galaxy.values():
        index[entry["name"].lower()] = entry["name"]
    for entry in galaxy.values():
        for syn in entry.get("synonyms") or []:
            low = syn.lower()
            if low not in index:
                index[low] = entry["name"]
    return index
