"""
CYBERWATCH — knowledge_base.py
===============================
The Library: one canonical page per actor, malware family, tool, technique,
mitigation and campaign, merged from every corpus the pipeline holds.

THE PROBLEM THIS SOLVES
-----------------------
By v4 this project had four entity corpora and no entities. ATT&CK knew APT29's
techniques. Malpedia knew what WellMess is. MISP galaxy knew that Midnight
Blizzard, Cozy Bear, Nobelium and UNC2452 are all the same organisation. The
feed knew APT29 was mentioned four times this week. Not one of those facts could
reach any of the others, so the answer to "tell me about APT29" was a filtered
list of headlines.

A Library entry joins them:

    APT29  (Cozy Bear · Midnight Blizzard · Nobelium · UNC2452 · The Dukes)
      identity      RU, SVR-attributed, active since 2008
      description   MITRE's prose, or the galaxy's where MITRE has none
      arsenal       WellMess, WellMail, Cobalt Strike, ...
      techniques    with detection coverage per technique
      campaigns     SolarWinds Compromise (C0024), ...
      observed      4 items in this feed, most recent 3 days ago
      literature    37 reports from ORKL
      references    every external citation the corpora carry

NAME DECONFLICTION
------------------
Every alias from every corpus points at the same entry, so all five names above
resolve to one page. That single feature removes a real daily tax: vendors do
not coordinate actor naming and never will.

SHARDING IS NOT AN OPTIMISATION HERE
------------------------------------
The merged corpus is several thousand entities and tens of megabytes. Shipping
it as one blob would mean every visitor downloading all of it to read one page,
which is precisely the mistake v4 fixed for the research artifacts.

So the payload splits in two:

    entity_index.json        id, name, kind, aliases, counts. ~1 MB, loaded once.
    entity/<slug>.json       the full record. Fetched only when opened.

Nothing is committed to git (the workflow assembles the site fresh each run),
so file count costs deploy time and nothing else.
"""

from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from pathlib import Path

from fetchlib import CONFIG, item_technique_ids, item_url, log, now_utc

_SLUG_STRIP = re.compile(r"[^a-z0-9]+")

# Entity kinds, in the order the Library lists them.
KINDS = ("actor", "malware", "tool", "technique", "attack-campaign", "mitigation")


# Kinds whose IDENTITY is an id, not a name. Techniques and mitigations must
# be slugged from the id or they collide: ATT&CK reuses 23 technique names
# across 48 different ids ("Spearphishing Attachment" is both T1566.001 and
# T1598.002; "Domains" is both T1583.001 and T1584.001). Slugging those by name
# silently dropped 25 techniques from the Library, and made every one of them
# unreachable by its own id.
_ID_KEYED = {"technique", "mitigation"}


def slugify(kind: str, name: str, entity_id: str = "") -> str:
    """
    Stable, filesystem-safe id.

        actor / APT29          -> actor-apt29
        technique / T1566.001  -> technique-t1566-001
    """
    key = entity_id if (kind in _ID_KEYED and entity_id) else name
    base = _SLUG_STRIP.sub("-", str(key or "").lower()).strip("-")
    if not base:
        base = "unnamed"
    return f"{kind}-{base}"[:120]


def _text(value, limit: int) -> str:
    return " ".join(str(value or "").split())[:limit]


def _merge_aliases(*groups) -> list[str]:
    seen, out = set(), []
    for group in groups:
        for alias in group or []:
            a = str(alias).strip()
            low = a.lower()
            if not a or low in seen:
                continue
            seen.add(low)
            out.append(a)
    return out[:60]


# ── Feed observations ─────────────────────────────────────────────────────────

def _observations(items: list[dict]) -> dict:
    """
    What the CURRENT feed says about each named entity.

    This is the half no static corpus can supply, and the half that makes an
    encyclopedia entry worth opening today rather than a year ago.
    """
    actors: dict[str, list] = defaultdict(list)
    malware: dict[str, list] = defaultdict(list)
    techniques: Counter = Counter()

    for item in items or []:
        row = {
            "title": _text(item.get("title"), 200),
            "url": item_url(item)[:400],
            "published": str(item.get("published") or "")[:10],
            "severity": str(item.get("severity") or ""),
            "priority": item.get("priority_label") or "",
            "source": _text(item.get("source"), 60),
        }
        for actor in item.get("threat_actors") or []:
            actors[actor].append(row)
        for name in item.get("malware") or []:
            malware[name].append(row)
        for tid in item_technique_ids(item):
            techniques[tid] += 1

    def _trim(table):
        for key, rows in table.items():
            rows.sort(key=lambda r: r["published"], reverse=True)
            table[key] = rows[:12]
        return table

    return {"actors": _trim(actors), "malware": _trim(malware),
            "techniques": dict(techniques)}


def _galaxy_lookup(galaxy: dict) -> dict:
    """alias.lower() -> galaxy entry, for merging by any known name."""
    table = {}
    for entry in (galaxy or {}).values():
        table.setdefault(entry["name"].lower(), entry)
        for syn in entry.get("synonyms") or []:
            table.setdefault(syn.lower(), entry)
    return table


# ── Entity builders ───────────────────────────────────────────────────────────

def _build_actor(name: str, attack_row: dict, galaxy_row: dict, observed: list,
                 orkl_index: dict, leak_view: dict, kb: dict,
                 sigma_index: dict) -> dict:
    attack_row = attack_row or {}
    galaxy_row = galaxy_row or {}
    technique_names = (kb or {}).get("technique_names") or {}
    by_technique = (sigma_index or {}).get("by_technique") or {}

    aliases = _merge_aliases(attack_row.get("all_aliases"),
                             attack_row.get("aliases"),
                             galaxy_row.get("synonyms"))

    techniques = []
    for tid in attack_row.get("techniques") or []:
        techniques.append({
            "id": tid,
            "name": technique_names.get(tid, tid),
            "rules": len(by_technique.get(tid, [])),
        })
    techniques.sort(key=lambda t: t["id"])

    try:
        from orkl import reports_for
        reports = reports_for(name, aliases, orkl_index or {})
    except ImportError:  # pragma: no cover
        reports = []

    try:
        from ransomware_leaks import leak_activity_for
        leaks = leak_activity_for(name, leak_view)
    except ImportError:  # pragma: no cover
        leaks = None

    # ATT&CK prose is preferred; the galaxy fills the gap for the ~600 actors
    # ATT&CK has never written up. Which one you are reading is recorded, so
    # the page can attribute it rather than presenting both as one voice.
    description = attack_row.get("description") or ""
    origin = "MITRE ATT&CK" if description else ""
    if not description and galaxy_row.get("description"):
        description = galaxy_row["description"]
        origin = "MISP galaxy"

    return {
        "kind": "actor",
        "name": name,
        "id": attack_row.get("id") or "",
        "aliases": aliases,
        "description": _text(description, CONFIG.kb_description_chars),
        "description_source": origin,
        "country": galaxy_row.get("country") or "",
        "sponsor": galaxy_row.get("sponsor") or "",
        "motive": galaxy_row.get("motive") or "",
        "attribution_confidence": galaxy_row.get("attribution_confidence") or "",
        "target_categories": galaxy_row.get("target_categories") or [],
        "known_victims": galaxy_row.get("victims") or [],
        "first_seen": attack_row.get("first_seen") or "",
        "last_seen": attack_row.get("last_seen") or "",
        "software": attack_row.get("software") or [],
        "techniques": techniques,
        "campaigns": attack_row.get("campaigns") or [],
        "observed": observed,
        "observed_count": len(observed),
        "leak_activity": leaks,
        "reports": reports,
        "references": (attack_row.get("references") or [])[:12],
        "external": [u for u in (galaxy_row.get("references") or [])][:10],
        "url": attack_row.get("url") or "",
        "in_attack": bool(attack_row),
        "in_galaxy": bool(galaxy_row),
    }


def _build_software(name: str, attack_row: dict, family_row: dict,
                    galaxy_row: dict, observed: list, kb: dict,
                    sigma_index: dict) -> dict:
    attack_row = attack_row or {}
    family_row = family_row or {}
    galaxy_row = galaxy_row or {}
    technique_names = (kb or {}).get("technique_names") or {}
    by_technique = (sigma_index or {}).get("by_technique") or {}

    kind = attack_row.get("kind") or ("tool" if galaxy_row.get("kind") == "tool"
                                      else "malware")
    aliases = _merge_aliases(attack_row.get("all_aliases"),
                             attack_row.get("aliases"),
                             family_row.get("aliases"),
                             galaxy_row.get("synonyms"))

    techniques = []
    for tid in attack_row.get("techniques") or []:
        techniques.append({"id": tid, "name": technique_names.get(tid, tid),
                           "rules": len(by_technique.get(tid, []))})

    description = (attack_row.get("description") or family_row.get("description")
                   or galaxy_row.get("description") or "")
    origin = ("MITRE ATT&CK" if attack_row.get("description")
              else "Malpedia" if family_row.get("description")
              else "MISP galaxy" if galaxy_row.get("description") else "")

    return {
        "kind": kind,
        "name": name,
        "id": attack_row.get("id") or family_row.get("id") or "",
        "aliases": aliases,
        "description": _text(description, CONFIG.kb_description_chars),
        "description_source": origin,
        "platform": family_row.get("platform") or "",
        "platforms": attack_row.get("platforms") or [],
        "actors": _merge_aliases(attack_row.get("actors"), family_row.get("actors")),
        "techniques": sorted(techniques, key=lambda t: t["id"]),
        "campaigns": attack_row.get("campaigns") or [],
        "observed": observed,
        "observed_count": len(observed),
        "references": (attack_row.get("references") or [])[:12],
        "external": _merge_aliases(family_row.get("references"),
                                   galaxy_row.get("references")),
        "url": attack_row.get("url") or family_row.get("url") or "",
        "in_attack": bool(attack_row),
        "in_malpedia": bool(family_row),
        "in_galaxy": bool(galaxy_row),
    }


def _build_technique(tid: str, row: dict, kb: dict, sigma_index: dict,
                     d3fend_table: dict, control_frameworks: dict,
                     atomics: dict, observed_count: int) -> dict:
    row = row or {}
    technique_names = (kb or {}).get("technique_names") or {}
    mitigations = (kb or {}).get("mitigations") or {}
    by_technique = (sigma_index or {}).get("by_technique") or {}
    totals = (sigma_index or {}).get("totals") or {}

    try:
        from d3fend import countermeasures_for
        counters = countermeasures_for(tid, d3fend_table or {})
    except ImportError:  # pragma: no cover
        counters = []
    try:
        from control_mappings import controls_for
        controls = controls_for(tid, control_frameworks or {})
    except ImportError:  # pragma: no cover
        controls = {}
    try:
        from atomics import tests_for
        tests = tests_for(tid, atomics or {}, 4)
    except ImportError:  # pragma: no cover
        tests = []

    return {
        "kind": "technique",
        "name": row.get("name") or technique_names.get(tid, tid),
        "id": tid,
        "aliases": [],
        "description": row.get("description") or "",
        "description_source": "MITRE ATT&CK" if row.get("description") else "",
        "detection": row.get("detection") or "",
        "tactics": row.get("tactics") or [],
        "platforms": row.get("platforms") or [],
        "data_sources": row.get("data_sources") or [],
        "telemetry": row.get("detects") or [],
        "is_subtechnique": bool(row.get("is_subtechnique")),
        "parent": row.get("parent") or "",
        "subtechniques": row.get("subtechniques") or [],
        "actors": row.get("actors") or [],
        "software": row.get("software") or [],
        "rules": by_technique.get(tid, [])[:12],
        "rules_total": int(totals.get(tid, 0)),
        "atomics": tests,
        "countermeasures": counters[:16],
        "attack_mitigations": [
            {"id": mid, "name": (mitigations.get(mid) or {}).get("name", mid),
             "description": (mitigations.get(mid) or {}).get("description", "")}
            for mid in (row.get("mitigations") or [])
        ][:12],
        "controls": controls,
        "observed_count": int(observed_count or 0),
        "references": (row.get("references") or [])[:10],
        "url": row.get("url") or "",
    }


def _build_campaign(name: str, row: dict, kb: dict) -> dict:
    technique_names = (kb or {}).get("technique_names") or {}
    return {
        "kind": "attack-campaign",
        "name": name,
        "id": row.get("id") or "",
        "aliases": row.get("aliases") or [],
        "description": row.get("description") or "",
        "description_source": "MITRE ATT&CK",
        "first_seen": row.get("first_seen") or "",
        "last_seen": row.get("last_seen") or "",
        "actors": row.get("actors") or [],
        "software": row.get("software") or [],
        "techniques": [{"id": t, "name": technique_names.get(t, t)}
                       for t in (row.get("techniques") or [])],
        "references": (row.get("references") or [])[:12],
        "url": row.get("url") or "",
    }


def _build_mitigation(mid: str, row: dict, kb: dict) -> dict:
    technique_names = (kb or {}).get("technique_names") or {}
    return {
        "kind": "mitigation",
        "name": row.get("name") or mid,
        "id": mid,
        "aliases": [],
        "description": row.get("description") or "",
        "description_source": "MITRE ATT&CK",
        "techniques": [{"id": t, "name": technique_names.get(t, t)}
                       for t in (row.get("techniques") or [])][:80],
        "url": row.get("url") or "",
    }


# ── Top level ─────────────────────────────────────────────────────────────────

def build_knowledge_base(attack_kb: dict | None, galaxy: dict, families: dict,
                         orkl_index: dict, d3fend_table: dict,
                         control_frameworks: dict, sigma_index: dict,
                         atomics: dict, leak_view: dict | None,
                         items: list[dict]) -> dict | None:
    """Merge every corpus into canonical entities plus a search index."""
    if not CONFIG.enable_knowledge_base:
        return None
    kb = attack_kb or {}
    galaxy = galaxy or {}
    families = families or {}
    observed = _observations(items or [])
    galaxy_by_alias = _galaxy_lookup(galaxy)

    entities: dict[str, dict] = {}

    def _add(entity: dict) -> str:
        slug = slugify(entity["kind"], entity["name"], entity.get("id") or "")
        # Two different entities can still slug identically — ATT&CK's
        # "SILENTTRINITY" the tool and a galaxy actor of the same name. Suffix
        # rather than overwrite.
        #
        # The collision test compares IDENTITY, not just the display name. An
        # earlier version compared names alone, which meant two entities that
        # shared a name were treated as the same thing and the second silently
        # replaced the first. That is the quiet data loss this branch exists to
        # prevent, and it was happening inside the guard against it.
        def _identity(row: dict) -> tuple:
            return (row.get("kind"), row.get("id") or "", row.get("name"))

        while slug in entities and _identity(entities[slug]) != _identity(entity):
            suffix = 2
            candidate = f"{slug}-{suffix}"
            while candidate in entities and _identity(entities[candidate]) != _identity(entity):
                suffix += 1
                candidate = f"{slug}-{suffix}"
            slug = candidate
        entity["slug"] = slug
        entities[slug] = entity
        return slug

    # ── Actors ────────────────────────────────────────────────────────────
    actor_names = set(kb.get("actors") or {})
    for entry in galaxy.values():
        if entry.get("kind") == "actor":
            actor_names.add(entry["name"])
    # Names the feed itself found that no corpus lists: still worth a page,
    # because "we saw this name six times and nobody has written it up" is a
    # real state of affairs, not an error.
    actor_names.update(observed["actors"].keys())

    for name in sorted(actor_names):
        attack_row = (kb.get("actors") or {}).get(name)
        galaxy_row = galaxy_by_alias.get(name.lower())
        if galaxy_row and galaxy_row.get("kind") != "actor":
            galaxy_row = None
        seen = observed["actors"].get(name, [])
        if not attack_row and not galaxy_row and not seen:
            continue
        _add(_build_actor(name, attack_row, galaxy_row, seen, orkl_index,
                          leak_view, kb, sigma_index))

    # ── Malware and tools ─────────────────────────────────────────────────
    software_names = set(kb.get("software") or {}) | set(families)
    for entry in galaxy.values():
        if entry.get("kind") in ("malware", "tool"):
            software_names.add(entry["name"])
    software_names.update(observed["malware"].keys())

    for name in sorted(software_names):
        attack_row = (kb.get("software") or {}).get(name)
        family_row = families.get(name)
        galaxy_row = galaxy_by_alias.get(name.lower())
        if galaxy_row and galaxy_row.get("kind") == "actor":
            galaxy_row = None
        seen = observed["malware"].get(name, [])
        if not (attack_row or family_row or galaxy_row or seen):
            continue
        _add(_build_software(name, attack_row, family_row, galaxy_row, seen,
                             kb, sigma_index))

    # ── Techniques ────────────────────────────────────────────────────────
    for tid, row in (kb.get("techniques") or {}).items():
        _add(_build_technique(tid, row, kb, sigma_index, d3fend_table,
                              control_frameworks, atomics,
                              observed["techniques"].get(tid, 0)))

    # ── ATT&CK campaigns and mitigations ──────────────────────────────────
    for name, row in (kb.get("attack_campaigns") or {}).items():
        _add(_build_campaign(name, row, kb))
    for mid, row in (kb.get("mitigations") or {}).items():
        _add(_build_mitigation(mid, row, kb))

    if not entities:
        return None

    index, aliases = _build_index(entities)
    stats = Counter(e["kind"] for e in entities.values())
    described = sum(1 for e in entities.values() if e.get("description"))

    log.info(f"  Knowledge base: {len(entities)} entities "
             f"({dict(sorted(stats.items()))}), {described} with prose, "
             f"{len(aliases)} alias keys")
    return {
        "built": now_utc(),
        "count": len(entities),
        "by_kind": dict(stats),
        "described": described,
        "entities": entities,
        "index": index,
        "aliases": aliases,
    }


def _substance(entity: dict) -> int:
    """
    How much an entry actually says. Used to settle name collisions.

    Names are claimed by more than one entity more often than you would think.
    "Emotet" is both an ATT&CK malware family (S0367, with prose, aliases and
    an arsenal) and a bare actor name the feed mentioned once — and the empty
    stub won the alias, so searching for Emotet landed on a page with nothing
    on it while the real entry sat one row below.

    Observation count alone cannot break that tie: both were seen once. What
    separates them is that one is backed by a corpus and the other is a name.
    """
    score = 0
    if entity.get("id"):
        score += 30                      # a corpus assigned it an identifier
    score += min(len(entity.get("description") or "") // 50, 20)
    score += min(len(entity.get("aliases") or []) * 2, 20)
    score += min(len(entity.get("techniques") or []), 10)
    score += min(len(entity.get("software") or []), 6)
    score += min(len(entity.get("references") or []), 6)
    if entity.get("leak_activity"):
        score += 8
    if entity.get("reports"):
        score += 6
    return score


def _build_index(entities: dict) -> tuple[list, dict]:
    """
    The one file loaded up front, plus the alias -> slug lookup.

    Kept to identity and counts only. Every field added here is paid for by
    every visitor before they have opened anything.
    """
    index = []
    aliases: dict[str, str] = {}
    # name.lower() -> [slug, ...], so an entity page can offer the other
    # readings of an ambiguous name rather than pretending it is the only one.
    ambiguous: dict[str, list] = defaultdict(list)

    ranked = sorted(
        entities.values(),
        key=lambda e: (-int(e.get("observed_count") or 0),
                       -_substance(e),
                       e["kind"], e["name"]),
    )
    for entity in ranked[:CONFIG.kb_index_max_entities]:
        slug = entity["slug"]
        index.append({
            "slug": slug,
            "name": entity["name"],
            "kind": entity["kind"],
            "id": entity.get("id") or "",
            "aliases": (entity.get("aliases") or [])[:12],
            "observed": int(entity.get("observed_count") or 0),
            "country": entity.get("country") or "",
            # A one-line teaser so search results are readable without a fetch.
            "teaser": _text(entity.get("description"), 150),
        })
        aliases.setdefault(entity["name"].lower(), slug)
        ambiguous[entity["name"].lower()].append(slug)
        for alias in entity.get("aliases") or []:
            aliases.setdefault(str(alias).lower(), slug)
        if entity.get("id"):
            aliases.setdefault(str(entity["id"]).lower(), slug)

    # Attach the alternatives to each entity that shares its name, so the page
    # can say "Emotet is also a malware family" instead of silently being one
    # of two things called the same thing.
    for name, slugs in ambiguous.items():
        if len(slugs) < 2:
            continue
        for slug in slugs:
            entity = entities.get(slug)
            if not entity:
                continue
            entity["also_known_here"] = [
                {"slug": other, "kind": entities[other]["kind"],
                 "name": entities[other]["name"]}
                for other in slugs if other != slug and other in entities
            ][:6]

    return index, aliases


def write_entity_shards(payload: dict, api_dir: Path) -> int:
    """
    Write entity_index.json plus one file per entity. Returns the shard count.

    Stale shards from a previous build are removed: an entity ATT&CK deprecates
    would otherwise stay reachable by URL forever, quietly serving a record no
    index points at any more.
    """
    if not payload:
        return 0
    api_dir = Path(api_dir)
    shard_dir = api_dir / CONFIG.kb_shard_dir
    shard_dir.mkdir(parents=True, exist_ok=True)

    entities = payload.get("entities") or {}
    wanted = set()
    for slug, entity in entities.items():
        wanted.add(f"{slug}.json")
        (shard_dir / f"{slug}.json").write_text(
            json.dumps(entity, ensure_ascii=False, separators=(",", ":")),
            encoding="utf-8")

    removed = 0
    for existing in shard_dir.glob("*.json"):
        if existing.name not in wanted:
            existing.unlink()
            removed += 1

    (api_dir / "entity_index.json").write_text(
        json.dumps({
            "built": payload.get("built"),
            "count": payload.get("count"),
            "by_kind": payload.get("by_kind"),
            "entities": payload.get("index"),
            "aliases": payload.get("aliases"),
        }, ensure_ascii=False, separators=(",", ":")),
        encoding="utf-8")

    if removed:
        log.info(f"  Removed {removed} stale entity shard(s)")
    return len(entities)
