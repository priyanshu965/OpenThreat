"""
CYBERWATCH — entity_graph.py
=============================
Turns the feed from a list of rows into connected intelligence.

Every item already carries threat actors, ATT&CK techniques and a target
sector, but they are carried INDEPENDENTLY: nothing says that the APT28 on one
row and the T1071 on another are the same story. MITRE's CTI bundle ships the
missing half as explicit relationship objects —

    intrusion-set  --uses-->  malware      --uses-->  attack-pattern
    intrusion-set  --uses-->  attack-pattern

— so the edges cost nothing to obtain. This module loads them once, keeps a
compact derived copy, and crosses them with what the feed actually observed:

    APT28 ──uses──▶ X-Agent ──implements──▶ T1071 ──seen in──▶ 4 items this week
      │                                        │
      └──targets──▶ Government ◀───────────────┘

Two kinds of edge, and the distinction is the point:

    KNOWN     from MITRE ATT&CK. A curated claim about the world.
    OBSERVED  from this feed, this window. actor→sector, technique→item counts.

They are tagged separately in the output so the UI never presents "we saw these
two things in the same week" as if MITRE had asserted a relationship.

Size. enterprise-attack.json is 48 MB, which is far too large to keep in the
CI cache or the published state tarball. cached_derive() downloads it, reduces
it to ~1 MB of names/aliases/edges, stores only that, and throws the rest away.
"""

from __future__ import annotations

import re
from collections import defaultdict

from fetchlib import CONFIG, cached_derive, log, now_utc, stream_json

# MITRE publishes the Enterprise matrix as one STIX 2.1 bundle.
_CTI_URL = ("https://raw.githubusercontent.com/mitre/cti/master/"
            "enterprise-attack/enterprise-attack.json")

_KB_CACHE = "attack_kb.json"

# Aliases below this length, or in this list, produce nothing but false
# positives when matched against prose. "Fancy Bear" is a useful alias;
# "Group 5", "Sedan" and "ALPHA" are not.
_MIN_ALIAS_LEN = 5
_ALIAS_DENYLIST = {
    "operation", "group", "team", "unit", "cluster", "actor", "malware",
    "windows", "linux", "android", "python", "powershell", "office", "cloud",
    "chrome", "safari", "cobalt", "shadow", "storm", "night",
    "winter", "spider", "panda", "kitten", "tiger", "bear", "dragon",
    "silence", "orange", "purple", "black", "white", "green",
    "gold", "silver", "china", "russia", "korea", "north korea", "iran",
    "sandbox", "update", "system", "service", "network", "server", "client",
    "remote", "access", "trojan", "backdoor", "loader", "stealer",
    "ransom", "banker", "botnet", "downloader", "dropper", "rootkit",

    # ATT&CK software names that are also ordinary English words. Without this
    # the matcher tagged a story about a shipping EMBARGO as the Embargo
    # ransomware family, and "Expand", "Route" and "Chaos" fired constantly.
    # These are dropped rather than made case-sensitive because half the feed
    # is headline-cased, so casing carries no signal here.
    #
    # Security-distinctive tool names (Mimikatz, Impacket, Rclone, Rubeus,
    # LaZagne, AdFind, Sliver, Koadic, Cobalt Strike) are deliberately NOT in
    # this list: in a security corpus those words genuinely mean the tool.
    "agenda", "anchor", "apostle", "aurora", "avenger", "cannon", "carbon",
    "chaos", "covenant", "crimson", "crutch", "denis", "disco", "donut",
    "embargo", "empire", "explosive", "ferocious", "flame", "flamer",
    "havoc", "james", "kevin", "machete", "mango", "meteor", "milan",
    "mythic", "ninja", "octopus", "pandora", "peppy", "prestige", "proton",
    "responder", "rover", "royal", "ruler", "samurai", "scorpion", "shark",
    "snake", "solar", "soldier", "spark", "trinity", "wiper", "expand",
    "route", "tasklist", "diskpart", "forfiles", "nltest", "winexe",
    "wevtutil", "reaver", "pandora", "prestige", "warzone", "trinity",

    # A second round, found by reading the graph rather than by guessing.
    # Malpedia carries families literally called Global, Payload, Crisis,
    # Globe, Phoenix, Glasses, BRAIN and mozart, and every one of them fired
    # constantly against ordinary security prose — "Global" alone matched 11
    # items in a single run, which is more than every real family combined.
    #
    # The general shape of the trap: a family name that is also a word an
    # analyst would write in a sentence about something else. Where a name is
    # ambiguous the item is dropped, because a missed family is a gap and a
    # wrong one is a false claim about who is behind an incident.
    "global", "payload", "crisis", "globe", "phoenix", "glasses", "brain",
    "mozart", "dark shades", "titan", "atlas", "hermes", "apollo", "mercury",
    "nexus", "matrix", "oracle", "vision", "signal", "beacon", "gateway",
    "sentinel", "guardian", "hunter", "raptor", "falcon", "eagle", "condor",
    "python", "cobra", "viper", "mamba", "scorpio", "phantom", "spectre",
    "shadow", "eclipse", "aurora", "horizon", "summit", "vertex", "origin",
}


def canonical_actor_names(items: list[dict]) -> int:
    """
    Collapse case variants of the same actor across the whole feed.

    Leak-site fetchers hand us the group name exactly as the crew writes it,
    so one run carried 'Qilin', 'qilin', 'SafePay', 'safepay', 'Dark Project'
    and 'dark project' as six distinct actors. That splits every count that
    keys on the name: trends momentum, geopolitical attribution and the graph
    all saw half the activity they should have.

    The surviving spelling is the one with the most capital letters, which
    picks 'SafePay' over 'safepay' and leaves already-correct names alone.
    Returns the number of names rewritten.
    """
    best: dict[str, str] = {}
    for item in items:
        for raw in item.get("threat_actors") or []:
            name = str(raw).strip()
            if not name:
                continue
            key = name.lower()
            current = best.get(key)
            if current is None or _caps(name) > _caps(current):
                best[key] = name

    rewritten = 0
    for item in items:
        actors = item.get("threat_actors")
        if not actors:
            continue
        seen: list[str] = []
        for raw in actors:
            name = best.get(str(raw).strip().lower(), str(raw).strip())
            if name and name not in seen:
                seen.append(name)
            if name != str(raw).strip():
                rewritten += 1
        item["threat_actors"] = seen
    return rewritten


def _caps(value: str) -> int:
    return sum(1 for ch in value if ch.isupper())


def _external_id(obj: dict) -> str:
    for ref in obj.get("external_references", []) or []:
        if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
            return ref["external_id"]
    return ""


def _external_url(obj: dict) -> str:
    for ref in obj.get("external_references", []) or []:
        if ref.get("source_name") == "mitre-attack" and ref.get("url"):
            return ref["url"]
    return ""


def _live(obj: dict) -> bool:
    """Skip revoked and deprecated objects — ATT&CK keeps them in the bundle."""
    return not (obj.get("revoked") or obj.get("x_mitre_deprecated"))


def _usable_aliases(name: str, raw) -> list[str]:
    """Aliases worth matching against prose, minus the ones that are traps."""
    out = []
    for alias in raw or []:
        a = str(alias).strip()
        if not a or a.lower() == name.lower():
            continue
        if len(a) < _MIN_ALIAS_LEN or a.lower() in _ALIAS_DENYLIST:
            continue
        out.append(a)
    return sorted(set(out))


def _derive_kb() -> dict | None:
    """Download the CTI bundle and reduce it to names, aliases and edges."""
    log.info("  Building ATT&CK knowledge base from MITRE CTI (48 MB, once a month)...")
    bundle = stream_json(_CTI_URL)
    objects = bundle.get("objects", [])

    by_id: dict[str, dict] = {}
    actors: dict[str, dict] = {}
    software: dict[str, dict] = {}
    technique_names: dict[str, str] = {}
    technique_tactics: dict[str, list[str]] = {}

    for obj in objects:
        oid = obj.get("id")
        if not oid:
            continue
        otype = obj.get("type")
        if otype in ("intrusion-set", "malware", "tool", "attack-pattern"):
            by_id[oid] = obj
        if otype == "attack-pattern" and _live(obj):
            tid = _external_id(obj)
            if tid:
                technique_names[tid] = obj.get("name", tid)
                technique_tactics[tid] = [
                    p.get("phase_name", "") for p in obj.get("kill_chain_phases", []) or []
                    if p.get("kill_chain_name") == "mitre-attack"
                ]

    for obj in objects:
        if not _live(obj):
            continue
        name = (obj.get("name") or "").strip()
        if not name:
            continue
        if obj.get("type") == "intrusion-set":
            actors[name] = {
                "name": name,
                "aliases": _usable_aliases(name, obj.get("aliases")),
                "url": _external_url(obj),
                "techniques": [], "software": [],
            }
        elif obj.get("type") in ("malware", "tool"):
            software[name] = {
                "name": name,
                "kind": obj.get("type"),
                "aliases": _usable_aliases(name, obj.get("x_mitre_aliases")),
                "url": _external_url(obj),
                "techniques": [], "actors": [],
            }

    # Relationship pass. ATT&CK expresses everything we want as `uses`.
    id_to_name = {oid: (o.get("name") or "").strip() for oid, o in by_id.items()}
    edges = 0
    for obj in objects:
        if obj.get("type") != "relationship" or obj.get("relationship_type") != "uses":
            continue
        if not _live(obj):
            continue
        src = by_id.get(obj.get("source_ref"))
        dst = by_id.get(obj.get("target_ref"))
        if not src or not dst:
            continue
        src_name = id_to_name.get(obj["source_ref"], "")
        dst_name = id_to_name.get(obj["target_ref"], "")
        src_type, dst_type = src.get("type"), dst.get("type")

        if src_type == "intrusion-set" and dst_type == "attack-pattern":
            tid = _external_id(dst)
            if tid and src_name in actors:
                actors[src_name]["techniques"].append(tid)
                edges += 1
        elif src_type == "intrusion-set" and dst_type in ("malware", "tool"):
            if src_name in actors and dst_name in software:
                actors[src_name]["software"].append(dst_name)
                software[dst_name]["actors"].append(src_name)
                edges += 1
        elif src_type in ("malware", "tool") and dst_type == "attack-pattern":
            tid = _external_id(dst)
            if tid and src_name in software:
                software[src_name]["techniques"].append(tid)
                edges += 1

    for table in (actors, software):
        for row in table.values():
            for key in ("techniques", "software", "actors"):
                if key in row:
                    row[key] = sorted(set(row[key]))

    log.info(f"  ATT&CK KB: {len(actors)} actors, {len(software)} software, "
             f"{len(technique_names)} techniques, {edges} edges")
    return {
        "built": now_utc(),
        "source": _CTI_URL,
        "actors": actors,
        "software": software,
        "technique_names": technique_names,
        "technique_tactics": technique_tactics,
    }


def load_attack_kb(force: bool = False) -> dict | None:
    """The derived ATT&CK knowledge base, cached for a month."""
    ttl = 0 if force else CONFIG.attack_kb_ttl_hours
    return cached_derive(_KB_CACHE, ttl, _derive_kb)


# ── Matching feed prose against software names ────────────────────────────────
# Actors are already detected by fetch_intel.detect_threat_actors. Malware and
# tool families are not, and Malpedia/ATT&CK give us thousands of names — so the
# same whole-token discipline used everywhere else in this pipeline applies:
# substring matching would have "Emotet" fire inside "emotethreat" and, far
# worse, one-word family names fire inside ordinary prose.

def build_software_matcher(kb: dict, extra: dict | None = None):
    """Return (compiled_pattern, term -> canonical name). None if nothing to match."""
    lookup: dict[str, str] = {}
    for table in (kb.get("software", {}), (extra or {})):
        for name, row in table.items():
            terms = [name] + list(row.get("aliases", []) or [])
            for term in terms:
                t = str(term).strip()
                if len(t) < _MIN_ALIAS_LEN or t.lower() in _ALIAS_DENYLIST:
                    continue
                lookup.setdefault(t.lower(), name)
    if not lookup:
        return None, {}
    pattern = re.compile(
        r"(?<![0-9A-Za-z])("
        + "|".join(re.escape(t) for t in sorted(lookup, key=len, reverse=True))
        + r")(?![0-9A-Za-z])",
        re.IGNORECASE,
    )
    return pattern, lookup


def detect_software(text: str, matcher, lookup: dict, limit: int = 6) -> list[str]:
    if not text or matcher is None:
        return []
    found: list[str] = []
    for m in matcher.finditer(text):
        name = lookup.get(m.group(1).lower())
        if name and name not in found:
            found.append(name)
            if len(found) >= limit:
                break
    return found


# ── The observed graph ────────────────────────────────────────────────────────

def annotate_malware(items: list[dict], kb: dict, families: dict | None = None) -> int:
    """Tag each item with the malware/tool families named in it. Returns count."""
    matcher, lookup = build_software_matcher(kb, families)
    if matcher is None:
        return 0
    tagged = 0
    for item in items:
        text = f"{item.get('title', '')} {item.get('description', '')}"
        names = detect_software(text, matcher, lookup)
        if names:
            item["malware"] = names
            tagged += 1
    return tagged


def build_entity_graph(items: list[dict], kb: dict | None,
                       families: dict | None = None,
                       max_nodes: int = 400) -> dict | None:
    """
    Cross ATT&CK's curated edges with what this feed observed.

    Only entities the feed actually mentions become nodes, so the graph is a
    picture of THIS week rather than a redrawing of all of ATT&CK.
    """
    if not items:
        return None
    kb = kb or {"actors": {}, "software": {}, "technique_names": {}}
    kb_actors = kb.get("actors", {})
    kb_software = kb.get("software", {})
    tech_names = kb.get("technique_names", {})

    # Resolve a feed actor string onto its ATT&CK canonical name via aliases.
    alias_to_actor: dict[str, str] = {}
    for name, row in kb_actors.items():
        alias_to_actor[name.lower()] = name
        for a in row.get("aliases", []) or []:
            alias_to_actor.setdefault(a.lower(), name)

    seen_actors: dict[str, int] = defaultdict(int)
    seen_software: dict[str, int] = defaultdict(int)
    seen_tech: dict[str, int] = defaultdict(int)
    seen_sectors: dict[str, int] = defaultdict(int)
    actor_sector: dict[tuple[str, str], int] = defaultdict(int)
    actor_tech_observed: dict[tuple[str, str], int] = defaultdict(int)
    tech_sector: dict[tuple[str, str], int] = defaultdict(int)
    actor_items: dict[str, list[str]] = defaultdict(list)
    tech_items: dict[str, list[str]] = defaultdict(list)

    for item in items:
        raw_actors = item.get("threat_actors") or []
        actors = []
        for raw in raw_actors:
            canonical = alias_to_actor.get(str(raw).lower(), str(raw))
            actors.append(canonical)
            seen_actors[canonical] += 1
            if len(actor_items[canonical]) < 8:
                actor_items[canonical].append(item.get("title", "")[:120])
        for name in item.get("malware") or []:
            seen_software[name] += 1
        techs = [t.get("id") for t in (item.get("ttps") or []) if t.get("id")]
        for tid in techs:
            seen_tech[tid] += 1
            if len(tech_items[tid]) < 8:
                tech_items[tid].append(item.get("title", "")[:120])
        sector = item.get("sector")
        if sector:
            seen_sectors[sector] += 1

        for a in actors:
            for tid in techs:
                actor_tech_observed[(a, tid)] += 1
            if sector:
                actor_sector[(a, sector)] += 1
        if sector:
            for tid in techs:
                tech_sector[(tid, sector)] += 1

    if not (seen_actors or seen_tech or seen_software):
        return None

    # Pull in the software an observed actor is KNOWN to use, even when the
    # feed did not name it this week — that is the entire value of the KB.
    for actor in list(seen_actors):
        for sw in kb_actors.get(actor, {}).get("software", [])[:6]:
            seen_software.setdefault(sw, 0)

    nodes = []
    edges = []

    def _trim(counter: dict, cap: int) -> list[str]:
        return [k for k, _ in sorted(counter.items(), key=lambda kv: -kv[1])[:cap]]

    keep_actors = _trim(seen_actors, max_nodes // 4)
    keep_tech = _trim(seen_tech, max_nodes // 3)
    keep_software = _trim(seen_software, max_nodes // 4)
    keep_sectors = _trim(seen_sectors, max_nodes // 8)

    for name in keep_actors:
        row = kb_actors.get(name, {})
        nodes.append({
            "id": f"actor:{name}", "type": "actor", "label": name,
            "count": seen_actors[name],
            "aliases": (row.get("aliases") or [])[:6],
            "url": row.get("url", ""),
            "known_techniques": len(row.get("techniques", []) or []),
            "examples": actor_items.get(name, []),
        })
    for name in keep_software:
        row = kb_software.get(name, {}) or (families or {}).get(name, {})
        nodes.append({
            "id": f"software:{name}", "type": "software", "label": name,
            "count": seen_software.get(name, 0),
            "kind": row.get("kind", "malware"),
            "aliases": (row.get("aliases") or [])[:6],
            "url": row.get("url", ""),
        })
    for tid in keep_tech:
        nodes.append({
            "id": f"technique:{tid}", "type": "technique", "label": tid,
            "name": tech_names.get(tid, ""),
            "count": seen_tech[tid],
            "examples": tech_items.get(tid, []),
        })
    for sector in keep_sectors:
        nodes.append({
            "id": f"sector:{sector}", "type": "sector", "label": sector,
            "count": seen_sectors[sector],
        })

    node_ids = {n["id"] for n in nodes}

    def _edge(src: str, dst: str, kind: str, origin: str, weight: int = 1) -> None:
        if src in node_ids and dst in node_ids:
            edges.append({"source": src, "target": dst, "kind": kind,
                          "origin": origin, "weight": weight})

    # KNOWN edges: MITRE says so.
    for name in keep_actors:
        row = kb_actors.get(name, {})
        for sw in row.get("software", []) or []:
            _edge(f"actor:{name}", f"software:{sw}", "uses", "attack")
        for tid in row.get("techniques", []) or []:
            _edge(f"actor:{name}", f"technique:{tid}", "uses", "attack")
    for name in keep_software:
        for tid in (kb_software.get(name, {}).get("techniques", []) or []):
            _edge(f"software:{name}", f"technique:{tid}", "implements", "attack")

    # OBSERVED edges: this feed, this window.
    for (actor, sector), n in actor_sector.items():
        _edge(f"actor:{actor}", f"sector:{sector}", "targets", "observed", n)
    for (actor, tid), n in actor_tech_observed.items():
        _edge(f"actor:{actor}", f"technique:{tid}", "seen-with", "observed", n)
    for (tid, sector), n in tech_sector.items():
        _edge(f"technique:{tid}", f"sector:{sector}", "seen-against", "observed", n)

    # Collapse duplicate (source,target,kind) pairs, keeping the heaviest.
    unique: dict[tuple, dict] = {}
    for e in edges:
        key = (e["source"], e["target"], e["kind"])
        prev = unique.get(key)
        if not prev or e["weight"] > prev["weight"]:
            unique[key] = e
    edges = list(unique.values())

    return {
        "generated": now_utc(),
        "kb_built": kb.get("built", ""),
        "counts": {
            "actors": len(keep_actors), "software": len(keep_software),
            "techniques": len(keep_tech), "sectors": len(keep_sectors),
            "edges": len(edges),
            "known_edges": sum(1 for e in edges if e["origin"] == "attack"),
            "observed_edges": sum(1 for e in edges if e["origin"] == "observed"),
        },
        "nodes": nodes,
        "edges": edges,
    }


if __name__ == "__main__":  # pragma: no cover - manual refresh
    import json
    from pathlib import Path
    kb = load_attack_kb(force="--force" in __import__("sys").argv)
    if not kb:
        raise SystemExit("could not build the ATT&CK knowledge base")
    root = Path(__file__).resolve().parent.parent
    intel = json.loads((root / "data/intel.json").read_text(encoding="utf-8"))
    annotate_malware(intel["items"], kb)
    graph = build_entity_graph(intel["items"], kb)
    print(json.dumps(graph["counts"], indent=2))
