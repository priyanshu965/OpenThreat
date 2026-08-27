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

# v3 reads detection from ATT&CK's CURRENT structure. v2 read
# `x_mitre_detection` and `x_mitre_data_sources` off the attack-pattern,
# which is where they lived until ATT&CK v18 moved them out. Those fields
# are now absent from every technique, so v2 published an empty 'how to see
# it' section for all 697 of them and reported nothing wrong.
#
# The cache NAME carries the version deliberately. A warm v1 cache is a
# different shape, and the KEV incident in this repo is what a silently
# accepted stale shape costs: the loader accepted it, nothing errored, and the
# published output was wrong for a full TTL. A new name makes a v1 cache a
# miss by construction rather than by a check somebody has to remember.
_KB_CACHE = "attack_kb_v3.json"

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


def _prose(value, limit: int | None = None) -> str:
    """Collapse STIX markdown prose to a single clean string."""
    text = " ".join(str(value or "").split())
    # ATT&CK descriptions are markdown with inline citation markers like
    # "(Citation: FireEye APT29)". They are noise on a rendered page and they
    # are most of the byte count, so they go.
    text = re.sub(r"\(Citation:[^)]*\)", "", text)
    text = re.sub(r"\[([^\]]+)\]\((?:https?://)?[^)]*\)", r"", text)
    text = " ".join(text.split())
    cap = limit if limit is not None else CONFIG.kb_description_chars
    return text[:cap]


def _references(obj: dict, limit: int = 12) -> list[dict]:
    """External references worth showing a reader, minus the ATT&CK self-link."""
    out = []
    for ref in obj.get("external_references", []) or []:
        url = str(ref.get("url") or "")
        if not url.startswith("http"):
            continue
        if ref.get("source_name") == "mitre-attack":
            continue
        out.append({"name": str(ref.get("source_name") or "")[:120],
                    "url": url[:400],
                    "description": _prose(ref.get("description"), 220)})
        if len(out) >= limit:
            break
    return out


def _derive_kb() -> dict | None:
    """
    Download the CTI bundle and reduce it to the encyclopedia.

    v1 kept names, aliases and `uses` edges — about 5% of what the bundle
    carries — and discarded the descriptions, the detection guidance, the
    mitigations and the campaigns. Those are precisely the content an entity
    page is made of, and they were already on the wire. This keeps them.
    """
    log.info("  Building ATT&CK knowledge base from MITRE CTI (48 MB, once a month)...")
    bundle = stream_json(_CTI_URL)
    objects = bundle.get("objects", [])

    by_id: dict[str, dict] = {}
    actors: dict[str, dict] = {}
    software: dict[str, dict] = {}
    techniques: dict[str, dict] = {}
    mitigations: dict[str, dict] = {}
    campaigns: dict[str, dict] = {}
    technique_names: dict[str, str] = {}
    technique_tactics: dict[str, list[str]] = {}
    # ATT&CK v18 replaced the free-text `x_mitre_detection` field with a small
    # object graph, and it is a considerable improvement:
    #
    #   x-mitre-detection-strategy --detects--> attack-pattern
    #            |  x_mitre_analytic_refs
    #            v
    #   x-mitre-analytic  (concrete detection logic + the log sources it needs)
    #            |  x_mitre_log_source_references
    #            v
    #   x-mitre-data-component  ("auditd:SYSCALL", channel "socket/connect")
    #
    # The old field was one paragraph of prose per technique. This is 1,758
    # analytics naming the actual telemetry and channel, which is what a hunter
    # needs to know whether they can run the detection at all.
    data_components: dict[str, str] = {}
    analytics: dict[str, dict] = {}
    strategies: dict[str, dict] = {}

    _ENTITY_TYPES = ("intrusion-set", "malware", "tool", "attack-pattern",
                     "course-of-action", "campaign")

    for obj in objects:
        oid = obj.get("id")
        if not oid:
            continue
        otype = obj.get("type")
        if otype in _ENTITY_TYPES:
            by_id[oid] = obj
        if otype == "x-mitre-data-component" and _live(obj):
            data_components[oid] = (obj.get("name") or "").strip()
        elif otype == "x-mitre-analytic" and _live(obj):
            sources = []
            for ref in obj.get("x_mitre_log_source_references") or []:
                if not isinstance(ref, dict):
                    continue
                sources.append({
                    "name": str(ref.get("name") or "")[:80],
                    "channel": str(ref.get("channel") or "")[:120],
                    "component": str(ref.get("x_mitre_data_component_ref") or ""),
                })
            analytics[oid] = {
                "id": _external_id(obj),
                "name": (obj.get("name") or "").strip()[:80],
                "description": _prose(obj.get("description"), 1200),
                "platforms": [str(x) for x in (obj.get("x_mitre_platforms") or [])][:10],
                "log_sources": sources[:12],
                "url": _external_url(obj),
            }
        elif otype == "x-mitre-detection-strategy" and _live(obj):
            strategies[oid] = {
                "id": _external_id(obj),
                "name": (obj.get("name") or "").strip()[:120],
                "description": _prose(obj.get("description"), 900),
                "url": _external_url(obj),
                "analytic_refs": [str(r) for r in
                                  (obj.get("x_mitre_analytic_refs") or [])][:20],
            }
        if otype == "attack-pattern" and _live(obj):
            tid = _external_id(obj)
            if tid:
                technique_names[tid] = obj.get("name", tid)
                tactics = [
                    p.get("phase_name", "") for p in obj.get("kill_chain_phases", []) or []
                    if p.get("kill_chain_name") == "mitre-attack"
                ]
                technique_tactics[tid] = tactics
                techniques[tid] = {
                    "id": tid,
                    "name": obj.get("name", tid),
                    "kind": "technique",
                    "description": _prose(obj.get("description")),
                    # Filled in from the detection-strategy graph below, not
                    # from the technique object: ATT&CK v18 no longer carries
                    # either of these on the attack-pattern.
                    "detection": "",
                    "detection_strategies": [],
                    "platforms": [str(x) for x in (obj.get("x_mitre_platforms") or [])][:14],
                    "data_sources": [],
                    "permissions": [str(x) for x in
                                    (obj.get("x_mitre_permissions_required") or [])][:8],
                    "is_subtechnique": bool(obj.get("x_mitre_is_subtechnique")),
                    "parent": tid.split(".")[0] if "." in tid else "",
                    "tactics": tactics,
                    "url": _external_url(obj),
                    "references": _references(obj),
                    "mitigations": [], "actors": [], "software": [],
                    "subtechniques": [], "detects": [],
                }

    for obj in objects:
        if not _live(obj):
            continue
        name = (obj.get("name") or "").strip()
        if not name:
            continue
        otype = obj.get("type")
        if otype == "intrusion-set":
            actors[name] = {
                "name": name,
                "id": _external_id(obj),
                "kind": "actor",
                # TWO alias lists, and the difference matters.
                #   aliases      match-safe: what may be fired against prose.
                #   all_aliases  every name MITRE records, for display and for
                #                name deconfliction.
                # "Group 5" is useless as a matcher (it would hit any sentence
                # containing the words) and essential as a lookup key, because
                # somebody will search for it.
                "aliases": _usable_aliases(name, obj.get("aliases")),
                "all_aliases": sorted({str(a).strip() for a in (obj.get("aliases") or [])
                                       if str(a).strip() and str(a).strip() != name}),
                "description": _prose(obj.get("description")),
                "url": _external_url(obj),
                "references": _references(obj),
                "first_seen": "", "last_seen": "",
                "techniques": [], "software": [], "campaigns": [],
            }
        elif otype in ("malware", "tool"):
            software[name] = {
                "name": name,
                "id": _external_id(obj),
                "kind": "malware" if otype == "malware" else "tool",
                "aliases": _usable_aliases(name, obj.get("x_mitre_aliases")),
                "all_aliases": sorted({str(a).strip() for a in
                                       (obj.get("x_mitre_aliases") or [])
                                       if str(a).strip() and str(a).strip() != name}),
                "description": _prose(obj.get("description")),
                "platforms": [str(x) for x in (obj.get("x_mitre_platforms") or [])][:14],
                "url": _external_url(obj),
                "references": _references(obj),
                "techniques": [], "actors": [], "campaigns": [],
            }
        elif otype == "course-of-action":
            mid = _external_id(obj)
            if mid:
                mitigations[mid] = {
                    "id": mid, "name": name, "kind": "mitigation",
                    "description": _prose(obj.get("description"), 1600),
                    "url": _external_url(obj),
                    "techniques": [],
                }
        elif otype == "campaign":
            cid = _external_id(obj)
            campaigns[name] = {
                "name": name, "id": cid, "kind": "attack-campaign",
                "description": _prose(obj.get("description")),
                "aliases": sorted({str(a).strip() for a in (obj.get("aliases") or [])
                                   if str(a).strip() and str(a).strip() != name}),
                "first_seen": str(obj.get("first_seen") or "")[:10],
                "last_seen": str(obj.get("last_seen") or "")[:10],
                "url": _external_url(obj),
                "references": _references(obj),
                "actors": [], "software": [], "techniques": [],
            }

    # ── Relationship pass ─────────────────────────────────────────────────
    # v1 read only `uses`. The bundle also carries `mitigates` (how to stop
    # it), `detects` (what telemetry sees it), `attributed-to` (campaign ->
    # actor) and `subtechnique-of` (the matrix hierarchy). Each one is a
    # section of an entity page that had no data behind it before.
    id_to_name = {oid: (o.get("name") or "").strip() for oid, o in by_id.items()}
    edges = 0
    _WANTED = {"uses", "mitigates", "detects", "attributed-to", "subtechnique-of"}
    for obj in objects:
        if obj.get("type") != "relationship":
            continue
        rel = obj.get("relationship_type")
        if rel not in _WANTED or not _live(obj):
            continue

        src_ref, dst_ref = obj.get("source_ref"), obj.get("target_ref")

        # `detects` runs from an x-mitre-data-component, which is not in by_id
        # (it is not an entity anyone browses to), so it is resolved from its
        # own table before the by_id lookup below would reject it.
        if rel == "detects":
            # v2 expected a data-component here. The source is a
            # DETECTION STRATEGY, so the lookup never matched and every
            # technique's telemetry list stayed empty.
            strategy = strategies.get(src_ref)
            dst_obj = by_id.get(dst_ref)
            if not strategy or not dst_obj or dst_obj.get("type") != "attack-pattern":
                continue
            tid = _external_id(dst_obj)
            row = techniques.get(tid)
            if not row:
                continue

            resolved = []
            for ref in strategy["analytic_refs"]:
                analytic = analytics.get(ref)
                if not analytic:
                    continue
                for source in analytic["log_sources"]:
                    label = source["name"]
                    if source["channel"]:
                        label = f"{label} ({source['channel']})"
                    if label and label not in row["detects"]:
                        row["detects"].append(label)
                    component = data_components.get(source["component"])
                    if component and component not in row["data_sources"]:
                        row["data_sources"].append(component)
                resolved.append({k: analytic[k] for k in
                                 ("id", "name", "description", "platforms", "url")})

            row["detection_strategies"].append({
                "id": strategy["id"], "name": strategy["name"],
                "description": strategy["description"], "url": strategy["url"],
                "analytics": resolved[:8],
            })
            # The prose field every consumer already reads: the analytics,
            # joined. Keeps one place to look for "how do I see this".
            row["detection"] = " ".join(
                a["description"] for s2 in row["detection_strategies"]
                for a in s2["analytics"] if a["description"])[:2500]
            edges += 1
            continue

        src = by_id.get(src_ref)
        dst = by_id.get(dst_ref)
        if not src or not dst:
            continue
        src_name = id_to_name.get(src_ref, "")
        dst_name = id_to_name.get(dst_ref, "")
        src_type, dst_type = src.get("type"), dst.get("type")

        if rel == "mitigates":
            mid = _external_id(src)
            if dst_type == "attack-pattern" and mid in mitigations:
                tid = _external_id(dst)
                if tid:
                    mitigations[mid]["techniques"].append(tid)
                    if tid in techniques:
                        techniques[tid]["mitigations"].append(mid)
                    edges += 1
            continue

        if rel == "subtechnique-of":
            if src_type == dst_type == "attack-pattern":
                child, parent = _external_id(src), _external_id(dst)
                if child and parent in techniques:
                    techniques[parent]["subtechniques"].append(child)
                    edges += 1
            continue

        if rel == "attributed-to":
            # campaign --attributed-to--> intrusion-set
            if src_type == "campaign" and dst_type == "intrusion-set":
                if src_name in campaigns and dst_name in actors:
                    campaigns[src_name]["actors"].append(dst_name)
                    actors[dst_name]["campaigns"].append(src_name)
                    edges += 1
            continue

        # rel == "uses"
        if src_type == "intrusion-set" and dst_type == "attack-pattern":
            tid = _external_id(dst)
            if tid and src_name in actors:
                actors[src_name]["techniques"].append(tid)
                if tid in techniques:
                    techniques[tid]["actors"].append(src_name)
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
                if tid in techniques:
                    techniques[tid]["software"].append(src_name)
                edges += 1
        elif src_type == "campaign" and dst_type == "attack-pattern":
            tid = _external_id(dst)
            if tid and src_name in campaigns:
                campaigns[src_name]["techniques"].append(tid)
                edges += 1
        elif src_type == "campaign" and dst_type in ("malware", "tool"):
            if src_name in campaigns and dst_name in software:
                campaigns[src_name]["software"].append(dst_name)
                edges += 1

    # A campaign's dates are the best evidence ATT&CK carries for WHEN an actor
    # was active; the intrusion-set objects have no dates of their own.
    for camp in campaigns.values():
        for actor_name in camp["actors"]:
            row = actors.get(actor_name)
            if not row:
                continue
            for key, value in (("first_seen", camp["first_seen"]),
                               ("last_seen", camp["last_seen"])):
                if not value:
                    continue
                current = row.get(key) or ""
                if not current or (value < current if key == "first_seen"
                                   else value > current):
                    row[key] = value

    for table in (actors, software, techniques, mitigations, campaigns):
        for row in table.values():
            for key in ("techniques", "software", "actors", "campaigns",
                        "mitigations", "subtechniques"):
                if key in row:
                    row[key] = sorted(set(row[key]))
            # `detects` and `data_sources` are already deduplicated in the
            # order the analytics list them, which is the order a defender
            # would set the telemetry up in. Re-sorting alphabetically would
            # throw that away for no gain.
            for key in ("detects", "data_sources"):
                if key in row:
                    row[key] = row[key][:20]

    log.info(f"  ATT&CK KB v3: {len(actors)} actors, {len(software)} software, "
             f"{len(technique_names)} techniques, {len(mitigations)} mitigations, "
             f"{len(campaigns)} campaigns, {edges} edges")
    log.info(f"  Detection: {sum(1 for t in techniques.values() if t['detection_strategies'])} "
             f"techniques carry a detection strategy, "
             f"{sum(len(t['detection_strategies']) for t in techniques.values())} "
             f"strategies over {len(analytics)} analytics")
    log.info(f"  Prose kept for "
             f"{sum(1 for t in list(actors.values()) + list(software.values()) if t.get('description'))}"
             f" actor/software entities; "
             f"{sum(1 for t in techniques.values() if t['detection'])} techniques "
             f"carry detection guidance")
    return {
        "built": now_utc(),
        "source": _CTI_URL,
        "version": 3,
        "actors": actors,
        "software": software,
        "techniques": techniques,
        "mitigations": mitigations,
        "attack_campaigns": campaigns,
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
