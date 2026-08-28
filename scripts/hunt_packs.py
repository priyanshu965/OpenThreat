"""
OPENTHREAT — hunt_packs.py
===========================
The thing that turns a reader into an instrument.

Everything the pipeline built before this told you something. Nothing let you
DO anything. You could learn that Akira used T1486 this week and the tool's
contribution ended there — the analyst still had to go and find a rule, work
out what it says, translate it into whatever SIEM they actually run, and dig up
a way to test it. That is twenty minutes of tab-shuffling per technique, done
independently by every person who reads the same advisory.

A hunt pack is that work, precomputed:

    T1486  Data Encrypted for Impact
      ├─ what it is            ATT&CK prose + MITRE's own detection guidance
      ├─ detections            the Sigma rules that cover it
      ├─ queries               those rules COMPILED for Splunk / ES|QL /
      │                        Lucene / KQL — paste-ready
      ├─ validation            Atomic Red Team tests that make it happen
      ├─ telemetry             the data sources you need to be collecting
      └─ countermeasures       D3FEND + ATT&CK mitigations + your control set

All of it is static JSON built in CI. There is no server, no licence, and no
account. As far as I can tell nobody else gives this away.

WHY COMPILATION IS OPTIONAL
---------------------------
pySigma and its backends are a fast-moving set of packages, and this pipeline
runs unattended 24 times a day. Pinning four extra libraries into the critical
path of an hourly job — where a resolver conflict means no feed at all — buys a
convenience feature at the cost of the whole product.

So they live in requirements-hunt.txt, are installed best-effort, and every
backend is probed independently at import. With none of them present the packs
still publish, still carry the rules, the atomics and the countermeasures, and
say plainly that queries are unavailable. Degraded, not broken.
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from pathlib import Path

from fetchlib import (CONFIG, cached_derive, item_technique_ids,
                      item_url, log, now_utc)

# A pack's technique id becomes a filename. It comes from ATT&CK and always
# matches this, but it is validated rather than trusted: it reaches a path.
_TECHNIQUE_ID = re.compile(r"^T\d{4}(?:\.\d{3})?$")


# ── Backend registry ──────────────────────────────────────────────────────────
# Each entry: (key, human label, zero-arg factory). Factories are called inside
# a try/except at build time, so a backend that is missing, broken, or
# incompatible with the installed pySigma core simply does not appear in the
# output — it never takes the run down with it.
def _backend_factories():
    factories = []

    def _splunk():
        from sigma.backends.splunk import SplunkBackend
        return SplunkBackend()

    def _esql():
        from sigma.backends.elasticsearch import ESQLBackend
        return ESQLBackend()

    def _lucene():
        from sigma.backends.elasticsearch import LuceneBackend
        return LuceneBackend()

    def _eql():
        from sigma.backends.elasticsearch import EqlBackend
        return EqlBackend()

    def _sentinel():
        # The Kusto backend needs an explicit pipeline: the same rule targets
        # Sentinel's ASIM schema and Defender XDR's tables differently, and
        # emitting one and labelling it the other would be worse than emitting
        # nothing.
        from sigma.backends.kusto import KustoBackend
        from sigma.pipelines.sentinelasim import sentinel_asim_pipeline
        return KustoBackend(processing_pipeline=sentinel_asim_pipeline())

    def _defender():
        # `sigma.pipelines.microsoftxdr`, NOT the older
        # `sigma.pipelines.microsoft365defender` — the latter still exists as a
        # deprecated shim and does not export this pipeline. Verified against
        # the installed backend rather than guessed; the wrong one raises
        # ImportError and would have silently cost this backend.
        from sigma.backends.kusto import KustoBackend
        from sigma.pipelines.microsoftxdr import microsoft_xdr_pipeline
        return KustoBackend(processing_pipeline=microsoft_xdr_pipeline())

    factories.append(("splunk", "Splunk SPL", _splunk))
    factories.append(("esql", "Elastic ES|QL", _esql))
    factories.append(("lucene", "Elastic Lucene", _lucene))
    factories.append(("eql", "Elastic EQL", _eql))
    factories.append(("sentinel", "Microsoft Sentinel (KQL)", _sentinel))
    factories.append(("defender", "Defender XDR (KQL)", _defender))
    return factories


def _live_backends() -> list[tuple]:
    """(key, label, backend) for every backend that actually imported."""
    live = []
    for key, label, factory in _backend_factories():
        try:
            live.append((key, label, factory()))
        except Exception as e:  # noqa: BLE001 - absent or incompatible: skip it
            log.info(f"    query backend {key} unavailable ({type(e).__name__})")
    return live


def _compile_one(body: str, backends: list[tuple]) -> dict:
    """
    rule YAML -> {backend key: query}. Silent per-backend failure.

    A FRESH SigmaCollection is parsed for every backend, and that is not
    defensive habit — it is required. A backend's processing pipeline rewrites
    field names IN PLACE on the collection it is handed, so passing one
    collection to several backends corrupts it after the first:

        KustoBackend(microsoft_xdr)   Image -> FolderPath          (succeeds)
        KustoBackend(sentinel_asim)   FolderPath -> ???            (raises)

    The failure is quiet in the worst way. Splunk and the Elastic backends
    carry no field mappings, so they convert correctly regardless and the bug
    only eats the SECOND Kusto dialect — one missing query among thousands,
    with an exception swallowed by the per-backend guard below. Verified
    against the installed packages: converting a fresh collection for the same
    rule produces valid output for both dialects.
    """
    try:
        from sigma.collection import SigmaCollection
    except ImportError:
        return {}

    out = {}
    for key, _label, backend in backends:
        try:
            collection = SigmaCollection.from_yaml(body)
        except Exception:  # noqa: BLE001 - a rule using an unsupported construct
            return {}
        try:
            queries = backend.convert(collection)
        except Exception:  # noqa: BLE001
            continue
        if not queries:
            continue
        text = queries[0] if isinstance(queries, list) else str(queries)
        text = str(text).strip()
        # A "compiled" query longer than this is a rule with a 400-item value
        # list; it is not something anyone pastes into a search bar.
        if text and len(text) <= 12000:
            out[key] = text
    return out


# ── Pack construction ─────────────────────────────────────────────────────────

def _rank_techniques(technique_counts: dict, sigma_index: dict,
                     limit: int) -> list[str]:
    """
    Which techniques get a pack.

    Observed activity first — a pack for something in this week's feed is worth
    more than a pack for a technique nobody has touched — then coverage, so the
    remaining slots go to techniques with rules worth compiling.
    """
    by_technique = (sigma_index or {}).get("by_technique") or {}
    ranked = sorted(
        set(by_technique) | set(technique_counts or {}),
        key=lambda tid: (-(technique_counts or {}).get(tid, 0),
                         -len(by_technique.get(tid, [])),
                         tid),
    )
    return ranked[:limit]


def _derive_queries(rule_ids: list[str], fetch_bodies) -> dict:
    """
    rule id -> {backend: query}, cached weekly.

    Cached on its own rather than inside the pack build because it is the only
    expensive part: fetching the archive plus a few thousand conversions. The
    packs themselves are rebuilt every run from cheap joins.
    """
    backends = _live_backends()
    if not backends:
        log.warning("  No Sigma query backends installed - packs will carry raw rules only")
        return {"built": now_utc(), "backends": [], "queries": {}}

    labels = {key: label for key, label, _ in _backend_factories()}
    log.info(f"  Compiling Sigma rules for {len(backends)} backends: "
             f"{', '.join(k for k, _, _ in backends)}")

    try:
        bodies = fetch_bodies(rule_ids)
    except Exception as e:  # noqa: BLE001
        log.warning(f"  Could not fetch Sigma rule bodies: {e}")
        return {"built": now_utc(), "backends": [], "queries": {}}

    queries: dict[str, dict] = {}
    converted = 0
    for rid, body in bodies.items():
        result = _compile_one(body, backends)
        if result:
            queries[rid] = result
            converted += 1

    log.info(f"  Compiled {converted} of {len(bodies)} rules into "
             f"{sum(len(v) for v in queries.values())} queries")
    return {
        "built": now_utc(),
        "backends": [{"key": k, "label": labels.get(k, k)} for k, _, _ in backends],
        "queries": queries,
    }


def load_compiled_queries(rule_ids: list[str], fetch_bodies,
                          force: bool = False) -> dict:
    """{backends: [...], queries: {rule_id: {backend: query}}}."""
    if not (CONFIG.enable_hunt_packs and CONFIG.enable_sigma_compile):
        return {}
    ttl = 0 if force else CONFIG.sigma_ttl_hours
    return cached_derive("sigma_queries.json", ttl,
                         lambda: _derive_queries(rule_ids, fetch_bodies)) or {}


def build_hunt_packs(technique_counts: dict, sigma_index: dict, kb: dict,
                     atomics: dict, d3fend_table: dict, control_frameworks: dict,
                     fetch_bodies=None) -> dict | None:
    """
    One pack per technique, assembled from everything the pipeline knows.

    `technique_counts` is technique id -> observed count this run, and is what
    makes a pack timely rather than merely encyclopedic.
    """
    if not CONFIG.enable_hunt_packs:
        return None
    sigma_index = sigma_index or {}
    by_technique = sigma_index.get("by_technique") or {}
    totals = sigma_index.get("totals") or {}
    kb = kb or {}
    kb_techniques = kb.get("techniques") or {}
    technique_names = kb.get("technique_names") or {}
    technique_counts = technique_counts or {}

    chosen = _rank_techniques(technique_counts, sigma_index, CONFIG.hunt_packs_max)
    if not chosen:
        return None

    rules_per_pack = CONFIG.hunt_pack_rules_max
    wanted_rule_ids: list[str] = []
    for tid in chosen:
        for rule in by_technique.get(tid, [])[:rules_per_pack]:
            if rule.get("id"):
                wanted_rule_ids.append(rule["id"])
        if len(wanted_rule_ids) >= CONFIG.sigma_compile_budget:
            break

    compiled = {}
    backends = []
    if fetch_bodies is not None and wanted_rule_ids:
        payload = load_compiled_queries(wanted_rule_ids[:CONFIG.sigma_compile_budget],
                                        fetch_bodies)
        compiled = (payload or {}).get("queries") or {}
        backends = (payload or {}).get("backends") or []

    # Lazily imported so this module does not hard-depend on either.
    try:
        from d3fend import countermeasures_for
    except ImportError:  # pragma: no cover
        countermeasures_for = None
    try:
        from control_mappings import controls_for
    except ImportError:  # pragma: no cover
        controls_for = None
    try:
        from atomics import tests_for
    except ImportError:  # pragma: no cover
        tests_for = None

    packs = []
    with_queries = 0
    with_tests = 0
    for tid in chosen:
        meta = kb_techniques.get(tid) or {}
        rules = []
        for rule in by_technique.get(tid, [])[:rules_per_pack]:
            row = dict(rule)
            row["queries"] = compiled.get(rule.get("id") or "", {})
            rules.append(row)
        if any(r["queries"] for r in rules):
            with_queries += 1

        tests = tests_for(tid, atomics or {}, 4) if tests_for else []
        if tests:
            with_tests += 1

        counters = countermeasures_for(tid, d3fend_table or {}) if countermeasures_for else []
        controls = controls_for(tid, control_frameworks or {}) if controls_for else {}

        packs.append({
            "technique": tid,
            "name": meta.get("name") or technique_names.get(tid) or tid,
            "tactics": meta.get("tactics") or [],
            "description": (meta.get("description") or "")[:900],
            # MITRE's written detection guidance. The single best paragraph in
            # the whole bundle for a hunter, and v4 downloaded and binned it.
            "mitre_detection": meta.get("detection") or "",
            "detection_strategies": meta.get("detection_strategies") or [],
            "platforms": meta.get("platforms") or [],
            "data_sources": meta.get("data_sources") or [],
            "telemetry": meta.get("detects") or [],
            "observed": int(technique_counts.get(tid, 0)),
            "rules": rules,
            "rules_total": int(totals.get(tid, len(rules))),
            "atomics": tests,
            "countermeasures": counters[:12],
            "attack_mitigations": meta.get("mitigations") or [],
            "controls": controls,
            "url": meta.get("url") or f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/",
        })

    packs.sort(key=lambda p: (-p["observed"], -len(p["rules"]), p["technique"]))
    log.info(f"  Hunt packs: {len(packs)} techniques "
             f"({with_queries} with compiled queries, {with_tests} with atomics)")
    return {
        "built": now_utc(),
        "count": len(packs),
        "backends": backends,
        "queries_available": bool(backends),
        "with_queries": with_queries,
        "with_atomics": with_tests,
        "packs": packs,
    }


def write_hunt_shards(payload: dict, api_dir) -> int:
    """
    Split the packs into an index plus one file per technique.

    A pack carries MITRE's prose, up to eight Sigma rules, each compiled for
    six SIEMs, four atomic tests with their full command and cleanup, and a
    countermeasure set. That is ~20 KB each and 4.5 MB across 220 of them --
    downloaded in full, by every visitor, to read ONE technique.

    This is the same split the Library uses, for the same reason. The index
    holds what the list view renders (id, name, tactics, counts); the shard
    holds everything the detail view needs. Opening a pack costs 20 KB.
    """
    if not payload or not payload.get("packs"):
        return 0
    api_dir = Path(api_dir)
    shard_dir = api_dir / "hunt"
    shard_dir.mkdir(parents=True, exist_ok=True)

    wanted = set()
    index = []
    for pack in payload["packs"]:
        tid = str(pack.get("technique") or "")
        if not _TECHNIQUE_ID.match(tid):
            log.warning(f"  Skipping hunt shard for malformed technique id {tid!r}")
            continue
        name = f"{tid}.json"
        wanted.add(name)
        (shard_dir / name).write_text(
            json.dumps(pack, ensure_ascii=False, separators=(",", ":")),
            encoding="utf-8")
        index.append({
            "technique": tid,
            "name": pack.get("name", tid),
            "tactics": pack.get("tactics", []),
            "observed": pack.get("observed", 0),
            "rules": len(pack.get("rules") or []),
            "rules_total": pack.get("rules_total", 0),
            "atomics": len(pack.get("atomics") or []),
            "has_queries": any(r.get("queries") for r in pack.get("rules") or []),
        })

    removed = 0
    for existing in shard_dir.glob("*.json"):
        if existing.name not in wanted:
            existing.unlink()
            removed += 1

    (api_dir / "hunt_packs.json").write_text(
        json.dumps({
            "built": payload.get("built"),
            "count": len(index),
            "backends": payload.get("backends", []),
            "queries_available": payload.get("queries_available", False),
            "with_queries": payload.get("with_queries", 0),
            "with_atomics": payload.get("with_atomics", 0),
            "packs": index,
        }, ensure_ascii=False, separators=(",", ":")),
        encoding="utf-8")

    if removed:
        log.info(f"  Removed {removed} stale hunt shard(s)")
    return len(index)



def build_hunt_queue(items: list[dict], technique_counts: dict,
                     kb: dict, sigma_index: dict, actor_counts: dict) -> dict | None:
    """
    The hypothesis generator.

    The chain has been sitting in the data since v4 and nothing ever walked it:

        actor active this week -> techniques ATT&CK says they use
          -> Sigma rules that cover those -> hunts you should run today

    What makes this a QUEUE rather than a list is that each row carries its own
    justification and a stop condition. "Hunt T1078 because Scattered Spider is
    active and you have 6 rules for it" is a task somebody can pick up, finish,
    and tick off. "Here are 400 techniques" is not.
    """
    if not CONFIG.enable_hunt_queue or not items:
        return None
    kb = kb or {}
    kb_actors = kb.get("actors") or {}
    kb_techniques = kb.get("techniques") or {}
    technique_names = kb.get("technique_names") or {}
    by_technique = (sigma_index or {}).get("by_technique") or {}
    technique_counts = technique_counts or {}

    # technique -> why we are suggesting it
    reasons: dict[str, dict] = defaultdict(
        lambda: {"actors": set(), "observed": 0, "items": []})

    for tid, count in technique_counts.items():
        reasons[tid]["observed"] = int(count or 0)

    for actor, count in (actor_counts or {}).items():
        row = kb_actors.get(actor)
        if not row:
            continue
        for tid in row.get("techniques", [])[:40]:
            reasons[tid]["actors"].add(actor)

    # A representative headline per technique, so a row is traceable back to
    # the thing that triggered it.
    for item in items:
        for tid in item_technique_ids(item):
            slot = reasons.get(tid)
            if slot is not None and len(slot["items"]) < 3:
                slot["items"].append({
                    "title": str(item.get("title") or "")[:160],
                    "url": item_url(item)[:400],
                })

    rows = []
    for tid, why in reasons.items():
        rules = by_technique.get(tid, [])
        actors = sorted(why["actors"])
        observed = why["observed"]
        if not actors and not observed:
            continue
        # Score: what is happening, weighted by whether you can actually see it.
        # A technique with no rules still scores — that IS the finding, and it
        # is surfaced as a coverage gap rather than dropped.
        score = observed * 3 + len(actors) * 2 + min(len(rules), 6)
        meta = kb_techniques.get(tid) or {}
        rows.append({
            "technique": tid,
            "name": meta.get("name") or technique_names.get(tid) or tid,
            "tactics": meta.get("tactics") or [],
            "score": score,
            "observed": observed,
            "actors": actors[:8],
            "rule_count": len(rules),
            "has_coverage": bool(rules),
            "data_sources": (meta.get("data_sources") or [])[:6],
            "evidence": why["items"],
            "hypothesis": _hypothesis(tid, meta.get("name") or tid, actors, observed,
                                      len(rules)),
        })

    rows.sort(key=lambda r: (-r["score"], r["technique"]))
    rows = rows[:CONFIG.hunt_queue_max]
    if not rows:
        return None

    gaps = sum(1 for r in rows if not r["has_coverage"])
    log.info(f"  Hunt queue: {len(rows)} hypotheses ({gaps} with no public detection)")
    return {"built": now_utc(), "count": len(rows), "uncovered": gaps, "hunts": rows}


def _hypothesis(tid: str, name: str, actors: list, observed: int,
                rule_count: int) -> str:
    """One sentence a human can act on, in the shape a hunt hypothesis takes."""
    if actors:
        who = actors[0] if len(actors) == 1 else f"{actors[0]} and {len(actors) - 1} others"
        lead = f"{who} are active in this window and ATT&CK attributes {tid} to them"
    elif observed:
        lead = (f"{tid} appeared in {observed} item"
                f"{'s' if observed != 1 else ''} in this window")
    else:
        lead = f"{tid} is worth a periodic sweep"
    if rule_count:
        tail = (f"; {rule_count} public Sigma rule{'s' if rule_count != 1 else ''} "
                f"can be run as-is")
    else:
        tail = ("; there is NO public Sigma rule for it, so this one needs "
                "telemetry review rather than a query")
    return f"Hunt for {name} ({tid}): {lead}{tail}."
