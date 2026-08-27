"""
CYBERWATCH — d3fend.py
=======================
MITRE D3FEND: what to DO about a technique.

The pipeline could already say "this week's actors used T1566.001". It had no
answer at all to the obvious next question — "so what do I change?" — because
nothing in the ingest carried countermeasures.

Two independent answers now exist, and they are complementary rather than
redundant:

    ATT&CK course-of-action   (entity_graph)  ~43 broad enterprise mitigations,
                                              e.g. "M1049 Antivirus/Antimalware"
    D3FEND defensive technique (here)         ~600 specific countermeasures with
                                              a defensive tactic and the digital
                                              artifact they act on

D3FEND is the more actionable of the two, because it names the artifact:
"Credential Hardening hardens Credential, which Create Process with Token
copies". That sentence tells a defender where to intervene, not merely that
they should.

THE SOURCE
----------
d3fend.mitre.org publishes the full inferred mapping as SPARQL JSON results —
16k bindings, 1.6 MB. Each binding is one path from an offensive technique to a
defensive one. We reduce that to `technique -> countermeasures`, deduplicated,
and keep about 90 KB.

The server is slow (multi-second, occasionally 60s+), so the fetch takes a
generous timeout and the DERIVED table is cached for a month. D3FEND ships a
few releases a year; there is nothing to gain from asking more often.
"""

from __future__ import annotations

import re
from collections import defaultdict

from fetchlib import CONFIG, SESSION, cached_derive, log, now_utc

_URL = "https://d3fend.mitre.org/api/ontology/inference/d3fend-full-mappings.json"
_CACHE = "d3fend_map.json"

# The five D3FEND defensive tactics, in the order a defender works through
# them. Presenting countermeasures grouped this way is the difference between
# a list of 40 controls and an actual plan.
TACTIC_ORDER = ["Model", "Harden", "Detect", "Isolate", "Deceive", "Evict",
                "Restore"]

_TECH_ID = re.compile(r"^T\d{4}(?:\.\d{3})?$")


def _lit(binding: dict, key: str) -> str:
    node = binding.get(key)
    if not isinstance(node, dict):
        return ""
    return str(node.get("value") or "").strip()


def _d3fend_url(iri: str) -> str:
    """`...d3fend.owl#CredentialHardening` -> the human page for it."""
    frag = iri.rsplit("#", 1)[-1].strip()
    if not frag or not frag.isidentifier():
        return ""
    return f"https://d3fend.mitre.org/technique/d3f:{frag}/"


def _derive() -> dict | None:
    log.info("  Building D3FEND countermeasure map (1.6 MB, monthly)...")
    # Deliberately not stream_json: this endpoint is slow to FIRST byte, which
    # is a read timeout rather than a size problem.
    resp = SESSION.get(_URL, timeout=max(180, CONFIG.request_timeout * 4))
    resp.raise_for_status()
    payload = resp.json()

    bindings = (payload.get("results") or {}).get("bindings") or []
    if not bindings:
        return None

    by_technique: dict[str, dict[str, dict]] = defaultdict(dict)
    tactics_seen: set[str] = set()

    for row in bindings:
        tid = _lit(row, "off_tech_id")
        if not _TECH_ID.match(tid):
            continue
        name = _lit(row, "def_tech_label")
        if not name:
            continue
        tactic = _lit(row, "def_tactic_label")
        if tactic:
            tactics_seen.add(tactic)
        # One defensive technique can reach a given ATT&CK technique by several
        # artifact paths. Keep one row per countermeasure and collect the
        # artifacts onto it — 16k bindings collapse to ~4k pairs this way.
        entry = by_technique[tid].get(name)
        if entry is None:
            entry = {
                "name": name,
                "tactic": tactic,
                "family": _lit(row, "top_def_tech_label"),
                "url": _d3fend_url(_lit(row, "def_tech")),
                "artifacts": [],
                # "hardens", "isolates", "analyzes" — the verb is what makes
                # the countermeasure legible.
                "relation": _lit(row, "def_artifact_rel_label"),
            }
            by_technique[tid][name] = entry
        artifact = _lit(row, "def_artifact_label")
        if artifact and artifact not in entry["artifacts"]:
            entry["artifacts"].append(artifact)

    def _tactic_rank(entry: dict) -> tuple:
        tactic = entry.get("tactic") or ""
        rank = TACTIC_ORDER.index(tactic) if tactic in TACTIC_ORDER else len(TACTIC_ORDER)
        return (rank, entry.get("name") or "")

    table = {}
    for tid, entries in by_technique.items():
        rows = sorted(entries.values(), key=_tactic_rank)
        for row in rows:
            row["artifacts"] = sorted(row["artifacts"])[:6]
        table[tid] = rows[:24]

    pairs = sum(len(v) for v in table.values())
    log.info(f"  D3FEND: {pairs} countermeasure links across {len(table)} techniques "
             f"({len(tactics_seen)} defensive tactics)")
    return {"built": now_utc(), "source": _URL,
            "tactics": sorted(tactics_seen), "techniques": table}


def load_d3fend(force: bool = False) -> dict:
    """technique id -> [countermeasure, ...]. {} when disabled/unavailable."""
    if not CONFIG.enable_d3fend:
        return {}
    ttl = 0 if force else CONFIG.d3fend_ttl_hours
    data = cached_derive(_CACHE, ttl, _derive)
    return (data or {}).get("techniques", {})


def countermeasures_for(technique_id: str, table: dict) -> list[dict]:
    """
    Countermeasures for a technique, falling back to its parent.

    Sub-techniques are frequently unmapped while their parent is well covered:
    D3FEND has nothing specific for T1566.001 but plenty for T1566. Returning
    the parent's advice is correct — every countermeasure for phishing applies
    to spearphishing attachments — so the fallback is marked `inherited` rather
    than hidden, and the UI says so.
    """
    if not technique_id:
        return []
    direct = table.get(technique_id)
    if direct:
        return direct
    if "." in technique_id:
        parent = technique_id.split(".")[0]
        return [dict(row, inherited=parent) for row in table.get(parent, [])]
    return []
