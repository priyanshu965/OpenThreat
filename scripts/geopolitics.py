"""
OPENTHREAT — geopolitics.py
===========================
Cross the SUSPECTED origin of a threat actor with the country and sector it is
targeting, for the geopolitical dashboard.

Attribution honesty is the whole design constraint here. Cyber attribution is
contested, political, and frequently wrong, so:

  * Actor origins come from data/actor_origins.json — version-controlled, so
    every attribution is reviewable in a diff, and each one carries a source.
  * Nothing is asserted. An origin is "suspected" unless a government has made
    a formal on-record attribution ("attributed"), and the UI must show which.
  * No confidence percentage is invented. We did not make these judgements and
    will not manufacture a number for them.
  * Target countries are extracted by whole-token matching of country names and
    demonyms — never substring, for the reasons documented across this codebase.

This module only READS actor tags that fetch_intel already produced; it adds no
new detection of its own.
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from pathlib import Path

_ORIGINS_PATH = Path(__file__).resolve().parent.parent / "data" / "actor_origins.json"

# Country name + demonym -> ISO alpha-2, for target extraction. Demonyms matter:
# "Ukrainian energy company" names a target that "Ukraine" alone would miss.
_TARGET_TERMS: dict[str, tuple[str, str]] = {}


def _add(cc: str, name: str, *terms: str) -> None:
    for t in (name, *terms):
        _TARGET_TERMS[t.lower()] = (cc, name)


_add("US", "United States", "u.s.", "usa", "american", "americans")
_add("GB", "United Kingdom", "uk", "britain", "british", "england")
_add("UA", "Ukraine", "ukrainian")
_add("RU", "Russia", "russian")
_add("CN", "China", "chinese")
_add("KP", "North Korea", "north korean")
_add("KR", "South Korea", "south korean")
_add("JP", "Japan", "japanese")
_add("IN", "India", "indian")
_add("IR", "Iran", "iranian")
_add("IL", "Israel", "israeli")
_add("DE", "Germany", "german")
_add("FR", "France", "french")
_add("TW", "Taiwan", "taiwanese")
_add("AU", "Australia", "australian")
_add("CA", "Canada", "canadian")
_add("BR", "Brazil", "brazilian")
_add("IT", "Italy", "italian")
_add("ES", "Spain", "spanish")
_add("PL", "Poland", "polish")
_add("NL", "Netherlands", "dutch")
_add("SA", "Saudi Arabia", "saudi")
_add("AE", "United Arab Emirates", "emirati", "uae")
_add("TR", "Turkey", "turkish")
_add("PK", "Pakistan", "pakistani")
_add("SG", "Singapore", "singaporean")
_add("VN", "Vietnam", "vietnamese")
_add("TH", "Thailand", "thai")
_add("ID", "Indonesia", "indonesian")
_add("MX", "Mexico", "mexican")

_TARGET_MATCHER = re.compile(
    r"(?<![0-9A-Za-z])(?:" +
    "|".join(sorted((re.escape(t).replace(r"\ ", r"\s+") for t in _TARGET_TERMS),
                    key=len, reverse=True)) +
    r")(?![0-9A-Za-z])",
    re.IGNORECASE,
)


def load_actor_origins() -> dict:
    try:
        return json.loads(_ORIGINS_PATH.read_text(encoding="utf-8")).get("actors", {})
    except Exception:
        return {}


def extract_target_countries(text: str) -> list[dict]:
    """Whole-token country/demonym extraction. Returns [{cc, name}] deduped."""
    if not text:
        return []
    seen = {}
    for m in _TARGET_MATCHER.finditer(text):
        # Normalise internal whitespace so "United\nStates" keys the same as
        # the stored "united states".
        hit = _target_lookup(m.group(0))
        if hit:
            cc, name = hit
            seen[cc] = name
    return [{"cc": cc, "name": name} for cc, name in seen.items()]


def _target_lookup(token: str):
    key = re.sub(r"\s+", " ", token.strip().lower())
    return _TARGET_TERMS.get(key)


def build_geopolitics(items: list[dict]) -> dict:
    """Compose the geopolitical view from already-tagged items.

    Reads item['threat_actors'] (produced by detect_threat_actors) and
    item['sector'] (produced by sectors.annotate_sectors), crosses them with the
    suspected-origin map and the target-country extraction, and rolls the result
    up so no per-item PII or raw text leaves this function.
    """
    origins = load_actor_origins()

    origin_activity = defaultdict(lambda: {"country": "", "confidence": "", "count": 0,
                                           "actors": set(), "sources": set(),
                                           "motives": defaultdict(int)})
    origin_vs_sector = defaultdict(lambda: defaultdict(int))
    target_country_hits = defaultdict(int)
    origin_vs_target = defaultdict(lambda: defaultdict(int))
    attributions = []       # per-actor provenance, for the honesty panel

    for item in items:
        actors = item.get("threat_actors") or []
        sector = item.get("sector")
        text = f"{item.get('title', '')} {item.get('description', '')}"
        targets = extract_target_countries(text)

        for actor in actors:
            info = origins.get(actor)
            if not info:
                continue
            cc = info["cc"]
            row = origin_activity[cc]
            row["country"] = info["country"]
            row["confidence"] = _worst_confidence(row["confidence"], info["confidence"])
            row["count"] += 1
            row["actors"].add(actor)
            row["sources"].add(info.get("source", ""))
            # Motive matters for honesty: a criminal ransomware crew hosted in a
            # country is NOT the same claim as state-sponsored activity, and
            # collapsing the two would be the most misleading thing this view
            # could do.
            row["motives"][info.get("motive", "unknown")] += 1

            if sector:
                origin_vs_sector[cc][sector] += 1
            for t in targets:
                # Don't count an actor's own suspected origin as its target.
                if t["cc"] != cc:
                    origin_vs_target[cc][t["cc"]] += 1

        for t in targets:
            target_country_hits[t["cc"]] += 1

    # Per-actor attribution provenance (deduped), for the "show your source" panel.
    seen_actors = set()
    for item in items:
        for actor in item.get("threat_actors") or []:
            if actor in seen_actors or actor not in origins:
                continue
            seen_actors.add(actor)
            info = origins[actor]
            attributions.append({
                "actor": actor, "cc": info["cc"], "country": info["country"],
                "confidence": info["confidence"], "motive": info.get("motive", "unknown"),
                "source": info.get("source", ""),
            })

    origins_out = []
    for cc, row in origin_activity.items():
        origins_out.append({
            "cc": cc, "country": row["country"], "confidence": row["confidence"],
            "count": row["count"], "actors": sorted(row["actors"]),
            "by_motive": dict(row["motives"]),
            "by_sector": dict(origin_vs_sector.get(cc, {})),
            "by_target": dict(origin_vs_target.get(cc, {})),
            "sources": sorted(s for s in row["sources"] if s),
        })
    origins_out.sort(key=lambda r: -r["count"])

    return {
        "suspected_origins": origins_out,
        "target_countries": dict(sorted(target_country_hits.items(), key=lambda kv: -kv[1])),
        "attributions": sorted(attributions, key=lambda a: a["actor"]),
        "disclaimer": ("Origins are the widely-reported public assessment, not "
                       "assertions of fact. 'suspected' unless a government has "
                       "formally attributed the actor."),
    }


def _worst_confidence(a: str, b: str) -> str:
    """When items disagree, keep the more cautious label."""
    order = {"": 0, "attributed": 2, "suspected": 1}
    return a if order.get(a, 0) and order[a] <= order.get(b, 0) else b
