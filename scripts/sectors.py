"""
OPENTHREAT — sectors.py
=======================
Assign each intel item a target SECTOR, on a confidence ladder so a guess is
never presented as a fact.

    explicit  — the source told us (Ransomware.live victim sector; a CISA ICS
                advisory's own sector tagging). Trusted.
    inferred  — whole-token keyword rules over title + description. A signal,
                not a fact.
    none      — nothing matched; sector is left unset rather than guessed.

Whole-token matching is mandatory, for the same reason it is everywhere else in
this pipeline: substring matching already burned the project once ("rce" inside
"source" mislabelled a third of critical items). "navy" inside "navigate" and
"army" inside "armygrp" are the identical trap, so the matcher below is built on
the same word-boundary regex used for threat-actor detection.
"""

from __future__ import annotations

import re

# Fixed taxonomy. Order matters only for tie-breaking (earlier wins), so the
# more specific / higher-stakes sectors are listed before the catch-alls.
DEFENCE     = "defence"
MARITIME    = "maritime"
AEROSPACE   = "aerospace"
AVIATION    = "aviation"
HEALTHCARE  = "healthcare"
ENERGY      = "energy"
WATER       = "water"
FINANCIAL   = "financial"
GOVERNMENT  = "government"
TELECOM     = "telecom"
EDUCATION   = "education"
MANUFACTURING = "manufacturing"
TRANSPORT   = "transport"
CORPORATE   = "corporate"

SECTORS = [
    DEFENCE, MARITIME, AEROSPACE, AVIATION, HEALTHCARE, ENERGY, WATER,
    FINANCIAL, GOVERNMENT, TELECOM, EDUCATION, MANUFACTURING, TRANSPORT, CORPORATE,
]

SECTOR_LABELS = {
    DEFENCE: "Defence & Army", MARITIME: "Maritime", AEROSPACE: "Aerospace",
    AVIATION: "Aviation & Airlines", HEALTHCARE: "Healthcare",
    ENERGY: "Energy & Utilities", WATER: "Water", FINANCIAL: "Financial",
    GOVERNMENT: "Government", TELECOM: "Telecom", EDUCATION: "Education",
    MANUFACTURING: "Manufacturing", TRANSPORT: "Transport & Logistics",
    CORPORATE: "Corporate / Other",
}

# Whole-token keyword rules, most-specific sector first. Multi-word phrases are
# matched as phrases (with flexible whitespace); single tokens are matched with
# word boundaries so "army" never fires inside "armygrp".
_SECTOR_KEYWORDS: list[tuple[str, list[str]]] = [
    (DEFENCE, ["army", "navy", "military", "defense", "defence", "armed forces",
               "pentagon", "warfare", "soldier", "battalion", "nato",
               "ministry of defense", "ministry of defence", "dod"]),
    (MARITIME, ["maritime", "shipping", "seaport", "port authority", "shipyard",
                "naval", "vessel", "cargo ship", "container ship", "offshore"]),
    (AEROSPACE, ["aerospace", "satellite", "spacecraft", "space agency", "nasa",
                 "esa", "launch vehicle", "orbital", "defense contractor"]),
    (AVIATION, ["airline", "airport", "aviation", "air traffic", "aircraft",
                "flight", "boeing", "airbus", "faa", "carrier"]),
    (HEALTHCARE, ["hospital", "healthcare", "health care", "medical", "clinic",
                  "patient", "pharma", "pharmaceutical", "health system",
                  "medtech", "ehr", "nhs"]),
    (ENERGY, ["energy", "power grid", "electric utility", "oil and gas",
              "pipeline", "refinery", "nuclear plant", "power plant", "scada",
              "utility company", "petroleum", "gas company"]),
    (WATER, ["water utility", "wastewater", "water treatment", "water system",
             "drinking water", "sewage"]),
    (FINANCIAL, ["bank", "banking", "financial", "fintech", "insurance",
                 "brokerage", "stock exchange", "payment processor",
                 "credit union", "trading platform"]),
    (GOVERNMENT, ["government", "federal agency", "municipal", "ministry",
                  "public sector", "city council", "state agency", "election",
                  "embassy", "parliament", "cisa", "gov agency"]),
    (TELECOM, ["telecom", "telecommunications", "isp", "mobile carrier",
               "5g network", "broadband", "network operator", "cellular"]),
    (EDUCATION, ["university", "college", "school district", "education",
                 "student data", "academic", "campus", "k-12"]),
    (MANUFACTURING, ["manufacturing", "factory", "industrial control",
                     "production plant", "assembly line", "automotive plant",
                     "semiconductor fab", "supply chain manufacturer"]),
    (TRANSPORT, ["railway", "logistics", "freight", "trucking", "transit",
                 "public transport", "supply chain", "warehouse", "port operator"]),
]


def _compile(keywords: list[str]) -> re.Pattern:
    # Word-boundary alternation, longest phrase first so it wins the match.
    parts = sorted((re.escape(k).replace(r"\ ", r"\s+") for k in keywords),
                   key=len, reverse=True)
    return re.compile(r"(?<![0-9A-Za-z])(?:" + "|".join(parts) + r")(?![0-9A-Za-z])",
                      re.IGNORECASE)


_SECTOR_MATCHERS = [(sector, _compile(kws)) for sector, kws in _SECTOR_KEYWORDS]

# Ransomware.live's `activity` values, normalised onto our taxonomy. Anything
# not mapped keeps its explicit label but lands in CORPORATE for filtering.
_ACTIVITY_MAP = {
    "healthcare": HEALTHCARE, "health care": HEALTHCARE,
    "hospital & health care": HEALTHCARE, "pharmaceuticals": HEALTHCARE,
    "banking": FINANCIAL, "financial services": FINANCIAL, "insurance": FINANCIAL,
    "government": GOVERNMENT, "government administration": GOVERNMENT,
    "public administration": GOVERNMENT,
    "education": EDUCATION, "higher education": EDUCATION,
    "telecommunications": TELECOM,
    "oil & energy": ENERGY, "utilities": ENERGY, "energy": ENERGY,
    "manufacturing": MANUFACTURING, "automotive": MANUFACTURING,
    "machinery": MANUFACTURING, "electrical/electronic manufacturing": MANUFACTURING,
    "transportation/trucking/railroad": TRANSPORT, "logistics & supply chain": TRANSPORT,
    "maritime": MARITIME, "aviation & aerospace": AEROSPACE, "airlines/aviation": AVIATION,
    "defense & space": DEFENCE, "military": DEFENCE,
}


def _normalise_activity(activity: str) -> str | None:
    a = (activity or "").strip().lower()
    if not a:
        return None
    if a in _ACTIVITY_MAP:
        return _ACTIVITY_MAP[a]
    # Fall back to a keyword pass over the activity string itself.
    for sector, matcher in _SECTOR_MATCHERS:
        if matcher.search(a):
            return sector
    return CORPORATE      # an explicit-but-unmapped activity is still a real target


def classify_sector(item: dict) -> tuple[str | None, str]:
    """Return (sector, confidence) for one item.

    confidence is "explicit" | "inferred" | "none".
    """
    # 1. Explicit: the source named the sector.
    hint = item.get("sector_hint")
    if hint:
        sector = _normalise_activity(hint)
        if sector:
            return sector, "explicit"

    # 2. Inferred: whole-token keyword rules over the visible text.
    text = f"{item.get('title', '')} {item.get('description', '')}"
    for sector, matcher in _SECTOR_MATCHERS:
        if matcher.search(text):
            return sector, "inferred"

    return None, "none"


def annotate_sectors(items: list[dict]) -> dict[str, int]:
    """Tag every item in place, and return a sector -> count breakdown."""
    counts: dict[str, int] = {}
    for item in items:
        sector, confidence = classify_sector(item)
        if sector:
            item["sector"] = sector
            item["sector_confidence"] = confidence
            counts[sector] = counts.get(sector, 0) + 1
    return counts
