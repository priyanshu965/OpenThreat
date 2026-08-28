"""
OPENTHREAT — control_mappings.py
=================================
ATT&CK techniques mapped to the control frameworks people are audited against.

The gap this closes is a translation problem, not an information problem.
Security teams work in two vocabularies that rarely meet:

    the threat side   "Scattered Spider used T1621 against us"
    the control side  "we assert IA-2(1) to our auditor, and we pay for
                       Defender for Identity"

Nobody publishes the join in the product, so it gets done by hand, badly, once
a year. MITRE's Center for Threat-Informed Defense publishes exactly that join
as versioned JSON, for NIST 800-53 rev5, the CSA Cloud Controls Matrix, and the native
security capabilities of Azure and AWS.

(CIS Critical Security Controls would be the obvious fifth. CTID does not
publish a CIS mapping in this repository, so it is not here — rather than
shipping a hand-rolled approximation of one.)

WHAT THIS BUYS THE TOOL
-----------------------
Two things that were impossible before:

  1. An entity page can end with "the controls that address this", in the
     language of the reader's audit.
  2. The hunt bench can invert it: given the techniques active THIS WEEK, which
     controls are load-bearing right now. That is a defensible way to sequence
     control work, and it beats the usual method (whichever control the last
     assessor complained about).

NOTE ON `status`
----------------
The mapping files include deliberate NEGATIVE assertions — rows with
`status: "non_mappable"` and a comment such as "no mitigations in att&ck".
Those are findings, not junk: they mark techniques no control framework claims
to address. They are counted and reported rather than silently dropped, because
"nothing covers this" is exactly what a defender needs to know.
"""

from __future__ import annotations

from collections import defaultdict

from fetchlib import CONFIG, cached_derive, log, now_utc, stream_json

_BASE = ("https://raw.githubusercontent.com/center-for-threat-informed-defense/"
         "mappings-explorer/main/mappings")

# (label, url, control-catalogue home). The ATT&CK version in the path is the
# one CTID has published a full mapping for; it trails the live matrix by a
# release or two, which is fine — control mappings are stable at technique
# level and we degrade to the parent technique anyway.
_FRAMEWORKS = {
    "nist_800_53": {
        "label": "NIST SP 800-53 rev5",
        "kind": "audit",
        "url": (f"{_BASE}/nist_800_53/attack-16.1/nist_800_53-rev5/enterprise/"
                "nist_800_53-rev5_attack-16.1-enterprise.json"),
    },
    "csa_ccm": {
        "label": "CSA Cloud Controls Matrix 4.1",
        "kind": "audit",
        "url": (f"{_BASE}/csa_ccm/attack-17.1/csa_ccm-4.1/enterprise/"
                "csa_ccm-4.1_attack-17.1-enterprise.json"),
    },
    # The two cloud mappings are a different KIND of answer: not "which control
    # do I claim" but "which service do I switch on". For anyone running in
    # these clouds that is a far shorter path from reading to doing.
    "azure": {
        "label": "Microsoft Azure security capabilities",
        "kind": "platform",
        "url": (f"{_BASE}/azure/attack-16.1/azure-04.26.2025/enterprise/"
                "azure-04.26.2025_attack-16.1-enterprise.json"),
    },
    "aws": {
        "label": "AWS security capabilities",
        "kind": "platform",
        "url": (f"{_BASE}/aws/attack-16.1/aws-12.12.2024/enterprise/"
                "aws-12.12.2024_attack-16.1-enterprise.json"),
    },
}

_CACHE = "control_mappings.json"


def _derive() -> dict | None:
    log.info("  Building ATT&CK -> control-framework mappings (monthly)...")
    frameworks: dict[str, dict] = {}

    for key, spec in _FRAMEWORKS.items():
        try:
            raw = stream_json(spec["url"], max_bytes=64 * 1024 * 1024)
        except Exception as e:  # noqa: BLE001 - one framework is not the run
            log.warning(f"  Control mapping {key} unavailable: {e}")
            continue
        objects = (raw or {}).get("mapping_objects") or []
        if not objects:
            continue
        meta = (raw or {}).get("metadata") or {}
        groups = meta.get("capability_groups") or {}

        by_technique: dict[str, list[dict]] = defaultdict(list)
        unmapped: dict[str, str] = {}
        for row in objects:
            if not isinstance(row, dict):
                continue
            tid = str(row.get("attack_object_id") or "").strip()
            if not tid:
                continue
            if str(row.get("status") or "") == "non_mappable":
                # Keep the reason: "no mitigations in att&ck" and "unrelated to
                # the control catalogue" mean very different things to a reader.
                unmapped[tid] = " ".join(str(row.get("comments") or "").split())[:200]
                continue
            cid = str(row.get("capability_id") or "").strip()
            if not cid:
                continue
            group = str(row.get("capability_group") or "").strip()
            by_technique[tid].append({
                "id": cid,
                "name": " ".join(str(row.get("capability_description") or "").split())[:200],
                "group": group,
                "group_name": str(groups.get(group) or "")[:80],
            })

        for tid, rows in by_technique.items():
            seen, deduped = set(), []
            for row in sorted(rows, key=lambda r: r["id"]):
                if row["id"] in seen:
                    continue
                seen.add(row["id"])
                deduped.append(row)
            by_technique[tid] = deduped[:20]

        frameworks[key] = {
            "label": spec["label"],
            "kind": spec.get("kind", "audit"),
            "version": str(meta.get("mapping_framework_version") or ""),
            "attack_version": str(meta.get("attack_version") or ""),
            "last_update": str(meta.get("last_update") or ""),
            "techniques": dict(by_technique),
            "unmapped": unmapped,
        }
        log.info(f"    {spec['label']}: {len(by_technique)} techniques mapped, "
                 f"{len(unmapped)} explicitly unmappable")

    if not frameworks:
        return None
    return {"built": now_utc(), "frameworks": frameworks}


def load_control_mappings(force: bool = False) -> dict:
    """framework key -> {label, techniques: {tid: [controls]}, unmapped}."""
    if not CONFIG.enable_control_mappings:
        return {}
    ttl = 0 if force else CONFIG.control_map_ttl_hours
    data = cached_derive(_CACHE, ttl, _derive)
    return (data or {}).get("frameworks", {})


def controls_for(technique_id: str, frameworks: dict) -> dict:
    """
    {framework_key: {label, controls, inherited}} for one technique.

    Falls back to the parent technique for sub-techniques, and says so, for the
    same reason d3fend.countermeasures_for does: AC-3 addresses T1078 and
    therefore addresses T1078.004, and pretending otherwise would report a
    coverage hole that is not real.
    """
    out: dict[str, dict] = {}
    if not technique_id:
        return out
    parent = technique_id.split(".")[0] if "." in technique_id else ""
    for key, fw in (frameworks or {}).items():
        table = fw.get("techniques") or {}
        controls = table.get(technique_id)
        inherited = ""
        if not controls and parent:
            controls = table.get(parent)
            inherited = parent if controls else ""
        if not controls:
            continue
        out[key] = {"label": fw.get("label", key), "controls": controls,
                    "inherited": inherited}
    return out


def build_control_focus(technique_counts: dict, frameworks: dict,
                        limit: int = 20) -> dict | None:
    """
    Invert the mapping: which controls carry the most weight THIS week.

    `technique_counts` is technique id -> how often the feed saw it. A control
    that addresses six actively-observed techniques is a better next investment
    than one that addresses a technique nobody has touched in a year, and this
    is the only place in the tool that can say so.
    """
    if not technique_counts or not frameworks:
        return None

    out = {}
    for key, fw in frameworks.items():
        table = fw.get("techniques") or {}
        weight: dict[str, dict] = {}
        for tid, count in technique_counts.items():
            for control in table.get(tid, []) or []:
                slot = weight.setdefault(control["id"], {
                    "id": control["id"], "name": control["name"],
                    "group": control.get("group", ""),
                    "group_name": control.get("group_name", ""),
                    "techniques": [], "activity": 0,
                })
                slot["techniques"].append(tid)
                slot["activity"] += int(count or 0)
        ranked = sorted(weight.values(),
                        key=lambda r: (-r["activity"], -len(r["techniques"]), r["id"]))
        for row in ranked:
            row["techniques"] = sorted(set(row["techniques"]))[:12]
        if ranked:
            out[key] = {"label": fw.get("label", key), "controls": ranked[:limit]}

    if not out:
        return None
    return {"built": now_utc(), "frameworks": out,
            "techniques_considered": len(technique_counts)}
