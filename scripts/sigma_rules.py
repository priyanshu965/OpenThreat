"""
CYBERWATCH — sigma_rules.py
============================
Closes the loop from intelligence to detection.

The pipeline already maps every item onto ATT&CK, which turns a headline into
"T1566 Phishing, seen 29 times this week". That is where most threat-intel
projects stop, and it is the least useful place to stop: knowing a technique is
active tells a defender nothing they can deploy. SigmaHQ publishes ~3,300
vendor-neutral detection rules, tagged with the very ATT&CK technique ids we
already carry, so the join is free and turns

    T1566 Phishing — seen 29 times

into

    T1566 Phishing — seen 29 times · 12 detection rules available

Implementation notes:

  * The packaged release zip is ~3 MB against ~3,300 individual raw files, so
    the release asset is the only sane transport. It is cut roughly monthly.
  * Rules are parsed with a deliberately small line scanner rather than a YAML
    library. The four fields we want (title, id, level, attack tags) are all
    flat top-level scalars, and adding PyYAML to a pinned dependency set to
    read four fields is a poor trade. The scanner only ever reads, never
    constructs — there is no eval path here.
  * Nothing is extracted to disk. Zip entries are read from memory, so the
    classic zip-slip path-traversal cannot apply.
"""

from __future__ import annotations

import io
import re
import zipfile
from collections import defaultdict

from fetchlib import CONFIG, SESSION, cached_derive, log, now_utc

_RELEASE_API = "https://api.github.com/repos/SigmaHQ/sigma/releases/latest"
_ASSET_NAME = "sigma_all_rules.zip"
_CACHE = "sigma_index.json"
_BLOB = "https://github.com/SigmaHQ/sigma/blob/master/"

# Only these four fields are read, and only at column 0 so the `related:` block
# (which carries its own `- id:` lines) cannot be mistaken for the rule id.
_TITLE = re.compile(r"^title:\s*(.+?)\s*$", re.MULTILINE)
_ID = re.compile(r"^id:\s*([0-9a-fA-F-]{8,})\s*$", re.MULTILINE)
_LEVEL = re.compile(r"^level:\s*([a-z]+)\s*$", re.MULTILINE)
_STATUS = re.compile(r"^status:\s*([a-z]+)\s*$", re.MULTILINE)
_ATTACK_TAG = re.compile(r"^\s*-\s*attack\.(t\d{4}(?:\.\d{3})?)\s*$",
                         re.MULTILINE | re.IGNORECASE)

_LEVEL_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}


def _parse_rule(text: str, path: str) -> dict | None:
    techniques = sorted({m.group(1).upper() for m in _ATTACK_TAG.finditer(text)})
    if not techniques:
        return None
    title = _TITLE.search(text)
    rule_id = _ID.search(text)
    level = _LEVEL.search(text)
    status = _STATUS.search(text)
    if not title:
        return None
    # rules/windows/process_creation/foo.yml -> "windows / process_creation"
    parts = path.split("/")
    logsource = " / ".join(parts[1:-1]) if len(parts) > 2 else ""
    return {
        "title": title.group(1).strip('"\'')[:160],
        "id": rule_id.group(1) if rule_id else "",
        "level": (level.group(1) if level else "medium"),
        "status": (status.group(1) if status else ""),
        "logsource": logsource,
        "path": path,
        "url": _BLOB + path,
        "techniques": techniques,
    }


def _latest_asset_url() -> str | None:
    resp = SESSION.get(_RELEASE_API, timeout=CONFIG.request_timeout,
                       headers={"Accept": "application/vnd.github+json"})
    resp.raise_for_status()
    release = resp.json()
    for asset in release.get("assets", []) or []:
        if asset.get("name") == _ASSET_NAME:
            return asset.get("browser_download_url")
    return None


def _derive_index() -> dict | None:
    log.info("  Building Sigma detection index from the SigmaHQ release (weekly)...")
    url = _latest_asset_url()
    if not url:
        log.warning(f"  SigmaHQ release has no {_ASSET_NAME} asset")
        return None

    resp = SESSION.get(url, timeout=max(120, CONFIG.request_timeout), stream=True)
    resp.raise_for_status()
    blob = io.BytesIO()
    total = 0
    for chunk in resp.iter_content(chunk_size=1 << 16):
        total += len(chunk)
        if total > 64 * 1024 * 1024:
            raise ValueError("sigma archive exceeded 64 MB")
        blob.write(chunk)

    by_technique: dict[str, list] = defaultdict(list)
    rules_seen = 0
    with zipfile.ZipFile(blob) as archive:
        for entry in archive.infolist():
            if entry.is_dir() or not entry.filename.endswith((".yml", ".yaml")):
                continue
            if entry.file_size > 512 * 1024:      # a Sigma rule is never this big
                continue
            try:
                text = archive.read(entry).decode("utf-8", "replace")
            except Exception:  # noqa: BLE001 - one bad entry must not kill the index
                continue
            rule = _parse_rule(text, entry.filename)
            if not rule:
                continue
            rules_seen += 1
            for tid in rule["techniques"]:
                by_technique[tid].append(rule)

    # Rank within a technique: severity first, then a stable title order, so
    # the dashboard's "top N" is the N most severe rather than zip order.
    cap = CONFIG.sigma_rules_per_technique
    trimmed = {}
    for tid, rules in by_technique.items():
        rules.sort(key=lambda r: (_LEVEL_RANK.get(r["level"], 9), r["title"]))
        trimmed[tid] = [
            {k: r[k] for k in ("title", "id", "level", "status", "logsource", "url")}
            for r in rules[:cap]
        ]

    log.info(f"  Sigma: {rules_seen} ATT&CK-tagged rules across "
             f"{len(trimmed)} techniques")
    return {
        "built": now_utc(),
        "source": url,
        "rules_indexed": rules_seen,
        "techniques_covered": len(trimmed),
        "by_technique": trimmed,
        # Full per-technique totals survive the cap, so the UI can say
        # "12 of 47" rather than pretending 12 is all there is.
        "totals": {tid: len(rules) for tid, rules in by_technique.items()},
    }


def load_sigma_index(force: bool = False) -> dict:
    """Technique id -> detection rules. Returns {} when unavailable."""
    if not CONFIG.enable_sigma:
        return {}
    ttl = 0 if force else CONFIG.sigma_ttl_hours
    return cached_derive(_CACHE, ttl, _derive_index) or {}


def annotate_detections(items: list[dict], index: dict) -> int:
    """
    Record, per item, how many Sigma rules cover the techniques it maps to.

    Only a count and the technique ids ride in intel.json; the rules themselves
    are served from data/api/sigma.json so 3,300 rules never land in the feed
    payload.
    """
    by_technique = (index or {}).get("by_technique") or {}
    totals = (index or {}).get("totals") or {}
    if not by_technique:
        return 0
    tagged = 0
    for item in items:
        covered = []
        rule_count = 0
        for ttp in item.get("ttps") or []:
            tid = ttp.get("id")
            if not tid:
                continue
            # A sub-technique's rules also count for its parent and vice versa:
            # a rule tagged attack.t1059.001 detects an instance of T1059.
            hits = totals.get(tid, 0)
            if not hits and "." not in tid:
                hits = sum(n for t, n in totals.items() if t.startswith(tid + "."))
            if hits:
                covered.append(tid)
                rule_count += hits
        if covered:
            item["detection_techniques"] = covered
            item["detection_rule_count"] = rule_count
            tagged += 1
    return tagged


def build_detection_view(items: list[dict], index: dict,
                         technique_names: dict | None = None) -> dict | None:
    """
    The detection-coverage view: techniques the feed saw, ranked by activity,
    each with the rules that would catch them — and, just as usefully, the
    techniques with NO rule coverage at all.
    """
    by_technique = (index or {}).get("by_technique") or {}
    if not by_technique or not items:
        return None
    technique_names = technique_names or {}

    seen: dict[str, int] = defaultdict(int)
    names: dict[str, str] = {}
    for item in items:
        for ttp in item.get("ttps") or []:
            tid = ttp.get("id")
            if tid:
                seen[tid] += 1
                names[tid] = ttp.get("name", "")

    totals = (index or {}).get("totals") or {}
    rows, gaps = [], []
    for tid, count in sorted(seen.items(), key=lambda kv: -kv[1]):
        rules = by_technique.get(tid) or []
        if not rules and "." not in tid:
            for sub, sub_rules in by_technique.items():
                if sub.startswith(tid + "."):
                    rules = rules + sub_rules
            rules = rules[:CONFIG.sigma_rules_per_technique]
        if rules:
            rows.append({
                "technique": tid,
                "name": names.get(tid) or technique_names.get(tid, ""),
                "seen": count,
                "rule_total": totals.get(tid, len(rules)),
                "rules": rules,
            })
        else:
            gaps.append({"technique": tid,
                         "name": names.get(tid) or technique_names.get(tid, ""),
                         "seen": count})

    covered_activity = sum(r["seen"] for r in rows)
    total_activity = covered_activity + sum(g["seen"] for g in gaps)
    return {
        "generated": now_utc(),
        "built": index.get("built", ""),
        "rules_indexed": index.get("rules_indexed", 0),
        "techniques_active": len(seen),
        "techniques_covered": len(rows),
        "techniques_uncovered": len(gaps),
        # The honest headline number: what share of THIS WEEK's observed
        # technique activity has a public detection rule behind it.
        "coverage_pct": round(100.0 * covered_activity / total_activity, 1) if total_activity else 0.0,
        "techniques": rows,
        "gaps": gaps,
    }


if __name__ == "__main__":  # pragma: no cover - manual refresh
    import json
    idx = load_sigma_index(force="--force" in __import__("sys").argv)
    print(json.dumps({k: v for k, v in idx.items()
                      if k not in ("by_technique", "totals")}, indent=2))
