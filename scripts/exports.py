"""
CYBERWATCH — exports.py
========================
Turns the aggregated intel feed into machine-consumable artifacts so the
dashboard can feed SIEMs, firewalls, and RSS readers — not just eyeballs.

Produces (under data/exports/):
  iocs.csv    — flat IOC table (type,value,source,...) for spreadsheet / block lists
  iocs.json   — same data as JSON, grouped by type
  stix.json   — STIX 2.1 bundle of Indicator objects (import into TIPs / MISP)
  feed.xml    — RSS 2.0 feed of the aggregated items (subscribe in any reader)

All IDs are deterministic (uuid5) so re-running the pipeline produces stable
diffs instead of churning the whole file every hour.
"""

import csv
import io
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from email.utils import format_datetime
from xml.sax.saxutils import escape as xml_escape

# Deterministic namespace for STIX/indicator IDs (a fixed random UUID).
_NS = uuid.UUID("6f2d1c9e-4b7a-4e2a-9c3d-8a1b2c3d4e5f")

# IOC type -> STIX pattern builder + CSV grouping.
_STIX_PATTERN = {
    "ipv4":   lambda v: f"[ipv4-addr:value = '{v}']",
    "domain": lambda v: f"[domain-name:value = '{v}']",
    "url":    lambda v: f"[url:value = '{v}']",
    "sha256": lambda v: f"[file:hashes.'SHA-256' = '{v}']",
    "sha1":   lambda v: f"[file:hashes.'SHA-1' = '{v}']",
    "md5":    lambda v: f"[file:hashes.'MD5' = '{v}']",
    "email":  lambda v: f"[email-addr:value = '{v}']",
    "cidr":   lambda v: f"[ipv4-addr:value = '{v}']",
}

# Which IOC types are worth exporting as network/file indicators.
_EXPORT_TYPES = ["ipv4", "domain", "url", "sha256", "sha1", "md5", "email", "cidr"]


# Only sources that actually publish indicators are exported. Without this the
# bundle shipped gmail.com, redhat.com, cern.ch and two named maintainers' work
# email addresses as `indicator_types: malicious-activity` — a public STIX file
# that was both useless and a PII leak. Kept in sync with fetch_intel.IOC_SOURCES.
_IOC_SOURCES = {
    "URLhaus", "ThreatFox", "Feodo Tracker", "Spamhaus", "MalwareBazaar",
    "AbuseIPDB", "PhishTank", "AlienVault OTX",
}


def _iter_iocs(items):
    """Yield (type, value, source, title, cve, published) for every IOC, deduped.

    Restricted to indicator feeds — prose from a news article is not a threat feed.
    """
    seen = set()
    for item in items:
        src = item.get("source", "")
        if src not in _IOC_SOURCES:
            continue
        iocs = item.get("iocs") or {}
        title = item.get("title", "")
        cve = item.get("cve_id") or ""
        published = item.get("published", "")
        for ioc_type in _EXPORT_TYPES:
            for value in iocs.get(ioc_type, []) or []:
                value = (value or "").strip()
                if not value:
                    continue
                dedup = (ioc_type, value)
                if dedup in seen:
                    continue
                seen.add(dedup)
                yield ioc_type, value, src, title, cve, published


def _write_csv(rows, path: Path) -> None:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["type", "value", "source", "context", "related_cve", "first_seen"])
    for ioc_type, value, src, title, cve, published in rows:
        writer.writerow([ioc_type, value, src, title[:160], cve, published])
    path.write_text(buf.getvalue(), encoding="utf-8")


def _write_json(rows, path: Path, generated: str) -> int:
    grouped: dict[str, list] = {}
    total = 0
    for ioc_type, value, src, title, cve, published in rows:
        grouped.setdefault(ioc_type, []).append({
            "value": value, "source": src, "context": title[:160],
            "related_cve": cve or None, "first_seen": published,
        })
        total += 1
    payload = {
        "generated": generated,
        "count": total,
        "types": {k: len(v) for k, v in grouped.items()},
        "iocs": grouped,
    }
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return total


def _write_stix(rows, path: Path, generated: str) -> int:
    objects = []
    for ioc_type, value, src, title, cve, published in rows:
        builder = _STIX_PATTERN.get(ioc_type)
        if not builder:
            continue
        # STIX single-quoted string values can't contain a raw single quote.
        if "'" in value:
            continue
        ind_id = f"indicator--{uuid.uuid5(_NS, ioc_type + ':' + value)}"
        stamp = published or generated
        objects.append({
            "type": "indicator",
            "spec_version": "2.1",
            "id": ind_id,
            "created": generated,
            "modified": generated,
            "name": f"{ioc_type} observed by {src or 'CyberWatch'}",
            "description": (title or "")[:400],
            "indicator_types": ["malicious-activity"],
            "pattern": builder(value),
            "pattern_type": "stix",
            "valid_from": stamp,
            "labels": [ioc_type] + ([cve] if cve else []),
        })
    bundle = {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid5(_NS, 'cyberwatch-bundle')}",
        "objects": objects,
    }
    path.write_text(json.dumps(bundle, indent=2, ensure_ascii=False), encoding="utf-8")
    return len(objects)


def _rfc822(dt_str: str) -> str:
    """Convert ISO-8601 string to RFC 822 (required by RSS 2.0)."""
    try:
        dt = datetime.fromisoformat(dt_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return format_datetime(dt)
    except Exception:
        return format_datetime(datetime.now(timezone.utc))

def _write_rss(output: dict, path: Path, limit: int = 60) -> None:
    items = output.get("items", [])[:limit]
    updated = _rfc822(output.get("last_updated", ""))
    parts = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<rss version="2.0"><channel>',
        "<title>CyberWatch Threat Intelligence</title>",
        "<link>https://github.com/</link>",
        "<description>Aggregated CVEs, advisories, incidents and IOCs</description>",
        f"<lastBuildDate>{xml_escape(updated)}</lastBuildDate>",
    ]
    for item in items:
        title = xml_escape((item.get("title") or "Untitled")[:200])
        link = xml_escape(item.get("url") or "")
        desc = xml_escape((item.get("description") or "")[:500])
        sev = (item.get("severity") or "").upper()
        cats = xml_escape(item.get("category") or "")
        guid = xml_escape(item.get("url") or item.get("title") or title)
        pub = xml_escape(_rfc822(item.get("published") or output.get("last_updated", "")))
        parts.append(
            "<item>"
            f"<title>[{sev}] {title}</title>"
            f"<link>{link}</link>"
            f"<guid isPermaLink=\"false\">{guid}</guid>"
            f"<category>{cats}</category>"
            f"<pubDate>{pub}</pubDate>"
            f"<description>{desc}</description>"
            "</item>"
        )
    parts.append("</channel></rss>")
    path.write_text("\n".join(parts), encoding="utf-8")


def write_exports(output: dict, export_dir: Path) -> list[str]:
    """Write all export artifacts. Returns the list of filenames created."""
    export_dir = Path(export_dir)
    export_dir.mkdir(parents=True, exist_ok=True)
    items = output.get("items", [])
    generated = output.get("last_updated", datetime.now(timezone.utc).isoformat())

    # Materialize once — the generator is consumed by each writer.
    rows = list(_iter_iocs(items))

    _write_csv(rows, export_dir / "iocs.csv")
    _write_json(rows, export_dir / "iocs.json", generated)
    _write_stix(rows, export_dir / "stix.json", generated)
    _write_rss(output, export_dir / "feed.xml")

    # Static JSON "API" endpoints, generated at build time. This is what
    # rest_api.py was reaching for, minus the runtime, the open port and the
    # unvalidated int() parsing that returned 500s with a traceback.
    api_dir = export_dir.parent / "api"
    api_dir.mkdir(parents=True, exist_ok=True)
    _write_static_api(output, api_dir)

    return ["iocs.csv", "iocs.json", "stix.json", "feed.xml", "api/*.json"]


def _write_static_api(output: dict, api_dir: Path) -> None:
    """Pre-rendered query results: cacheable on a CDN, zero attack surface."""
    items = output.get("items", [])
    generated = output.get("last_updated", "")

    def dump(name: str, payload: dict) -> None:
        (api_dir / name).write_text(
            json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")

    dump("stats.json", {
        "generated": generated,
        "total_items": len(items),
        "pipeline_version": output.get("pipeline_version"),
        "severity": _count_by(items, "severity"),
        "category": _count_by(items, "category"),
        "source": _count_by(items, "source"),
        "priority_label": _count_by(items, "priority_label"),
        "kev": sum(1 for i in items if i.get("cisa_kev")),
        "with_poc": sum(1 for i in items if i.get("has_poc")),
        "ssvc_active": sum(1 for i in items if i.get("ssvc_exploitation") == "active"),
        "ai_enriched": output.get("ai_enriched_count", 0),
        "sources_ok": output.get("sources_ok"),
        "sources_stale": output.get("sources_stale"),
    })

    urgent = [i for i in items if i.get("priority_label") in ("urgent", "elevated")]
    dump("urgent.json", {"generated": generated, "count": len(urgent), "items": urgent})

    kev = [i for i in items if i.get("cisa_kev") or i.get("ssvc_exploitation") == "active"]
    dump("exploited.json", {"generated": generated, "count": len(kev), "items": kev})

    if output.get("brief"):
        dump("brief.json", output["brief"])

    dump("health.json", {"generated": generated, "sources": output.get("source_health", {})})


def _count_by(items, field: str) -> dict:
    counts: dict[str, int] = {}
    for item in items:
        key = item.get(field)
        if key:
            counts[str(key)] = counts.get(str(key), 0) + 1
    return dict(sorted(counts.items(), key=lambda kv: -kv[1]))


if __name__ == "__main__":
    # Standalone: regenerate exports from the current intel.json.
    root = Path(__file__).resolve().parent.parent
    intel = json.loads((root / "data/intel.json").read_text(encoding="utf-8"))
    created = write_exports(intel, root / "data/exports")
    print("Wrote:", ", ".join(created))
