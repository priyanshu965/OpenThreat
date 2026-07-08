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


def _iter_iocs(items):
    """Yield (type, value, source, title, cve, published) for every IOC, deduped."""
    seen = set()
    for item in items:
        iocs = item.get("iocs") or {}
        src = item.get("source", "")
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


def _write_rss(output: dict, path: Path, limit: int = 60) -> None:
    items = output.get("items", [])[:limit]
    updated = output.get("last_updated", datetime.now(timezone.utc).isoformat())
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
        pub = xml_escape(item.get("published") or updated)
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

    return ["iocs.csv", "iocs.json", "stix.json", "feed.xml"]


if __name__ == "__main__":
    # Standalone: regenerate exports from the current intel.json.
    import sys
    root = Path(__file__).resolve().parent.parent
    intel = json.loads((root / "data/intel.json").read_text(encoding="utf-8"))
    created = write_exports(intel, root / "data/exports")
    print("Wrote:", ", ".join(created))
