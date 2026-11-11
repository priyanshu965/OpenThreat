"""
OPENTHREAT — exports.py
========================
Turns the aggregated intel feed into machine-consumable artifacts so the
dashboard can feed SIEMs, firewalls, and RSS readers — not just eyeballs.

Produces (under data/exports/):
  iocs.csv    — flat IOC table (type,value,source,...) for spreadsheet / block lists
  iocs.json   — same data as JSON, grouped by type
  stix.json   — STIX 2.1 bundle: Indicator objects, a Vulnerability object per
                CVE in the feed, and the relationships between them
  feed.xml    — RSS 2.0 feed of the aggregated items (subscribe in any reader)
  feed-<name>.xml — the same feed narrowed to one question (see FILTERED_FEEDS)

All IDs are deterministic (uuid5) so re-running the pipeline produces stable
diffs instead of churning the whole file every hour.
"""

import csv
import io
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

try:
    from config import CONFIG
except ImportError:  # pragma: no cover - standalone use
    import importlib.util
    _spec = importlib.util.spec_from_file_location(
        "config", Path(__file__).parent / "config.py")
    _mod = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_mod)
    CONFIG = _mod.CONFIG
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


def _csv_cell(value) -> str:
    """Neutralise spreadsheet formulas.

    Excel, LibreOffice and Google Sheets all evaluate a cell that begins with
    = + - or @ (and tab or carriage return, which they strip first). Titles and
    indicator values here come from third-party feeds, so `=HYPERLINK(...)` or
    a DDE payload in a feed item would run in the analyst's spreadsheet the
    moment they opened the export. A leading apostrophe makes the cell text.
    """
    text = str(value if value is not None else "")
    if text[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + text
    return text


def _write_csv(rows, path: Path) -> None:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["type", "value", "source", "context", "related_cve", "first_seen"])
    for ioc_type, value, src, title, cve, published in rows:
        writer.writerow([_csv_cell(c) for c in
                         (ioc_type, value, src, title[:160], cve, published)])
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


def _stix_time(value: str) -> str:
    """A STIX 2.1 timestamp: UTC, millisecond precision, `Z` suffix.

    The bundle used to carry Python's isoformat() (`...761991+00:00`). The
    specification requires the `Z` form, and importers that validate reject
    the whole bundle over it.
    """
    try:
        stamp = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        stamp = datetime.now(timezone.utc)
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=timezone.utc)
    return stamp.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + f"{stamp.microsecond // 1000:03d}Z"


def _stix_vulnerabilities(items, identity_id: str, generated: str) -> dict[str, dict]:
    """One Vulnerability object per CVE in the feed, keyed by CVE id.

    Indicators alone tell a platform what to block. They do not tell it what
    to patch, which is most of what this feed is about. A Vulnerability object
    is the STIX type a TIP correlates against its asset inventory.

    Standard properties only. The verdict travels as labels and in the
    description rather than as custom `x_` properties, which STIX 2.1
    deprecates and strict importers reject.
    """
    out: dict[str, dict] = {}
    for item in items:
        cve = str(item.get("cve_id") or "").upper()
        if not cve or cve in out:
            continue
        labels = []
        if item.get("priority_label"):
            labels.append(f"priority-{item['priority_label']}")
        if item.get("cisa_kev"):
            labels.append("cisa-kev")
        if item.get("cisa_kev") or item.get("ssvc_exploitation") == "active":
            labels.append("exploited-in-the-wild")
        if item.get("has_poc"):
            labels.append("public-poc")
        if item.get("epss_rising"):
            labels.append("epss-rising")
        facts = []
        if item.get("priority_score") is not None:
            facts.append(f"Priority {item['priority_score']:g}/100")
        if item.get("action"):
            facts.append(str(item["action"]))
        if item.get("cvss_score") is not None:
            facts.append(f"CVSS {float(item['cvss_score']):.1f}")
        if item.get("epss_score") is not None:
            facts.append(f"EPSS {float(item['epss_score']) * 100:.1f}%")
        text = (item.get("description") or item.get("title") or "").strip()[:800]
        refs = [{"source_name": "cve", "external_id": cve}]
        link = str(item.get("url") or "").strip()
        if link.lower().startswith(("http://", "https://")):
            refs.append({"source_name": str(item.get("source") or "OpenThreat"), "url": link})
        obj = {
            "type": "vulnerability",
            "spec_version": "2.1",
            "id": f"vulnerability--{uuid.uuid5(_NS, 'vulnerability:' + cve)}",
            "created": generated,
            "modified": generated,
            "created_by_ref": identity_id,
            "name": cve,
            "description": (" · ".join(facts) + ". " if facts else "") + text,
            "external_references": refs,
        }
        if labels:
            obj["labels"] = labels
        out[cve] = obj
    return out


def _write_stix(rows, path: Path, generated: str, items=None) -> int:
    # An identity object, and every indicator attributed to it.
    #
    # The bundle previously carried bare indicators with no producer. On import
    # that is an anonymous pile of patterns: a TIP cannot tell one feed's
    # indicators from another's, cannot filter by source, and has nobody to
    # contact about a false positive. `created_by_ref` is the field that fixes
    # all three, and it costs one object.
    #
    # The uuid5 is derived from the org name only, so the identity id is stable
    # across runs and re-importing updates in place rather than duplicating.
    generated = _stix_time(generated)
    identity_id = f"identity--{uuid.uuid5(_NS, f'identity-{CONFIG.misp_org_name}')}"
    identity = {
        "type": "identity",
        "spec_version": "2.1",
        "id": identity_id,
        "created": generated,
        "modified": generated,
        "name": str(CONFIG.misp_org_name or "OpenThreat"),
        "identity_class": "organization",
        "sectors": ["technology"],
        "contact_information": str(CONFIG.contact_email or ""),
    }
    objects = [identity]
    vulnerabilities = _stix_vulnerabilities(items or [], identity_id, generated)
    relationships = []
    indicators = 0
    for ioc_type, value, src, title, cve, published in rows:
        builder = _STIX_PATTERN.get(ioc_type)
        if not builder:
            continue
        # STIX single-quoted string values can't contain a raw single quote.
        if "'" in value:
            continue
        ind_id = f"indicator--{uuid.uuid5(_NS, ioc_type + ':' + value)}"
        stamp = _stix_time(published) if published else generated
        objects.append({
            "type": "indicator",
            "spec_version": "2.1",
            "id": ind_id,
            "created": generated,
            "modified": generated,
            "created_by_ref": identity_id,
            "name": f"{ioc_type} observed by {src or 'OpenThreat'}",
            "description": (title or "")[:400],
            "indicator_types": ["malicious-activity"],
            "pattern": builder(value),
            "pattern_type": "stix",
            "valid_from": stamp,
            "labels": [ioc_type] + ([cve] if cve else []),
        })
        indicators += 1
        target = vulnerabilities.get(str(cve).upper()) if cve else None
        if target:
            relationships.append({
                "type": "relationship",
                "spec_version": "2.1",
                "id": f"relationship--{uuid.uuid5(_NS, ind_id + ':indicates:' + target['id'])}",
                "created": generated,
                "modified": generated,
                "created_by_ref": identity_id,
                "relationship_type": "indicates",
                "source_ref": ind_id,
                "target_ref": target["id"],
            })
    objects += list(vulnerabilities.values()) + relationships
    bundle = {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid5(_NS, 'openthreat-bundle')}",
        "objects": objects,
    }
    path.write_text(json.dumps(bundle, indent=2, ensure_ascii=False), encoding="utf-8")
    # The caller reports this as an INDICATOR count, so neither the identity
    # that leads the bundle nor the vulnerabilities and relationships that
    # follow may be counted as one. Counting the objects and subtracting one
    # was only right while indicators were the only other kind in the bundle.
    return indicators


# MISP attribute type + category per IOC type. MISP validates both, so a wrong
# category is rejected at import rather than silently downgraded.
_MISP_TYPES = {
    "ipv4":   ("ip-dst", "Network activity"),
    "cidr":   ("ip-dst", "Network activity"),
    "domain": ("domain", "Network activity"),
    "url":    ("url", "Network activity"),
    "sha256": ("sha256", "Payload delivery"),
    "sha1":   ("sha1", "Payload delivery"),
    "md5":    ("md5", "Payload delivery"),
    "email":  ("email-src", "Payload delivery"),
}


def _write_misp(output: dict, rows, path: Path, generated: str) -> int:
    """
    One MISP event carrying the run's indicators, so the feed can be pushed
    into a real TIP rather than only read in a browser.

    STIX 2.1 was already emitted, and STIX and MISP are the two halves of the
    interoperability story: STIX is what you hand a commercial platform, MISP
    is what most CERTs and sharing communities actually run. Emitting only one
    of them makes the project standalone in practice.

    Deterministic uuid5 ids again, so re-importing the same event updates it
    in place instead of creating a duplicate every hour.
    """
    date = (generated or "")[:10] or datetime.now(timezone.utc).strftime("%Y-%m-%d")
    event_uuid = str(uuid.uuid5(_NS, f"openthreat-event-{date}"))
    org_uuid = str(uuid.uuid5(_NS, f"org-{CONFIG.misp_org_name}"))

    attributes = []
    seen = set()
    for ioc_type, value, source, title, cve, published in rows:
        mapping = _MISP_TYPES.get(ioc_type)
        if not mapping:
            continue
        misp_type, category = mapping
        key = (misp_type, value)
        if key in seen:
            continue
        seen.add(key)
        attributes.append({
            "uuid": str(uuid.uuid5(_NS, f"misp-{misp_type}-{value}")),
            "type": misp_type,
            "category": category,
            "value": value,
            # to_ids marks an attribute as safe to turn into a detection rule.
            # Only indicator feeds get it; a hash mentioned in a news article
            # is context, and pushing it into an IDS is how false positives
            # get into someone's SOC.
            "to_ids": source in _IOC_SOURCES,
            "distribution": "1",
            "comment": f"{source}: {title}"[:250],
            "timestamp": str(int(datetime.now(timezone.utc).timestamp())),
            "Tag": [{"name": f'openthreat:source="{source}"'}] if source else [],
        })

    # Vulnerabilities that are actively exploited ride along as attributes too:
    # a TIP that knows the indicators but not which CVE they belong to is only
    # half useful.
    for item in output.get("items", []) or []:
        cve = (item.get("cve_id") or "").upper()
        if not cve or not (item.get("cisa_kev") or item.get("priority_label") == "urgent"):
            continue
        key = ("vulnerability", cve)
        if key in seen:
            continue
        seen.add(key)
        attributes.append({
            "uuid": str(uuid.uuid5(_NS, f"misp-vuln-{cve}")),
            "type": "vulnerability",
            "category": "External analysis",
            "to_ids": False,
            "distribution": "1",
            "comment": (item.get("action_detail") or item.get("priority_rationale") or "")[:250],
            "value": cve,
            "timestamp": str(int(datetime.now(timezone.utc).timestamp())),
        })

    tags = [{"name": "tlp:clear"}, {"name": "openthreat:automated"}]
    for actor in sorted({a for i in output.get("items", []) or []
                         for a in (i.get("threat_actors") or [])})[:20]:
        tags.append({"name": f'misp-galaxy:threat-actor="{actor}"'})
    for tid in sorted({t.get("id") for i in output.get("items", []) or []
                       for t in (i.get("ttps") or []) if t.get("id")})[:40]:
        tags.append({"name": f'mitre-attack-pattern:{tid}'})

    brief = (output.get("brief") or {}).get("headline") or "OpenThreat daily intelligence"
    event = {
        "Event": {
            "uuid": event_uuid,
            "info": f"OpenThreat {date} — {brief}"[:255],
            "date": date,
            "threat_level_id": "2",
            "analysis": "2",
            "published": True,
            "distribution": "1",
            "timestamp": str(int(datetime.now(timezone.utc).timestamp())),
            "Orgc": {"name": CONFIG.misp_org_name, "uuid": org_uuid},
            "Tag": tags,
            "Attribute": [a for a in attributes if a.get("value")],
        }
    }
    path.write_text(json.dumps(event, indent=2, ensure_ascii=False), encoding="utf-8")
    return len(event["Event"]["Attribute"])


def _rfc822(dt_str: str) -> str:
    """Convert ISO-8601 string to RFC 822 (required by RSS 2.0)."""
    try:
        dt = datetime.fromisoformat(dt_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return format_datetime(dt)
    except Exception:
        return format_datetime(datetime.now(timezone.utc))

def _is_exploited(item: dict) -> bool:
    return bool(item.get("cisa_kev")) or item.get("ssvc_exploitation") == "active"


# One feed per question a reader subscribes to answer. feed.xml is everything,
# newest first, which at a hundred-odd sources is far more than anyone reads;
# these are the cuts worth a slot in a feed reader or a SIEM's RSS input.
# name -> (channel title, channel description, predicate)
FILTERED_FEEDS = {
    "urgent": ("OpenThreat: patch now",
               "Items scored urgent: confirmed exploitation or trivially weaponisable",
               lambda i: i.get("priority_label") == "urgent"),
    "exploited": ("OpenThreat: exploited in the wild",
                  "CVEs in CISA KEV or with SSVC exploitation active",
                  _is_exploited),
    "rising": ("OpenThreat: EPSS rising",
               "CVEs whose exploitation probability rose sharply this week",
               lambda i: bool(i.get("epss_rising"))),
    "cve": ("OpenThreat: vulnerabilities", "CVE records and vulnerability advisories",
            lambda i: i.get("category") == "cve"),
    "incident": ("OpenThreat: incidents", "Breaches, intrusions and ransomware claims",
                 lambda i: i.get("category") == "incident"),
    "advisory": ("OpenThreat: advisories", "Government and vendor advisories",
                 lambda i: i.get("category") == "advisory"),
}


def write_filtered_feeds(output: dict, export_dir: Path) -> list[str]:
    """Write feed-<name>.xml for each entry in FILTERED_FEEDS."""
    names = []
    for name, (title, description, keep) in FILTERED_FEEDS.items():
        subset = [i for i in output.get("items", []) if keep(i)]
        # Most urgent first where there is a score; the feed's own order
        # (newest first) otherwise.
        if name in ("urgent", "exploited", "rising"):
            subset.sort(key=lambda i: -(i.get("priority_score") or 0))
        fname = f"feed-{name}.xml"
        _write_rss({**output, "items": subset}, export_dir / fname,
                   title=title, description=description)
        names.append(fname)
    return names


def _write_rss(output: dict, path: Path, limit: int = 60,
               title: str = "OpenThreat Threat Intelligence",
               description: str = "Aggregated CVEs, advisories, incidents and IOCs") -> None:
    items = output.get("items", [])[:limit]
    updated = _rfc822(output.get("last_updated", ""))
    parts = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<rss version="2.0"><channel>',
        f"<title>{xml_escape(title)}</title>",
        # This was "https://github.com/" — a placeholder that shipped. A reader
        # that follows the channel link is supposed to land on the feed's own
        # site, so it now points where the feed actually lives.
        f"<link>{xml_escape(str(CONFIG.dashboard_url or '').rstrip('/') or '')}</link>",
        f"<description>{xml_escape(description)}</description>",
        f"<lastBuildDate>{xml_escape(updated)}</lastBuildDate>",
        # RFC-era RSS expects bare addresses here, not mailto: URIs.
        f"<managingEditor>{xml_escape(str(CONFIG.contact_email or ''))}</managingEditor>",
        f"<webMaster>{xml_escape(str(CONFIG.contact_email or ''))}</webMaster>",
    ]
    for item in items:
        title = xml_escape((item.get("title") or "Untitled")[:200])
        # Escaping stops markup injection; it does not stop `javascript:`.
        # Feed readers render <link> as a clickable anchor, so the scheme is
        # checked here exactly as safeUrl() checks it in the dashboard.
        raw_link = str(item.get("url") or "").strip()
        link = xml_escape(raw_link if raw_link.lower().startswith(("http://", "https://")) else "")
        desc = xml_escape((item.get("description") or "")[:500])
        # Escaped like every other field. Severity is currently always one of
        # four inferred literals, so this cannot inject today — but it is the
        # only interpolation on this line that was trusting its input, and the
        # reason it is safe lives in a different file.
        sev = xml_escape((item.get("severity") or "").upper())
        cats = xml_escape(item.get("category") or "")
        # Built from the vetted link, not the raw URL. isPermaLink is false, but
        # readers that find no <link> fall back to the guid, and a rejected
        # `javascript:` URL must not come back in through it.
        guid = link or xml_escape(item.get("title") or "Untitled")
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


def write_exports(output: dict, export_dir: Path, darkweb_index: dict = None) -> list[str]:
    """Write all export artifacts. Returns the list of filenames created."""
    export_dir = Path(export_dir)
    export_dir.mkdir(parents=True, exist_ok=True)
    items = output.get("items", [])
    generated = output.get("last_updated", datetime.now(timezone.utc).isoformat())

    # Materialize once — the generator is consumed by each writer.
    rows = list(_iter_iocs(items))

    _write_csv(rows, export_dir / "iocs.csv")
    _write_json(rows, export_dir / "iocs.json", generated)
    _write_stix(rows, export_dir / "stix.json", generated, items)
    _write_rss(output, export_dir / "feed.xml")
    written_names = ["iocs.csv", "iocs.json", "stix.json", "feed.xml"]
    written_names += write_filtered_feeds(output, export_dir)
    if CONFIG.enable_misp_export:
        count = _write_misp(output, rows, export_dir / "misp_event.json", generated)
        written_names.append(f"misp_event.json ({count} attributes)")

    # Static JSON "API" endpoints, generated at build time. This is what
    # rest_api.py was reaching for, minus the runtime, the open port and the
    # unvalidated int() parsing that returned 500s with a traceback.
    api_dir = export_dir.parent / "api"
    api_dir.mkdir(parents=True, exist_ok=True)
    _write_static_api(output, api_dir)

    # The dark-web index is ~550 KB and only the Dark Web view needs it, so it
    # is published as its own file and lazily fetched rather than riding in
    # intel.json on every page load.
    # Own-estate artefacts. exposure/attack_surface describe YOUR estate, so
    # they are withheld from the published site unless explicitly opted in --
    # see CONFIG.publish_own_estate. sector_benchmark and breaches are industry
    # -wide public data and always publish.
    _own_estate = {"exposure", "attack_surface"}
    for key, fname in (("sector_benchmark", "sector_benchmark.json"),
                       ("exposure", "exposure.json"),
                       ("breach_catalogue", "breaches.json"),
                       ("attack_surface", "attack_surface.json")):
        if key in _own_estate and not CONFIG.publish_own_estate:
            continue
        if output.get(key):
            (api_dir / fname).write_text(
                json.dumps(output[key], ensure_ascii=False, separators=(",", ":")),
                encoding="utf-8")

    if darkweb_index:
        (api_dir / "darkweb_index.json").write_text(
            json.dumps(darkweb_index, ensure_ascii=False, separators=(",", ":")),
            encoding="utf-8")

    # ── v4 research artifacts ──────────────────────────────────────────────
    # Each is published as its own lazily-fetched endpoint rather than riding
    # in intel.json. The graph alone is ~200 KB and only the Graph view needs
    # it; folding these into the feed payload would roughly triple what every
    # visitor downloads to read a list of headlines.
    for key, fname in (("entity_graph", "graph.json"),
                       ("malware_view", "malware.json"),
                       ("detections", "sigma.json"),
                       ("backtest", "backtest.json"),
                       ("source_reliability", "source_reliability.json"),
                       ("exploit_lag", "exploit_lag.json"),
                       ("campaigns", "campaigns.json"),
                       # v5. hunt_packs is NOT here: it is sharded below, for
                       # the same reason the Library is.
                       ("hunt_queue", "hunt_queue.json"),
                       ("detection_diff", "detection_diff.json"),
                       ("control_focus", "control_focus.json"),
                       ("leak_sites", "leak_sites.json"),
                       ("telegram", "telegram.json"),
                       ("lifecycle", "lifecycle.json"),
                       ("kev_table", "kev.json")):
        if output.get(key):
            (api_dir / fname).write_text(
                json.dumps(output[key], ensure_ascii=False, separators=(",", ":")),
                encoding="utf-8")
            written_names.append(f"api/{fname}")

    # -- The Library ------------------------------------------------------
    # Sharded rather than written as one file: the merged corpus is several
    # thousand entities and tens of MB, and a reader opening one page must not
    # pay for the other 4,999. write_entity_shards also PRUNES shards that are
    # no longer in the index, so a deprecated entity does not stay reachable by
    # URL forever, serving a record nothing links to.
    if output.get("knowledge_base"):
        try:
            from knowledge_base import write_entity_shards
            count = write_entity_shards(output["knowledge_base"], api_dir)
            written_names.append(f"api/entity_index.json + {count} entity shards")
        except Exception as e:  # noqa: BLE001 - the feed still publishes
            print(f"  Entity shard write failed: {e}")

    # -- Hunt packs -------------------------------------------------------
    # Also sharded. One pack is MITRE's prose plus eight Sigma rules compiled
    # for six SIEMs plus four atomic tests -- ~20 KB, and 4.5 MB across all
    # 220. Nobody should download the other 219 to read one.
    if output.get("hunt_packs"):
        try:
            from hunt_packs import write_hunt_shards
            count = write_hunt_shards(output["hunt_packs"], api_dir)
            written_names.append(f"api/hunt_packs.json + {count} pack shards")
        except Exception as e:  # noqa: BLE001
            print(f"  Hunt shard write failed: {e}")

    return written_names + ["api/*.json"]


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

    if output.get("attack_map"):
        # Written compact rather than indented: it is machine-consumed by the
        # map, has ~180 country rows, and this keeps it under the size budget.
        (api_dir / "attack_map.json").write_text(
            json.dumps(output["attack_map"], ensure_ascii=False,
                       separators=(",", ":")), encoding="utf-8")

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
