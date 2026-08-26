"""
CYBERWATCH — timeline.py
=========================
Ninety days of daily snapshots that the dashboard could never open.

data/archive/ has held a full snapshot per day since the project started — 89
files, 24 MB — and the UI has only ever rendered today. Two things were missing:

  1. The archives are not published. update.yml deploys index.html, intel.json
     and the API, and ships the archive only as one state.tar.gz for the
     pipeline's own recovery. No page can fetch a specific day.
  2. They are too big to publish as they are. A full snapshot is ~270 KB and
     carries source health, the attacker map, the dark-web rollup and every
     item's full description — none of which a "what did the board look like
     on 12 July" view needs.

So this publishes a REDUCED copy per day (~60 KB), plus an index, which is what
makes the date slider and the two-day diff possible at all.

DURABILITY. Trends, the sector benchmark and the backtest all depend on the
archive surviving between runs, and it lives in the Actions cache — which is
evicted after 7 days of no reads, and capped at 10 GB per repo. The index
written here carries a SHA-256 and a size per day, so a run can SEE that
history has been silently truncated instead of quietly recomputing 30-day
trends from 3 days of data. `verify_archive()` reports exactly that, and main()
logs a warning when the archive shrinks.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fetchlib import CONFIG, log, now_utc

_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")

# What a past day needs to render as a feed. Everything else in a snapshot is
# either huge (descriptions, IOC lists), already global (source health, attack
# map), or meaningless out of context.
_SLIM_FIELDS = (
    "title", "url", "cve_id", "source", "category", "severity",
    "priority_score", "priority_label", "priority_rationale",
    "action", "action_detail", "cvss_score", "epss_score", "cisa_kev",
    "ssvc_exploitation", "ssvc_automatable", "has_poc", "published",
    "sector", "sector_confidence", "provenance", "human_authored",
    "threat_actors", "malware", "is_new", "detection_rule_count",
)


def slim_item(item: dict) -> dict:
    out = {k: item[k] for k in _SLIM_FIELDS if item.get(k) not in (None, "", [], {})}
    # Descriptions are the bulk of a snapshot. A day view is for scanning, and
    # the card links out, so one sentence is enough to recognise a row.
    desc = (item.get("description") or "").strip()
    if desc:
        out["description"] = desc[:220]
    ttps = [t.get("id") for t in (item.get("ttps") or []) if t.get("id")]
    if ttps:
        out["ttps"] = ttps
    return out


def slim_day(data: dict) -> dict:
    items = [slim_item(i) for i in data.get("items", []) or []]
    return {
        "date": (data.get("last_updated") or "")[:10],
        "generated": data.get("last_updated", ""),
        "total_items": len(items),
        "brief": data.get("brief"),
        "sector_breakdown": data.get("sector_breakdown", {}),
        "items": items,
    }


def _digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()[:16]


def verify_archive(archive_dir) -> dict:
    """
    Report on the archive's health: how many days, whether they are contiguous,
    and which ones are missing. Cheap, and the only warning anyone will get
    that a cache eviction has eaten the history the trends depend on.
    """
    archive_dir = Path(archive_dir)
    days = sorted(p.stem for p in archive_dir.glob("*.json")
                  if _DATE_RE.match(p.stem)) if archive_dir.exists() else []
    if not days:
        return {"days": 0, "first": "", "last": "", "missing": [], "contiguous": True,
                "bytes": 0}

    first = datetime.strptime(days[0], "%Y-%m-%d").date()
    last = datetime.strptime(days[-1], "%Y-%m-%d").date()
    present = set(days)
    missing = []
    cursor = first
    while cursor <= last:
        stamp = cursor.isoformat()
        if stamp not in present:
            missing.append(stamp)
        cursor += timedelta(days=1)

    total_bytes = sum(p.stat().st_size for p in archive_dir.glob("*.json"))
    return {
        "days": len(days),
        "first": days[0],
        "last": days[-1],
        "span_days": (last - first).days + 1,
        "missing": missing[:30],
        "missing_count": len(missing),
        "contiguous": not missing,
        "bytes": total_bytes,
    }


def publish_timeline(archive_dir, api_dir, today: dict | None = None) -> dict:
    """
    Write data/api/day/<date>.json for each archived day, plus the index.

    A day file is only rewritten when it is missing or its source archive is
    newer, so a normal hourly run rewrites at most one file rather than 90.
    """
    archive_dir = Path(archive_dir)
    api_dir = Path(api_dir)
    day_dir = api_dir / "day"
    day_dir.mkdir(parents=True, exist_ok=True)

    keep = CONFIG.timeline_days
    sources = sorted((p for p in archive_dir.glob("*.json") if _DATE_RE.match(p.stem)),
                     key=lambda p: p.stem)[-keep:]

    index = []
    written = 0
    for src in sources:
        dest = day_dir / f"{src.stem}.json"
        try:
            if not dest.exists() or dest.stat().st_mtime < src.stat().st_mtime:
                data = json.loads(src.read_text(encoding="utf-8"))
                payload = slim_day(data)
                payload["date"] = src.stem
                dest.write_text(json.dumps(payload, ensure_ascii=False,
                                           separators=(",", ":")), encoding="utf-8")
                written += 1
            summary = json.loads(dest.read_text(encoding="utf-8"))
        except Exception as e:  # noqa: BLE001 - one bad day must not stop the rest
            log.warning(f"  Timeline: could not publish {src.stem}: {e}")
            continue

        items = summary.get("items", [])
        index.append({
            "date": src.stem,
            "items": len(items),
            "urgent": sum(1 for i in items if i.get("priority_label") == "urgent"),
            "elevated": sum(1 for i in items if i.get("priority_label") == "elevated"),
            "kev": sum(1 for i in items if i.get("cisa_kev")),
            "scored": sum(1 for i in items if i.get("priority_score") is not None),
            "bytes": dest.stat().st_size,
            "sha256": _digest(dest),
        })

    # Today is not archived until the daily write fires, so the slider would
    # otherwise stop a day short of the dashboard's own contents.
    if today:
        stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        if not any(row["date"] == stamp for row in index):
            items = today.get("items", []) or []
            index.append({
                "date": stamp, "items": len(items),
                "urgent": sum(1 for i in items if i.get("priority_label") == "urgent"),
                "elevated": sum(1 for i in items if i.get("priority_label") == "elevated"),
                "kev": sum(1 for i in items if i.get("cisa_kev")),
                "scored": sum(1 for i in items if i.get("priority_score") is not None),
                "bytes": 0, "sha256": "", "live": True,
            })

    index.sort(key=lambda row: row["date"])

    # Prune day files that have fallen out of the retention window, so the
    # published site does not accumulate them forever.
    keep_dates = {row["date"] for row in index}
    pruned = 0
    for stale in day_dir.glob("*.json"):
        if _DATE_RE.match(stale.stem) and stale.stem not in keep_dates:
            stale.unlink()
            pruned += 1

    health = verify_archive(archive_dir)
    payload = {
        "generated": now_utc(),
        "retention_days": keep,
        "days": len(index),
        "first": index[0]["date"] if index else "",
        "last": index[-1]["date"] if index else "",
        "archive": health,
        "timeline": index,
    }
    (api_dir / "timeline.json").write_text(
        json.dumps(payload, ensure_ascii=False, separators=(",", ":")),
        encoding="utf-8")

    total_kb = sum(row["bytes"] for row in index) // 1024
    log.info(f"  Timeline: {len(index)} days published ({written} rewritten, "
             f"{pruned} pruned, {total_kb} KB total)")
    if not health["contiguous"]:
        log.warning(f"  Archive has {health['missing_count']} missing day(s) — "
                    f"trends and the backtest are working from a gapped history")
    return payload


if __name__ == "__main__":  # pragma: no cover - manual run
    root = Path(__file__).resolve().parent.parent
    out = publish_timeline(root / "data/archive", root / "data/api")
    print(json.dumps({k: v for k, v in out.items() if k != "timeline"}, indent=2))
