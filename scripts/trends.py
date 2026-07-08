"""
CYBERWATCH — trends.py
=======================
The pipeline already keeps ~90 daily snapshots under data/archive/. This module
turns that history into a compact data/trends.json the dashboard renders as a
"Trends" tab — threat volume over time, severity mix week-over-week, the most
active threat actors, and trending CVEs.

Everything is derived from the archive, so it costs nothing extra to fetch.
"""

import json
import re
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def _load_snapshots(archive_dir: Path, window_days: int):
    """Return [(date_str, data), ...] sorted ascending, newest `window_days` kept."""
    if not archive_dir.exists():
        return []
    files = sorted(
        (f for f in archive_dir.glob("*.json") if _DATE_RE.match(f.stem)),
        key=lambda f: f.stem,
    )
    files = files[-window_days:]
    snapshots = []
    for f in files:
        try:
            snapshots.append((f.stem, json.loads(f.read_text(encoding="utf-8"))))
        except Exception:
            continue
    return snapshots


def _severity(item):
    return (item.get("severity") or "medium").lower()


def build_trends(archive_dir, trends_path, window_days: int = 30) -> dict:
    """
    Aggregate the archive into trends.json. Returns the trends dict (also written
    to ``trends_path``). Safe to call with an empty/partial archive.
    """
    archive_dir = Path(archive_dir)
    trends_path = Path(trends_path)
    snapshots = _load_snapshots(archive_dir, window_days)

    daily = []
    severity_totals = defaultdict(int)
    actor_days = defaultdict(int)       # actor -> # of days it appeared
    ttp_days = defaultdict(lambda: {"name": "", "count": 0})
    source_days = defaultdict(int)
    cve_stats = {}                      # cve -> {days_seen, max_priority, kev, last_seen, title}

    for date_str, data in snapshots:
        items = data.get("items", [])
        row = {"date": date_str, "total": len(items),
               "critical": 0, "high": 0, "medium": 0, "low": 0,
               "cve": 0, "incident": 0, "advisory": 0, "news": 0}
        day_actors, day_ttps, day_sources, day_cves = set(), set(), set(), set()

        for item in items:
            sev = _severity(item)
            if sev in row:
                row[sev] += 1
                severity_totals[sev] += 1
            cat = (item.get("category") or "news").lower()
            if cat in row:
                row[cat] += 1

            for actor in item.get("threat_actors", []) or []:
                day_actors.add(actor)
            for ttp in item.get("ttps", []) or []:
                tid = ttp.get("id")
                if tid:
                    day_ttps.add(tid)
                    ttp_days[tid]["name"] = ttp.get("name", "")
            src = item.get("source")
            if src:
                day_sources.add(src)

            cve = (item.get("cve_id") or "").upper()
            if cve:
                day_cves.add(cve)
                prio = item.get("priority_score") or 0
                st = cve_stats.get(cve)
                if not st:
                    cve_stats[cve] = {
                        "cve": cve, "days_seen": 0, "max_priority": prio,
                        "kev": bool(item.get("cisa_kev")), "last_seen": date_str,
                        "title": (item.get("title") or "")[:120],
                    }
                    st = cve_stats[cve]
                st["max_priority"] = max(st["max_priority"], prio)
                st["kev"] = st["kev"] or bool(item.get("cisa_kev"))
                st["last_seen"] = date_str

        for a in day_actors:
            actor_days[a] += 1
        for t in day_ttps:
            ttp_days[t]["count"] += 1
        for s in day_sources:
            source_days[s] += 1
        for c in day_cves:
            cve_stats[c]["days_seen"] += 1

        daily.append(row)

    top_actors = sorted(
        ({"name": a, "count": c} for a, c in actor_days.items()),
        key=lambda x: x["count"], reverse=True,
    )[:10]

    top_ttps = sorted(
        ({"id": t, "name": d["name"], "count": d["count"]} for t, d in ttp_days.items()),
        key=lambda x: x["count"], reverse=True,
    )[:12]

    top_sources = sorted(
        ({"name": s, "count": c} for s, c in source_days.items()),
        key=lambda x: x["count"], reverse=True,
    )[:12]

    # Trending CVEs: active recently, ranked by priority then persistence.
    trending = sorted(
        cve_stats.values(),
        key=lambda x: (x["kev"], x["max_priority"], x["days_seen"]),
        reverse=True,
    )[:15]

    trends = {
        "generated": datetime.now(timezone.utc).isoformat(),
        "window_days": window_days,
        "days_covered": len(daily),
        "daily": daily,
        "severity_totals": dict(severity_totals),
        "top_actors": top_actors,
        "top_ttps": top_ttps,
        "top_sources": top_sources,
        "trending_cves": trending,
    }

    trends_path.parent.mkdir(parents=True, exist_ok=True)
    trends_path.write_text(json.dumps(trends, indent=2, ensure_ascii=False), encoding="utf-8")
    return trends


if __name__ == "__main__":
    root = Path(__file__).resolve().parent.parent
    out = build_trends(root / "data/archive", root / "data/trends.json")
    print(f"Trends over {out['days_covered']} days → data/trends.json")
