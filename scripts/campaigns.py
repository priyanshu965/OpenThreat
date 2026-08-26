"""
CYBERWATCH — campaigns.py
==========================
Six of these 320 items are one operation. Say so.

The feed is a flat list, so a coordinated campaign arrives as scattered rows:
a vendor write-up on Monday, a CERT advisory on Wednesday, two leak-site posts
and an indicator drop. Each is individually unremarkable and collectively the
most important thing in the week.

Clustering rule, in order of strength:

  1. Shared threat actor. The strongest link there is — attribution is the
     thing analysts already reason with. Actors seed the clusters.
  2. Shared malware family, when no actor is named.
  3. Overlapping techniques AND a shared sector, inside the window. This is
     the weakest link and is only allowed to EXTEND a cluster that already
     has an actor or family anchor, never to create one on its own.

Rule 3 is constrained deliberately. Left unconstrained it merges half the feed:
T1566 Phishing and "corporate" co-occur constantly and mean nothing together.
The anchor requirement is what keeps a campaign a claim about one operation
rather than a topic cloud.

Every cluster carries its evidence — which items, which rule joined them, how
confident — because a campaign assertion the reader cannot audit is worse than
no assertion.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone

from fetchlib import CONFIG, log, now_utc


def _when(item: dict) -> datetime | None:
    raw = item.get("published")
    if not raw:
        return None
    try:
        parsed = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _tech_ids(item: dict) -> set[str]:
    return {t.get("id") for t in (item.get("ttps") or []) if t.get("id")}


def build_campaigns(items: list[dict],
                    window_days: int | None = None,
                    min_items: int | None = None) -> dict | None:
    """Group the feed into campaigns. Returns None when nothing clusters."""
    if not items:
        return None
    window = timedelta(days=window_days or CONFIG.campaign_window_days)
    minimum = min_items or CONFIG.campaign_min_items

    dated = []
    for item in items:
        when = _when(item)
        if when is not None:
            dated.append((when, item))
    if not dated:
        return None
    dated.sort(key=lambda pair: pair[0])
    newest = dated[-1][0]

    # ── Anchors: actor first, then malware family ─────────────────────────
    anchored: dict[tuple[str, str], list] = defaultdict(list)
    for when, item in dated:
        if newest - when > window:
            continue
        actors = item.get("threat_actors") or []
        if actors:
            for actor in actors[:2]:
                anchored[("actor", actor)].append((when, item))
            continue
        for family in (item.get("malware") or [])[:2]:
            anchored[("malware", family)].append((when, item))

    campaigns = []
    used_keys: set[str] = set()

    for (anchor_type, anchor), members in anchored.items():
        if len(members) < minimum:
            continue
        member_items = [m[1] for m in members]
        seen_ids = {id(i) for i in member_items}
        tech = set()
        sectors = set()
        for i in member_items:
            tech |= _tech_ids(i)
            if i.get("sector"):
                sectors.add(i["sector"])

        # ── Rule 3, extension only ────────────────────────────────────────
        # Pull in un-anchored items that share BOTH a technique and a sector
        # with the anchored core, inside the same window.
        extended = []
        if tech and sectors:
            for when, item in dated:
                if id(item) in seen_ids or newest - when > window:
                    continue
                if item.get("threat_actors") or item.get("malware"):
                    continue
                if (_tech_ids(item) & tech) and item.get("sector") in sectors:
                    extended.append(item)
                    seen_ids.add(id(item))
                    if len(extended) >= 12:
                        break

        all_items = member_items + extended
        times = [m[0] for m in members] + [w for w, i in dated if id(i) in {id(x) for x in extended}]
        first, last = min(times), max(times)

        sources = sorted({i.get("source", "") for i in all_items if i.get("source")})
        cves = sorted({(i.get("cve_id") or "").upper() for i in all_items if i.get("cve_id")})
        top_score = max((i.get("priority_score") or 0) for i in all_items)
        kev = sum(1 for i in all_items if i.get("cisa_kev"))

        # Confidence is a function of how much INDEPENDENT evidence there is,
        # not of how many rows matched — five rows from one source is one
        # observation repeated, and it should not read as corroboration.
        if len(sources) >= 3 and (kev or len(cves) >= 2):
            confidence = "high"
        elif len(sources) >= 2:
            confidence = "medium"
        else:
            confidence = "low"

        key = f"{anchor_type}:{anchor}".lower()
        if key in used_keys:
            continue
        used_keys.add(key)

        campaigns.append({
            "id": key.replace(" ", "-"),
            "anchor": anchor,
            "anchor_type": anchor_type,
            "confidence": confidence,
            "items": len(all_items),
            "anchored_items": len(member_items),
            "extended_items": len(extended),
            "distinct_sources": len(sources),
            "sources": sources[:8],
            "first_seen": first.isoformat(),
            "last_seen": last.isoformat(),
            "span_days": max(0, (last - first).days),
            "sectors": sorted(sectors),
            "techniques": sorted(tech)[:12],
            "cves": cves[:12],
            "kev_count": kev,
            "top_priority": round(top_score, 1) if top_score else 0,
            "malware": sorted({m for i in all_items for m in (i.get("malware") or [])})[:8],
            "members": [
                {
                    "title": (i.get("title") or "")[:160],
                    "url": i.get("url", ""),
                    "source": i.get("source", ""),
                    "published": i.get("published", ""),
                    "key": (i.get("cve_id") or i.get("url") or i.get("title", ""))[:180],
                    "joined_by": ("anchor" if i in member_items else "technique+sector"),
                }
                for i in sorted(all_items,
                                key=lambda x: str(x.get("published") or ""), reverse=True)[:20]
            ],
        })

    if not campaigns:
        return None

    # Rank by evidence, then reach, then recency.
    rank = {"high": 0, "medium": 1, "low": 2}
    campaigns.sort(key=lambda c: (rank[c["confidence"]], -c["distinct_sources"],
                                  -c["items"], c["last_seen"]))

    log.info(f"  Campaigns: {len(campaigns)} clusters covering "
             f"{sum(c['items'] for c in campaigns)} items "
             f"({sum(1 for c in campaigns if c['confidence'] == 'high')} high confidence)")

    return {
        "generated": now_utc(),
        "window_days": window.days,
        "min_items": minimum,
        "count": len(campaigns),
        "campaigns": campaigns,
        "notes": [
            "A campaign here is a CLUSTER, not an attribution. Items are joined "
            "by a shared actor or malware family; technique-and-sector overlap "
            "can only extend an existing cluster, never create one.",
            "Confidence counts independent SOURCES, not rows: five items from "
            "one feed is one observation repeated.",
        ],
    }


if __name__ == "__main__":  # pragma: no cover - manual run
    import json
    from pathlib import Path
    root = Path(__file__).resolve().parent.parent
    intel = json.loads((root / "data/intel.json").read_text(encoding="utf-8"))
    out = build_campaigns(intel["items"])
    if not out:
        raise SystemExit("nothing clustered")
    for c in out["campaigns"][:10]:
        print(f"{c['confidence']:6s} {c['anchor'][:28]:28s} items={c['items']:2d} "
              f"src={c['distinct_sources']} span={c['span_days']}d "
              f"kev={c['kev_count']} sectors={','.join(c['sectors'][:3])}")
