"""
CYBERWATCH — source_reliability.py
===================================
Which of the 43 feeds are actually worth reading?

The pipeline treats every source as equal: a Spamhaus row and a Unit 42 write-up
land in the same list with the same standing. Source health already answers "is
it up", which is a liveness question. This answers a different and much more
useful one — "when this source publishes something, does it matter?"

The same archive that powers the scoring backtest answers it, using the same
outcome variable and the same discipline:

  coverage    of the distinct CVEs this source carried, what share are in KEV
              at all (`precision`). Mostly a measure of how promptly a source
              reports CISA's own announcement — useful, but not a forecast.

  early       the same measure restricted to CVEs the source carried BEFORE
  warning     the listing date (`ahead_precision`). This is the one that means
              something. Keeping the two apart matters: run together, a news
              site that writes up every KEV addition the day it lands scores a
              0.81 "precision" for predicting an announcement it was merely
              reporting.

  lead time   median days between this source first carrying a CVE and CISA
              listing it. Positive means ahead; negative means it published
              after CISA did.

  first-mover how often this source was the FIRST in the whole corpus to carry
              a CVE that later became KEV, and carried it before the listing.
              The sharpest measure, and the hardest to fake with volume.

  noise       items carrying no CVE, no score, no actor and no technique — the
              rows that pad a feed without adding a fact to it.

Nothing here is used to silently drop a source. It is published so the feed can
be weighted knowingly, and so a dead-weight source can be argued about with a
number rather than a hunch.
"""

from __future__ import annotations

import json
import re
import statistics
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fetchlib import CONFIG, log, now_utc

_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def _parse_day(value: str):
    try:
        return datetime.strptime(value, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return None


def _iter_snapshots(archive_dir: Path):
    if not archive_dir.exists():
        return
    for path in sorted(archive_dir.glob("*.json"), key=lambda p: p.stem):
        if not _DATE_RE.match(path.stem):
            continue
        try:
            yield path.stem, json.loads(path.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            continue


def build_source_reliability(archive_dir, kev: dict,
                             horizon_days: int | None = None) -> dict | None:
    archive_dir = Path(archive_dir)
    horizon = horizon_days or CONFIG.backtest_horizon_days
    if not kev:
        return None

    # source -> stats
    stats: dict[str, dict] = {}
    # cve -> earliest (date, source) seen anywhere in the corpus
    first_carrier: dict[str, tuple[str, str]] = {}
    # (source, cve) -> first date that source carried it
    source_first: dict[tuple[str, str], str] = {}

    days = 0
    for date_str, data in _iter_snapshots(archive_dir):
        days += 1
        for item in data.get("items", []) or []:
            source = item.get("source") or "unknown"
            row = stats.setdefault(source, {
                "source": source, "items": 0, "cve_items": 0, "distinct_cves": set(),
                "scored": 0, "urgent": 0, "with_actor": 0, "with_ttp": 0,
                "with_ioc": 0, "noise": 0, "days_active": set(),
            })
            row["items"] += 1
            row["days_active"].add(date_str)

            cve = (item.get("cve_id") or "").upper()
            has_score = item.get("priority_score") is not None
            has_actor = bool(item.get("threat_actors"))
            has_ttp = bool(item.get("ttps"))
            has_ioc = bool(item.get("iocs"))

            if cve:
                row["cve_items"] += 1
                row["distinct_cves"].add(cve)
                key = (source, cve)
                if key not in source_first or date_str < source_first[key]:
                    source_first[key] = date_str
                prev = first_carrier.get(cve)
                if prev is None or date_str < prev[0]:
                    first_carrier[cve] = (date_str, source)
            if has_score:
                row["scored"] += 1
            if item.get("priority_label") in ("urgent", "elevated"):
                row["urgent"] += 1
            if has_actor:
                row["with_actor"] += 1
            if has_ttp:
                row["with_ttp"] += 1
            if has_ioc:
                row["with_ioc"] += 1
            if not (cve or has_score or has_actor or has_ttp or has_ioc):
                row["noise"] += 1

    if not stats:
        return None

    now = datetime.now(timezone.utc)

    def _became_kev(cve: str, seen_on: str) -> bool | None:
        """True / False / None(censored) — same rule as the scoring backtest."""
        added = _parse_day((kev.get(cve) or {}).get("added") or "")
        seen = _parse_day(seen_on)
        if seen is None:
            return None
        deadline = seen + timedelta(days=horizon)
        if added is not None and added <= deadline:
            return True
        if now < deadline:
            return None
        return False

    # Corpus-wide base rate, on the same censoring rule AND the same
    # already-listed exclusion the per-source figures use, so `lift` compares
    # like with like.
    corpus_eval = 0
    corpus_hits = 0
    for cve, (date_str, _src) in first_carrier.items():
        verdict = _became_kev(cve, date_str)
        if verdict is None:
            continue
        added = _parse_day((kev.get(cve) or {}).get("added") or "")
        seen = _parse_day(date_str)
        if added and seen and added < seen:
            continue                      # the corpus met it after CISA did
        corpus_eval += 1
        corpus_hits += 1 if verdict else 0
    base_rate = corpus_hits / corpus_eval if corpus_eval else 0.0

    rows = []
    for source, row in stats.items():
        evaluated = 0
        hits = 0
        ahead_evaluated = 0
        ahead_hits = 0
        leads: list[float] = []
        first_mover = 0
        for cve in row["distinct_cves"]:
            seen_on = source_first.get((source, cve), "")
            verdict = _became_kev(cve, seen_on)
            if verdict is None:
                continue
            evaluated += 1
            added = _parse_day((kev.get(cve) or {}).get("added") or "")
            seen = _parse_day(seen_on)

            # COVERAGE vs EARLY WARNING. These are different questions and the
            # first version of this module ran them together, which is why
            # Bleeping Computer scored a 0.81 "precision": it writes about KEV
            # CVEs the day CISA lists them, so it was being credited with
            # predicting an announcement it was reporting. A source only counts
            # as early warning if it carried the CVE BEFORE the listing date.
            already_listed = bool(added and seen and added < seen)
            if not already_listed:
                ahead_evaluated += 1

            if not verdict:
                continue
            hits += 1
            if added and seen:
                leads.append((added - seen).days)
            if not already_listed:
                ahead_hits += 1
                if first_carrier.get(cve, ("", ""))[1] == source:
                    first_mover += 1

        precision = hits / evaluated if evaluated else 0.0
        ahead_precision = ahead_hits / ahead_evaluated if ahead_evaluated else 0.0
        signal_items = row["scored"] + row["with_actor"] + row["with_ttp"]
        rows.append({
            "source": source,
            "items": row["items"],
            "days_active": len(row["days_active"]),
            "items_per_day": round(row["items"] / max(1, len(row["days_active"])), 1),
            "cve_items": row["cve_items"],
            "distinct_cves": len(row["distinct_cves"]),
            "evaluated_cves": evaluated,
            "kev_hits": hits,
            "ahead_evaluated": ahead_evaluated,
            "ahead_hits": ahead_hits,
            "ahead_precision": round(ahead_precision, 4),
            "first_mover_hits": first_mover,
            "precision": round(precision, 4),
            "lift": round(ahead_precision / base_rate, 2) if base_rate else 0.0,
            "median_lead_days": round(statistics.median(leads), 1) if leads else None,
            "urgent_items": row["urgent"],
            "with_actor": row["with_actor"],
            "with_ttp": row["with_ttp"],
            "with_ioc": row["with_ioc"],
            "noise_items": row["noise"],
            "noise_ratio": round(row["noise"] / row["items"], 3) if row["items"] else 0.0,
            "signal_ratio": round(min(1.0, signal_items / row["items"]), 3) if row["items"] else 0.0,
        })

    # Rank on EARLY WARNING: first to a CVE that later mattered, then how many
    # it carried ahead of the listing, then how often it was right. Volume
    # deliberately does not rank a source up, and neither does coverage —
    # reporting a KEV addition after the fact is not intelligence.
    rows.sort(key=lambda r: (-r["first_mover_hits"], -r["ahead_hits"],
                             -r["ahead_precision"], -r["signal_ratio"]))

    ranked = [r for r in rows if r["ahead_evaluated"] >= 3]
    log.info(f"  Source reliability: {len(rows)} sources over {days} days, "
             f"base rate {base_rate * 100:.2f}%")

    return {
        "generated": now_utc(),
        "horizon_days": horizon,
        "archive_days": days,
        "base_rate": round(base_rate, 5),
        "corpus_evaluated_cves": corpus_eval,
        "sources": rows,
        "ranked": ranked[:20],
        # Sources that publish steadily and contribute nothing enrichable.
        "dead_weight": sorted(
            (r for r in rows if r["items"] >= 20 and r["noise_ratio"] >= 0.9),
            key=lambda r: -r["items"])[:12],
        "notes": [
            "Two different numbers. `precision` is COVERAGE — of the CVEs this "
            "source carried, how many are in KEV at all. `ahead_precision` is "
            "EARLY WARNING — the same measure restricted to CVEs the source "
            "carried BEFORE CISA listed them. Only the second is a forecast; "
            "the first largely measures how promptly a source reports the "
            "KEV announcement itself.",
            "First-mover counts only fire when a source was the earliest in the "
            "whole corpus to carry a CVE that was later listed, and carried it "
            "before the listing.",
            "A negative median lead means the source typically published after "
            "CISA did. PoC-in-GitHub's large negative lead is expected: it "
            "indexes exploit repositories for CVEs long after disclosure.",
            "A source specialising in indicators rather than CVEs scores zero "
            "here and can still be valuable — read it next to noise ratio.",
        ],
    }


if __name__ == "__main__":  # pragma: no cover - manual run
    from kev_catalog import load_kev
    root = Path(__file__).resolve().parent.parent
    out = build_source_reliability(root / "data/archive", load_kev())
    if not out:
        raise SystemExit("no result")
    print(f"base rate {out['base_rate'] * 100:.2f}%  over {out['archive_days']} days")
    for r in out["ranked"][:14]:
        print(f"  {r['source']:22s} first={r['first_mover_hits']:2d} "
              f"ahead={r['ahead_hits']:2d}/{r['ahead_evaluated']:<4d} "
              f"aheadP={r['ahead_precision']:.3f} lift={r['lift']:5.2f} "
              f"cover={r['precision']:.3f} lead={r['median_lead_days']} "
              f"noise={r['noise_ratio']:.2f}")
