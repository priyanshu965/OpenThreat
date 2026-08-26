"""
CYBERWATCH — backtest.py
=========================
Does the priority score actually predict exploitation?

The pipeline blends CVSS, EPSS, SSVC, public-PoC availability and KEV listing
into a 0-100 number using weights (40/40/25/15/20/10/5) that were chosen by
intuition and have never been checked against an outcome. There are ~90 daily
snapshots under data/archive/ carrying a score for every CVE on the day it was
scored, and CISA KEV records the date each CVE was added. That is enough to ask
the question properly.

METHOD — and the one detail that makes or breaks it

    A CVE enters the cohort on the first archived day it was scored.
    It is EXCLUDED if it was already in KEV on that day.

Without that exclusion the experiment is circular: the score adds 20 points and
floors at 90 for KEV membership, so "high score predicts KEV" would be
measuring the arithmetic, not the world. What we want to know is whether the
score saw it coming.

    Outcome  = the CVE was added to KEV within HORIZON days of being scored.
    Censoring= CVEs first scored fewer than HORIZON days ago are dropped;
               they have not had their chance yet, and counting them as
               failures would silently punish every recent item.

WHAT IS REPORTED

  * precision / recall / F1 at each score threshold, for the blended score and
    for CVSS-alone and EPSS-alone as baselines. If the blend does not beat
    CVSS alone, that is a real result and it will say so.
  * precision@K — of the top K items the tool put in front of you, how many
    turned out to be exploited. This is the number that matches how the
    dashboard is actually used.
  * lift over base rate. A precision of 4% sounds terrible until you see the
    base rate is 0.6%.
  * a small grid search over the CVSS/EPSS weights, reporting the weights that
    would have maximised average precision on this history — so the constants
    in config.py can be argued with instead of assumed.

CAVEATS, stated in the output rather than buried here: the archive is short,
KEV additions are rare, and CISA listing is a proxy for exploitation rather
than exploitation itself. A result from 90 days is a signal, not a finding.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fetchlib import CONFIG, log, now_utc

_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")

# Score thresholds reported. These are the band edges the UI already uses plus
# a few in between, so the table lines up with what a reader sees on a card.
_THRESHOLDS = [90, 80, 70, 60, 50, 40, 30, 20, 10]
_TOP_K = [5, 10, 25, 50, 100]


def _parse_day(value: str):
    try:
        return datetime.strptime(value, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return None


def _iter_snapshots(archive_dir: Path):
    """(date_str, data) ascending. Snapshots are read one at a time — the
    archive is 24 MB and holding all 90 in memory is pointless."""
    if not archive_dir.exists():
        return
    for path in sorted(archive_dir.glob("*.json"), key=lambda p: p.stem):
        if not _DATE_RE.match(path.stem):
            continue
        try:
            yield path.stem, json.loads(path.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001 - a truncated snapshot is not fatal
            continue


def collect_cohort(archive_dir: Path, kev: dict) -> list[dict]:
    """
    One row per CVE, describing it as it looked the FIRST day we scored it.

    Later snapshots are used only to fill in signals we did not have on day
    one (a CVSS that arrived late, for instance) — never to update the score,
    which would leak the future into the prediction.
    """
    cohort: dict[str, dict] = {}
    for date_str, data in _iter_snapshots(archive_dir):
        for item in data.get("items", []) or []:
            cve = (item.get("cve_id") or "").upper()
            if not cve or item.get("priority_score") is None:
                continue
            if cve in cohort:
                continue
            kev_row = kev.get(cve) or {}
            kev_added = kev_row.get("added") or ""
            # Already listed when we first scored it: nothing to predict.
            already_kev = bool(item.get("cisa_kev")) or (
                bool(kev_added) and kev_added <= date_str)
            cohort[cve] = {
                "cve": cve,
                "scored_on": date_str,
                "score": float(item.get("priority_score") or 0.0),
                "cvss": item.get("cvss_score"),
                "epss": item.get("epss_score"),
                "has_poc": bool(item.get("has_poc")),
                "ssvc": item.get("ssvc_exploitation") or "",
                "automatable": item.get("ssvc_automatable") == "yes",
                "total_impact": item.get("ssvc_technical_impact") == "total",
                "already_kev": already_kev,
                "kev_added": kev_added,
                "source": item.get("source", ""),
                "title": (item.get("title") or "")[:120],
            }
    return list(cohort.values())


def _label(row: dict, horizon_days: int) -> bool | None:
    """True = listed within the horizon, False = not, None = still censored."""
    scored = _parse_day(row["scored_on"])
    if scored is None:
        return None
    deadline = scored + timedelta(days=horizon_days)
    added = _parse_day(row.get("kev_added") or "")
    if added is not None and scored <= added <= deadline:
        return True
    if datetime.now(timezone.utc) < deadline:
        return None          # not enough time has passed to call it a miss
    return False


def _confusion(rows: list[tuple[float, bool]], threshold: float) -> dict:
    tp = sum(1 for score, hit in rows if score >= threshold and hit)
    fp = sum(1 for score, hit in rows if score >= threshold and not hit)
    fn = sum(1 for score, hit in rows if score < threshold and hit)
    tn = len(rows) - tp - fp - fn
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    return {
        "threshold": threshold, "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "flagged": tp + fp,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
    }


def _average_precision(rows: list[tuple[float, bool]]) -> float:
    """
    Area under the precision-recall curve, computed the standard way: walk the
    ranking, and every time a positive is hit add the precision at that depth.

    AP is used rather than ROC-AUC because the positive class here is ~1% of
    the cohort, and ROC-AUC flatters a ranker on data that imbalanced.
    """
    ordered = sorted(rows, key=lambda r: -r[0])
    positives = sum(1 for _, hit in ordered if hit)
    if not positives:
        return 0.0
    hits = 0
    total = 0.0
    for depth, (_, hit) in enumerate(ordered, start=1):
        if hit:
            hits += 1
            total += hits / depth
    return round(total / positives, 4)


def _precision_at_k(rows: list[tuple[float, bool]]) -> list[dict]:
    ordered = sorted(rows, key=lambda r: -r[0])
    out = []
    for k in _TOP_K:
        if k > len(ordered):
            break
        head = ordered[:k]
        hits = sum(1 for _, hit in head if hit)
        out.append({"k": k, "hits": hits, "precision": round(hits / k, 4)})
    return out


def _blend(row: dict, cvss_w: float, epss_w: float) -> float:
    """
    Re-score a cohort row with different CVSS/EPSS weights.

    The KEV term is deliberately absent: every row in the cohort was NOT in KEV
    when it was scored, so its KEV contribution was zero by construction.
    Including it here would invent points the live scorer never awarded.
    """
    score = 0.0
    if row.get("cvss") is not None:
        score += cvss_w * (float(row["cvss"]) / 10.0)
    if row.get("epss") is not None:
        score += epss_w * float(row["epss"])
    ssvc = row.get("ssvc") or ""
    if ssvc == "active":
        score += CONFIG.priority_ssvc_active_bonus
    elif ssvc == "poc":
        score += CONFIG.priority_ssvc_active_bonus * 0.45
    if row.get("automatable"):
        score += CONFIG.priority_ssvc_auto_bonus
    if row.get("total_impact"):
        score += CONFIG.priority_ssvc_total_bonus
    if row.get("has_poc"):
        score += CONFIG.priority_poc_bonus
    return min(100.0, score)


def _evaluate(name: str, rows: list[tuple[float, bool]], base_rate: float) -> dict:
    curve = [_confusion(rows, t) for t in _THRESHOLDS]
    ap = _average_precision(rows)
    best = max((c for c in curve if c["flagged"]), key=lambda c: c["f1"], default=None)
    return {
        "name": name,
        "average_precision": ap,
        "lift_over_base": round(ap / base_rate, 2) if base_rate else 0.0,
        "precision_at_k": _precision_at_k(rows),
        "curve": curve,
        "best_f1": best,
    }


def build_backtest(archive_dir, kev: dict,
                   horizon_days: int | None = None) -> dict | None:
    """
    Run the experiment. Returns None when the archive is too thin to say
    anything — which is a legitimate answer, not a failure.
    """
    archive_dir = Path(archive_dir)
    horizon = horizon_days or CONFIG.backtest_horizon_days
    if not kev:
        log.info("  Backtest skipped: no KEV catalogue to score against")
        return None

    cohort = collect_cohort(archive_dir, kev)
    predictable = [r for r in cohort if not r["already_kev"]]

    labelled: list[dict] = []
    censored = 0
    for row in predictable:
        label = _label(row, horizon)
        if label is None:
            censored += 1
            continue
        row["became_kev"] = label
        labelled.append(row)

    positives = sum(1 for r in labelled if r["became_kev"])
    base_rate = positives / len(labelled) if labelled else 0.0

    result = {
        "generated": now_utc(),
        "horizon_days": horizon,
        "archive_days": sum(1 for _ in _iter_snapshots(archive_dir)),
        "cohort": {
            "cves_scored": len(cohort),
            "already_kev_at_scoring": sum(1 for r in cohort if r["already_kev"]),
            "still_within_horizon": censored,
            "evaluated": len(labelled),
            "became_kev": positives,
            "base_rate": round(base_rate, 5),
        },
        "weights_in_use": {
            "cvss": CONFIG.priority_cvss_weight,
            "epss": CONFIG.priority_epss_weight,
            "kev": CONFIG.priority_kev_bonus,
            "poc": CONFIG.priority_poc_bonus,
            "ssvc_active": CONFIG.priority_ssvc_active_bonus,
        },
        "caveats": [
            "CISA KEV listing is a proxy for exploitation, not exploitation itself: "
            "a CVE exploited quietly and never listed counts here as a miss.",
            "CVEs already in KEV when first scored are excluded, otherwise the "
            "score's own KEV bonus would be predicting its own input.",
            "CVEs first scored less than the horizon ago are censored, not "
            "counted as failures.",
        ],
    }

    if len(labelled) < CONFIG.backtest_min_samples or positives == 0:
        result["verdict"] = (
            f"Not enough history yet: {len(labelled)} evaluable CVEs and "
            f"{positives} KEV additions inside the window. The archive needs to "
            f"deepen past {horizon} days before this can say anything."
        )
        result["insufficient_data"] = True
        log.info(f"  Backtest: insufficient data ({len(labelled)} evaluable, "
                 f"{positives} positive)")
        return result

    blended = [(r["score"], r["became_kev"]) for r in labelled]
    cvss_only = [((float(r["cvss"]) * 10.0 if r["cvss"] is not None else 0.0),
                  r["became_kev"]) for r in labelled]
    epss_only = [((float(r["epss"]) * 100.0 if r["epss"] is not None else 0.0),
                  r["became_kev"]) for r in labelled]
    poc_only = [((100.0 if r["has_poc"] else 0.0), r["became_kev"]) for r in labelled]

    models = [
        _evaluate("Blended priority score", blended, base_rate),
        _evaluate("CVSS alone", cvss_only, base_rate),
        _evaluate("EPSS alone", epss_only, base_rate),
        _evaluate("Public PoC alone", poc_only, base_rate),
    ]
    result["models"] = models

    # ── Weight grid search ────────────────────────────────────────────────
    # Coarse on purpose. With a few hundred samples a fine grid would be
    # fitting noise, and reporting a weight to one decimal place would imply a
    # precision this data cannot support.
    grid = []
    for cvss_w in (0, 10, 20, 30, 40, 50, 60):
        for epss_w in (0, 10, 20, 30, 40, 50, 60):
            if cvss_w == 0 and epss_w == 0:
                continue
            rows = [(_blend(r, cvss_w, epss_w), r["became_kev"]) for r in labelled]
            grid.append({"cvss": cvss_w, "epss": epss_w,
                         "average_precision": _average_precision(rows)})
    grid.sort(key=lambda g: -g["average_precision"])
    current = next((g for g in grid
                    if g["cvss"] == round(CONFIG.priority_cvss_weight / 10) * 10
                    and g["epss"] == round(CONFIG.priority_epss_weight / 10) * 10), None)
    result["weight_search"] = {
        "best": grid[0],
        "current": current,
        "top": grid[:8],
        "note": ("Coarse 7x7 grid. With this sample size a finer search would "
                 "be fitting noise, and the difference between adjacent cells "
                 "is not meaningful."),
    }

    blend_ap = models[0]["average_precision"]
    cvss_ap = models[1]["average_precision"]
    epss_ap = models[2]["average_precision"]
    best_baseline = max(cvss_ap, epss_ap)
    if blend_ap > best_baseline * 1.05:
        verdict = (f"The blend beats its best single input: average precision "
                   f"{blend_ap:.3f} vs {best_baseline:.3f}, on {len(labelled)} "
                   f"CVEs with a {base_rate * 100:.2f}% base rate.")
    elif blend_ap >= best_baseline * 0.95:
        verdict = (f"The blend matches rather than beats its best single input "
                   f"({blend_ap:.3f} vs {best_baseline:.3f}). On this history the "
                   f"extra signals are not earning their weight.")
    else:
        verdict = (f"The blend is WORSE than its best single input "
                   f"({blend_ap:.3f} vs {best_baseline:.3f}). Worth taking "
                   f"seriously before defending the current weights.")
    result["verdict"] = verdict
    log.info(f"  Backtest: {verdict}")
    return result


if __name__ == "__main__":  # pragma: no cover - manual run
    from kev_catalog import load_kev
    root = Path(__file__).resolve().parent.parent
    out = build_backtest(root / "data/archive", load_kev())
    print(json.dumps(out, indent=2)[:4000] if out else "no result")
