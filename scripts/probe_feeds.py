"""
OPENTHREAT — probe_feeds.py
===========================
Asks each feed the one question a desktop cannot answer: does it work from
where the pipeline actually runs?

Four feeds were added after passing every check on a laptop, and all four came
back empty on the first hosted run - two refused the runner's address range
outright and two never completed a handshake with it. A feed is only usable if
it answers a GitHub runner, so that is where this is meant to be run; the
source-health workflow does it daily.

  python scripts/probe_feeds.py --configured             every feed in RSS_SOURCES
  python scripts/probe_feeds.py --candidates FILE        a waiting list, Name|URL per line
  python scripts/probe_feeds.py --configured --strict    exit 1 if a configured feed fails

Verdicts
  ok          answers, parses, dated, median item age inside SOURCE_STALE_DAYS
  slow        the same, but posts too rarely for that rule - add with "cadence": "slow"
  dormant     nothing newer than SOURCE_SLOW_STALE_DAYS
  undated     entries carry no usable date, so every item would look new each run
  empty       answered, but with no entries (often an HTML page, not a feed)
  blocked     an HTTP error status
  unreachable no response at all
"""

from __future__ import annotations

import argparse
import os
import statistics
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import feedparser  # noqa: E402
import requests  # noqa: E402

from config import CONFIG  # noqa: E402
from feedutil import entry_date  # noqa: E402

FAILING = {"empty", "blocked", "unreachable"}
USABLE = {"ok", "slow"}


def read_candidates(path: Path) -> list[tuple[str, str]]:
    """`Name|URL` per line; blank lines and # comments are skipped."""
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "|" not in line:
            continue
        name, url = line.split("|", 1)
        # Same rule the pipeline's own list is held to.
        if url.strip().startswith("https://"):
            out.append((name.strip(), url.strip()))
    return out


def classify(status_code: int | None, text: str, now: datetime | None = None) -> tuple[str, str]:
    """Turn one response into (verdict, detail). Pure, so it is testable."""
    if status_code is None:
        return "unreachable", text
    if status_code != 200:
        return "blocked", f"HTTP {status_code}"
    feed = feedparser.parse(text)
    entries = feed.entries[:CONFIG.max_items_per_source]
    if not entries:
        return "empty", "no entries"
    now = now or datetime.now(timezone.utc)
    ages = []
    for entry in entries:
        stamp = entry_date(entry)
        if stamp:
            ages.append((now - datetime.fromisoformat(stamp)).total_seconds() / 86400)
    if not ages:
        return "undated", f"{len(entries)} entries, none dated"
    median, newest = statistics.median(ages), min(ages)
    detail = f"median {median:.0f}d, newest {newest:.0f}d"
    if median <= CONFIG.source_stale_days:
        return "ok", detail
    if newest <= CONFIG.source_slow_stale_days:
        return "slow", detail
    return "dormant", detail


def probe(name: str, url: str) -> dict:
    headers = {"User-Agent": CONFIG.http_user_agent}
    last = ""
    # One retry: a single timeout from a shared runner is weather, two is climate.
    for _ in range(2):
        try:
            resp = requests.get(url, headers=headers, timeout=20)
            verdict, detail = classify(resp.status_code, resp.text)
            if verdict != "blocked" or resp.status_code < 500:
                return {"name": name, "url": url, "verdict": verdict, "detail": detail}
            last = detail
        except requests.RequestException as e:
            last = type(e).__name__
    verdict = "blocked" if last.startswith("HTTP") else "unreachable"
    return {"name": name, "url": url, "verdict": verdict, "detail": last}


def render(title: str, rows: list[dict]) -> str:
    lines = [f"### {title}", "", "| Feed | Verdict | Detail |", "|---|---|---|"]
    for row in sorted(rows, key=lambda r: (r["verdict"] in USABLE, r["verdict"], r["name"].lower())):
        name = row["name"].replace("|", "/")
        lines.append(f"| {name} | {row['verdict']} | {row['detail']} |")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--configured", action="store_true", help="probe RSS_SOURCES")
    parser.add_argument("--candidates", type=Path, help="probe a Name|URL waiting list")
    parser.add_argument("--strict", action="store_true",
                        help="exit 1 when a configured feed is empty, blocked or unreachable")
    args = parser.parse_args(argv)

    sections = []
    if args.configured:
        from sources import RSS_SOURCES
        sections.append(("Configured feeds", [(s["name"], s["url"]) for s in RSS_SOURCES]))
    if args.candidates:
        sections.append(("Waiting list", read_candidates(args.candidates)))
    if not sections:
        parser.error("nothing to probe: pass --configured and/or --candidates")

    report, failed = [], []
    for title, feeds in sections:
        with ThreadPoolExecutor(max_workers=12) as pool:
            rows = list(pool.map(lambda f: probe(*f), feeds))
        report.append(render(title, rows))
        if title == "Configured feeds":
            failed = [r for r in rows if r["verdict"] in FAILING]
        else:
            usable = [r["name"] for r in rows if r["verdict"] in USABLE]
            if usable:
                report.append(f"Now usable from here: {', '.join(sorted(usable))}\n")

    text = "\n".join(report)
    print(text)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as fh:
            fh.write(text + "\n")
    if failed:
        print("FAILING: " + ", ".join(f"{r['name']} ({r['verdict']}: {r['detail']})" for r in failed))
    return 1 if (failed and args.strict) else 0


if __name__ == "__main__":
    sys.exit(main())
