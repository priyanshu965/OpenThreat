"""Locate the current intel feed, wherever it happens to live.

`data/intel.json` is no longer committed — it is regenerated every run and
published as a GitHub Pages deploy artifact, because committing a 300 KB
document that genuinely changes every hour was adding ~106 MB a year to the
repository and nothing read the history back.

That leaves three places a consumer might legitimately find the feed, in
descending order of freshness:

  1. A local file, when the pipeline just produced one in this same job.
  2. The deployed dashboard, which is the canonical published copy.
  3. The newest committed daily archive snapshot — same document shape, but up
     to 24 hours old. This is the offline fallback, so a network blip degrades
     the digest instead of failing it.

Usage:
    python scripts/resolve_feed.py --out feed.json
    python scripts/resolve_feed.py --out feed.json --url https://example.github.io/Cyberwatch/
"""

import argparse
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
LOCAL_INTEL = PROJECT_ROOT / "data" / "intel.json"
ARCHIVE_DIR = PROJECT_ROOT / "data" / "archive"

USER_AGENT = "CyberWatch-resolve-feed/1.0"


def _valid(doc) -> bool:
    """A feed we can actually use has items in it."""
    return isinstance(doc, dict) and bool(doc.get("items"))


def from_local() -> dict | None:
    if not LOCAL_INTEL.exists():
        return None
    try:
        doc = json.loads(LOCAL_INTEL.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        print(f"local intel.json unreadable: {e}", file=sys.stderr)
        return None
    return doc if _valid(doc) else None


def from_dashboard(base_url: str, timeout: int = 30) -> dict | None:
    if not base_url:
        return None
    url = base_url.rstrip("/") + "/data/intel.json"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            doc = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, ValueError) as e:
        print(f"could not fetch {url}: {e}", file=sys.stderr)
        return None
    return doc if _valid(doc) else None


def from_archive() -> dict | None:
    """Newest committed daily snapshot. Same shape, up to 24h stale."""
    if not ARCHIVE_DIR.exists():
        return None
    for path in sorted(ARCHIVE_DIR.glob("*.json"), key=lambda p: p.stem, reverse=True):
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if _valid(doc):
            print(f"falling back to archive snapshot {path.name}", file=sys.stderr)
            return doc
    return None


def resolve(base_url: str = "") -> tuple[dict, str]:
    """Return (feed, where_it_came_from). Raises SystemExit if nothing works."""
    for name, doc in (("local", from_local()),
                      ("dashboard", from_dashboard(base_url)),
                      ("archive", from_archive())):
        if doc is not None:
            return doc, name
    raise SystemExit("no intel feed available from local file, dashboard, or archive")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", required=True, help="Where to write the resolved feed")
    ap.add_argument("--url", default="", help="Dashboard base URL to try before the archive")
    args = ap.parse_args()

    feed, source = resolve(args.url)
    Path(args.out).write_text(json.dumps(feed, ensure_ascii=False), encoding="utf-8")
    print(f"resolved feed from: {source} ({len(feed.get('items', []))} items)")


if __name__ == "__main__":
    main()
