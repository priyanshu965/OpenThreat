"""
CyberWatch REST API Server
===========================
Provides programmatic access to threat intelligence data.

Endpoints:
  GET  /api/intel           → Full intel feed (with optional ?search=&severity=&category=&source=)
  GET  /api/intel/:id       → Single item by index
  GET  /api/stats           → Summary statistics
  GET  /api/sources         → Active sources
  GET  /api/archive         → List available archive dates
  GET  /api/archive/:date   → Specific archive date
  GET  /health              → Health check

Usage:
  python scripts/rest_api.py [--port 8081]
"""

import json
import os
import sys
import argparse
from datetime import datetime, timezone
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

DATA_DIR     = Path(__file__).parent.parent / "data"
ARCHIVE_DIR  = DATA_DIR / "archive"
INTEL_FILE   = DATA_DIR / "intel.json"

MIME_JSON = ("Content-Type", "application/json")
MIME_HTML = ("Content-Type", "text/html")
CORS_HDR  = ("Access-Control-Allow-Origin", os.environ.get("CORS_ORIGIN", "*"))


class APIHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        ts = datetime.now(timezone.utc).isoformat()
        sys.stderr.write(f"[{ts}] {args[0]} {args[1]} {args[2]}\n")

    def _send_json(self, data, status=200):
        self.send_response(status)
        self.send_header(*MIME_JSON)
        self.send_header(*CORS_HDR)
        self.send_header("Cache-Control", "max-age=60")
        self.end_headers()
        self.wfile.write(json.dumps(data, indent=2, default=str).encode())

    def _send_error(self, msg, status=404):
        self._send_json({"error": msg}, status)

    def _load_intel(self):
        if not INTEL_FILE.exists():
            return None
        with open(INTEL_FILE) as f:
            return json.load(f)

    def do_GET(self):
        parsed = urlparse(self.path)
        path   = parsed.path.rstrip("/")
        params = parse_qs(parsed.query)

        # ── Health ──────────────────────────────────────────────
        if path == "/health":
            intel_exists = INTEL_FILE.exists()
            archive_files = list(ARCHIVE_DIR.glob("*.json")) if ARCHIVE_DIR.exists() else []
            self._send_json({
                "status": "ok",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "intel_file_exists": intel_exists,
                "archive_count": len(archive_files),
                "version": "2.0.0",
            })
            return

        # ── API ─────────────────────────────────────────────────
        if not path.startswith("/api"):
            self._send_error("Not found", 404)
            return

        data = self._load_intel()
        if data is None:
            self._send_error("Intel data not available. Run fetch_intel.py first.", 503)
            return

        # ── GET /api/stats ──────────────────────────────────────
        if path == "/api/stats":
            items = data.get("items", [])
            severity_counts = {}
            category_counts = {}
            source_counts = {}
            for item in items:
                s = item.get("severity", "unknown").lower()
                severity_counts[s] = severity_counts.get(s, 0) + 1
                c = item.get("category", "unknown")
                category_counts[c] = category_counts.get(c, 0) + 1
                src = item.get("source", "unknown")
                source_counts[src] = source_counts.get(src, 0) + 1

            self._send_json({
                "total_items": len(items),
                "last_updated": data.get("last_updated", ""),
                "pipeline_version": data.get("pipeline_version", "1.0"),
                "severity_breakdown": severity_counts,
                "category_breakdown": category_counts,
                "source_breakdown": source_counts,
                "critical_items": [i["title"] for i in items if i.get("severity") == "critical"],
                "ai_enriched": sum(1 for i in items if i.get("ai_provider") != "none"),
                "exploits_available": sum(1 for i in items if i.get("exploit_available")),
            })
            return

        # ── GET /api/sources ─────────────────────────────────────
        if path == "/api/sources":
            sources = set()
            for item in data.get("items", []):
                src = item.get("source")
                if src:
                    sources.add(src)
            self._send_json({"sources": sorted(sources), "count": len(sources)})
            return

        # ── GET /api/archive ─────────────────────────────────────
        if path == "/api/archive":
            if not ARCHIVE_DIR.exists():
                self._send_json({"archives": []})
                return
            dates = sorted(
                [f.stem for f in ARCHIVE_DIR.glob("*.json")],
                reverse=True
            )
            self._send_json({"archives": dates, "count": len(dates)})
            return

        # ── GET /api/archive/:date ──────────────────────────────
        if path.startswith("/api/archive/"):
            date_str = path.split("/")[-1]
            archive_path = ARCHIVE_DIR / f"{date_str}.json"
            if not archive_path.exists():
                self._send_error(f"Archive not found: {date_str}", 404)
                return
            with open(archive_path) as f:
                archive_data = json.load(f)
            self._send_json(archive_data)
            return

        # ── GET /api/intel (with optional filters) ──────────────
        if path == "/api/intel":
            items = data.get("items", [])
            search  = (params.get("search", [""])[0]).lower()
            severity = params.get("severity", [""])[0].lower()
            category = params.get("category", [""])[0].lower()
            source   = params.get("source", [""])[0].lower()
            limit    = int(params.get("limit", ["50"])[0])
            offset   = int(params.get("offset", ["0"])[0])

            if search:
                items = [i for i in items if
                    search in (i.get("title", "") + i.get("description", "")).lower() or
                    search in (i.get("cve_id", "") or "").lower()]
            if severity:
                items = [i for i in items if i.get("severity", "").lower() == severity]
            if category:
                items = [i for i in items if i.get("category", "").lower() == category]
            if source:
                items = [i for i in items if (i.get("source", "") or "").lower() == source]

            total = len(items)
            items = items[offset:offset + limit]

            self._send_json({
                "total": total,
                "limit": limit,
                "offset": offset,
                "last_updated": data.get("last_updated", ""),
                "items": items,
            })
            return

        # ── GET /api/intel/:id ──────────────────────────────────
        if path.startswith("/api/intel/"):
            idx_str = path.split("/")[-1]
            try:
                idx = int(idx_str)
                items = data.get("items", [])
                if 0 <= idx < len(items):
                    self._send_json(items[idx])
                else:
                    self._send_error(f"Item index out of range (0-{len(items)-1})", 404)
            except ValueError:
                self._send_error("Invalid index. Use integer.", 400)
            return

        self._send_error("Not found", 404)


def main():
    parser = argparse.ArgumentParser(description="CyberWatch REST API")
    parser.add_argument("--port", type=int, default=8081, help="Port to listen on")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind to")
    args = parser.parse_args()

    server = HTTPServer((args.host, args.port), APIHandler)
    print(f"CyberWatch API running on http://{args.host}:{args.port}")
    print(f"Endpoints:")
    print(f"  GET /health")
    print(f"  GET /api/stats")
    print(f"  GET /api/sources")
    print(f"  GET /api/intel[?search=&severity=&category=&source=&limit=&offset=]")
    print(f"  GET /api/intel/:id")
    print(f"  GET /api/archive")
    print(f"  GET /api/archive/:date")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down...")
        server.shutdown()


if __name__ == "__main__":
    main()
