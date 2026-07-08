"""
CYBERWATCH — daily_digest.py
=============================
Scheduled daily summary of everything the pipeline collected in the last 24h,
grouped by category with top priorities highlighted. Sent to the same webhook
(Slack/Discord/Telegram/email) as the per-run alerts, but as a compact digest
rather than per-item firehose.

Usage:
    python scripts/daily_digest.py [--hour 8] [--dry-run]

Designed to be triggered by a separate cron / scheduled workflow
(e.g. .github/workflows/daily-digest.yml).

Env vars: same as webhook_post.py + DIGEST_HOUR (default 8 AM local).
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from scripts.config import CONFIG

DIGEST_STATE = CONFIG.data_dir / ".digest_state.json"


# ── Helpers ─────────────────────────────────────────────────────────────────────

def _group_items(items: list) -> dict:
    """Categorise items by their `category` field."""
    groups = {}
    for item in items:
        cat = (item.get("category") or "other").strip().lower()
        groups.setdefault(cat, []).append(item)
    return groups


def _summarise(items: list, top_n: int = 5) -> str:
    """Bulleted summary of the top `top_n` items sorted by priority."""
    ranked = sorted(items, key=lambda i: i.get("priority_score") or 0, reverse=True)
    lines = []
    for item in ranked[:top_n]:
        sev = (item.get("severity") or "?").upper()
        score = item.get("priority_score")
        prio = f" [P{score}]" if score is not None else ""
        kev = " 🔴KEV" if item.get("cisa_kev") else ""
        poc = " 💥PoC" if item.get("has_poc") else ""
        title = (item.get("title") or "?")[:120]
        lines.append(f"• [{sev}]{prio}{kev}{poc} {title}")
    return "\n".join(lines)


# ── Payload builder ─────────────────────────────────────────────────────────────

_DIGEST_EMOJI = {
    "cve": "🛡️", "exploit": "💀", "malware": "🦠", "incident": "🚨",
    "ransomware": "💰", "phishing": "🎣", "advisory": "📋", "news": "📰",
}


def build_digest_payload(items: list, webhook_type: str) -> dict:
    groups = _group_items(items)
    total = len(items)
    critical = sum(1 for i in items if (i.get("severity") or "").lower() == "critical")
    high = sum(1 for i in items if (i.get("severity") or "").lower() == "high")
    kev_count = sum(1 for i in items if i.get("cisa_kev"))
    poc_count = sum(1 for i in items if i.get("has_poc"))

    if webhook_type == "slack":
        blocks = [
            {"type": "header", "text": {"type": "plain_text",
             "text": f"📊 CyberWatch Daily Digest — {total} items ({critical} critical, {high} high)"}},
            {"type": "context", "elements": [{"type": "mrkdwn",
             "text": f"KEV: {kev_count} · PoC: {poc_count} · Sources: {len(groups)}"}]},
            {"type": "divider"},
        ]
        for cat, cat_items in sorted(groups.items()):
            emoji = _DIGEST_EMOJI.get(cat, "📌")
            sev_count = sum(1 for i in cat_items
                            if (i.get("severity") or "").lower() in ("critical", "high"))
            blocks.append({"type": "section", "text": {"type": "mrkdwn",
                "text": f"*{emoji} {cat.title()}* ({len(cat_items)} items, {sev_count} high+)"}})
            summary = _summarise(cat_items, 3)
            if summary:
                blocks.append({"type": "section", "text": {"type": "mrkdwn",
                    "text": summary}})
        blocks.append({"type": "context", "elements": [{"type": "mrkdwn",
            "text": f"🕐 {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} · "
                    f"<{CONFIG.output_path.parent}/index.html|Open Dashboard>"}]})
        return {"text": f"CyberWatch Daily Digest: {total} items", "blocks": blocks}

    if webhook_type == "discord":
        desc_lines = []
        for cat, cat_items in sorted(groups.items()):
            emoji = _DIGEST_EMOJI.get(cat, "📌")
            sev_count = sum(1 for i in cat_items
                            if (i.get("severity") or "").lower() in ("critical", "high"))
            desc_lines.append(f"**{emoji} {cat.title()}** ({len(cat_items)}, {sev_count} high+)")
            summary = _summarise(cat_items, 2)
            if summary:
                desc_lines.append(summary)
        return {
            "embeds": [{
                "title": f"📊 CyberWatch Daily Digest — {total} items",
                "description": "\n".join(desc_lines),
                "color": 0x3366FF,
                "fields": [
                    {"name": "Critical", "value": str(critical), "inline": True},
                    {"name": "High", "value": str(high), "inline": True},
                    {"name": "KEV / PoC", "value": f"{kev_count} / {poc_count}", "inline": True},
                ],
                "footer": {"text": f"{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}"},
            }],
        }

    if webhook_type == "telegram":
        text = f"📊 *CyberWatch Daily Digest* — {total} items\n"
        text += f"Critical: {critical} · High: {high} · KEV: {kev_count} · PoC: {poc_count}\n\n"
        for cat, cat_items in sorted(groups.items()):
            emoji = _DIGEST_EMOJI.get(cat, "📌")
            text += f"{emoji} *{cat.title()}* ({len(cat_items)})\n"
            text += _summarise(cat_items, 2) + "\n\n"
        return {"text": text, "parse_mode": "Markdown", "disable_web_page_preview": True}

    if webhook_type == "email":
        lines = [
            f"📊 CyberWatch Daily Digest — {datetime.now(timezone.utc).strftime('%Y-%m-%d')}",
            f"Total: {total} items · Critical: {critical} · High: {high} · KEV: {kev_count} · PoC: {poc_count}",
            "",
        ]
        for cat, cat_items in sorted(groups.items()):
            emoji = _DIGEST_EMOJI.get(cat, "📌")
            lines.append(f"{emoji} {cat.title()} ({len(cat_items)} items)")
            lines.append(_summarise(cat_items, 3))
            lines.append("")
        return {"subject": f"CyberWatch Daily Digest — {total} items ({critical} critical)",
                "body": "\n".join(lines)}

    return {"type": webhook_type, "items": items}


# ── Delivery ────────────────────────────────────────────────────────────────────

def _post_with_retry(url: str, payload: dict, retries: int = 3) -> bool:
    for attempt in range(1, retries + 1):
        try:
            resp = requests.post(url, json=payload, timeout=15)
            if resp.status_code == 429:
                import time
                wait = min(2 ** attempt, 30)
                print(f"Rate limited (429), retrying in {wait}s...")
                time.sleep(wait)
                continue
            resp.raise_for_status()
            print(f"Digest delivered ({resp.status_code}) on attempt {attempt}")
            return True
        except Exception as e:
            wait = min(2 ** attempt, 30)
            print(f"Digest attempt {attempt}/{retries} failed: {e}")
            if attempt < retries:
                import time
                time.sleep(wait)
    print("Digest delivery failed after all retries.")
    return False


# ── State tracking (once-daily dedup) ──────────────────────────────────────────

def _should_run_today() -> bool:
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    if DIGEST_STATE.exists():
        try:
            last = json.loads(DIGEST_STATE.read_text()).get("last_digest_date", "")
            if last == today:
                print(f"Digest already sent today ({today}) — skipping.")
                return False
        except Exception:
            pass
    return True


def _mark_run():
    DIGEST_STATE.parent.mkdir(parents=True, exist_ok=True)
    DIGEST_STATE.write_text(json.dumps({"last_digest_date": datetime.now(timezone.utc).strftime("%Y-%m-%d")}))


# ── Main ────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="CyberWatch Daily Digest")
    parser.add_argument("--dry-run", action="store_true", help="Print digest to stdout without sending")
    args = parser.parse_args()

    if not args.dry_run and not _should_run_today():
        return

    data_path = CONFIG.output_path
    if not data_path.exists():
        print(f"Intel data not found at {data_path} — nothing to digest.")
        return

    data = json.loads(data_path.read_text(encoding="utf-8"))
    items = data.get("items", [])
    if not items:
        print("No items in intel data — nothing to digest.")
        return

    payload = build_digest_payload(items, CONFIG.webhook_type or "slack")

    if args.dry_run:
        print("=== DRY RUN: Daily Digest ===")
        print(json.dumps(payload, indent=2))
        return

    # Try webhook first, fall back to email
    url = CONFIG.webhook_url
    if url:
        ok = _post_with_retry(url, payload, CONFIG.alert_retry_count)
    else:
        # Send as email if SMTP configured
        smtp_to = os.environ.get("SMTP_TO", "")
        if smtp_to:
            from scripts.webhook_post import _send_email
            ok = _send_email(CONFIG, items)
        else:
            print("No WEBHOOK_URL or SMTP_TO configured — printing digest.")
            print(json.dumps(payload, indent=2))
            ok = True

    if ok:
        _mark_run()


if __name__ == "__main__":
    main()
