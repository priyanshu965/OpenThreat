"""
CyberWatch Webhook Poster
==========================
Pushes high-priority threat intel to Slack / Discord / Telegram / generic
webhooks — with retry-on-failure and a persistent dedup memory so the same CVE
isn't re-alerted every hour.

Two entry points:

  send_alerts(output, config)         ← called by the pipeline (fetch_intel.py)
      Selects items worth alerting (severity in ALERT_SEVERITIES, or CISA KEV),
      skips anything already alerted (data/.alert_state.json), posts the rest,
      and records what was sent. Returns the number of *new* items alerted.

  python scripts/webhook_post.py <intel.json> [--url URL] [--type slack]
      One-shot CLI over a saved intel.json (ignores the dedup memory unless the
      state file is present).

Environment variables (see scripts/config.py):
  WEBHOOK_URL, WEBHOOK_TYPE, ALERT_SEVERITIES, ALERT_MAX_ITEMS,
  ALERT_RETRY_COUNT, ALERT_STATE_TTL_DAYS
"""

import argparse
import json
import os
import smtplib
import sys
import time
from datetime import datetime, timezone
from email.mime.text import MIMEText
from pathlib import Path

import requests


# ── Selection ─────────────────────────────────────────────────────────────────

def _alert_key(item: dict) -> str:
    """Stable identity for dedup — mirrors fetch_intel.item_key."""
    cve = (item.get("cve_id") or "").upper()
    if cve:
        return f"cve:{cve}"
    url = (item.get("url") or "").strip().lower()
    if url:
        return f"url:{url}"
    return f"title:{(item.get('title') or '').strip().lower()[:100]}"


def select_alertable(items, severities: set) -> list:
    """Items whose severity is in `severities`, or which are CISA KEV-listed."""
    out = []
    for item in items:
        sev = (item.get("severity") or "").lower()
        if sev in severities or item.get("cisa_kev"):
            out.append(item)
    # Highest priority first, so truncation keeps the scariest items.
    out.sort(key=lambda i: i.get("priority_score") or 0, reverse=True)
    return out


# ── Dedup state ───────────────────────────────────────────────────────────────

def _load_state(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _save_state(path: Path, state: dict, ttl_days: int) -> None:
    now = datetime.now(timezone.utc)
    pruned = {}
    for key, iso in state.items():
        try:
            when = datetime.fromisoformat(iso)
            if (now - when).days <= ttl_days:
                pruned[key] = iso
        except Exception:
            continue
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(pruned, indent=2), encoding="utf-8")


# ── Payload builders ──────────────────────────────────────────────────────────

def build_payload(items, webhook_type: str, total: int) -> dict:
    crit = sum(1 for i in items if (i.get("severity") or "").lower() == "critical")
    if webhook_type == "slack":
        blocks = [
            {"type": "header", "text": {"type": "plain_text",
             "text": f"🚨 CyberWatch: {len(items)} new high-priority ({crit} critical)"}},
            {"type": "divider"},
        ]
        for item in items:
            kev = " · *KEV*" if item.get("cisa_kev") else ""
            prio = item.get("priority_score")
            prio_s = f" · P{prio}" if prio is not None else ""
            blocks.append({"type": "section", "text": {"type": "mrkdwn",
                "text": f"*{(item.get('severity') or '').upper()}*{kev}{prio_s}: "
                        f"<{item.get('url','')}|{(item.get('title') or '')[:200]}>"}})
        return {"text": f"CyberWatch: {len(items)} new high-priority threats", "blocks": blocks}

    if webhook_type == "discord":
        embeds = []
        for item in items[:10]:  # Discord caps embeds at 10
            color = 0xFF0000 if (item.get("severity") or "").lower() == "critical" else 0xFF8C42
            fields = [
                {"name": "Severity", "value": (item.get("severity") or "?").upper(), "inline": True},
                {"name": "CVSS", "value": str(item.get("cvss_score", "N/A")), "inline": True},
            ]
            if item.get("priority_score") is not None:
                fields.append({"name": "Priority", "value": str(item["priority_score"]), "inline": True})
            if item.get("cisa_kev"):
                fields.append({"name": "CISA KEV", "value": "Yes", "inline": True})
            embeds.append({
                "title": (item.get("title") or "")[:256],
                "url": item.get("url", ""),
                "description": (item.get("description") or "")[:400],
                "color": color, "fields": fields,
            })
        return {"content": "🚨 **CyberWatch Intel Update**", "embeds": embeds}

    if webhook_type == "telegram":
        text = "🚨 *CyberWatch Intel Update*\n\n"
        for item in items:
            kev = " (KEV)" if item.get("cisa_kev") else ""
            text += f"• *{(item.get('severity') or '').upper()}*{kev}: [{(item.get('title') or '')[:150]}]({item.get('url','')})\n"
        return {"text": text, "parse_mode": "Markdown", "disable_web_page_preview": True}

    if webhook_type == "email":
        body_lines = [f"🚨 CyberWatch Intel Update — {len(items)} new alert(s)"]
        for item in items:
            kev = " (KEV)" if item.get("cisa_kev") else ""
            body_lines.append(f"\n• {(item.get('severity') or '').upper()}{kev}: {item.get('title','')[:200]}")
            if item.get("url"):
                body_lines.append(f"  {item['url']}")
        return {"subject": f"CyberWatch: {len(items)} new threat(s)", "body": "\n".join(body_lines)}

    return {"type": webhook_type, "items": items, "total": total}


# ── Delivery with retry ───────────────────────────────────────────────────────

def _post_with_retry(url: str, payload: dict, retries: int = 3) -> bool:
    for attempt in range(1, retries + 1):
        try:
            resp = requests.post(url, json=payload, timeout=15)
            if resp.status_code == 429:
                wait = min(2 ** attempt, 30)
                print(f"Rate limited (429), retrying in {wait}s...")
                time.sleep(wait)
                continue
            resp.raise_for_status()
            print(f"Webhook delivered ({resp.status_code}) on attempt {attempt}")
            return True
        except Exception as e:
            wait = min(2 ** attempt, 30)
            print(f"Webhook attempt {attempt}/{retries} failed: {e}")
            if attempt < retries:
                time.sleep(wait)
    print("Webhook delivery failed after all retries.")
    return False


# ── Email sender ───────────────────────────────────────────────────────────────

def _send_email(config, items: list) -> bool:
    """Send alert via SMTP. Expects env vars: SMTP_HOST, SMTP_PORT, SMTP_USER,
    SMTP_PASS, SMTP_TO. Falls back to print() if not configured."""
    host = os.environ.get("SMTP_HOST", "")
    port = int(os.environ.get("SMTP_PORT", "587"))
    user = os.environ.get("SMTP_USER", "")
    pwd  = os.environ.get("SMTP_PASS", "")
    to   = os.environ.get("SMTP_TO", "")
    frm  = os.environ.get("SMTP_FROM", user or "cyberwatch@localhost")
    if not host or not to:
        print("Email alerts requested but SMTP_HOST / SMTP_TO not set — printing instead.")
        payload = build_payload(items, "email", 0)
        print(payload["body"])
        return True
    payload = build_payload(items, "email", 0)
    msg = MIMEText(payload["body"])
    msg["Subject"] = payload["subject"]
    msg["From"]    = frm
    msg["To"]      = to
    try:
        with smtplib.SMTP(host, port) as s:
            s.starttls()
            if user and pwd:
                s.login(user, pwd)
            s.send_message(msg)
        print(f"Email alert sent to {to} ({len(items)} items)")
        return True
    except Exception as e:
        print(f"Email send failed: {e}")
        return False

# ── Pipeline entry point ──────────────────────────────────────────────────────

def send_alerts(output: dict, config) -> int:
    """
    Alert on new high-priority items. Returns count of newly-alerted items.
    Deduped against config.alert_state_path so nothing is sent twice.
    """
    url = config.webhook_url
    if not url:
        print("No WEBHOOK_URL configured — skipping alerts.")
        return 0

    items = output.get("items", [])
    candidates = select_alertable(items, config.alert_severity_set)
    if not candidates:
        print("No alertable items this run.")
        return 0

    state_path = Path(config.alert_state_path)
    state = _load_state(state_path)

    fresh = [i for i in candidates if _alert_key(i) not in state]
    if not fresh:
        print(f"All {len(candidates)} alertable items already sent previously.")
        return 0

    to_send = fresh[:config.alert_max_items]
    if config.webhook_type == "email":
        ok = _send_email(config, to_send)
    else:
        payload = build_payload(to_send, config.webhook_type, len(items))
        ok = _post_with_retry(url, payload, config.alert_retry_count)

    if ok:
        now_iso = datetime.now(timezone.utc).isoformat()
        for item in to_send:
            state[_alert_key(item)] = now_iso
        _save_state(state_path, state, config.alert_state_ttl_days)
        return len(to_send)
    return 0


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="CyberWatch Webhook Poster")
    parser.add_argument("intel_file", help="Path to intel.json")
    parser.add_argument("--url", help="Webhook URL (defaults to WEBHOOK_URL env var)")
    parser.add_argument("--type", choices=["slack", "discord", "telegram", "generic"],
                        default=os.environ.get("WEBHOOK_TYPE", "slack"))
    parser.add_argument("--severities", default=os.environ.get("ALERT_SEVERITIES", "critical"),
                        help="Comma-separated severities to alert on")
    args = parser.parse_args()

    url = args.url or os.environ.get("WEBHOOK_URL", "")
    if not url:
        print("No webhook URL. Set WEBHOOK_URL or pass --url.")
        sys.exit(1)

    data = json.loads(Path(args.intel_file).read_text(encoding="utf-8"))
    sev_set = {s.strip().lower() for s in args.severities.split(",") if s.strip()}
    items = select_alertable(data.get("items", []), sev_set)
    if not items:
        print("No alertable items.")
        return
    payload = build_payload(items[:10], args.type, len(data.get("items", [])))
    _post_with_retry(url, payload, int(os.environ.get("ALERT_RETRY_COUNT", "3")))


if __name__ == "__main__":
    main()
