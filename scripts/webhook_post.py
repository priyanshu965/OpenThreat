"""
CyberWatch Webhook Poster
==========================
Posts critical threat intelligence items to configured webhooks.

Supports: Slack, Discord, Telegram, and generic webhooks.

Usage:
  python scripts/webhook_post.py <intel.json> [--url URL] [--type slack|discord|telegram]

Environment variables:
  WEBHOOK_URL  — Webhook endpoint URL
  WEBHOOK_TYPE — slack (default), discord, or telegram
"""

import json
import os
import sys
import argparse
import requests


def post_webhook(intel_path: str, webhook_url: str = None, webhook_type: str = "slack"):
    if not webhook_url:
        webhook_url = os.environ.get("WEBHOOK_URL", "")
    if not webhook_url:
        print("No webhook URL configured. Set WEBHOOK_URL env var or use --url")
        return False

    with open(intel_path) as f:
        data = json.load(f)

    items = data.get("items", [])
    critical = [i for i in items if i.get("severity") == "critical"]
    high = [i for i in items if i.get("severity") == "high"]

    if not critical and not high:
        print(f"No critical/high items to post ({len(items)} total items)")
        return False

    print(f"Posting {len(critical)} critical + {len(high)} high items to {webhook_type}")

    payload = {}
    if webhook_type == "slack":
        blocks = [
            {"type": "header", "text": {"type": "plain_text", "text": f"🚨 CyberWatch: {len(critical)} Critical, {len(high)} High"}},
            {"type": "divider"},
        ]
        for item in (critical + high)[:8]:
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*{item['severity'].upper()}*: <{item['url']}|{item['title'][:200]}>"
                }
            })
        payload = {"text": f"CyberWatch: {len(critical)} critical threats", "blocks": blocks}

    elif webhook_type == "discord":
        embeds = []
        for item in (critical + high)[:8]:
            color = 0xFF0000 if item.get("severity") == "critical" else 0xFF8C42
            embeds.append({
                "title": item["title"][:256],
                "url": item.get("url", ""),
                "description": (item.get("description", "") or "")[:400],
                "color": color,
                "fields": [
                    {"name": "Severity", "value": item["severity"].upper(), "inline": True},
                    {"name": "CVSS", "value": str(item.get("cvss_score", "N/A")), "inline": True},
                ]
            })
        payload = {"embeds": embeds, "content": f"🚨 **CyberWatch Intel Update**"}

    elif webhook_type == "telegram":
        text = f"🚨 *CyberWatch Intel Update*\n\n"
        for item in (critical + high)[:8]:
            text += f"• *{item['severity'].upper()}*: [{item['title'][:150]}]({item['url']})\n"
        payload = {"text": text, "parse_mode": "Markdown", "disable_web_page_preview": True}

    else:
        payload = {"type": webhook_type, "items": (critical + high)[:8], "total": len(items)}

    try:
        resp = requests.post(webhook_url, json=payload, timeout=15)
        resp.raise_for_status()
        print(f"Webhook posted successfully ({resp.status_code})")
        return True
    except Exception as e:
        print(f"Webhook post failed: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(description="CyberWatch Webhook Poster")
    parser.add_argument("intel_file", help="Path to intel.json")
    parser.add_argument("--url", help="Webhook URL (defaults to WEBHOOK_URL env var)")
    parser.add_argument("--type", choices=["slack", "discord", "telegram"],
                        default=os.environ.get("WEBHOOK_TYPE", "slack"),
                        help="Webhook type")
    args = parser.parse_args()

    post_webhook(args.intel_file, args.url, args.type)


if __name__ == "__main__":
    main()
