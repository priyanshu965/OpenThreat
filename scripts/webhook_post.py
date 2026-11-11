"""
OpenThreat Webhook Poster
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
import hashlib
import json
import re
import os
import smtplib
import sys
import time
from datetime import datetime, timedelta, timezone
from email.mime.text import MIMEText
from pathlib import Path

import requests


# ── Selection ─────────────────────────────────────────────────────────────────

def _canonical_url(url: str) -> str:
    """Strip scheme, www, query and fragment — mirrors fetch_intel._canonical_url."""
    if not url:
        return ""
    u = url.strip().lower()
    u = re.sub(r"^https?://", "", u)
    u = re.sub(r"^www\.", "", u)
    return u.split("?")[0].split("#")[0].rstrip("/")


def _alert_key(item: dict) -> str:
    """Stable identity for dedup — mirrors fetch_intel.item_key.

    Previously used the raw lowercased URL, so the same story re-alerted the
    moment a source appended a tracking parameter.
    """
    cve = (item.get("cve_id") or "").upper()
    if cve:
        return f"cve:{cve}"
    url = _canonical_url(item.get("url") or "")
    if url:
        return f"url:{url}"
    return f"title:{(item.get('title') or '').strip().lower()[:100]}"


def select_alertable(items, severities: set, min_priority: float = 0.0) -> list:
    """Items worth paging someone about.

    Severity alone is a weak signal (it is inferred from headline keywords), so
    confirmed-exploitation signals always qualify and an optional priority floor
    filters the rest.
    """
    out = []
    for item in items:
        sev = (item.get("severity") or "").lower()
        confirmed = item.get("cisa_kev") or item.get("ssvc_exploitation") == "active"
        if not (sev in severities or confirmed):
            continue
        if min_priority and not confirmed:
            if (item.get("priority_score") or 0) < min_priority:
                continue
        out.append(item)
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


# ── Untrusted text ────────────────────────────────────────────────────────────
# Titles, descriptions and URLs come from 71 third-party feeds, several of
# which anyone can post to (Reddit, OTX), and leak-site victim names are written
# by the adversary. Each chat platform treats some characters as markup, so an
# unescaped title could ping a whole channel (`<!channel>` in Slack), swap the
# link an alert points at, or simply break the message so it is never delivered
# - a way to silence the alert for the very item that carried it.
#
# Every feed-derived string therefore goes through the escaper for its
# destination before it reaches a payload. Truncation happens BEFORE escaping so
# a cut never lands in the middle of an escape sequence.

_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f  ]+")


def _one_line(value, limit: int = 200) -> str:
    """Plain text on one line: control characters and newlines collapsed."""
    return _CONTROL_RE.sub(" ", str(value or "")).strip()[:limit]


def _slack(value, limit: int = 200) -> str:
    """Slack mrkdwn. Escaping & < > is Slack's own documented rule, and it is
    what neutralises `<!channel>`, `<@U123>` and `<url|label>`."""
    return (_one_line(value, limit)
            .replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


_DISCORD_MD_RE = re.compile(r"([\\*_~`|\[\]()>#])")


def _discord(value, limit: int = 200) -> str:
    """Discord markdown: backslash-escape markup so `[label](url)` cannot form
    a masked link. Mentions are switched off separately - see _DISCORD_QUIET."""
    return _DISCORD_MD_RE.sub(r"\\\1", _one_line(value, limit))


# The actual control for Discord pings: with this on the payload no @everyone,
# role or user mention is honoured, whatever the text contains.
_DISCORD_QUIET = {"parse": []}

_TELEGRAM_STRIP = str.maketrans({"[": "(", "]": ")", "*": "", "`": "'", "_": " "})


def _telegram(value, limit: int = 200) -> str:
    """Telegram legacy Markdown. Its escapes do not work inside a link label or
    an emphasis run - which is where these strings go - so the four markup
    characters are replaced rather than escaped. An unbalanced one makes the
    Bot API reject the whole message."""
    return _one_line(value, limit).translate(_TELEGRAM_STRIP)


_LINK_UNSAFE = str.maketrans({"<": "%3C", ">": "%3E", "|": "%7C", "(": "%28",
                              ")": "%29", " ": "%20", '"': "%22", "`": "%60"})


def _link(url) -> str:
    """An http(s) URL that cannot break out of link syntax, or ''.

    Mirrors safeUrl() in app.js: the scheme allowlist is what keeps a
    `javascript:` or `slack://` target out of an alert."""
    cleaned = _CONTROL_RE.sub("", str(url or "")).strip()
    if not re.match(r"^https?://", cleaned, re.IGNORECASE):
        return ""
    return cleaned.translate(_LINK_UNSAFE)[:2000]


def _slack_link(url, label: str) -> str:
    target = _link(url)
    return f"<{target}|{label}>" if target else label


def _telegram_link(url, label: str) -> str:
    target = _link(url)
    return f"[{label}]({target})" if target else label


_ESCAPERS = {"slack": _slack, "discord": _discord, "telegram": _telegram}


# ── Payload builders ──────────────────────────────────────────────────────────

def build_payload(items, webhook_type: str, total: int) -> dict:
    crit = sum(1 for i in items if (i.get("severity") or "").lower() == "critical")
    if webhook_type == "slack":
        blocks = [
            {"type": "header", "text": {"type": "plain_text",
             "text": f"🚨 OpenThreat: {len(items)} new high-priority ({crit} critical)"}},
            {"type": "divider"},
        ]
        for item in items:
            kev = " · *KEV*" if item.get("cisa_kev") else ""
            prio = item.get("priority_score")
            prio_s = f" · P{prio}" if prio is not None else ""
            action = f"\n_{_slack(item['action'])}_" if item.get("action") else ""
            blocks.append({"type": "section", "text": {"type": "mrkdwn",
                "text": f"*{_slack(item.get('severity'), 20).upper()}*{kev}{prio_s}: "
                        f"{_slack_link(item.get('url'), _slack(item.get('title')))}{action}"}})
        # Slack rejects payloads over 50 blocks.
        blocks = blocks[:48]
        return {"text": f"OpenThreat: {len(items)} new high-priority threats", "blocks": blocks}

    if webhook_type == "discord":
        embeds = []
        for item in items[:10]:  # Discord caps embeds at 10
            color = 0xFF0000 if (item.get("severity") or "").lower() == "critical" else 0xFF8C42
            fields = [
                {"name": "Severity", "value": _discord(item.get("severity") or "?", 20).upper(),
                 "inline": True},
                {"name": "CVSS", "value": _discord(item.get("cvss_score", "N/A"), 20), "inline": True},
            ]
            if item.get("priority_score") is not None:
                fields.append({"name": "Priority", "value": _discord(item["priority_score"], 20),
                               "inline": True})
            if item.get("cisa_kev"):
                fields.append({"name": "CISA KEV", "value": "Yes", "inline": True})
            embeds.append({
                "title": _discord(item.get("title"), 200)[:256],
                # Discord rejects the WHOLE payload over one non-http(s) embed
                # URL, so an invalid one is dropped rather than passed through.
                "url": _link(item.get("url")) or None,
                "description": _discord(item.get("description"), 400),
                "color": color, "fields": fields,
            })
        return {"content": "🚨 **OpenThreat Intel Update**", "embeds": embeds,
                "allowed_mentions": _DISCORD_QUIET}

    if webhook_type == "telegram":
        text = "🚨 *OpenThreat Intel Update*\n\n"
        for item in items:
            kev = " (KEV)" if item.get("cisa_kev") else ""
            act = f" — {_telegram(item['action'])}" if item.get("action") else ""
            text += (f"• *{_telegram(item.get('severity'), 20).upper()}*{kev}: "
                     f"{_telegram_link(item.get('url'), _telegram(item.get('title'), 150))}{act}\n")
        payload = {"text": text, "parse_mode": "Markdown", "disable_web_page_preview": True}
        # The Bot API rejects sendMessage without chat_id. The previous payload
        # omitted it entirely, so this transport could never have worked.
        chat_id = os.environ.get("TELEGRAM_CHAT_ID", "")
        if chat_id:
            payload["chat_id"] = chat_id
        else:
            print("WARNING: WEBHOOK_TYPE=telegram but TELEGRAM_CHAT_ID is unset — "
                  "Telegram will reject this message.")
        return payload

    if webhook_type == "email":
        body_lines = [f"🚨 OpenThreat Intel Update — {len(items)} new alert(s)"]
        for item in items:
            kev = " (KEV)" if item.get("cisa_kev") else ""
            body_lines.append(f"\n• {_one_line(item.get('severity'), 20).upper()}{kev}: "
                              f"{_one_line(item.get('title'))}")
            if _link(item.get("url")):
                body_lines.append(f"  {_link(item.get('url'))}")
        return {"subject": f"OpenThreat: {len(items)} new threat(s)", "body": "\n".join(body_lines)}

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
    frm  = os.environ.get("SMTP_FROM", user or "openthreat@localhost")
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
    is_email = config.webhook_type == "email"
    if not url and not is_email:
        print("No WEBHOOK_URL configured — skipping alerts.")
        return 0
    # Email delivery goes over SMTP and needs no webhook URL. The previous
    # early return made WEBHOOK_TYPE=email unreachable without setting a dummy
    # WEBHOOK_URL first.
    if is_email and not os.environ.get("SMTP_TO"):
        print("WEBHOOK_TYPE=email but SMTP_TO is unset — skipping alerts.")
        return 0

    items = output.get("items", [])
    candidates = select_alertable(items, config.alert_severity_set,
                                  getattr(config, "alert_min_priority", 0.0))
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


# -- Dark-web watchlist alerts -------------------------------------------------
# A standing watch is only monitoring if it can reach you between visits. These
# reuse the same dedup state as item alerts, keyed on (term, victim, group), so
# a listing that stays up does not re-page every hour - only genuinely new
# matches do.

def _watch_key(term: str, match: dict) -> str:
    return ("dwwatch:" + str(term).strip().lower() + "|" +
            str(match.get("v", "")).strip().lower() + "|" +
            str(match.get("g", "")).strip().lower())


def build_watch_payload(term: str, matches: list, webhook_type: str,
                        dashboard_url: str = "") -> dict:
    """Format a watchlist hit for the configured webhook."""
    # Leak-site listings are written by the adversary, so every field of a
    # match is escaped for its destination - see "Untrusted text" above.
    esc = _ESCAPERS.get(webhook_type, _slack)
    term = esc(term, 100)
    lines = []
    for m in matches[:10]:
        bits = [esc(m.get("v")) or "unknown victim"]
        if m.get("g"):
            bits.append("claimed by " + esc(m["g"], 80))
        if m.get("d"):
            bits.append(esc(m["d"], 20))
        where = " / ".join(esc(x, 60) for x in (m.get("c"), m.get("s")) if x)
        row = "- " + " - ".join(bits)
        if where:
            row += " (" + where + ")"
        lines.append(row)
    body = "\n".join(lines)
    n = len(matches)
    plural = "s" if n != 1 else ""
    headline = ("Dark-web watchlist hit: " + term + " - " + str(n) +
                " leak-site listing" + plural)
    caveat = ("A leak-site listing is the crew's own claim, not a confirmed "
              "breach. Verify before acting.")

    if webhook_type == "discord":
        return {"embeds": [{
            "title": ("[dark web] " + headline)[:256],
            "description": (body + "\n\n_" + caveat + "_")[:4000],
            "color": 0xD6454F,
            "footer": {"text": "OpenThreat dark-web watch"},
        }], "allowed_mentions": _DISCORD_QUIET}
    if webhook_type == "telegram":
        return {"text": "*" + headline + "*\n" + body + "\n\n_" + caveat + "_",
                "parse_mode": "Markdown"}
    # Slack (and Slack-compatible) blocks.
    return {"blocks": [
        {"type": "header",
         "text": {"type": "plain_text", "text": "Dark-web watchlist hit"}},
        {"type": "section",
         "text": {"type": "mrkdwn",
                  "text": "*" + term + "* - " + str(n) + " leak-site listing" +
                          plural + "\n" + body}},
        {"type": "context", "elements": [{"type": "mrkdwn", "text": caveat}]},
    ]}


def send_watch_alerts(output: dict, config) -> int:
    """Page on NEW dark-web watchlist matches. Returns how many were sent."""
    hits = output.get("darkweb_watch") or []
    if not hits:
        return 0

    url = config.webhook_url
    is_email = config.webhook_type == "email"
    if not url and not is_email:
        return 0

    state_path = Path(config.alert_state_path)
    state = _load_state(state_path)
    now_iso = datetime.now(timezone.utc).isoformat()
    sent = 0

    for hit in hits:
        term = hit.get("term", "")
        matches = hit.get("matches") or []
        fresh = [m for m in matches if _watch_key(term, m) not in state]
        if not fresh:
            continue
        if is_email:
            rows = [str(m.get("v")) + " - claimed by " + str(m.get("g")) +
                    " on " + str(m.get("d")) for m in fresh[:10]]
            ok = _send_email_payload(config, {
                "subject": "[OpenThreat] Dark-web watchlist hit: " + term,
                "body": "\n".join(rows),
            })
        else:
            payload = build_watch_payload(term, fresh, config.webhook_type,
                                          getattr(config, "dashboard_url", ""))
            ok = _post_with_retry(url, payload, config.alert_retry_count)
        if ok:
            for m in fresh:
                state[_watch_key(term, m)] = now_iso
            sent += len(fresh)
            print("Dark-web watch alert sent for '" + term + "' (" +
                  str(len(fresh)) + " new)")

    if sent:
        _save_state(state_path, state, config.alert_state_ttl_days)
    return sent


# -- Own-estate report ---------------------------------------------------------
# Exposure and attack-surface findings are withheld from the public site, and
# on a public repository from the run log and summary too. That leaves this as
# the only route by which they reach you, so it has to exist.
#
# Sent when the findings CHANGE, not every run: the state key is a hash of the
# report, so an unchanged estate is silent and a new hostname or a new
# infostealer hit pages once. The key expires with the rest of the alert state,
# which makes an unchanged report repeat roughly fortnightly - a useful
# reminder that the watch is still running.

def _estate_lines(output: dict, esc=_one_line) -> list:
    lines = []
    for row in ((output.get("exposure") or {}).get("domains") or [])[:20]:
        lines.append("- " + esc(row.get("domain"), 100) + ": "
                     + str(int(row.get("employees") or 0)) + " employee, "
                     + str(int(row.get("users") or 0)) + " user, "
                     + str(int(row.get("third_parties") or 0))
                     + " third-party machine(s) in infostealer logs")
    for row in ((output.get("attack_surface") or {}).get("domains") or [])[:20]:
        noteworthy = row.get("noteworthy") or []
        lines.append("- " + esc(row.get("domain"), 100) + ": "
                     + str(int(row.get("hostnames") or 0))
                     + " hostname(s) in Certificate Transparency, "
                     + str(len(noteworthy)) + " noteworthy")
        for host in noteworthy[:10]:
            lines.append("    " + esc(host, 120))
    return lines


def build_estate_payload(output: dict, webhook_type: str) -> dict | None:
    """Format the own-estate findings, or None when there are none."""
    title = "OpenThreat: findings on your own estate"
    note = "Withheld from the public site and the run log. Delivered here only."
    if webhook_type == "slack":
        lines = _estate_lines(output, _slack)
        if not lines:
            return None
        return {"text": title, "blocks": [
            {"type": "header", "text": {"type": "plain_text", "text": title}},
            {"type": "section",
             "text": {"type": "mrkdwn", "text": "\n".join(lines)[:2900]}},
            {"type": "context", "elements": [{"type": "mrkdwn", "text": note}]},
        ]}
    if webhook_type == "discord":
        lines = _estate_lines(output, _discord)
        if not lines:
            return None
        return {"allowed_mentions": _DISCORD_QUIET, "embeds": [{
            "title": title, "description": "\n".join(lines)[:4000],
            "color": 0xD6454F, "footer": {"text": note},
        }]}
    lines = _estate_lines(output)
    if not lines:
        return None
    body = "\n".join(lines)
    if webhook_type == "email":
        return {"subject": "[OpenThreat] Findings on your own estate",
                "body": body + "\n\n" + note}
    if webhook_type == "telegram":
        # Plain text on purpose: hostnames contain characters Telegram's
        # Markdown treats as markup, and a report is no place to alter them.
        payload = {"text": (title + "\n\n" + body + "\n\n" + note)[:4000],
                   "disable_web_page_preview": True}
        chat_id = os.environ.get("TELEGRAM_CHAT_ID", "")
        if chat_id:
            payload["chat_id"] = chat_id
        return payload
    return {"text": title + "\n\n" + body + "\n\n" + note}


def send_estate_report(output: dict, config) -> bool:
    """Deliver own-estate findings when they have changed. True if sent."""
    plain = _estate_lines(output)
    if not plain:
        return False
    url = config.webhook_url
    is_email = config.webhook_type == "email"
    if not url and not is_email:
        return False

    key = "estate:" + hashlib.sha256("\n".join(plain).encode("utf-8")).hexdigest()[:16]
    state_path = Path(config.alert_state_path)
    state = _load_state(state_path)
    if key in state:
        return False

    payload = build_estate_payload(output, config.webhook_type)
    if is_email:
        ok = _send_email_payload(config, payload)
    else:
        ok = _post_with_retry(url, payload, config.alert_retry_count)
    if ok:
        state[key] = datetime.now(timezone.utc).isoformat()
        _save_state(state_path, state, config.alert_state_ttl_days)
    return bool(ok)


# ── Daily digest ──────────────────────────────────────────────────────────────
# Merged in from the former scripts/daily_digest.py, which duplicated this
# module's payload builders, retry loop and state handling in 241 lines, and
# whose Slack footer rendered a LOCAL FILESYSTEM PATH as the dashboard link
# (`</app/data/index.html|Open Dashboard>`) — proof it had never been used.

_DIGEST_EMOJI = {
    "cve": "🛡️", "exploit": "💀", "malware": "🦠", "incident": "🚨",
    "ransomware": "💰", "phishing": "🎣", "advisory": "📋", "news": "📰",
}


def _recent_items(items: list, hours: int = 24) -> list:
    """Items published within the window. The old digest claimed 'last 24h' in
    its docstring but digested the entire feed."""
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
    out = []
    for item in items:
        raw = item.get("published")
        if not raw:
            continue
        try:
            published = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
        except ValueError:
            continue
        if published.tzinfo is None:
            published = published.replace(tzinfo=timezone.utc)
        if published >= cutoff:
            out.append(item)
    return out or items


def _summarise(items: list, top_n: int = 5, esc=_one_line) -> str:
    """Top items as bullet lines. ``esc`` is the escaper for the destination;
    the default is plain text (email, generic webhooks)."""
    ranked = sorted(items, key=lambda i: i.get("priority_score") or 0, reverse=True)
    lines = []
    for item in ranked[:top_n]:
        sev = esc(item.get("severity") or "?", 20).upper()
        score = item.get("priority_score")
        # Parentheses, not brackets: `[HIGH]` reads as the start of a link
        # label to Telegram's Markdown parser.
        prio = f" (P{esc(score, 10)})" if score is not None else ""
        kev = " 🔴KEV" if item.get("cisa_kev") else ""
        poc = " 💥PoC" if item.get("has_poc") else ""
        lines.append(f"• {sev}{prio}{kev}{poc} {esc(item.get('title') or '?', 120)}")
    return "\n".join(lines)


def build_digest_payload(output: dict, webhook_type: str, dashboard_url: str = "") -> dict:
    items = _recent_items(output.get("items", []))
    brief = output.get("brief") or {}
    groups: dict[str, list] = {}
    for item in items:
        groups.setdefault((item.get("category") or "other").strip().lower(), []).append(item)

    total = len(items)
    critical = sum(1 for i in items if (i.get("severity") or "").lower() == "critical")
    high     = sum(1 for i in items if (i.get("severity") or "").lower() == "high")
    kev      = sum(1 for i in items if i.get("cisa_kev"))
    poc      = sum(1 for i in items if i.get("has_poc"))
    headline = brief.get("headline", "")

    if webhook_type == "slack":
        blocks = [
            {"type": "header", "text": {"type": "plain_text",
             "text": f"📊 OpenThreat Daily Digest — {total} items ({critical} critical, {high} high)"}},
        ]
        if headline:
            blocks.append({"type": "section", "text": {"type": "mrkdwn",
                                                       "text": f"_{_slack(headline, 300)}_"}})
        for pick in brief.get("items", [])[:5]:
            blocks.append({"type": "section", "text": {"type": "mrkdwn",
                "text": f"*{_slack_link(pick.get('url'), _slack(pick.get('title'), 180))}*\n"
                        f"{_slack(pick.get('reason'), 300)}"}})
        blocks.append({"type": "context", "elements": [{"type": "mrkdwn",
            "text": f"KEV: {kev} · PoC: {poc} · Categories: {len(groups)}"}]})
        blocks.append({"type": "divider"})
        for cat, cat_items in sorted(groups.items()):
            emoji = _DIGEST_EMOJI.get(cat, "📌")
            sev_count = sum(1 for i in cat_items
                            if (i.get("severity") or "").lower() in ("critical", "high"))
            blocks.append({"type": "section", "text": {"type": "mrkdwn",
                "text": f"*{emoji} {_slack(cat, 40).title()}* ({len(cat_items)} items, {sev_count} high+)\n"
                        f"{_summarise(cat_items, 3, _slack)}"}})
        if _link(dashboard_url):
            blocks.append({"type": "context", "elements": [{"type": "mrkdwn",
                "text": f"🕐 {datetime.now(timezone.utc):%Y-%m-%d %H:%M UTC} · "
                        f"{_slack_link(dashboard_url, 'Open Dashboard')}"}]})
        return {"text": f"OpenThreat Daily Digest: {total} items", "blocks": blocks[:48]}

    if webhook_type == "discord":
        lines = ([f"_{_discord(headline, 300)}_", ""] if headline else [])
        for cat, cat_items in sorted(groups.items()):
            emoji = _DIGEST_EMOJI.get(cat, "📌")
            lines.append(f"**{emoji} {_discord(cat, 40).title()}** ({len(cat_items)})")
            lines.append(_summarise(cat_items, 2, _discord))
        return {"allowed_mentions": _DISCORD_QUIET, "embeds": [{
            "title": f"📊 OpenThreat Daily Digest — {total} items",
            "description": "\n".join(lines)[:4000],
            "url": _link(dashboard_url) or None,
            "color": 0x3366FF,
            "fields": [
                {"name": "Critical", "value": str(critical), "inline": True},
                {"name": "High", "value": str(high), "inline": True},
                {"name": "KEV / PoC", "value": f"{kev} / {poc}", "inline": True},
            ],
            "footer": {"text": f"{datetime.now(timezone.utc):%Y-%m-%d %H:%M UTC}"},
        }]}

    if webhook_type == "telegram":
        text = f"📊 *OpenThreat Daily Digest* — {total} items\n"
        if headline:
            text += f"_{_telegram(headline, 300)}_\n"
        text += f"Critical: {critical} · High: {high} · KEV: {kev} · PoC: {poc}\n\n"
        for cat, cat_items in sorted(groups.items()):
            text += f"{_DIGEST_EMOJI.get(cat, '📌')} *{_telegram(cat, 40).title()}* ({len(cat_items)})\n"
            text += _summarise(cat_items, 2, _telegram) + "\n\n"
        payload = {"text": text[:4000], "parse_mode": "Markdown",
                   "disable_web_page_preview": True}
        chat_id = os.environ.get("TELEGRAM_CHAT_ID", "")
        if chat_id:
            payload["chat_id"] = chat_id
        return payload

    lines = [f"OpenThreat Daily Digest — {datetime.now(timezone.utc):%Y-%m-%d}"]
    if headline:
        lines.append(headline)
    lines.append(f"Total: {total} · Critical: {critical} · High: {high} · KEV: {kev} · PoC: {poc}")
    lines.append("")
    for cat, cat_items in sorted(groups.items()):
        lines.append(f"{cat.title()} ({len(cat_items)} items)")
        lines.append(_summarise(cat_items, 3))
        lines.append("")
    if dashboard_url:
        lines.append(dashboard_url)
    body = "\n".join(lines)
    if webhook_type == "email":
        return {"subject": f"OpenThreat Daily Digest — {total} items ({critical} critical)",
                "body": body}
    return {"text": body}


def send_digest(output: dict, config) -> bool:
    """Send the daily digest. Deduped to once per UTC day."""
    state_path = Path(config.data_dir) / ".digest_state.json"
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    if state_path.exists():
        try:
            if json.loads(state_path.read_text()).get("last_digest_date") == today:
                print(f"Digest already sent today ({today}) — skipping.")
                return False
        except Exception:
            pass

    payload = build_digest_payload(output, config.webhook_type or "slack",
                                   getattr(config, "dashboard_url", ""))
    if config.webhook_type == "email":
        ok = _send_email_payload(config, payload)
    elif config.webhook_url:
        ok = _post_with_retry(config.webhook_url, payload, config.alert_retry_count)
    else:
        print("No WEBHOOK_URL or email config — printing digest instead.")
        print(json.dumps(payload, indent=2)[:4000])
        ok = True

    if ok:
        state_path.parent.mkdir(parents=True, exist_ok=True)
        state_path.write_text(json.dumps({"last_digest_date": today}))
    return ok


def _send_email_payload(config, payload: dict) -> bool:
    host = os.environ.get("SMTP_HOST", "")
    to   = os.environ.get("SMTP_TO", "")
    if not host or not to:
        print("SMTP_HOST / SMTP_TO not set — printing digest instead.")
        print(payload.get("body", ""))
        return True
    msg = MIMEText(payload.get("body", ""))
    msg["Subject"] = payload.get("subject", "OpenThreat Digest")
    msg["From"] = os.environ.get("SMTP_FROM", os.environ.get("SMTP_USER") or "openthreat@localhost")
    msg["To"] = to
    try:
        with smtplib.SMTP(host, int(os.environ.get("SMTP_PORT", "587"))) as s:
            s.starttls()
            user, pwd = os.environ.get("SMTP_USER", ""), os.environ.get("SMTP_PASS", "")
            if user and pwd:
                s.login(user, pwd)
            s.send_message(msg)
        print(f"Digest emailed to {to}")
        return True
    except Exception as e:
        print(f"Digest email failed: {e}")
        return False


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="OpenThreat Webhook Poster")
    parser.add_argument("intel_file", help="Path to intel.json")
    parser.add_argument("--url", help="Webhook URL (defaults to WEBHOOK_URL env var)")
    parser.add_argument("--type", choices=["slack", "discord", "telegram", "generic"],
                        default=os.environ.get("WEBHOOK_TYPE", "slack"))
    parser.add_argument("--severities", default=os.environ.get("ALERT_SEVERITIES", "critical"),
                        help="Comma-separated severities to alert on")
    parser.add_argument("--mode", choices=["alert", "digest"], default="alert",
                        help="alert = per-item high-priority push; digest = daily rollup")
    parser.add_argument("--dry-run", action="store_true", help="Print the payload, don't send")
    args = parser.parse_args()

    if args.mode == "digest":
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        from config import CONFIG
        data = json.loads(Path(args.intel_file).read_text(encoding="utf-8"))
        if args.dry_run:
            print(json.dumps(build_digest_payload(data, args.type, CONFIG.dashboard_url), indent=2))
            return
        send_digest(data, CONFIG)
        return

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
