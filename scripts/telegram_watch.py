"""
OPENTHREAT — telegram_watch.py
===============================
Public Telegram channel previews.

Hacktivist crews, DDoS-for-hire operators and several ransomware brands post to
Telegram before — sometimes instead of — anything reaching a leak site. That
traffic is genuinely early, and reaching it needs no special access at all:
`t.me/s/<channel>` is the ordinary public web preview of a public channel. No
API key, no login, no session, nothing private. It is the same page anyone gets
by clicking a channel link in a browser.

OFF BY DEFAULT, AND WHY
-----------------------
This is the one v5 source whose value depends entirely on WHICH channels you
choose to watch, and that choice is editorial, not technical. Shipping a
default list would mean this project deciding whose propaganda gets a feed on
your dashboard. So `ENABLE_TELEGRAM` defaults to false and
`TELEGRAM_CHANNELS` defaults to empty: it does nothing until you name channels.

TREAT EVERYTHING HERE AS HOSTILE INPUT
--------------------------------------
The content is written by the actors being monitored. It is DATA:

  * Parsed with a narrow regex over the preview markup, never executed.
  * HTML-unescaped then stripped of all tags, so no markup survives to a
    renderer.
  * Post URLs are constructed from the validated channel name and a numeric
    post id — never from anything in the page body — so a crafted post cannot
    plant a link.
  * Channel names are validated against Telegram's own charset before they
    reach a URL, which also stops path traversal into the cache filename.

Nothing here is enriched by AI or given a priority score. It is a monitoring
sidebar, not part of the scored feed, and it is labelled as unverified actor
claims wherever it is shown.
"""

from __future__ import annotations

import html
import re

from fetchlib import CONFIG, cached_derive, http_text, log, now_utc

_BASE = "https://t.me/s/"

# Telegram usernames: 5-32 chars, letters/digits/underscore. Anything else
# never reaches a URL or a cache filename.
_CHANNEL_RE = re.compile(r"^[A-Za-z0-9_]{4,32}$")

# The preview page wraps each post in a widget div carrying its "channel/id"
# and a message-text span. This is deliberately narrow: it matches the two
# things needed and ignores the rest of the markup.
_POST_RE = re.compile(
    r'<div class="tgme_widget_message[^"]*"[^>]*data-post="([^"]+)"',
    re.IGNORECASE)
_TEXT_RE = re.compile(
    r'<div class="tgme_widget_message_text[^"]*"[^>]*>(.*?)</div>',
    re.IGNORECASE | re.DOTALL)
_TIME_RE = re.compile(r'<time[^>]+datetime="([^"]+)"', re.IGNORECASE)
_TAG_RE = re.compile(r"<[^>]+>")
_POST_ID_RE = re.compile(r"^([A-Za-z0-9_]{4,32})/(\d{1,12})$")


def _channels() -> list[str]:
    raw = str(CONFIG.telegram_channels or "")
    out = []
    # Split on commas and newlines ONLY, never on spaces. Splitting on
    # whitespace turned a single malformed entry such as "bad name" into two
    # candidates, and "name" then passed validation -- so a typo silently
    # subscribed you to somebody else's channel.
    for chunk in re.split(r"[,\r\n]+", raw):
        name = chunk.strip().lstrip("@")
        if not name:
            continue
        if not _CHANNEL_RE.match(name):
            log.warning(f"  Ignoring malformed Telegram channel {chunk!r}")
            continue
        if name not in out:
            out.append(name)
    return out[:20]


def _strip(markup: str) -> str:
    """Preview HTML -> plain text. Tags removed BEFORE entities are decoded."""
    text = markup.replace("<br/>", "\n").replace("<br>", "\n")
    text = _TAG_RE.sub(" ", text)
    # Order matters: unescaping first could reintroduce a '<' that then looks
    # like markup to something downstream.
    text = html.unescape(text)
    return " ".join(text.split())


def _parse_channel(name: str, markup: str) -> list[dict]:
    posts: list[dict] = []
    ids = _POST_RE.findall(markup or "")
    texts = _TEXT_RE.findall(markup or "")
    times = _TIME_RE.findall(markup or "")

    for index, raw_id in enumerate(ids):
        match = _POST_ID_RE.match(html.unescape(raw_id).strip())
        if not match or match.group(1).lower() != name.lower():
            # A post id that does not belong to the channel we asked for is
            # either a forward or something crafted. Either way it is not ours.
            continue
        body = _strip(texts[index]) if index < len(texts) else ""
        if not body:
            continue
        posts.append({
            "channel": name,
            "id": match.group(2),
            # Built from validated parts only.
            "url": f"https://t.me/{match.group(1)}/{match.group(2)}",
            "posted": (times[index][:19] if index < len(times) else ""),
            "text": body[:1200],
            "unverified": True,
        })
    return posts


def _derive() -> dict | None:
    channels = _channels()
    if not channels:
        return None
    log.info(f"  Reading {len(channels)} public Telegram channel preview(s)...")

    posts: list[dict] = []
    ok = 0
    for name in channels:
        markup, err = http_text(f"{_BASE}{name}", timeout=CONFIG.request_timeout)
        if not markup:
            log.warning(f"  Telegram channel {name} unavailable: {err}")
            continue
        found = _parse_channel(name, markup)
        if found:
            ok += 1
            posts.extend(found[-CONFIG.telegram_max_posts:])

    if not posts:
        return None
    posts.sort(key=lambda p: (p.get("posted") or "", p.get("id") or ""), reverse=True)
    posts = posts[:CONFIG.telegram_max_posts * max(1, len(channels))]

    log.info(f"  Telegram: {len(posts)} posts from {ok}/{len(channels)} channels")
    return {
        "built": now_utc(),
        "channels": channels,
        "channels_ok": ok,
        "count": len(posts),
        "posts": posts,
        "disclaimer": ("Unverified claims published by the monitored channels. "
                       "Presented verbatim as monitoring data, not as findings."),
    }


def load_telegram(force: bool = False) -> dict | None:
    if not CONFIG.enable_telegram:
        return None
    ttl = 0 if force else CONFIG.telegram_ttl_hours
    return cached_derive("telegram_watch.json", ttl, _derive)
