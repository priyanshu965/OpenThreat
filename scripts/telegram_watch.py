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


# ── The scrubber ─────────────────────────────────────────────────────────────
# Even a channel that normally reports on breaches will sometimes paste a
# sample OF one. Republishing that on a public static site would make this
# project a distribution point for other people's credentials — the same
# objection that keeps ransomware extortion notes off the leak-site page, and
# a more serious one, because these are individuals rather than companies.
#
# Two layers, in this order:
#   1. DROP the post entirely when it looks like a dump. A post whose value is
#      the credentials has no analytical value left once they are removed.
#   2. REDACT what survives, so a single address quoted in prose does not get
#      republished either.
#
# Both are deliberately blunt. A false positive costs one monitoring post; a
# false negative publishes somebody's password.

_EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]{2,}\b")

# user:pass / email:pass / url:user:pass — the shape of every combolist.
_COMBO_RE = re.compile(
    r"\b[\w.+@-]{3,}:[^\s:]{4,}(?::[^\s:]{3,})?\b")

# Long unbroken hex or base64: API keys, session tokens, cookies.
#
# MD5, SHA-1 and SHA-256 are EXCLUDED by length. A file hash is the single most
# useful indicator a post can carry, and it is not a secret — publishing one is
# the entire point of an IOC. The first version of this redacted them, which
# quietly turned the most valuable line in a malware report into
# "[redacted:secret]".
#
# 32/40/64 hex are exactly those three digests, so anything hex of another
# length long enough to matter is something else, and base64 of 40+ characters
# is a token rather than a digest.
_HASH_LENGTHS = (32, 40, 64)
_LONG_HEX_RE = re.compile(r"\b[A-Fa-f0-9]{24,}\b")
# No \b on this one, deliberately. Real tokens are prefixed — `ghp_`, `xoxb-`,
# `sk-` — and `_` is a word character, so a leading \b never matches after the
# prefix and the secret sails through. Matching mid-word costs the occasional
# long URL path segment; missing a live credential costs somebody their
# account.
_B64_RE = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")


_HEX_ONLY_RE = re.compile(r"^[A-Fa-f0-9]+$")


def _is_digest(token: str) -> bool:
    """A file hash, as opposed to a credential that happens to be as long.

    BOTH conditions are required. Length alone is not enough: a 40-character
    GitHub token is exactly as long as a SHA-1, so a length-only check kept
    live credentials in the published text while claiming to have removed
    them. Hex-only is what separates a digest from a token.
    """
    return len(token) in _HASH_LENGTHS and bool(_HEX_ONLY_RE.match(token))


def _redact_secrets(text: str) -> str:
    def sub(match):
        token = match.group(0)
        return token if _is_digest(token) else "[redacted:secret]"
    text = _LONG_HEX_RE.sub(sub, text)
    return _B64_RE.sub(sub, text)

_CARD_RE = re.compile(r"\b(?:\d[ -]?){13,19}\b")

# Phrases that mark a post as a dump rather than a report about one. Matched
# on the lowercased body as whole tokens — this project has been burned by
# substring matching before ("rce" inside "source").
_DUMP_MARKERS = (
    "combolist", "combo list", "cracked accounts", "fresh logs", "stealer logs",
    "logs cloud", "private logs", "uhq combo", "hq combo", "mail access",
    "smtp access", "cc fullz", "fullz", "dumps+pin", "track1", "track2",
    "rdp shop", "brute results", "checked accounts", "valid mail",
)


# URLs are stripped before the credential heuristics run, and that is not a
# refinement — without it this filter deletes most of the feed.
#
# `_COMBO_RE` looks for `something:something`, which is exactly the shape of
# `https://example.org/path`. A research post carrying three links therefore
# scored three "credential pairs" and was dropped as a dump. Measured against
# the real channels: it silently discarded three vx-underground posts and one
# from Hacker News on the first live run, and the only symptom would have been
# a thinner feed.
_URL_RE = re.compile(r"\b(?:https?://|www\.|t\.me/)\S+", re.IGNORECASE)


def _looks_like_a_dump(text: str) -> bool:
    low = text.lower()
    if any(marker in low for marker in _DUMP_MARKERS):
        return True
    bare = _URL_RE.sub(" ", text)
    # Several credential pairs in one post is a dump regardless of wording.
    if len(_COMBO_RE.findall(bare)) >= 3:
        return True
    if len(_EMAIL_RE.findall(bare)) >= 5:
        return True
    return bool(_CARD_RE.search(bare))


def _redact(text: str) -> str:
    """Remove anything that could identify or authenticate a person.

    URLs are lifted out first and put back afterwards. `_COMBO_RE` looks for
    `word:word`, which is the shape of `https://example.org/path`, so running
    it over raw text rewrote every link in the feed as
    "[redacted:credential]". Measured on the ten configured channels that hit
    59% of posts — a filter that was destroying ordinary reporting while
    looking like it was working.
    """
    kept: list[str] = []

    def stash(match):
        kept.append(match.group(0))
        # A placeholder no rule below can match: no colon, no long hex run,
        # no @, and short.
        return f"\x00{len(kept) - 1}\x00"

    text = _URL_RE.sub(stash, text)
    text = _COMBO_RE.sub("[redacted:credential]", text)
    text = _EMAIL_RE.sub("[redacted:email]", text)
    text = _CARD_RE.sub("[redacted:number] ", text)
    text = _redact_secrets(text)
    for index, url in enumerate(kept):
        text = text.replace(f"\x00{index}\x00", url)
    return " ".join(text.split())


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
        # Drop before redact: a post whose entire content is a credential dump
        # has nothing left worth showing once the credentials are gone, and
        # publishing the husk would only advertise that the dump exists.
        if _looks_like_a_dump(body):
            log.info(f"  Dropped a {name} post that looks like a credential dump")
            continue
        body = _redact(body)
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
