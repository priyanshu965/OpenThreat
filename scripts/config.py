"""
CYBERWATCH — config.py
=======================
Central configuration for the intel pipeline. Every "magic number" that used to
live inline in fetch_intel.py has a single home here, and each value can be
overridden with an environment variable (handy for CI, local runs, and Docker).

Usage:
    from config import CONFIG
    CONFIG.max_items_per_source   # -> int

Override examples:
    MAX_ITEMS_PER_SOURCE=25 python scripts/fetch_intel.py
    AI_ENRICH_LIMIT=0 python scripts/fetch_intel.py   # disable AI enrichment
"""

import os
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _float(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return float(raw)
    except ValueError:
        return default


def _str(name: str, default: str) -> str:
    val = os.environ.get(name, default)
    return val if val is not None else default


def _bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


class Config:
    """Immutable-ish view over pipeline settings, resolved once at import time."""

    # ── Paths ──────────────────────────────────────────────────────────────
    project_root = PROJECT_ROOT
    data_dir     = PROJECT_ROOT / "data"
    output_path  = PROJECT_ROOT / "data" / "intel.json"
    archive_dir  = PROJECT_ROOT / "data" / "archive"
    export_dir   = PROJECT_ROOT / "data" / "exports"
    trends_path  = PROJECT_ROOT / "data" / "trends.json"
    alert_state_path = PROJECT_ROOT / "data" / ".alert_state.json"
    # Rolled-up per-source last-seen summary. Replaces the unbounded
    # source_health_history.jsonl the browser used to download in full.
    health_summary_path = PROJECT_ROOT / "data" / "source_health_summary.json"
    feed_meta_path      = PROJECT_ROOT / "data" / ".feed_meta.json"

    # ── Fetch tuning ───────────────────────────────────────────────────────
    max_items_per_source   = _int("MAX_ITEMS_PER_SOURCE", 10)
    nvd_lookback_days      = _int("NVD_LOOKBACK_DAYS", 10)
    request_timeout        = _int("REQUEST_TIMEOUT", 30)
    ai_enrich_limit        = _int("AI_ENRICH_LIMIT", 40)
    ai_batch_size          = _int("AI_BATCH_SIZE", 10)
    # Slots reserved for items with no priority score — incidents and news.
    # Ranking candidates purely by priority_score sent the entire budget to
    # CVEs, which are the items that least need a model: they already carry
    # CVSS, EPSS, KEV and SSVC. 167 of 241 items in a typical run are unscored
    # and were never enriched at all.
    ai_enrich_unscored_limit = _int("AI_ENRICH_UNSCORED_LIMIT", 12)
    # Enrichment is cached across runs by item key. The feed barely changes
    # hour to hour, so without this the same top-N items were re-sent to the
    # model on all 24 daily runs.
    ai_cache_ttl_days      = _int("AI_CACHE_TTL_DAYS", 14)
    ai_cache_max_entries   = _int("AI_CACHE_MAX_ENTRIES", 5000)
    # The "daily" brief was regenerated on every hourly run. It is now reused
    # until it goes stale OR the set of urgent items changes — so it still
    # reacts to a breaking KEV addition within the hour, without paying for
    # 24 identical briefs a day.
    brief_max_age_hours    = _int("BRIEF_MAX_AGE_HOURS", 12)
    archive_retention_days = _int("ARCHIVE_RETENTION_DAYS", 90)
    fetch_workers          = _int("FETCH_WORKERS", 8)

    # A source whose newest item is older than this is reported "stale" rather
    # than "ok" — a dead feed serving a 4-year-old archive is not healthy.
    source_stale_days      = _int("SOURCE_STALE_DAYS", 30)

    # ── Attacker map (geoip + infrastructure feeds) ────────────────────────
    # DB-IP Country Lite is a monthly file, so a 30-day cache is the natural
    # cadence; nothing fresher exists to fetch.
    geoip_ttl_hours        = _int("GEOIP_TTL_HOURS", 24 * 30)
    # Attacker feeds are large IP lists that change slowly through the day.
    # 6h keeps them fresh without re-pulling ~7 MB every hour.
    attacker_feed_ttl_hours = _int("ATTACKER_FEED_TTL_HOURS", 6)
    enable_attacker_map    = _bool("ENABLE_ATTACKER_MAP", True)
    # Cap per-feed rows parsed, as a guard against a feed ballooning. 0 = no cap.
    attacker_feed_max_rows = _int("ATTACKER_FEED_MAX_ROWS", 0)

    # ── AI models ──────────────────────────────────────────────────────────
    # Gemini 3.x Flash-Lite is on the free tier and materially better at
    # instruction-following than the 2.5 line this project shipped with.
    gemini_model        = _str("GEMINI_MODEL", "gemini-3.5-flash-lite")
    gemini_brief_model  = _str("GEMINI_BRIEF_MODEL", "gemini-3-flash")
    groq_model_primary  = _str("GROQ_MODEL_PRIMARY", "llama-3.3-70b-versatile")
    groq_model_fallback = _str("GROQ_MODEL_FALLBACK", "llama-3.1-8b-instant")
    ai_retry_count      = _int("AI_RETRY_COUNT", 2)

    # ── API keys ───────────────────────────────────────────────────────────
    otx_api_key       = os.environ.get("OTX_API_KEY", "")
    groq_api_key      = os.environ.get("GROQ_API_KEY", "")
    gemini_api_key    = os.environ.get("GEMINI_API_KEY", "")
    abuseipdb_api_key = os.environ.get("ABUSEIPDB_API_KEY", "")
    phishtank_api_key = os.environ.get("PHISHTANK_API_KEY", "")
    nvd_api_key       = os.environ.get("NVD_API_KEY", "")
    threatfox_api_key = os.environ.get("THREATFOX_API_KEY", "")
    mb_api_key        = os.environ.get("MB_API_KEY", "")
    # NEVER hardcode this. Set it as a GitHub Actions secret / local .env entry.
    vulncheck_api_key = os.environ.get("VULNCHECK_API_KEY", "")

    # ── Enrichment toggles ─────────────────────────────────────────────────
    enable_vulnrichment = _bool("ENABLE_VULNRICHMENT", True)
    enable_epss_bulk    = _bool("ENABLE_EPSS_BULK", True)
    enable_ai_brief     = _bool("ENABLE_AI_BRIEF", True)

    # ── Alerting ───────────────────────────────────────────────────────────
    webhook_url   = os.environ.get("WEBHOOK_URL", "")
    webhook_type  = _str("WEBHOOK_TYPE", "slack")
    telegram_chat_id = os.environ.get("TELEGRAM_CHAT_ID", "")
    dashboard_url = _str("DASHBOARD_URL", "https://priyanshu965.github.io/Cyberwatch/")
    # Which items justify a push. Comma-separated severities, plus KEV always alerts.
    alert_severities     = _str("ALERT_SEVERITIES", "critical").lower()
    alert_max_items      = _int("ALERT_MAX_ITEMS", 10)
    alert_retry_count    = _int("ALERT_RETRY_COUNT", 3)
    alert_state_ttl_days = _int("ALERT_STATE_TTL_DAYS", 14)
    # Only alert on items at/above this blended priority score. 0 disables.
    alert_min_priority   = _float("ALERT_MIN_PRIORITY", 0.0)

    # ── Priority scoring weights (see fetch_intel.compute_priority) ─────────
    # Blended 0-100 score = CVSS component + EPSS component + KEV/PoC bonuses.
    priority_cvss_weight = _float("PRIORITY_CVSS_WEIGHT", 40.0)
    priority_epss_weight = _float("PRIORITY_EPSS_WEIGHT", 40.0)
    priority_kev_bonus   = _float("PRIORITY_KEV_BONUS", 20.0)
    priority_poc_bonus   = _float("PRIORITY_POC_BONUS", 15.0)
    # SSVC (CISA Vulnrichment) contribution.
    priority_ssvc_active_bonus = _float("PRIORITY_SSVC_ACTIVE_BONUS", 25.0)
    priority_ssvc_auto_bonus   = _float("PRIORITY_SSVC_AUTO_BONUS", 10.0)
    priority_ssvc_total_bonus  = _float("PRIORITY_SSVC_TOTAL_BONUS", 5.0)

    http_user_agent = _str("HTTP_USER_AGENT", "CyberWatch/3.0 (+https://github.com/priyanshu965/Cyberwatch)")

    @property
    def alert_severity_set(self) -> set:
        return {s.strip() for s in self.alert_severities.split(",") if s.strip()}


CONFIG = Config()
