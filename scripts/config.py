"""
CYBERWATCH — config.py
=======================
Central configuration for the intel pipeline. Every "magic number" that used to
live inline in fetch_intel.py now has a single home here, and each value can be
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

    # ── Fetch tuning ───────────────────────────────────────────────────────
    max_items_per_source   = _int("MAX_ITEMS_PER_SOURCE", 10)
    nvd_lookback_days       = _int("NVD_LOOKBACK_DAYS", 10)
    request_timeout         = _int("REQUEST_TIMEOUT", 30)
    ai_enrich_limit         = _int("AI_ENRICH_LIMIT", 15)
    archive_retention_days  = _int("ARCHIVE_RETENTION_DAYS", 90)
    inter_source_sleep      = _float("INTER_SOURCE_SLEEP", 0.5)

    # ── AI models ──────────────────────────────────────────────────────────
    groq_model_primary  = _str("GROQ_MODEL_PRIMARY", "llama-3.3-70b-versatile")
    groq_model_fallback = _str("GROQ_MODEL_FALLBACK", "llama-3.1-8b-instant")
    gemini_model        = _str("GEMINI_MODEL", "gemini-2.5-flash-lite")
    groq_sleep_secs     = _int("GROQ_SLEEP_SECS", 3)
    gemini_sleep_secs   = _int("GEMINI_SLEEP_SECS", 6)

    # ── API keys ───────────────────────────────────────────────────────────
    otx_api_key       = os.environ.get("OTX_API_KEY", "")
    groq_api_key      = os.environ.get("GROQ_API_KEY", "")
    gemini_api_key    = os.environ.get("GEMINI_API_KEY", "")
    abuseipdb_api_key = os.environ.get("ABUSEIPDB_API_KEY", "")
    phishtank_api_key = os.environ.get("PHISHTANK_API_KEY", "")

    # ── Alerting ───────────────────────────────────────────────────────────
    webhook_url   = os.environ.get("WEBHOOK_URL", "")
    webhook_type  = _str("WEBHOOK_TYPE", "slack")
    # Which items justify a push. Comma-separated severities, plus KEV always alerts.
    alert_severities   = _str("ALERT_SEVERITIES", "critical").lower()
    alert_max_items    = _int("ALERT_MAX_ITEMS", 10)
    alert_retry_count  = _int("ALERT_RETRY_COUNT", 3)
    alert_state_ttl_days = _int("ALERT_STATE_TTL_DAYS", 14)

    # ── Priority scoring weights (see fetch_intel.compute_priority) ─────────
    # Blended 0-100 score = CVSS component + EPSS component + KEV bonus.
    priority_cvss_weight = _float("PRIORITY_CVSS_WEIGHT", 40.0)
    priority_epss_weight = _float("PRIORITY_EPSS_WEIGHT", 40.0)
    priority_kev_bonus   = _float("PRIORITY_KEV_BONUS", 20.0)

    http_user_agent = _str("HTTP_USER_AGENT", "CyberWatch/2.3 (threat-intel dashboard)")

    @property
    def alert_severity_set(self) -> set:
        return {s.strip() for s in self.alert_severities.split(",") if s.strip()}


CONFIG = Config()
