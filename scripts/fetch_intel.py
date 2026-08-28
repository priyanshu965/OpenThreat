"""
OPENTHREAT DASHBOARD — fetch_intel.py
======================================
Fetches threat intelligence from multiple free sources:
  - 14 RSS feeds          → News, advisories, incident reports
  - NVD (NIST) CVE API    → Latest vulnerabilities
  - Reddit r/netsec       → Community intel (RSS)
  - AlienVault OTX API    → Threat pulses (API key)
  - URLhaus               → Malware URLs & payload hashes
  - Spamhaus DROP         → Malicious IP ranges
  - Feodo Tracker         → C2 server IPs
  - AbuseIPDB             → IP blacklist (API key)
  - PhishTank             → Phishing URLs (API key)
  - MalwareBazaar         → Malware samples (API key)
  - ThreatFox             → C2 IOCs (API key)
  - MSRC                  → Microsoft advisories (RSS)
  - Fedora Bodhi          → Fedora security updates (API)
  - Gentoo GLSA           → Gentoo advisories (RSS)
  - Arch Linux            → Arch security issues (JSON)
  - Amazon Linux          → ALAS advisories (RSS)
  - CentOS Stream         → CentOS blog (RSS)
  - VMware                → Broadcom advisories (JSON API)
  - Mitre CWE             → CWE taxonomy (API)
  - IOC Extraction        → Regex-based from all item descriptions
  - AI Enrichment         → Gemini (primary) with Groq fallback

Output: data/intel.json  +  data/archive/YYYY-MM-DD.json
"""

import hashlib
import json
import os
import re
import threading
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed

import csv
import requests
import feedparser

# ── Local modules (support both `python scripts/x.py` and package import) ─────
# `python -m scripts.fetch_intel` does NOT put scripts/ on sys.path, so the
# sibling imports below would fail there. One line makes every entry point
# behave the same instead of giving each import its own importlib fallback.
import sys                                                            # noqa: E402
if str(Path(__file__).resolve().parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent))

try:
    from config import CONFIG
except ImportError:
    import importlib.util
    _cspec = importlib.util.spec_from_file_location(
        "config", Path(__file__).parent / "config.py"
    )
    _cmod = importlib.util.module_from_spec(_cspec)
    _cspec.loader.exec_module(_cmod)
    CONFIG = _cmod.CONFIG

# Attacker-map modules. Optional: the core feed pipeline stays importable and
# runnable even if these are missing or their extra deps are unavailable.
try:
    from geoip import GeoIP
    from attacker_feeds import collect_attacker_infrastructure
except Exception:
    GeoIP = None
    collect_attacker_infrastructure = None
try:
    from sectors import annotate_sectors, SECTOR_LABELS
except Exception:
    annotate_sectors = None
    SECTOR_LABELS = {}
try:
    from geopolitics import build_geopolitics
except Exception:
    build_geopolitics = None
try:
    from darkweb import (fetch_leak_site_posts, build_darkweb_summary,
                         build_darkweb_index, check_watchlist,
                         build_sector_benchmark)
except Exception:
    fetch_leak_site_posts = None
    build_darkweb_summary = None
    build_darkweb_index = None
    check_watchlist = None
    build_sector_benchmark = None
try:
    from exposure import build_exposure, build_breach_catalogue
except Exception:
    build_exposure = None
    build_breach_catalogue = None
try:
    from attack_surface import build_attack_surface
except Exception:
    build_attack_surface = None
try:
    from provenance import (annotate_provenance, PROVENANCE_LABELS,
                            PROVENANCE_NOTES, PROVENANCE_ORDER)
except Exception:
    annotate_provenance = None
    PROVENANCE_LABELS, PROVENANCE_NOTES, PROVENANCE_ORDER = {}, {}, []

# ── v4 research + enrichment modules ─────────────────────────────────────────
# Every one is optional in exactly the same way the modules above are: the core
# feed still builds if a module is missing, its dependency is unavailable, or
# the upstream it reads is down.
from kev_catalog import load_kev as load_kev_catalog                  # noqa: E402
try:
    from entity_graph import (load_attack_kb, annotate_malware,
                              build_entity_graph, canonical_actor_names)
except Exception:
    load_attack_kb = annotate_malware = build_entity_graph = None
    canonical_actor_names = None
try:
    from malware import load_families, build_malware_view
except Exception:
    load_families = build_malware_view = None
try:
    from sigma_rules import load_sigma_index, annotate_detections, build_detection_view
except Exception:
    load_sigma_index = annotate_detections = build_detection_view = None
try:
    from backtest import build_backtest
except Exception:
    build_backtest = None
try:
    from source_reliability import build_source_reliability
except Exception:
    build_source_reliability = None
try:
    from exploit_lag import build_exploit_lag
except Exception:
    build_exploit_lag = None
try:
    from campaigns import build_campaigns
except Exception:
    build_campaigns = None
try:
    from timeline import publish_timeline
except Exception:
    publish_timeline = None

# -- v5: the Library (encyclopedia), the hunt bench, leak-site tracking -------
# Same contract as everything above: optional, and the feed builds without any
# of them. The Library in particular is a large, slow-moving corpus -- if MISP
# galaxy or ORKL are unreachable the entity pages simply carry less, and the
# hourly feed is untouched.
try:
    from misp_galaxy import load_galaxy
except Exception:
    load_galaxy = None
try:
    from orkl import load_orkl
except Exception:
    load_orkl = None
try:
    from d3fend import load_d3fend
except Exception:
    load_d3fend = None
try:
    from control_mappings import load_control_mappings, build_control_focus
except Exception:
    load_control_mappings = build_control_focus = None
try:
    from atomics import load_atomics
except Exception:
    load_atomics = None
try:
    from knowledge_base import build_knowledge_base
except Exception:
    build_knowledge_base = None
try:
    from hunt_packs import build_hunt_packs, build_hunt_queue
except Exception:
    build_hunt_packs = build_hunt_queue = None
try:
    from ransomware_leaks import load_leak_sites
except Exception:
    load_leak_sites = None
try:
    from telegram_watch import load_telegram
except Exception:
    load_telegram = None
try:
    from sigma_rules import build_detection_diff, fetch_rule_bodies
except Exception:
    build_detection_diff = fetch_rule_bodies = None

# ── MITRE ATT&CK full database ────────────────────────────────────────────────
try:
    from mitre_ttps import MITRE_TECHNIQUES, TACTIC_ORDER, map_ttps
except ImportError:
    import importlib.util
    _spec = importlib.util.spec_from_file_location(
        "mitre_ttps", Path(__file__).parent / "mitre_ttps.py"
    )
    _mod = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_mod)
    MITRE_TECHNIQUES = _mod.MITRE_TECHNIQUES
    TACTIC_ORDER     = _mod.TACTIC_ORDER
    map_ttps         = _mod.map_ttps

# ── Trends + alerting helpers (optional; degrade gracefully if missing) ───────
try:
    from trends import build_trends
except Exception:
    build_trends = None
try:
    from exports import write_exports
except Exception:
    write_exports = None
try:
    from wellknown import write_wellknown
except Exception:
    write_wellknown = None
try:
    from webhook_post import send_alerts, send_watch_alerts
except Exception:
    send_alerts = None
    send_watch_alerts = None

# ── Logging + shared HTTP session + disk cache ────────────────────────────────
# These all live in fetchlib now, so the satellite modules (darkweb, malware,
# entity_graph, sigma_rules, …) can share exactly one session and one cache
# without importing this module — which they could never do successfully, since
# under `python scripts/fetch_intel.py` this module is `__main__` and
# `from fetch_intel import _SESSION` would import a whole second copy of it.
# The aliases are re-exported deliberately, not accidentally: the security
# regression suite pins the cache path-traversal guard through
# fetch_intel._cache_path / _safe_cache_name / _CACHE_DIR, and several call
# sites in this file still use the underscored names. Ruff cannot see a test
# reaching in from another module, hence the explicit noqa.
from fetchlib import (                                          # noqa: E402,F401
    log,
    SESSION as _SESSION,
    CACHE_DIR as _CACHE_DIR,
    safe_cache_name as _safe_cache_name,
    cache_path as _cache_path,
    cached_fetch as _cached_fetch,
    StructuredAdapter as _StructuredAdapter,
    item_technique_ids,
)

# ── Configuration (see scripts/config.py; override via env vars) ──────────────
PROJECT_ROOT         = CONFIG.project_root
OUTPUT_PATH          = CONFIG.output_path
ARCHIVE_DIR          = CONFIG.archive_dir
MAX_ITEMS_PER_SOURCE = CONFIG.max_items_per_source
NVD_LOOKBACK_DAYS    = CONFIG.nvd_lookback_days
REQUEST_TIMEOUT      = CONFIG.request_timeout
AI_ENRICH_LIMIT      = CONFIG.ai_enrich_limit
ARCHIVE_RETENTION_DAYS = CONFIG.archive_retention_days

# API keys (set as environment variables)
OTX_API_KEY       = CONFIG.otx_api_key
GROQ_API_KEY      = CONFIG.groq_api_key
GEMINI_API_KEY    = CONFIG.gemini_api_key
ABUSEIPDB_KEY     = CONFIG.abuseipdb_api_key
PHISHTANK_KEY     = CONFIG.phishtank_api_key
THREATFOX_API_KEY = CONFIG.threatfox_api_key
MB_API_KEY        = CONFIG.mb_api_key

GROQ_MODEL_PRIMARY  = CONFIG.groq_model_primary
GROQ_MODEL_FALLBACK = CONFIG.groq_model_fallback
GEMINI_MODEL        = CONFIG.gemini_model
VULNCHECK_API_KEY   = CONFIG.vulncheck_api_key
AI_BATCH_SIZE       = CONFIG.ai_batch_size

HEADERS = {"User-Agent": CONFIG.http_user_agent}

# ── RSS Feed Sources (15 total) ───────────────────────────────────────────────
RSS_SOURCES = [
    {"name": "CISA",             "url": "https://www.cisa.gov/cybersecurity-advisories/all.xml", "category": "advisory", "severity": "high"},
    {"name": "The Hacker News",  "url": "https://feeds.feedburner.com/TheHackersNews",            "category": "news",     "severity": "medium"},
    {"name": "Bleeping Computer","url": "https://www.bleepingcomputer.com/feed/",                 "category": "news",     "severity": "medium"},
    {"name": "Krebs on Security","url": "https://krebsonsecurity.com/feed/",                      "category": "news",     "severity": "medium"},
    {"name": "SANS ISC",         "url": "https://isc.sans.edu/rssfeed_full.xml",                  "category": "news",     "severity": "low"},
    {"name": "TheRecord Media",  "url": "https://therecord.media/feed",                           "category": "news",     "severity": "high"},
    {"name": "Dark Reading",     "url": "https://www.darkreading.com/rss.xml",                    "category": "news",     "severity": "medium"},
    {"name": "SecurityWeek",     "url": "https://www.securityweek.com/feed/",                     "category": "news",     "severity": "medium"},
    {"name": "Cisco Talos",      "url": "https://blog.talosintelligence.com/feed",                "category": "news",     "severity": "high"},
    {"name": "Unit 42",          "url": "https://feeds.feedburner.com/Unit42",                    "category": "news",     "severity": "high"},
    {"name": "Graham Cluley",    "url": "https://grahamcluley.com/feed/",                         "category": "news",     "severity": "medium"},
    {"name": "ESET WeLiveSecurity","url": "https://welivesecurity.com/feed/",                     "category": "news",     "severity": "medium"},
    # ── Vendor threat-research blogs ────────────────────────────────────────
    # Added because the geopolitical view is only as good as actor detection,
    # and these are the sources that actually NAME groups (APT41, Volt Typhoon,
    # Sandworm) rather than describing incidents generically. All are free,
    # keyless, public RSS; verified live before adding.
    {"name": "Securelist",       "url": "https://securelist.com/feed/",                          "category": "news",     "severity": "medium"},
    {"name": "Check Point Research", "url": "https://research.checkpoint.com/feed/",             "category": "news",     "severity": "medium"},
    {"name": "Microsoft Security",   "url": "https://www.microsoft.com/en-us/security/blog/feed/", "category": "news",   "severity": "medium"},
    {"name": "SentinelOne",      "url": "https://www.sentinelone.com/blog/feed/",                "category": "news",     "severity": "medium"},
    {"name": "Malwarebytes",     "url": "https://www.malwarebytes.com/blog/feed/index.xml",      "category": "news",     "severity": "medium"},
    {"name": "Recorded Future",  "url": "https://www.recordedfuture.com/feed",                   "category": "news",     "severity": "medium"},
    {"name": "CyberSecurity News","url": "https://cybersecuritynews.com/feed/",                   "category": "news",     "severity": "medium"},
    # GBHackers removed — feed returns 403 from all automated clients
]

# ── Helpers ───────────────────────────────────────────────────────────────────

def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()

def parse_date(date_str) -> str:
    if not date_str:
        return now_utc()
    try:
        if hasattr(date_str, 'tm_year'):
            return datetime(*date_str[:6], tzinfo=timezone.utc).isoformat()
        for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S%z",
                    "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S",
                    "%Y-%m-%d %H:%M:%S UTC", "%Y-%m-%d"):
            try:
                return datetime.strptime(date_str, fmt).replace(tzinfo=timezone.utc).isoformat()
            except ValueError:
                continue
    except Exception:
        pass
    return now_utc()

_TAG_RE = re.compile(r"</?[a-zA-Z][a-zA-Z0-9-]*(?:\s[^<>]*)?/?>|<!--.*?-->", re.DOTALL)

def clean_html(text: str) -> str:
    """Strip HTML tags without destroying prose that merely contains '<'.

    The previous `<[^>]+>` pattern deleted everything between a bare '<' in
    text (e.g. `if (a < b)`) and the next '>', silently truncating code
    snippets in advisory descriptions."""
    if not text:
        return ""
    text = _TAG_RE.sub(" ", text)
    text = (text.replace("&nbsp;", " ").replace("&amp;", "&")
                .replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", '"'))
    text = re.sub(r"\s+", " ", text).strip()
    return text[:999]

def make_request(url: str, headers: dict = None, params: dict = None) -> dict | None:
    try:
        resp = requests.get(url, headers=headers or HEADERS, params=params, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        return resp.json()
    except requests.exceptions.Timeout:
        log.warning(f"Timeout: {url}")
    except requests.exceptions.HTTPError as e:
        log.warning(f"HTTP {e.response.status_code}: {url}")
    except requests.exceptions.RequestException as e:
        log.warning(f"Request failed {url}: {e}")
    except json.JSONDecodeError:
        log.warning(f"Invalid JSON: {url}")
    return None

def make_request_text(url: str, headers: dict = None) -> str | None:
    try:
        resp = requests.get(url, headers=headers or HEADERS, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        return resp.text
    except Exception as e:
        log.warning(f"Text request failed {url}: {e}")
        return None

# ── AI Enrichment ─────────────────────────────────────────────────────────────
# Design notes (this replaced a per-item, sequential, free-text-JSON design):
#
#  * BATCHED. One request carries AI_BATCH_SIZE items and returns an array.
#    The old loop made one call per item with an unconditional sleep between
#    them: ~90s to enrich 10 items. This does ~40 items in a handful of calls,
#    which is what makes AI_ENRICH_LIMIT=40 affordable on a free tier.
#
#  * SCHEMA-CONSTRAINED. The model is given a JSON schema and cannot emit
#    invalid JSON, which deleted a 60-line four-stage "repair the LLM's JSON"
#    recovery ladder (strip fences -> fix trailing commas -> balance braces ->
#    regex-salvage). One try/except is now enough.
#
#  * DIFFERENT JOB. We no longer ask the model to re-summarise a description we
#    already have, or to draw a boilerplate attack diagram. We ask for the two
#    things a model is actually good at and regex is not:
#       - affected vendor/product extraction (feeds "My Stack" matching)
#       - a one-line "why this matters / who should act" judgement

_ENRICH_ITEM_SCHEMA = {
    "type": "object",
    "properties": {
        "index":       {"type": "integer", "description": "The item index given in the prompt"},
        "summary":     {"type": "string",  "description": "3-4 sentence technical analysis: mechanism, affected versions, impact, remediation"},
        "why_it_matters": {"type": "string", "description": "One sentence: who should act and how urgently"},
        "vendors":     {"type": "array", "items": {"type": "string"}, "description": "Affected vendor names, lowercase"},
        "products":    {"type": "array", "items": {"type": "string"}, "description": "Affected product names, lowercase"},
        "confidence":  {"type": "number", "description": "0.0-1.0 confidence in this analysis"},
    },
    "required": ["index", "summary", "why_it_matters", "vendors", "products", "confidence"],
}

_ENRICH_BATCH_SCHEMA = {
    "type": "object",
    "properties": {"results": {"type": "array", "items": _ENRICH_ITEM_SCHEMA}},
    "required": ["results"],
}

_BRIEF_SCHEMA = {
    "type": "object",
    "properties": {
        "headline": {"type": "string", "description": "One sentence summarising today's threat landscape"},
        "top_items": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "index":  {"type": "integer"},
                    "reason": {"type": "string", "description": "Why this one matters today, one sentence"},
                },
                "required": ["index", "reason"],
            },
        },
    },
    "required": ["headline", "top_items"],
}


def build_batch_prompt(items: list[dict]) -> str:
    """One prompt covering a batch of items. Indices are how results map back."""
    lines = [
        "You are a senior threat intelligence analyst. Analyse each numbered "
        "threat item below and return one result object per item.",
        "",
        "Rules:",
        "- summary: 3-4 sentences. Technical and specific. Mechanism, affected "
        "versions, real impact, concrete remediation. Do not pad.",
        "- why_it_matters: ONE sentence naming who should act and how fast.",
        "- vendors/products: lowercase names extracted from the text (e.g. "
        '"fortinet", "fortios"). Empty arrays if none are identifiable. Do not guess.',
        "- confidence: 0.0-1.0. Be honest; low confidence on thin source text.",
        "",
        "ITEMS:",
    ]
    for idx, item in enumerate(items):
        ttps = ", ".join(f"{t['id']}" for t in (item.get("ttps") or [])[:6]) or "none"
        lines.append(
            f"\n[{idx}] title: {(item.get('title') or '')[:220]}"
            f"\n    description: {(item.get('description') or '')[:600]}"
            f"\n    cve: {item.get('cve_id') or 'N/A'} | cvss: {item.get('cvss_score') or 'N/A'}"
            f" | kev: {bool(item.get('cisa_kev'))} | poc: {bool(item.get('has_poc'))}"
            f"\n    ttps: {ttps}"
        )
    return "\n".join(lines)


def _call_gemini_json(prompt: str, schema: dict, model: str | None = None) -> dict | None:
    """Structured-output Gemini call. Returns a parsed dict or None.

    Tries the current `google-genai` SDK first and falls back to the legacy
    `google-generativeai` package so this keeps working during migration.
    """
    if not GEMINI_API_KEY:
        return None
    model = model or GEMINI_MODEL

    # Preferred: google-genai (current SDK).
    try:
        from google import genai  # type: ignore
        client = genai.Client(api_key=GEMINI_API_KEY)
        resp = client.models.generate_content(
            model=model,
            contents=prompt,
            config={"response_mime_type": "application/json", "response_schema": schema},
        )
        return json.loads(resp.text)
    except ImportError:
        pass
    except Exception as e:
        log.warning(f"Gemini ({model}) structured call failed: {e}")
        return None

    # Fallback: legacy google-generativeai.
    try:
        import google.generativeai as genai_legacy  # type: ignore
        genai_legacy.configure(api_key=GEMINI_API_KEY)
        gm = genai_legacy.GenerativeModel(model)
        resp = gm.generate_content(
            prompt,
            generation_config={"response_mime_type": "application/json",
                               "response_schema": schema},
        )
        return json.loads(resp.text)
    except Exception as e:
        log.warning(f"Gemini legacy ({model}) call failed: {e}")
        return None


def _call_groq_json(prompt: str) -> dict | None:
    """Groq fallback. Groq's free tier is small (100-2,000 req/day), so this is
    a failover for a handful of calls, not a primary path."""
    if not GROQ_API_KEY:
        return None
    headers = {"Authorization": f"Bearer {GROQ_API_KEY}", "Content-Type": "application/json"}
    for model in (GROQ_MODEL_PRIMARY, GROQ_MODEL_FALLBACK):
        try:
            resp = _SESSION.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers=headers, timeout=REQUEST_TIMEOUT,
                json={"model": model,
                      "messages": [{"role": "user", "content": prompt}],
                      "temperature": 0.1, "max_tokens": 4000,
                      "response_format": {"type": "json_object"}})
            if resp.status_code == 429:
                log.warning(f"Groq rate limited on {model}")
                continue
            resp.raise_for_status()
            return json.loads(resp.json()["choices"][0]["message"]["content"])
        except Exception as e:
            log.warning(f"Groq error ({model}): {e}")
    return None


def apply_enrichment(item: dict, result: dict) -> None:
    """Write one model result onto an item."""
    summary = str(result.get("summary", "")).strip()
    if summary:
        item["ai_summary"] = summary[:1200]
    why = str(result.get("why_it_matters", "")).strip()
    if why:
        item["why_it_matters"] = why[:400]

    vendors  = [str(v).strip().lower() for v in (result.get("vendors")  or []) if str(v).strip()]
    products = [str(p).strip().lower() for p in (result.get("products") or []) if str(p).strip()]
    if vendors:
        item["vendors"] = sorted(set(vendors))[:8]
    if products:
        item["products"] = sorted(set(products))[:8]

    try:
        item["ai_confidence"] = round(max(0.0, min(1.0, float(result.get("confidence", 0.5)))), 2)
    except (TypeError, ValueError):
        item["ai_confidence"] = 0.5


def rule_based_enrich(item: dict) -> None:
    """Zero-cost defaults for every item.

    Deliberately does NOT set `ai_summary`: 246 of 248 rule summaries were a
    prefix of `description`, which is already in the same JSON object, so
    shipping both wasted 58 KB per payload for zero information. The frontend
    derives a display summary from `description` when `ai_summary` is absent.
    """
    text = f"{item.get('title', '')} {item.get('description', '')}"
    item["severity"]    = infer_severity(text, item.get("severity") or "medium")
    item["category"]    = infer_category(text, item.get("category") or "news")
    item["ai_provider"] = "rule"


# ── Cross-run enrichment cache ────────────────────────────────────────────────
# A model result is a property of the ITEM, not of the run. The feed turns over
# slowly — most of what ranks in the top N this hour ranked there last hour too
# — so without a cache the same items were re-sent to Gemini on all 24 daily
# runs. Keyed by item_key() (CVE, else canonical URL, else title fingerprint),
# which is the same identity mark_new_since_last() diffs on.

_AI_CACHE_NAME = "ai_enrich.json"
_AI_CACHE_FIELDS = ("ai_summary", "why_it_matters", "vendors", "products",
                    "ai_confidence", "ai_provider", "ai_model")


def _load_ai_cache() -> dict:
    """Cached enrichments, with expired entries dropped."""
    path = _cache_path(_AI_CACHE_NAME)
    if not path.exists():
        return {}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        log.warning(f"AI cache unreadable, starting fresh: {e}")
        return {}
    if not isinstance(raw, dict):
        return {}
    cutoff = time.time() - CONFIG.ai_cache_ttl_days * 86400
    return {k: v for k, v in raw.items()
            if isinstance(v, dict) and float(v.get("cached_at") or 0) >= cutoff}


def _save_ai_cache(cache: dict) -> None:
    """Atomically persist the cache, newest entries first, size-capped."""
    if not cache:
        return
    entries = sorted(cache.items(), key=lambda kv: -float(kv[1].get("cached_at") or 0))
    trimmed = dict(entries[:CONFIG.ai_cache_max_entries])
    try:
        path = _cache_path(_AI_CACHE_NAME)
        tmp = path.with_suffix(f".{os.getpid()}.tmp")
        tmp.write_text(json.dumps(trimmed, ensure_ascii=False), encoding="utf-8")
        tmp.replace(path)
    except Exception as e:
        log.warning(f"Could not write AI cache: {e}")


def _cache_enrichment(cache: dict, item: dict) -> None:
    entry = {f: item[f] for f in _AI_CACHE_FIELDS if item.get(f) is not None}
    if entry.get("ai_provider") in (None, "rule"):
        return                      # nothing a model produced; not worth storing
    entry["cached_at"] = time.time()
    cache[item_key(item)] = entry


def _apply_cached_enrichment(item: dict, entry: dict) -> bool:
    """Replay a cached model result onto an item. True if anything was applied."""
    applied = False
    for field in _AI_CACHE_FIELDS:
        if entry.get(field) is not None:
            item[field] = entry[field]
            applied = True
    return applied


_UNSCORED_SEVERITY_RANK = {"critical": 3, "high": 2, "medium": 1, "low": 0}


def select_enrichment_candidates(items: list[dict]) -> list[dict]:
    """Pick which items get a model call.

    Two budgets, because ranking everything by ``priority_score`` sent the
    whole allowance to CVEs — the items that need a model least, since they
    already carry CVSS, EPSS, KEV and SSVC. Incidents and news carry none of
    that structure and never got enriched at all.
    """
    scored   = [i for i in items if i.get("priority_score") is not None]
    unscored = [i for i in items if i.get("priority_score") is None]

    scored.sort(key=lambda i: i.get("priority_score") or 0, reverse=True)
    unscored.sort(key=lambda i: (_UNSCORED_SEVERITY_RANK.get(i.get("severity"), 0),
                                 i.get("published") or ""), reverse=True)

    return (scored[:AI_ENRICH_LIMIT]
            + unscored[:CONFIG.ai_enrich_unscored_limit])


def enrich_with_ai(items: list[dict]) -> list[dict]:
    """Rule-based defaults for everything, cached results where we have them,
    then batched model calls for whatever is left in budget."""
    for item in items:
        rule_based_enrich(item)
    log.info(f"Rule-based defaults applied to {len(items)} items")

    if not GEMINI_API_KEY and not GROQ_API_KEY:
        log.info("No AI keys set — skipping AI enrichment")
        return items

    cache = _load_ai_cache()
    reused = 0
    for item in items:
        entry = cache.get(item_key(item))
        if entry and _apply_cached_enrichment(item, entry):
            reused += 1
    if reused:
        log.info(f"AI cache: reused {reused} enrichment(s), {len(cache)} entries on disk")

    # Only spend calls on items the cache could not answer.
    to_enrich = [i for i in select_enrichment_candidates(items)
                 if i.get("ai_provider") in (None, "rule")]
    if not to_enrich:
        log.info("AI enrichment: nothing new to enrich this run")
        _save_ai_cache(cache)
        return items

    batches = [to_enrich[i:i + AI_BATCH_SIZE] for i in range(0, len(to_enrich), AI_BATCH_SIZE)]
    log.info(f"AI enrichment: {len(to_enrich)} items in {len(batches)} batch(es) of <= {AI_BATCH_SIZE}")

    enriched = 0
    for bnum, batch in enumerate(batches, 1):
        prompt = build_batch_prompt(batch)
        parsed = _call_gemini_json(prompt, _ENRICH_BATCH_SCHEMA)
        provider, model = "gemini", GEMINI_MODEL
        if not parsed:
            parsed = _call_groq_json(prompt)
            provider, model = "groq", GROQ_MODEL_PRIMARY
        if not parsed:
            log.warning(f"  batch {bnum}/{len(batches)}: no AI result, keeping rule defaults")
            continue

        for result in parsed.get("results", []):
            try:
                idx = int(result.get("index", -1))
            except (TypeError, ValueError):
                continue
            if not (0 <= idx < len(batch)):
                continue
            item = batch[idx]
            apply_enrichment(item, result)
            item["ai_provider"] = provider
            item["ai_model"] = model
            _cache_enrichment(cache, item)
            enriched += 1
        log.info(f"  batch {bnum}/{len(batches)}: {len(parsed.get('results', []))} results")

    _save_ai_cache(cache)
    log.info(f"AI enrichment complete: {enriched} new, {reused} from cache")
    return items


def build_daily_brief(items: list[dict]) -> dict | None:
    """One call per run: 'of these N items, which few actually matter today?'

    This is the highest-value use of a model in the pipeline — a judgement over
    the whole feed, which is exactly what no amount of regex can produce.
    """
    if not CONFIG.enable_ai_brief or not GEMINI_API_KEY:
        return None

    ranked = sorted(items, key=lambda i: i.get("priority_score") or 0, reverse=True)[:40]
    if not ranked:
        return None

    # Reuse the last brief unless it has aged out or the urgent picture moved.
    # Regenerating hourly cost 24 calls a day to answer the same question with
    # the same inputs; keying on the urgent set means a new KEV entry still
    # forces a fresh brief within the hour.
    signature = _brief_signature(items)
    cached = _load_cached_brief()
    if cached and cached.get("signature") == signature:
        age_h = (time.time() - float(cached.get("cached_at") or 0)) / 3600.0
        if age_h < CONFIG.brief_max_age_hours:
            log.info(f"Daily brief: reusing cached brief ({age_h:.1f}h old, urgent set unchanged)")
            return cached["brief"]

    lines = ["Below are today's top threat-intel items. Pick the 3-5 that a "
             "defender should act on FIRST and say why in one sentence each. "
             "Prefer confirmed exploitation, public PoC, and wide blast radius "
             "over interesting-but-theoretical. Also write a single headline "
             "sentence summarising the day.", "", "ITEMS:"]
    for idx, item in enumerate(ranked):
        lines.append(
            f"[{idx}] {(item.get('title') or '')[:180]} "
            f"(src={item.get('source')}, sev={item.get('severity')}, "
            f"P={item.get('priority_score')}, kev={bool(item.get('cisa_kev'))}, "
            f"poc={bool(item.get('has_poc'))}, ssvc={item.get('ssvc_exploitation') or 'n/a'})")

    parsed = _call_gemini_json("\n".join(lines), _BRIEF_SCHEMA, model=CONFIG.gemini_brief_model)
    if not parsed:
        return None

    picks = []
    for entry in parsed.get("top_items", [])[:5]:
        try:
            idx = int(entry.get("index", -1))
        except (TypeError, ValueError):
            continue
        if 0 <= idx < len(ranked):
            item = ranked[idx]
            picks.append({
                "title":  item.get("title"),
                "url":    item.get("url"),
                "cve_id": valid_cve_id(item.get("cve_id")),
                "key":    item_key(item),
                "reason": str(entry.get("reason", ""))[:300],
            })
    if not picks:
        return None
    brief = {"headline": str(parsed.get("headline", ""))[:300],
             "items": picks,
             "model": CONFIG.gemini_brief_model,
             "generated": now_utc()}
    _save_cached_brief(brief, signature)
    return brief


_BRIEF_CACHE_NAME = "daily_brief.json"


def _brief_signature(items: list[dict]) -> str:
    """Identity of the current urgent picture. Changes only when the set of
    items a defender must act on changes — which is exactly when the brief
    needs rewriting."""
    urgent = sorted(item_key(i) for i in items
                    if i.get("priority_label") in ("urgent", "elevated"))
    return hashlib.sha256("|".join(urgent).encode("utf-8")).hexdigest()[:32]


def _load_cached_brief() -> dict | None:
    path = _cache_path(_BRIEF_CACHE_NAME)
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) and data.get("brief") else None
    except Exception:
        return None


def _save_cached_brief(brief: dict, signature: str) -> None:
    try:
        path = _cache_path(_BRIEF_CACHE_NAME)
        tmp = path.with_suffix(f".{os.getpid()}.tmp")
        tmp.write_text(json.dumps({"brief": brief, "signature": signature,
                                   "cached_at": time.time()}, ensure_ascii=False),
                       encoding="utf-8")
        tmp.replace(path)
    except Exception as e:
        log.warning(f"Could not cache daily brief: {e}")


# ── RSS Fetcher ───────────────────────────────────────────────────────────────

# Per-feed ETag / Last-Modified store, so hourly runs can send a conditional
# request instead of re-downloading unchanged feeds 24x/day. Most of these
# feeds publish a handful of times daily; several have already started 403ing
# aggressive clients (GBHackers is commented out of RSS_SOURCES for exactly
# that reason), so this is politeness as much as speed.
_FEED_META: dict[str, dict] = {}
_FEED_META_LOCK = threading.Lock()


def _load_feed_meta() -> None:
    global _FEED_META
    try:
        if CONFIG.feed_meta_path.exists():
            _FEED_META = json.loads(CONFIG.feed_meta_path.read_text(encoding="utf-8"))
    except Exception:
        _FEED_META = {}


def _save_feed_meta() -> None:
    try:
        CONFIG.feed_meta_path.parent.mkdir(parents=True, exist_ok=True)
        CONFIG.feed_meta_path.write_text(json.dumps(_FEED_META, indent=2), encoding="utf-8")
    except Exception as e:
        log.warning(f"Could not persist feed metadata: {e}")


def fetch_rss(source: dict) -> list[dict]:
    log.info(f"Fetching RSS: {source['name']}")
    items = []
    url = source["url"]
    hdrs = {**HEADERS, **source.get("headers", {})}
    with _FEED_META_LOCK:
        meta = dict(_FEED_META.get(url, {}))
    if meta.get("etag"):
        hdrs["If-None-Match"] = meta["etag"]
    if meta.get("last_modified"):
        hdrs["If-Modified-Since"] = meta["last_modified"]

    try:
        resp = _SESSION.get(url, headers=hdrs, timeout=15)
        if resp.status_code == 304:
            log.info(f"  {source['name']}: 304 Not Modified — reusing last snapshot")
            return _replay_cached_feed(url)
        resp.raise_for_status()
        with _FEED_META_LOCK:
            _FEED_META[url] = {
                "etag": resp.headers.get("ETag", ""),
                "last_modified": resp.headers.get("Last-Modified", ""),
                "checked": now_utc(),
            }
        feed = feedparser.parse(resp.text)
        if feed.bozo and not feed.entries:
            log.warning(f"Feed error {source['name']}")
            return items
        for entry in feed.entries[:MAX_ITEMS_PER_SOURCE]:
            title = entry.get("title", "Untitled")
            link = entry.get("link", "")
            description = ""
            if hasattr(entry, "summary"):
                description = clean_html(entry.summary)
            elif hasattr(entry, "content"):
                description = clean_html(entry.content[0].get("value", ""))
            description = description.strip()[:999]
            pub_date = parse_date(entry.get("published_parsed") or entry.get("updated_parsed"))
            severity = infer_severity(title + " " + description, source["severity"])
            category = infer_category(title + " " + description, source["category"])
            text = title + " " + description
            items.append({
                "title": title, "description": description, "url": link,
                "cve_id": extract_cve_id(text), "source": source["name"],
                "category": category, "severity": severity, "cvss_score": None,
                "published": pub_date,
            })
    except Exception as e:
        log.error(f"Unexpected error {source['name']}: {e}")
    if items:
        _store_cached_feed(source["url"], items)
    log.info(f"  Got {len(items)} items from {source['name']}")
    return items


def _feed_cache_path(url: str) -> Path:
    return _cache_path(f"feed_{hashlib.sha1(url.encode()).hexdigest()[:16]}.json")


def _store_cached_feed(url: str, items: list[dict]) -> None:
    try:
        _feed_cache_path(url).write_text(json.dumps(items, ensure_ascii=False), encoding="utf-8")
    except Exception:
        pass


def _replay_cached_feed(url: str) -> list[dict]:
    try:
        path = _feed_cache_path(url)
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        pass
    return []

# ── NVD CVE Fetcher ───────────────────────────────────────────────────────────

def fetch_nvd_cves() -> list[dict]:
    log.info("Fetching CVEs from NVD API...")
    items = []
    end_date = datetime.now(timezone.utc)
    start_date = end_date - timedelta(days=NVD_LOOKBACK_DAYS)
    nvd_params = {
        "pubStartDate": start_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate": end_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": MAX_ITEMS_PER_SOURCE,
    }
    if CONFIG.nvd_api_key:
        nvd_params["apiKey"] = CONFIG.nvd_api_key
    data = make_request("https://services.nvd.nist.gov/rest/json/cves/2.0", params=nvd_params)
    if not data:
        return items
    for vuln in data.get("vulnerabilities", []):
        cve = vuln.get("cve", {})
        cve_id = cve.get("id", "")
        descriptions = cve.get("descriptions", [])
        description = next((d["value"] for d in descriptions if d.get("lang") == "en"), "No description.")[:400]
        cvss_score = None
        severity = "medium"
        for mk in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            ml = cve.get("metrics", {}).get(mk, [])
            if ml:
                cvss_score = ml[0].get("cvssData", {}).get("baseScore")
                severity = cvss_to_severity(cvss_score)
                break
        # Affected vendor/product pairs from CPE criteria — powers the
        # dashboard's "my stack" watchlist matching.
        products = set()
        for conf in cve.get("configurations", []) or []:
            for node in conf.get("nodes", []) or []:
                for match in node.get("cpeMatch", []) or []:
                    parts = (match.get("criteria") or "").split(":")
                    if len(parts) > 4:  # cpe:2.3:a:vendor:product:...
                        products.add(f"{parts[3]}/{parts[4]}")
        items.append({
            "title": f"{cve_id}: {description[:80]}...", "description": description,
            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}", "cve_id": valid_cve_id(cve_id),
            "source": "NVD", "category": "cve", "severity": severity,
            "cvss_score": cvss_score, "published": parse_date(cve.get("published", "")),
            "affected_products": sorted(products)[:8],
        })
    log.info(f"  Got {len(items)} CVEs from NVD")
    return items

# ── Reddit r/netsec Fetcher ───────────────────────────────────────────────────

def fetch_reddit_netsec() -> list[dict]:
    log.info("Fetching Reddit r/netsec...")
    items = []
    try:
        resp = requests.get("https://www.reddit.com/r/netsec/.rss",
                             headers={**HEADERS, "User-Agent": f"{CONFIG.http_user_agent} (macOS; rv:1.0)"},
                            timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        feed = feedparser.parse(resp.text)
        for entry in feed.entries[:MAX_ITEMS_PER_SOURCE]:
            title = entry.get("title", "Untitled")
            link = entry.get("link", "")
            desc = clean_html(entry.get("summary", ""))[:400]
            pub = parse_date(entry.get("published_parsed"))
            items.append({
                "title": title, "description": desc or f"Reddit (score: {entry.get('slash_comments', '')})",
                "url": link, "cve_id": extract_cve_id(title),
                "source": "Reddit/netsec", "category": infer_category(title, "news"),
                "severity": infer_severity(title, "low"), "cvss_score": None, "published": pub,
            })
    except Exception as e:
        log.warning(f"Reddit r/netsec failed: {e}")
    log.info(f"  Got {len(items)} posts from Reddit r/netsec")
    return items

# ── AlienVault OTX Fetcher (API key) ──────────────────────────────────────────

def fetch_otx_pulse() -> list[dict]:
    if not OTX_API_KEY:
        log.info("OTX_API_KEY not set — skipping AlienVault OTX")
        return []
    log.info("Fetching AlienVault OTX pulses...")
    items = []
    data = make_request("https://otx.alienvault.com/api/v1/pulses/subscribed",
                        headers={**HEADERS, "X-OTX-API-KEY": OTX_API_KEY},
                        params={"limit": MAX_ITEMS_PER_SOURCE})
    if not data:
        return items
    for pulse in data.get("results", []):
        name = pulse.get("name", "Untitled")
        description = (pulse.get("description") or "")[:400]
        items.append({
            "title": name, "description": description,
            "url": f"https://otx.alienvault.com/pulse/{pulse.get('id','')}",
            "cve_id": None, "source": "AlienVault OTX", "category": "incident",
            "severity": infer_severity(name + " " + description, "medium"),
            "cvss_score": None, "published": parse_date(pulse.get("created", now_utc())),
        })
    log.info(f"  Got {len(items)} pulses from AlienVault OTX")
    return items

# ── URLhaus Fetcher (keyless) ─────────────────────────────────────────────────

def fetch_urlhaus() -> list[dict]:
    log.info("Fetching URLhaus malware URLs...")
    items = []
    try:
        resp = requests.get("https://urlhaus.abuse.ch/downloads/csv_recent/",
            headers=HEADERS, timeout=15, stream=True)
        resp.raise_for_status()
        lines = []
        for i, line in enumerate(resp.iter_lines(decode_unicode=True)):
            if i > MAX_ITEMS_PER_SOURCE + 2:
                break
            if line and not line.startswith("#") and not line.startswith("\"#\""):
                lines.append(line)
        reader = csv.DictReader(lines)
        for row in reader:
            url = row.get("url", "")
            threat = row.get("threat", "malware")
            date_added = row.get("dateadded", "")
            tags = row.get("tags", "")
            host = row.get("host", "") or (url.split("/")[2] if "//" in url else "unknown")
            items.append({
                "title": f"URLhaus: {host} serving {threat}",
                "description": f"Malicious URL: {url[:200]} | Tags: {tags}",
                "url": url, "cve_id": None, "source": "URLhaus",
                "category": "incident", "severity": infer_severity(threat + " " + tags, "high"),
                "cvss_score": None, "published": parse_date(date_added),
                "iocs": {"url": [url]}
            })
    except Exception as e:
        log.warning(f"URLhaus request failed: {e}")
    log.info(f"  Got {len(items)} URLs from URLhaus")
    return items

# ── Spamhaus DROP Fetcher (keyless) ──────────────────────────────────────────

def fetch_spamhaus_drop() -> list[dict]:
    log.info("Fetching Spamhaus DROP list...")
    items = []
    text = make_request_text("https://www.spamhaus.org/drop/drop.txt")
    if not text:
        return items
    for line in text.strip().split("\n"):
        line = line.strip()
        if not line or line.startswith(";") or ";" not in line:
            continue
        parts = line.split(";", 1)
        cidr = parts[0].strip()
        description = parts[1].strip() if len(parts) > 1 else "Spamhaus DROP"
        if not cidr:
            continue
        items.append({
            "title": f"Spamhaus DROP: {cidr}",
            "description": f"Malicious IP range: {cidr} — {description[:200]}",
            "url": "https://www.spamhaus.org/drop/", "cve_id": None,
            "source": "Spamhaus", "category": "advisory", "severity": "medium",
            "cvss_score": None, "published": now_utc(),
            "iocs": {"cidr": [cidr]},
        })
        if len(items) >= MAX_ITEMS_PER_SOURCE:
            break
    log.info(f"  Got {len(items)} IP ranges from Spamhaus")
    return items

# ── Feodo Tracker Fetcher (keyless) ───────────────────────────────────────────

def fetch_feodo() -> list[dict]:
    log.info("Fetching Feodo Tracker C2 IPs...")
    items = []
    data = make_request("https://feodotracker.abuse.ch/downloads/ipblocklist.json")
    if not data:
        return items
    for entry in data[:MAX_ITEMS_PER_SOURCE]:
        ip = entry.get("ip_address", "")
        port = entry.get("port", "")
        status = entry.get("status", "")
        hostname = entry.get("hostname", "")
        first_seen = entry.get("first_seen", "")
        malware = entry.get("malware", "")
        description = f"C2 server: {ip}:{port} | Malware: {malware} | Status: {status}"
        if hostname:
            description += f" | Hostname: {hostname}"
        items.append({
            "title": f"Feodo C2: {ip}:{port} ({malware})",
            "description": description,
            "url": f"https://feodotracker.abuse.ch/browse/host/{ip}/",
            "cve_id": None, "source": "Feodo Tracker", "category": "incident",
            "severity": "high", "cvss_score": None, "published": parse_date(first_seen),
            "iocs": {"ipv4": [ip]},
        })
    log.info(f"  Got {len(items)} C2 IPs from Feodo Tracker")
    return items

# ── AbuseIPDB Fetcher (API key) ──────────────────────────────────────────────

def fetch_abuseipdb() -> list[dict]:
    if not ABUSEIPDB_KEY:
        log.info("ABUSEIPDB_API_KEY not set — skipping AbuseIPDB")
        return []
    log.info("Fetching AbuseIPDB blacklist...")
    items = []
    data = make_request(
        "https://api.abuseipdb.com/api/v2/blacklist",
        headers={**HEADERS, "Key": ABUSEIPDB_KEY, "Accept": "application/json"},
        params={"confidenceMinimum": 90, "limit": MAX_ITEMS_PER_SOURCE}
    )
    if not data:
        return items
    for entry in data.get("data", []):
        ip = entry.get("ipAddress", "")
        confidence = entry.get("abuseConfidenceScore", 0)
        country = entry.get("countryCode", "")
        domain = entry.get("domain", "")
        desc_parts = [f"IP: {ip}", f"Confidence: {confidence}%"]
        if country:
            desc_parts.append(f"Country: {country}")
        if domain:
            desc_parts.append(f"Domain: {domain}")
        items.append({
            "title": f"AbuseIPDB: {ip} ({confidence}% confidence)",
            "description": " | ".join(desc_parts),
            "url": f"https://www.abuseipdb.com/check/{ip}",
            "cve_id": None, "source": "AbuseIPDB", "category": "incident",
            "severity": "high" if confidence >= 90 else "medium",
            "cvss_score": None, "published": now_utc(),
            "iocs": {"ipv4": [ip]},
        })
    log.info(f"  Got {len(items)} IPs from AbuseIPDB")
    return items

# ── PhishTank Fetcher (API key) ──────────────────────────────────────────────

def fetch_phishtank() -> list[dict]:
    if not PHISHTANK_KEY:
        log.info("PHISHTANK_API_KEY not set — skipping PhishTank")
        return []
    log.info("Fetching PhishTank phishing URLs...")
    items = []
    data = make_request(f"http://data.phishtank.com/data/{PHISHTANK_KEY}/online-valid.json")
    if not data:
        return items
    for entry in data[:MAX_ITEMS_PER_SOURCE]:
        phish_url = entry.get("url", "")
        phish_detail = entry.get("phish_detail_url", "")
        target = entry.get("target", "")
        verified = entry.get("verified", False)
        submission_time = entry.get("submission_time", "")
        description = f"Phishing URL: {phish_url[:200]}"
        if target:
            description += f" | Target: {target}"
        description += f" | Verified: {verified}"
        items.append({
            "title": f"PhishTank: {target or 'phishing'} page at {phish_url[:60]}...",
            "description": description,
            "url": phish_detail or phish_url, "cve_id": None,
            "source": "PhishTank", "category": "incident", "severity": "medium",
            "cvss_score": None, "published": parse_date(submission_time),
            "iocs": {"url": [phish_url]},
        })
    log.info(f"  Got {len(items)} phishing URLs from PhishTank")
    return items

# ── MalwareBazaar Fetcher (keyless) ──────────────────────────────────────────

def fetch_malwarebazaar() -> list[dict]:
    if not MB_API_KEY:
        log.info("MB_API_KEY not set — skipping MalwareBazaar")
        return []
    log.info("Fetching MalwareBazaar recent samples...")
    items = []
    try:
        resp = requests.post(
            "https://mb-api.abuse.ch/api/v1/",
            data={"query": "get_recent", "selector": "time"},
            headers={**HEADERS, "Auth-Key": MB_API_KEY}, timeout=15
        )
        resp.raise_for_status()
        data = resp.json()
        for entry in data.get("data", [])[:MAX_ITEMS_PER_SOURCE]:
            sha256 = entry.get("sha256_hash", "")
            md5 = entry.get("md5_hash", "")
            file_name = entry.get("file_name", "unknown")
            file_type = entry.get("file_type", "")
            signature = entry.get("signature", "")
            first_seen = entry.get("first_seen", "")
            tags = entry.get("tags", [])
            tag_str = ", ".join(tags[:5]) if tags else ""
            desc = f"SHA256: {sha256[:20]}... | MD5: {md5} | Type: {file_type} | Tags: {tag_str}"
            if signature:
                desc += f" | Malware: {signature}"
            items.append({
                "title": f"MalwareBazaar: {file_name} ({signature or file_type})",
                "description": desc,
                "url": f"https://bazaar.abuse.ch/sample/{sha256}/",
                "cve_id": None, "source": "MalwareBazaar",
                "category": "incident", "severity": "high",
                "cvss_score": None, "published": parse_date(first_seen),
                "iocs": {"sha256": [sha256], "md5": [md5]} if md5 else {"sha256": [sha256]},
            })
    except Exception as e:
        log.warning(f"MalwareBazaar failed: {e}")
    log.info(f"  Got {len(items)} samples from MalwareBazaar")
    return items

# ── ThreatFox Fetcher (keyless) ──────────────────────────────────────────────

# ThreatFox states the indicator type explicitly. The previous code ignored
# that field and re-derived the type from the string's shape, which was both
# redundant and wrong: the IPv4 branch required a ":port" suffix, so a bare
# address fell through to the domain branch and was published as a *domain*,
# and hashes matched no branch at all.
_THREATFOX_TYPE_MAP = {
    "ip:port": "ipv4", "ip": "ipv4",
    "domain": "domain", "url": "url", "email": "email",
    "md5_hash": "md5", "sha1_hash": "sha1", "sha256_hash": "sha256",
}


def _threatfox_ioc(ioc: str, ioc_type: str) -> dict[str, list[str]]:
    """Bucket one ThreatFox indicator using the type the API reports."""
    kind = _THREATFOX_TYPE_MAP.get((ioc_type or "").strip().lower())
    if not kind or not ioc:
        # Unknown type: fall back to the shared extractor rather than guessing.
        return extract_iocs(ioc, source="ThreatFox")
    value = ioc.rsplit(":", 1)[0] if kind == "ipv4" and ioc.count(":") == 1 else ioc
    return {kind: [value.lower() if kind in ("domain", "email") else value]}


def fetch_sslbl() -> list[dict]:
    """abuse.ch SSL Certificate Blacklist: SHA1 fingerprints of certs seen on
    malware C2 infrastructure. Listed in awesome-threat-intelligence; free, no
    key. The listing reason names the malware family, which is what makes these
    worth carrying alongside the IOC itself."""
    log.info("Fetching abuse.ch SSL Blacklist...")
    items = []
    try:
        resp = _SESSION.get("https://sslbl.abuse.ch/blacklist/sslblacklist.csv",
                            timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        rows = [ln for ln in resp.text.splitlines()
                if ln and not ln.startswith("#")]
        # The file is newest-first, so the head is the most recent listings.
        for line in rows[:MAX_ITEMS_PER_SOURCE]:
            parts = line.split(",")
            if len(parts) < 3:
                continue
            listed, sha1, reason = parts[0].strip(), parts[1].strip(), parts[2].strip()
            if len(sha1) != 40:
                continue
            items.append({
                "title": f"SSLBL: {reason} certificate",
                "description": (f"abuse.ch listed an SSL certificate used by "
                                f"{reason} infrastructure. SHA1: {sha1}"),
                "url": f"https://sslbl.abuse.ch/ssl-certificates/sha1/{sha1}/",
                "cve_id": None, "source": "SSL Blacklist",
                "category": "incident", "severity": "high",
                "cvss_score": None, "published": parse_date(listed),
                "iocs": {"sha1": [sha1]},
            })
    except Exception as e:
        log.warning(f"SSL Blacklist failed: {e}")
    log.info(f"  Got {len(items)} certificates from SSL Blacklist")
    return items


def fetch_threatfox() -> list[dict]:
    if not THREATFOX_API_KEY:
        log.info("THREATFOX_API_KEY not set — skipping ThreatFox")
        return []
    log.info("Fetching ThreatFox recent IOCs...")
    items = []
    try:
        resp = requests.post(
            "https://threatfox-api.abuse.ch/api/v1/",
            json={"query": "recent", "limit": MAX_ITEMS_PER_SOURCE},
            headers={**HEADERS, "Auth-Key": THREATFOX_API_KEY}, timeout=15
        )
        resp.raise_for_status()
        data = resp.json()
        for entry in data.get("data", [])[:MAX_ITEMS_PER_SOURCE]:
            ioc = entry.get("ioc", "")
            ioc_type = entry.get("ioc_type", "")
            malware = entry.get("malware", "")
            threat = entry.get("threat_type", "")
            first_seen = entry.get("first_seen", "")
            reference = entry.get("reference", "")
            malware_printable = entry.get("malware_printable", "")
            desc = f"IOC: {ioc} | Type: {malware_printable or malware} | Threat: {threat}"
            iocs = _threatfox_ioc(ioc, ioc_type)
            items.append({
                "title": f"ThreatFox: {ioc[:60]} ({malware_printable or malware})",
                "description": desc,
                "url": reference or f"https://threatfox.abuse.ch/browse/{ioc}/",
                "cve_id": None, "source": "ThreatFox",
                "category": "incident", "severity": "high",
                "cvss_score": None, "published": parse_date(first_seen),
                "iocs": iocs,
            })
    except Exception as e:
        log.warning(f"ThreatFox failed: {e}")
    log.info(f"  Got {len(items)} IOCs from ThreatFox")
    return items

# ── Generic RSS source fetcher ────────────────────────────────────────────────

_RSS_SOURCE_CONFIG: list[dict] = [
    {"name": "MSRC",          "url": "https://api.msrc.microsoft.com/update-guide/rss",                                   "severity": "high"},
    {"name": "Gentoo",        "url": "https://security.gentoo.org/glsa/feed.rss",                                         "severity": "medium"},
    {"name": "CentOS Stream", "url": "https://blog.centos.org/feed/",                                                     "severity": "medium"},
    {"name": "VMware",        "url": "https://www.broadcom.com/support/security/advisories/json",                         "severity": "high"},
]

def _fetch_rss_source(name: str, url: str, default_severity: str, extra_headers: dict | None = None) -> list[dict]:
    """Generic RSS feed parser. ``extra_headers`` override defaults for
    sources that need a different User-Agent (e.g. to bypass 403)."""
    hdrs = {**HEADERS, **(extra_headers or {})}
    try:
        resp = requests.get(url, headers=hdrs, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        feed = feedparser.parse(resp.text)
        items = []
        for entry in feed.entries[:MAX_ITEMS_PER_SOURCE]:
            title = entry.get("title", f"{name} Advisory")
            link = entry.get("link", "")
            desc = clean_html(entry.get("summary", ""))[:400]
            pub = parse_date(entry.get("published_parsed"))
            items.append({
                "title": title, "description": desc, "url": link,
                "cve_id": extract_cve_id(title + " " + desc),
                "source": name, "category": "advisory",
                "severity": infer_severity(title, default_severity),
                "cvss_score": None, "published": pub,
            })
        return items
    except Exception as e:
        log.warning(f"{name} failed: {e}")
        return []

# ── MSRC Fetcher (RSS) ───────────────────────────────────────────────────────

def fetch_msrc() -> list[dict]:
    return _fetch_rss_source("MSRC", "https://api.msrc.microsoft.com/update-guide/rss", "high")

# ── Fedora Bodhi Fetcher ────────────────────────────────────────────────────

def fetch_fedora() -> list[dict]:
    log.info("Fetching Fedora updates...")
    items = []
    try:
        data = make_request("https://bodhi.fedoraproject.org/updates/?limit=10&status=stable&type=security")
        if data:
            for update in data.get("updates", [])[:MAX_ITEMS_PER_SOURCE]:
                update_id = update.get("updateid") or update.get("alias") or ""
                title = update.get("title", update_id or "Fedora Update")
                # title is space-separated build names; show first build + ID
                first_build = title.split(" ")[0] if " " in title else title
                desc = update.get("notes", "")[:400]
                pub = parse_date(update.get("date_submitted", ""))
                items.append({
                    "title": f"Fedora: {first_build[:80]} ({update_id})",
                    "description": clean_html(desc) or "Fedora security update",
                    "url": update.get("url") or f"https://bodhi.fedoraproject.org/updates/{update_id}",
                    "cve_id": extract_cve_id(title + " " + desc), "source": "Fedora",
                    "category": "advisory", "severity": infer_severity(title, "medium"),
                    "cvss_score": None, "published": pub,
                })
    except Exception as e:
        log.warning(f"Fedora Bodhi failed: {e}")

    # Fallback: Bodhi is behind Anubis PoW and may block us at any time.
    # The HyperKitty package-announce list still ships plain RSS.
    if not items:
        log.info("  Bodhi returned nothing — falling back to package-announce RSS")
        fallback = _fetch_rss_source(
            "Fedora",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/feed/",
            "medium",
        )
        # Prefer security-looking entries; take the rest only if needed.
        sec = [i for i in fallback if "security" in (i["title"] + i["description"]).lower()
               or i.get("cve_id")]
        items = (sec + [i for i in fallback if i not in sec])[:MAX_ITEMS_PER_SOURCE]

    log.info(f"  Got {len(items)} from Fedora")
    return items

# ── Gentoo GLSA Fetcher (RSS) ──────────────────────────────────────────────

def fetch_gentoo() -> list[dict]:
    return _fetch_rss_source("Gentoo", "https://security.gentoo.org/glsa/feed.rss", "medium")

# ── Arch Linux Security Fetcher ─────────────────────────────────────────────

def fetch_archlinux() -> list[dict]:
    log.info("Fetching Arch Linux issues...")
    items = []
    try:
        data = make_request("https://security.archlinux.org/issues.json")
        if data:
            for issue in data[:MAX_ITEMS_PER_SOURCE]:
                title = issue.get("title", issue.get("id", "Arch Issue"))
                cve = issue.get("cve", [])
                cve_id = cve[0] if cve else None
                pub = parse_date(issue.get("created_at", ""))
                items.append({
                    "title": f"Arch Linux: {title[:120]}",
                    "description": f"Type: {issue.get('issue_type','')} | Severity: {issue.get('severity','')} | Package: {issue.get('package','')}",
                    "url": f"https://security.archlinux.org/{issue.get('id','')}",
                    "cve_id": valid_cve_id(cve_id), "source": "Arch Linux",
                    "category": "advisory", "severity": infer_severity(title, "medium"),
                    "cvss_score": None, "published": pub,
                })
    except Exception as e:
        log.warning(f"Arch Linux failed: {e}")
    log.info(f"  Got {len(items)} from Arch Linux")
    return items

# ── Amazon Linux Fetcher ───────────────────────────────────────────────────

def fetch_amazon_linux() -> list[dict]:
    log.info("Fetching Amazon Linux advisories...")
    items = []
    try:
        for feed_url in ["https://alas.aws.amazon.com/alas.rss",
                         "https://alas.aws.amazon.com/AL2/alas.rss",
                         "https://alas.aws.amazon.com/AL2023/alas.rss"]:
            try:
                resp = requests.get(feed_url, headers=HEADERS, timeout=REQUEST_TIMEOUT)
                resp.raise_for_status()
                feed = feedparser.parse(resp.text)
                for entry in feed.entries[:MAX_ITEMS_PER_SOURCE // 2]:
                    title = entry.get("title", "Amazon Linux Advisory")
                    link = entry.get("link", "")
                    desc = clean_html(entry.get("summary", ""))[:400]
                    pub = parse_date(entry.get("published_parsed"))
                    items.append({
                        "title": title, "description": desc, "url": link,
                        "cve_id": extract_cve_id(title + " " + desc), "source": "Amazon Linux",
                        "category": "advisory", "severity": infer_severity(title, "medium"),
                        "cvss_score": None, "published": pub,
                    })
            except Exception:
                continue  # try next Amazon Linux feed version
    except Exception as e:
        log.warning(f"Amazon Linux failed: {e}")
    log.info(f"  Got {len(items)} from Amazon Linux")
    return items

# ── CentOS Announce Fetcher ────────────────────────────────────────────────

def fetch_centos() -> list[dict]:
    return _fetch_rss_source("CentOS Stream", "https://blog.centos.org/feed/", "medium")

# ── VMware / Broadcom Security Fetcher ────────────────────────────────────

def fetch_vmware() -> list[dict]:
    log.info("Fetching Broadcom (VMware) security advisories...")
    items = []
    try:
        resp = requests.post(
            "https://support.broadcom.com/web/ecx/security-advisory/-/securityadvisory/getSecurityAdvisoryList",
            json={"pageNumber": 0, "pageSize": MAX_ITEMS_PER_SOURCE, "searchVal": "",
                  "segment": "VC", "sortInfo": {"column": "", "order": ""}},
            headers={**HEADERS, "accept": "application/json", "content-type": "application/json"},
            timeout=REQUEST_TIMEOUT
        )
        resp.raise_for_status()
        data = resp.json()
        for adv in (data.get("data", {}).get("list", []) if isinstance(data, dict) else data)[:MAX_ITEMS_PER_SOURCE]:
            title = adv.get("title", adv.get("name", "VMware Advisory"))
            desc = adv.get("description", adv.get("synopsis", ""))[:400]
            cve_id = extract_cve_id(title + " " + desc)
            pub = parse_date(adv.get("publishedDate", adv.get("releaseDate", "")))
            items.append({
                "title": f"VMware: {title[:150]}",
                "description": desc,
                "url": adv.get("url", adv.get("link", "https://support.broadcom.com/web/ecx/security-advisory?segment=VC")),
                "cve_id": valid_cve_id(cve_id), "source": "VMware",
                "category": "advisory", "severity": infer_severity(title, "high"),
                "cvss_score": None, "published": pub,
            })
    except Exception as e:
        log.warning(f"VMware failed: {e}")
    log.info(f"  Got {len(items)} from VMware")
    return items

# ── Mitre CWE Fetcher ─────────────────────────────────────────────────────

def fetch_mitre_cwe() -> list[dict]:
    log.info("Fetching Mitre CWE data...")
    items = []
    try:
        data = make_request("https://cwe-api.mitre.org/api/v1/cwe/cwe?limit=10&offset=0")
        if data:
            for weakness in data.get("weaknesses", [])[:MAX_ITEMS_PER_SOURCE]:
                cwe_id = weakness.get("id", "")
                name = weakness.get("name", "")
                desc = weakness.get("description", "")[:400]
                items.append({
                    "title": f"{cwe_id}: {name}",
                    "description": desc,
                    "url": f"https://cwe.mitre.org/data/definitions/{cwe_id.replace('CWE-','')}.html",
                    "cve_id": None, "source": "Mitre CWE",
                    "category": "advisory", "severity": "medium",
                    "cvss_score": None, "published": now_utc(),
                })
    except Exception as e:
        log.warning(f"Mitre CWE failed: {e}")
    log.info(f"  Got {len(items)} from Mitre CWE")
    return items

# ── GitHub Security Advisories (GHSA) Fetcher ────────────────────────────────

def fetch_ghsa() -> list[dict]:
    """GitHub's global advisory database — best-in-class OSS vuln coverage.
    Keyless (60 req/h) or authenticated via GITHUB_TOKEN (5000 req/h)."""
    log.info("Fetching GitHub Security Advisories...")
    items = []
    headers = {**HEADERS, "Accept": "application/vnd.github+json"}
    gh_token = os.environ.get("GITHUB_TOKEN", "")
    if gh_token:
        headers["Authorization"] = f"Bearer {gh_token}"
    try:
        resp = requests.get(
            "https://api.github.com/advisories",
            params={"per_page": MAX_ITEMS_PER_SOURCE, "sort": "published", "direction": "desc"},
            headers=headers, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        for adv in resp.json()[:MAX_ITEMS_PER_SOURCE]:
            summary = adv.get("summary", "GitHub Advisory")
            desc = clean_html(adv.get("description", ""))[:400]
            sev = (adv.get("severity") or "medium").lower()
            if sev == "moderate":
                sev = "medium"
            cvss = (adv.get("cvss") or {}).get("score")
            # Affected packages → stack-profile matching signal.
            packages = []
            for v in adv.get("vulnerabilities", []) or []:
                pkg = (v.get("package") or {})
                if pkg.get("name"):
                    packages.append(f"{pkg.get('ecosystem', '')}/{pkg['name']}".strip("/"))
            items.append({
                "title": f"GHSA: {summary[:150]}",
                "description": desc or summary,
                "url": adv.get("html_url", ""),
                "cve_id": valid_cve_id(adv.get("cve_id")),
                "source": "GitHub Advisories", "category": "cve",
                "severity": sev if sev in ("critical", "high", "medium", "low") else "medium",
                "cvss_score": cvss,
                "published": parse_date(adv.get("published_at", "")),
                "affected_products": packages[:8],
            })
    except Exception as e:
        log.warning(f"GHSA failed: {e}")
    log.info(f"  Got {len(items)} from GitHub Advisories")
    return items

# ── PoC-in-GitHub Fetcher ─────────────────────────────────────────────────────
# nomi-sec/PoC-in-GitHub tracks public exploit PoCs. The motikan2010 API serves
# it as JSON. Used two ways: (1) recent PoC drops as feed items, (2) a CVE→PoC
# map that feeds the exploitability score (has_poc flag).

def _fetch_recent_pocs() -> list[dict]:
    cached = _cached_fetch("pocs.json", 6, _fetch_pocs_raw)
    if not cached:
        return []
    try:
        return json.loads(cached)
    except Exception:
        return []

def _fetch_pocs_raw() -> tuple[str | None, str | None]:
    try:
        resp = requests.get(
            "https://poc-in-github.motikan2010.net/api/v1/",
            params={"sort": "created_at", "limit": 100},
            headers=HEADERS, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        return json.dumps(resp.json().get("pocs", [])), None
    except Exception as e:
        return None, str(e)

def build_poc_map() -> dict[str, str]:
    """CVE ID → PoC repo URL for recently-published public exploits."""
    poc_map = {}
    for poc in _fetch_recent_pocs():
        cve = (poc.get("cve_id") or "").upper()
        if cve.startswith("CVE-") and cve not in poc_map:
            poc_map[cve] = poc.get("html_url", "")
    return poc_map

def fetch_poc_github() -> list[dict]:
    log.info("Fetching PoC-in-GitHub recent exploits...")
    items = []
    for poc in _fetch_recent_pocs()[:MAX_ITEMS_PER_SOURCE]:
        cve = (poc.get("cve_id") or "").upper()
        name = poc.get("name", cve or "PoC")
        desc = (poc.get("description") or poc.get("vuln_description") or "")[:400]
        stars = poc.get("stargazers_count", "0")
        items.append({
            "title": f"PoC released: {cve or name}",
            "description": desc or f"Public proof-of-concept exploit published on GitHub ({stars}★).",
            "url": poc.get("html_url", ""),
            "cve_id": valid_cve_id(cve),
            "source": "PoC-in-GitHub", "category": "cve", "severity": "high",
            "cvss_score": None,
            "published": parse_date((poc.get("created_at") or "").replace(" ", "T")),
            "iocs": {},
            "has_poc": True,
        })
    log.info(f"  Got {len(items)} from PoC-in-GitHub")
    return items

# ── Zero Day Initiative (ZDI) Fetcher ─────────────────────────────────────────

def fetch_zdi() -> list[dict]:
    """ZDI advisories — often ahead of vendor announcements. Two feeds:
    published advisories and upcoming (unpatched, high-signal)."""
    items = []
    for feed_name, url in [("published", "https://www.zerodayinitiative.com/rss/published/"),
                           ("upcoming",  "https://www.zerodayinitiative.com/rss/upcoming/")]:
        got = _fetch_rss_source("ZDI", url, "high")
        for item in got[:MAX_ITEMS_PER_SOURCE // 2]:
            if feed_name == "upcoming":
                item["title"] = f"[0-day queue] {item['title']}"
            item["category"] = "cve"
            items.append(item)
    log.info(f"  Got {len(items)} from ZDI")
    return items

# ── Ransomware.live Fetcher ───────────────────────────────────────────────────

def fetch_ransomware_live() -> list[dict]:
    log.info("Fetching Ransomware.live recent victims...")
    items = []
    try:
        resp = requests.get("https://api.ransomware.live/v2/recentvictims",
                            headers=HEADERS, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        for victim in resp.json()[:MAX_ITEMS_PER_SOURCE]:
            group = victim.get("group_name", victim.get("group", "unknown group"))
            name = victim.get("victim", victim.get("post_title", "Unknown victim"))
            country = victim.get("country", "")
            activity = victim.get("activity", "")
            desc_parts = [f"Ransomware group '{group}' claimed victim: {name}."]
            if country:
                desc_parts.append(f"Country: {country}.")
            if activity and activity != "Not Found":
                desc_parts.append(f"Sector: {activity}.")
            when = victim.get("attackdate", victim.get("discovered", ""))
            items.append({
                "title": f"Ransomware: {group} claims {name[:80]}",
                "description": " ".join(desc_parts),
                "url": victim.get("url") or f"https://www.ransomware.live/group/{group}",
                "cve_id": None, "source": "Ransomware.live",
                "category": "incident", "severity": "high",
                "cvss_score": None, "published": parse_date(when),
                "iocs": {},
                "threat_actors_hint": [group] if group else [],
                "sector_hint": activity if activity and activity != "Not Found" else None,
            })
    except Exception as e:
        log.warning(f"Ransomware.live failed: {e}")
    log.info(f"  Got {len(items)} from Ransomware.live")
    return items

# ── Cached external data ──────────────────────────────────────────────────────
# EPSS scores and CISA KEV change at most daily, so they are read through the
# shared on-disk cache rather than re-fetched every run. _cache_path,
# _safe_cache_name and _cached_fetch are imported from fetchlib at the top of
# this module; the aliases keep every existing call site (and the security
# regression tests that pin the path-traversal guard) unchanged.

# ── EPSS Scoring (bulk daily CSV) ─────────────────────────────────────────────
# The previous implementation cached the API response under a single filename
# with a 24h TTL, but the payload was scored for whichever CVE list happened to
# populate it. For the next 23 hourly runs every newly-discovered CVE got a
# cache HIT on data that did not contain it, and silently received no EPSS
# score — 14 of 69 CVEs were unscored in the committed output.
#
# FIRST publishes the entire scored corpus daily as gzipped CSV. Download it
# once per day and look everything up locally: correct, and one request instead
# of one-per-run against a free API.

_EPSS_BULK_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
_EPSS_LEGACY_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"


def _fetch_epss_bulk_raw() -> tuple[str | None, str | None]:
    """Download and decompress the full EPSS corpus into `cve,score` lines."""
    import gzip
    for url in (_EPSS_BULK_URL, _EPSS_LEGACY_URL):
        try:
            resp = _SESSION.get(url, timeout=REQUEST_TIMEOUT)
            resp.raise_for_status()
            text = gzip.decompress(resp.content).decode("utf-8", "replace")
            out = []
            for line in text.splitlines():
                if not line or line.startswith("#") or line.startswith("cve,"):
                    continue
                parts = line.split(",")
                if len(parts) >= 2:
                    out.append(f"{parts[0].strip().upper()},{parts[1].strip()}")
            if out:
                return "\n".join(out), None
        except Exception as e:
            last = str(e)
            continue
    return None, locals().get("last", "all EPSS endpoints failed")


def _fetch_epss_api(cve_ids: list[str]) -> dict[str, float]:
    """Per-CVE API fallback, chunked to keep the query string sane."""
    scores: dict[str, float] = {}
    for i in range(0, len(cve_ids), 100):
        chunk = cve_ids[i:i + 100]
        try:
            resp = _SESSION.get("https://api.first.org/data/v1/epss",
                                params={"cve": ",".join(chunk)}, timeout=REQUEST_TIMEOUT)
            resp.raise_for_status()
            for entry in resp.json().get("data", []):
                cve, epss = entry.get("cve", ""), entry.get("epss")
                if cve and epss is not None:
                    scores[cve.upper()] = float(epss)
        except Exception as e:
            log.warning(f"  EPSS API chunk failed: {e}")
    return scores


def fetch_epss_scores(cve_ids: list[str]) -> dict[str, float]:
    if not cve_ids:
        return {}
    wanted = {c.upper() for c in cve_ids}
    log.info(f"Resolving EPSS scores for {len(wanted)} CVEs...")

    if CONFIG.enable_epss_bulk:
        cached = _cached_fetch("epss_bulk.csv", 24, _fetch_epss_bulk_raw)
        if cached:
            scores = {}
            for line in cached.splitlines():
                cve, _, val = line.partition(",")
                if cve in wanted:
                    try:
                        scores[cve] = float(val)
                    except ValueError:
                        continue
            log.info(f"  Matched {len(scores)}/{len(wanted)} CVEs from the bulk corpus")
            if scores:
                return scores

    log.info("  Falling back to the per-CVE EPSS API")
    return _fetch_epss_api(sorted(wanted))


# ── CISA KEV (+ optional VulnCheck KEV superset) ──────────────────────────────

def fetch_cisa_kev() -> set[str]:
    """CVE ids in CISA KEV, plus the VulnCheck superset when a key is set.

    The catalogue itself (with dateAdded, due date and the ransomware flag)
    lives in kev_catalog.load_kev(); the dates are what the backtest, the
    exploitation-lag timeline and the source-reliability scoring all read.
    """
    log.info("Fetching CISA KEV catalog...")
    kev = set(load_kev_catalog())
    if kev:
        log.info(f"  {len(kev)} CVEs in CISA KEV")

    extra = fetch_vulncheck_kev()
    if extra:
        new = extra - kev
        log.info(f"  VulnCheck KEV adds {len(new)} CVEs CISA has not listed")
        kev |= extra
    return kev


# ── VulnCheck KEV ─────────────────────────────────────────────────────────────
# A superset of CISA KEV that typically lists exploited vulnerabilities earlier.
# Requires a free API key. NEVER hardcode it — set VULNCHECK_API_KEY as a
# GitHub Actions secret (Settings -> Secrets and variables -> Actions) or in a
# local .env file, which .gitignore already excludes.

def _fetch_vulncheck_kev_raw() -> tuple[str | None, str | None]:
    try:
        cves, page = [], 1
        while page <= 20:
            resp = _SESSION.get(
                "https://api.vulncheck.com/v3/index/vulncheck-kev",
                headers={"Authorization": f"Bearer {VULNCHECK_API_KEY}"},
                params={"limit": 500, "page": page}, timeout=REQUEST_TIMEOUT)
            if resp.status_code in (401, 403):
                return None, f"VulnCheck auth rejected (HTTP {resp.status_code}) — check VULNCHECK_API_KEY"
            resp.raise_for_status()
            payload = resp.json()
            rows = payload.get("data", []) or []
            if not rows:
                break
            for row in rows:
                for cve in (row.get("cve") or []):
                    if cve:
                        cves.append(str(cve).upper())
            meta = payload.get("_meta", {}) or {}
            if not meta.get("next_page"):
                break
            page += 1
        return (json.dumps(sorted(set(cves))), None) if cves else (None, "empty response")
    except Exception as e:
        return None, str(e)


def fetch_vulncheck_kev() -> set[str]:
    if not VULNCHECK_API_KEY:
        log.info("VULNCHECK_API_KEY not set — skipping VulnCheck KEV")
        return set()
    log.info("Fetching VulnCheck KEV...")
    cached = _cached_fetch("vulncheck_kev.json", 12, _fetch_vulncheck_kev_raw)
    if not cached:
        return set()
    try:
        return set(json.loads(cached))
    except Exception as e:
        log.warning(f"VulnCheck KEV parse failed: {e}")
        return set()


# ── CISA Vulnrichment (SSVC decision points) ──────────────────────────────────
# Free, no key. Turns a score into a DECISION: Exploitation (none/poc/active),
# Automatable (can this be exploited at scale, unattended), and Technical
# Impact (partial/total). This is the enrichment that makes the priority score
# defensible rather than just "CVSS with extra steps".
#
# Layout: <year>/<N>xxx/CVE-<id>.json  e.g. 2026/12xxx/CVE-2026-12345.json

_VULNRICHMENT_RAW = ("https://raw.githubusercontent.com/cisagov/vulnrichment/develop/"
                     "{year}/{bucket}xxx/{cve}.json")


def _vulnrichment_url(cve_id: str) -> str | None:
    m = re.match(r"CVE-(\d{4})-(\d{4,7})$", cve_id.upper())
    if not m:
        return None
    year, num = m.group(1), m.group(2)
    return _VULNRICHMENT_RAW.format(year=year, bucket=num[:-3] or "0", cve=cve_id.upper())


def _parse_ssvc(record: dict) -> dict:
    """Pull SSVC decision points and any ADP-supplied CVSS/CWE out of a record."""
    out: dict = {}
    for container in (record.get("containers", {}) or {}).get("adp", []) or []:
        for metric in container.get("metrics", []) or []:
            ssvc = metric.get("other", {}).get("content", {}) if metric.get("other") else {}
            for option in ssvc.get("options", []) or []:
                for key, value in option.items():
                    k = key.strip().lower()
                    if k in ("exploitation", "automatable", "technical impact"):
                        out[k.replace(" ", "_")] = str(value).strip().lower()
            for version in ("cvssV4_0", "cvssV3_1", "cvssV3_0"):
                cvss = metric.get(version)
                if cvss and cvss.get("baseScore") is not None and "cvss" not in out:
                    try:
                        out["cvss"] = float(cvss["baseScore"])
                    except (TypeError, ValueError):
                        pass
        for problem in container.get("problemTypes", []) or []:
            for desc in problem.get("descriptions", []) or []:
                if desc.get("cweId") and "cwe" not in out:
                    out["cwe"] = desc["cweId"]
                    out["cwe_name"] = desc.get("description", "")[:120]
    return out


def fetch_vulnrichment(cve_ids: list[str]) -> dict[str, dict]:
    """Fetch SSVC enrichment for the CVEs in this run's feed, in parallel."""
    if not CONFIG.enable_vulnrichment or not cve_ids:
        return {}
    unique = sorted({c.upper() for c in cve_ids})
    log.info(f"Fetching CISA Vulnrichment SSVC for {len(unique)} CVEs...")

    results: dict[str, dict] = {}

    def _one(cve_id: str) -> None:
        # Vulnrichment records are effectively immutable once published.
        cached = _cached_fetch(f"ssvc_{cve_id}.json", 24 * 14,
                               lambda: _fetch_vulnrichment_raw(cve_id))
        if not cached:
            return
        try:
            parsed = _parse_ssvc(json.loads(cached))
        except Exception:
            return
        if parsed:
            results[cve_id] = parsed

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(_one, unique))

    log.info(f"  SSVC data for {len(results)} CVEs "
             f"({sum(1 for v in results.values() if v.get('exploitation') == 'active')} actively exploited)")
    return results


def _fetch_vulnrichment_raw(cve_id: str) -> tuple[str | None, str | None]:
    url = _vulnrichment_url(cve_id)
    if not url:
        return None, "unparseable CVE id"
    try:
        resp = _SESSION.get(url, timeout=REQUEST_TIMEOUT)
        if resp.status_code == 404:
            # Not every CVE is enriched. Cache the miss so we don't re-request
            # it every hour for the next two weeks.
            return "{}", None
        resp.raise_for_status()
        return resp.text, None
    except Exception as e:
        return None, str(e)


# ── Threat Actor Detection ────────────────────────────────────────────────────

THREAT_ACTORS = {
    "Lazarus": ["lazarus", "hidden cobra", "zinc", "labyrinth chollima"],
    "APT29": ["apt29", "cozy bear", "cozy duke", "yttrium"],
    "APT28": ["apt28", "fancy bear", "sednit", "pawn storm", "strontium"],
    "APT41": ["apt41", "barium", "winnti", "wicked panda"],
    "APT1": ["apt1", "comment crew"],
    "APT32": ["apt32", "oceanlotus", "fin6", "gold dragon"],
    "APT33": ["apt33", "elfin", "shamoon"],
    "APT34": ["apt34", "oilrig"],
    "FIN7": ["fin7", "carbanak"],
    "DarkSide": ["darkside", "blackmatter"],
    "REvil": ["revil", "sodinokibi"],
    "LockBit": ["lockbit"],
    "BlackCat": ["blackcat", "alphv"],
    "Clop": ["clop", "cl0p"],
    "Conti": ["conti", "wizard spider"],
    "TrickBot": ["trickbot"],
    "Emotet": ["emotet", "heodo"],
    "Sandworm": ["sandworm", "voodoo bear"],
    "Nobelium": ["nobelium", "solarwinds"],
    "FunkSec": ["funksec"],
    "MirrorFace": ["mirrorface"],
    "Salt Typhoon": ["salt typhoon"],
    # ── Expanded set ────────────────────────────────────────────────────────
    # The geopolitical view is only as good as actor detection: with ~22 groups
    # a typical run surfaced a single attributed origin. These are the groups
    # that actually recur in the feeds this pipeline reads.
    "Volt Typhoon": ["volt typhoon", "vanguard panda", "bronze silhouette"],
    "Flax Typhoon": ["flax typhoon", "ethereal panda"],
    "Silk Typhoon": ["silk typhoon", "hafnium"],
    "Midnight Blizzard": ["midnight blizzard"],
    "Star Blizzard": ["star blizzard", "callisto", "seaborgium"],
    "Secret Blizzard": ["secret blizzard", "turla", "venomous bear", "snake malware"],
    "Forest Blizzard": ["forest blizzard"],
    "Kimsuky": ["kimsuky", "velvet chollima", "black banshee", "thallium"],
    "Andariel": ["andariel", "onyx sleet", "silent chollima"],
    "BlueNoroff": ["bluenoroff", "sapphire sleet", "stardust chollima"],
    "Charming Kitten": ["charming kitten", "apt35", "phosphorus", "mint sandstorm"],
    "MuddyWater": ["muddywater", "mango sandstorm", "static kitten"],
    "Scattered Spider": ["scattered spider", "octo tempest", "unc3944", "muddled libra"],
    "APT10": ["apt10", "stone panda", "menupass", "cicada"],
    "APT27": ["apt27", "emissary panda", "lucky mouse", "bronze union"],
    "APT37": ["apt37", "reaper", "scarcruft", "ricochet chollima"],
    "APT38": ["apt38", "bluenoroff group"],
    "APT39": ["apt39", "chafer", "remix kitten"],
    "APT40": ["apt40", "leviathan", "kryptonite panda", "gingham typhoon"],
    "APT43": ["apt43", "kimsuky group", "thallium group"],
    "Mustang Panda": ["mustang panda", "twill typhoon", "bronze president"],
    "Gamaredon": ["gamaredon", "primitive bear", "armageddon", "shuckworm"],
    "TA505": ["ta505", "graceful spider", "evil corp"],
    "Wizard Spider": ["ryuk"],
    "Black Basta": ["black basta"],
    "Play": ["play ransomware", "playcrypt"],
    "Akira": ["akira ransomware"],
    "Rhysida": ["rhysida"],
    "Medusa": ["medusa ransomware", "medusalocker"],
    "BianLian": ["bianlian"],
    "Royal": ["royal ransomware"],
    "Hive": ["hive ransomware"],
    "Vice Society": ["vice society"],
    "Qilin": ["qilin", "agenda ransomware"],
    "INC Ransom": ["inc ransom", "inc ransomware"],
    "Cl0p": ["cl0p ransomware"],
    "8Base": ["8base"],
    "Everest": ["everest ransomware"],
    "SafePay": ["safepay"],
    "RansomHub": ["ransomhub"],
    "Lapsus$": ["lapsus", "lapsus$"],
    "Anonymous Sudan": ["anonymous sudan"],
    "Killnet": ["killnet"],
    "NoName057": ["noname057", "noname057(16)"],
    "Sidewinder": ["sidewinder", "rattlesnake"],
    "Transparent Tribe": ["transparent tribe", "apt36", "mythic leopard"],
    "Patchwork": ["patchwork", "dropping elephant"],
    "Winnti Group": ["winnti group"],
    "Storm-0558": ["storm-0558"],
    "UNC5537": ["unc5537"],
}

# Pre-compile a word-boundary regex per alias so "apt" no longer matches
# "adapter"/"adapt" and "clop" no longer matches "develop". Aliases with their
# own separators (spaces, digits, "cl0p") still match as whole tokens because
# \b sits at the alnum/non-alnum transition on each end.
_ACTOR_PATTERNS = {
    actor: [re.compile(r"(?<![0-9A-Za-z])" + re.escape(kw) + r"(?![0-9A-Za-z])", re.IGNORECASE)
            for kw in keywords]
    for actor, keywords in THREAT_ACTORS.items()
}

def detect_threat_actors(text: str) -> list[str]:
    if not text:
        return []
    actors = []
    for actor, patterns in _ACTOR_PATTERNS.items():
        if any(p.search(text) for p in patterns):
            actors.append(actor)
    # Preserve THREAT_ACTORS declaration order, no dupes.
    return actors

# ── Intel Inference Helpers ───────────────────────────────────────────────────

def cvss_to_severity(score) -> str:
    if score is None: return "medium"
    if score >= 9.0: return "critical"
    if score >= 7.0: return "high"
    if score >= 4.0: return "medium"
    return "low"

# ── CVE Prioritization Score ──────────────────────────────────────────────────

# SSVC (CISA Vulnrichment) contributions to the blended score.
_SSVC_EXPLOITATION_WEIGHT = {"active": 1.0, "poc": 0.45, "none": 0.0}

# Score -> what a defender should actually do. This is the point of the whole
# pipeline: a decision, not a number.
_ACTION_BY_LABEL = {
    "urgent":   ("Patch now",        "Confirmed exploitation or trivially weaponisable — act within 24h"),
    "elevated": ("Patch this week",  "Exploitation is plausible and impact is high"),
    "moderate": ("Next patch cycle", "Worth scheduling, not worth paging anyone"),
    "low":      ("Monitor",          "Track it; no action required today"),
}


def compute_priority(item: dict) -> dict | None:
    """
    Blend CVSS (impact), EPSS (probability), CISA KEV (confirmed exploitation),
    public PoC availability and SSVC decision points into one 0-100 "act on
    this first" score, plus a plain-language action.

        score = cvss_weight * (cvss/10)
              + epss_weight * epss
              + ssvc_active_bonus * exploitation_weight
              + ssvc_auto_bonus     (if Automatable)
              + ssvc_total_bonus    (if Technical Impact == total)
              + poc_bonus / kev_bonus

    KEV and SSVC-active items are floored at 90 — something confirmed to be
    exploited in the wild should sort to the top regardless of its CVSS.
    """
    cvss = item.get("cvss_score")
    epss = item.get("epss_score")
    kev  = bool(item.get("cisa_kev"))
    poc  = bool(item.get("has_poc"))
    exploitation = (item.get("ssvc_exploitation") or "").lower()
    automatable  = (item.get("ssvc_automatable") or "").lower() == "yes"
    total_impact = (item.get("ssvc_technical_impact") or "").lower() == "total"

    if cvss is None and epss is None and not kev and not poc and not exploitation:
        return None

    try:
        cvss_val = max(0.0, min(10.0, float(cvss))) if cvss is not None else 0.0
    except (TypeError, ValueError):
        cvss_val = 0.0
    try:
        epss_val = max(0.0, min(1.0, float(epss))) if epss is not None else 0.0
    except (TypeError, ValueError):
        epss_val = 0.0

    # Every term is recorded as it is added. The dashboard lets a reader click
    # the score open and see the arithmetic, and reconstructing it in
    # JavaScript from the weights would be a second implementation of this
    # function that could drift from it silently.
    components: list[dict] = []

    def _add(label: str, points: float, detail: str = "") -> None:
        if points:
            components.append({"label": label, "points": round(points, 1),
                               "detail": detail})

    cvss_points = CONFIG.priority_cvss_weight * (cvss_val / 10.0)
    epss_points = CONFIG.priority_epss_weight * epss_val
    score = cvss_points + epss_points
    if cvss is not None:
        _add("Impact (CVSS)", cvss_points,
             f"{cvss_val:.1f}/10 x {CONFIG.priority_cvss_weight:g} weight")
    if epss is not None:
        _add("Exploit probability (EPSS)", epss_points,
             f"{epss_val * 100:.1f}% x {CONFIG.priority_epss_weight:g} weight")

    if exploitation in _SSVC_EXPLOITATION_WEIGHT:
        bonus = CONFIG.priority_ssvc_active_bonus * _SSVC_EXPLOITATION_WEIGHT[exploitation]
        score += bonus
        _add(f"SSVC exploitation: {exploitation}", bonus,
             f"{CONFIG.priority_ssvc_active_bonus:g} x "
             f"{_SSVC_EXPLOITATION_WEIGHT[exploitation]:g}")
    if automatable:
        score += CONFIG.priority_ssvc_auto_bonus
        _add("SSVC automatable", CONFIG.priority_ssvc_auto_bonus,
             "exploitable at scale, unattended")
    if total_impact:
        score += CONFIG.priority_ssvc_total_bonus
        _add("SSVC total technical impact", CONFIG.priority_ssvc_total_bonus)
    if poc:
        # Bonus only — no floor. Flooring every PoC item at 70 pushed it into
        # "Patch this week" regardless of impact, and PoC-in-GitHub indexes a
        # lot of empty or scaffold repos. It also flattened the ordering: every
        # low-CVSS item with a PoC tied at exactly the same score, so the list
        # stopped ranking. A PoC raises urgency; it does not by itself make a
        # CVSS 3.1 information leak a weekly-patch item.
        score += CONFIG.priority_poc_bonus
        _add("Public PoC on GitHub", CONFIG.priority_poc_bonus,
             "raises urgency; deliberately does not floor the score")
    if kev or exploitation == "active":
        score += CONFIG.priority_kev_bonus
        _add("CISA KEV listing" if kev else "Active exploitation (SSVC)",
             CONFIG.priority_kev_bonus, "confirmed exploitation in the wild")
        if score < 90.0:
            components.append({
                "label": "Confirmed-exploitation floor", "points": round(90.0 - score, 1),
                "detail": "a CVSS 6.5 exploited today outranks a theoretical 9.8",
            })
            score = 90.0

    raw_total = score
    score = round(max(0.0, min(100.0, score)), 1)
    if raw_total > 100.0:
        components.append({"label": "Capped at 100",
                           "points": round(100.0 - raw_total, 1),
                           "detail": f"raw total was {raw_total:.1f}"})

    if score >= 90:   label = "urgent"
    elif score >= 70: label = "elevated"
    elif score >= 40: label = "moderate"
    else:             label = "low"

    reasons = []
    if kev:
        reasons.append("CISA KEV (actively exploited)")
    if exploitation == "active" and not kev:
        reasons.append("SSVC: active exploitation")
    elif exploitation == "poc":
        reasons.append("SSVC: public PoC")
    if automatable:
        reasons.append("SSVC: automatable")
    if total_impact:
        reasons.append("SSVC: total impact")
    if poc:
        reasons.append("Public PoC on GitHub")
    if epss is not None:
        reasons.append(f"EPSS {epss_val * 100:.1f}%")
    if cvss is not None:
        reasons.append(f"CVSS {cvss_val:.1f}")

    action, action_detail = _ACTION_BY_LABEL[label]
    return {"score": score, "label": label, "rationale": " · ".join(reasons),
            "action": action, "action_detail": action_detail,
            "components": components}


# Keyword sets for rule-based classification. Matched as WHOLE TOKENS — the
# original `kw in text` form fired "rce" inside "source"/"force"/"resource",
# which mislabelled 31% of all `critical` items and, because ALERT_SEVERITIES
# defaults to `critical`, sent those false positives straight to Slack.
_SEVERITY_KEYWORDS = [
    ("critical", ["critical", "zero-day", "0-day", "actively exploited", "rce",
                  "remote code execution", "unauthenticated", "wormable",
                  "exploited in the wild", "pre-auth"]),
    ("high",     ["high", "privilege escalation", "authentication bypass",
                  "ransomware", "data breach", "nation-state", "apt",
                  "sandbox escape", "arbitrary code"]),
    ("medium",   ["medium", "xss", "csrf", "injection", "phishing", "malware",
                  "denial of service", "dos", "information disclosure"]),
    ("low",      ["low", "informational", "advisory", "guide"]),
]

_CATEGORY_KEYWORDS = [
    ("cve",      ["cve", "vulnerability", "vulnerabilities", "patch", "exploit",
                  "nvd", "advisory id", "security update"]),
    ("incident", ["breach", "attack", "ransomware", "hack", "hacked", "intrusion",
                  "stolen", "compromised", "leaked", "incident", "victim"]),
    ("advisory", ["advisory", "alert", "directive", "guidance", "warning",
                  "cisa", "recommendation", "patch tuesday", "bulletin"]),
]


def _compile_keyword_matcher(keywords: list[str]) -> re.Pattern:
    """Whole-token alternation. Lookarounds rather than \b so that keywords
    containing digits or spaces ("0-day", "patch tuesday") still match."""
    return re.compile(
        r"(?<![0-9A-Za-z])(?:"
        + "|".join(re.escape(k) for k in sorted(keywords, key=len, reverse=True))
        + r")(?![0-9A-Za-z])",
        re.IGNORECASE,
    )


_SEVERITY_MATCHERS = [(label, _compile_keyword_matcher(kws)) for label, kws in _SEVERITY_KEYWORDS]
_CATEGORY_MATCHERS = [(label, _compile_keyword_matcher(kws)) for label, kws in _CATEGORY_KEYWORDS]


def infer_severity(text: str, default: str = "medium") -> str:
    """Infer severity from text via whole-token keyword matching, most severe first."""
    if not text:
        return default
    for label, pattern in _SEVERITY_MATCHERS:
        if pattern.search(text):
            return label
    return default


def infer_category(text: str, default: str = "news") -> str:
    """Infer category from text via whole-token keyword matching."""
    if not text:
        return default
    for label, pattern in _CATEGORY_MATCHERS:
        if pattern.search(text):
            return label
    return default


def extract_cve_id(text: str) -> str | None:
    match = re.search(r"CVE-\d{4}-\d{4,7}", text, re.IGNORECASE)
    return match.group(0).upper() if match else None


_CVE_EXACT = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)


def valid_cve_id(value) -> str | None:
    """Return the normalised CVE id only if it is EXACTLY well-formed.

    Several fetchers take cve_id straight from an upstream API field. A
    startswith("CVE-") check is not validation: "CVE-../../x" passes it, and
    that value goes on to build a cache filename. Anything not matching the
    full pattern is dropped rather than trusted.
    """
    if not value:
        return None
    text = str(value).strip()
    return text.upper() if _CVE_EXACT.match(text) else None

# ── IOC Extraction Engine ─────────────────────────────────────────────────────
# Previously this ran over EVERY item's prose, so the STIX/CSV exports ended up
# publishing gmail.com, redhat.com, cern.ch, `req.query`, `handlers.ts` and two
# named maintainers' work email addresses as `indicator_types: malicious-activity`.
# Essentially 100% false positives, plus a PII leak in a public repo.
#
# Two changes fix it:
#   1. Only sources that actually publish IOCs are scanned (IOC_SOURCES).
#   2. Everything else must clear a plausibility bar: defanged notation, a real
#      public suffix, and not the article's own host.

IOC_PATTERNS = {
    'sha256': re.compile(r'(?<![a-fA-F0-9])[a-fA-F0-9]{64}(?![a-fA-F0-9])'),
    'sha1':   re.compile(r'(?<![a-fA-F0-9])[a-fA-F0-9]{40}(?![a-fA-F0-9])'),
    'md5':    re.compile(r'(?<![a-fA-F0-9])[a-fA-F0-9]{32}(?![a-fA-F0-9])'),
    'ipv4':   re.compile(r'(?<![0-9.])(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?![0-9.])'),
    'domain': re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24}\b'),
    'url':    re.compile(r'https?://[^\s<>"\'{}|\\^`\[\]]+', re.I),
    'cve':    re.compile(r'CVE-\d{4}-\d{4,7}', re.I),
    'cidr':   re.compile(r'(?<![0-9.])(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}(?![0-9])'),
    'email':  re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'),
}

# Sources whose payloads ARE indicator feeds. Only these get network/file IOC
# extraction; everything else contributes CVE ids only.
IOC_SOURCES = {
    "URLhaus", "ThreatFox", "Feodo Tracker", "Spamhaus", "MalwareBazaar",
    "AbuseIPDB", "PhishTank", "AlienVault OTX",
}

# Never treat these as indicators: infrastructure, source hosts, and the
# vendors whose advisories we ingest.
_DOMAIN_DENYLIST = {
    "github.com", "githubusercontent.com", "gmail.com", "google.com", "twitter.com",
    "x.com", "linkedin.com", "youtube.com", "facebook.com", "microsoft.com",
    "redhat.com", "cern.ch", "cisa.gov", "nist.gov", "mitre.org", "apache.org",
    "debian.org", "ubuntu.com", "fedoraproject.org", "gentoo.org", "archlinux.org",
    "kernel.org", "python.org", "npmjs.com", "docker.com", "amazon.com", "aws.amazon.com",
    "oracle.com", "vmware.com", "broadcom.com", "cloudflare.com", "wordpress.org",
    "sans.edu", "isc.sans.edu", "abuse.ch", "virustotal.com", "first.org",
    "bleepingcomputer.com", "thehackernews.com", "krebsonsecurity.com", "reddit.com",
    "securityweek.com", "darkreading.com", "welivesecurity.com", "talosintelligence.com",
    "paloaltonetworks.com", "unit42.paloaltonetworks.com", "grahamcluley.com",
    "therecord.media", "cybersecuritynews.com", "zerodayinitiative.com", "example.com",
}

# Source-code and filename shapes the domain regex loves: `req.query`,
# `handlers.ts`, `ops.dispatch`, `security.txt`, `countid.substring`.
_CODE_TLD_DENYLIST = {
    "ts", "js", "py", "go", "rs", "rb", "sh", "md", "txt", "json", "yml", "yaml",
    "xml", "html", "css", "c", "h", "cpp", "java", "php", "sql", "log", "cfg",
    "conf", "ini", "toml", "lock", "map", "min", "test", "spec", "config",
    "query", "params", "body", "data", "value", "length", "push", "pop", "get",
    "set", "add", "remove", "dispatch", "dequeue", "substring", "insecure",
    "exe", "dll", "dat", "bin", "tmp", "bak", "old", "new", "local", "internal",
}

_DEFANG_HINT = re.compile(r"\[\.\]|\(\.\)|hxxp|\[at\]|\[:\]", re.IGNORECASE)


def _plausible_domain(value: str, own_host: str = "") -> bool:
    """Reject code identifiers, filenames, infrastructure and the item's own host."""
    v = value.strip().lower().rstrip(".")
    if "." not in v or len(v) < 4 or len(v) > 253:
        return False
    tld = v.rsplit(".", 1)[-1]
    if tld in _CODE_TLD_DENYLIST or not tld.isalpha() or len(tld) < 2:
        return False
    if v in _DOMAIN_DENYLIST:
        return False
    # Registrable-domain check against the denylist ("mail.google.com" -> "google.com").
    parts = v.split(".")
    if len(parts) >= 2 and ".".join(parts[-2:]) in _DOMAIN_DENYLIST:
        return False
    if own_host and (v == own_host or own_host.endswith("." + v) or v.endswith("." + own_host)):
        return False
    return True


def _is_private_ip(value: str) -> bool:
    try:
        parts = [int(p) for p in value.split(".")]
    except ValueError:
        return True
    if len(parts) != 4:
        return True
    a, b = parts[0], parts[1]
    return (a in (0, 10, 127) or (a == 172 and 16 <= b <= 31) or (a == 192 and b == 168)
            or (a == 169 and b == 254) or a >= 224)


def extract_iocs(text: str, source: str = "", own_url: str = "") -> dict[str, list[str]]:
    """Extract indicators from text.

    `source` gates network/file indicators: only feeds that publish IOCs get
    them. Any source may still contribute CVE ids, which are unambiguous.
    """
    if not text:
        return {}

    defanged = bool(_DEFANG_HINT.search(text))
    clean = (text.replace('[.]', '.').replace('(.)', '.')
                 .replace('hxxps', 'https').replace('hxxp', 'http')
                 .replace('[at]', '@').replace('[:]', ':'))

    own_host = ""
    if own_url:
        m = re.match(r'https?://([^/:]+)', own_url.strip().lower())
        if m:
            own_host = m.group(1).removeprefix("www.")

    result: dict[str, list[str]] = {}
    # CVE ids are safe from any source.
    types = ["cve"]
    # Network/file indicators only from IOC feeds, or when the text is defanged
    # (defanging is the author explicitly signalling "this is an indicator").
    if source in IOC_SOURCES or defanged:
        types += ["sha256", "sha1", "md5", "ipv4", "cidr", "url", "domain", "email"]

    for ioc_type in types:
        pattern = IOC_PATTERNS[ioc_type]
        seen: set[str] = set()
        unique: list[str] = []
        for match in pattern.findall(clean):
            value = match.strip().lower().rstrip('.,;)')
            if not value or len(value) <= 2 or value in seen:
                continue
            if ioc_type == 'ipv4' and _is_private_ip(value):
                continue
            if ioc_type == 'domain' and not _plausible_domain(value, own_host):
                continue
            if ioc_type == 'url' and own_host and own_host in value:
                continue
            if ioc_type == 'email':
                # Only from indicator feeds, never scraped from advisory metadata
                # (that is how maintainers' addresses ended up in the STIX bundle).
                if source not in IOC_SOURCES:
                    continue
            if ioc_type == 'cve':
                value = value.upper()
            seen.add(value)
            unique.append(value)
            if len(unique) >= 50:
                break
        if unique:
            result[ioc_type] = unique
    return result


_STOPWORDS = {
    "the", "a", "an", "of", "to", "in", "on", "for", "and", "with", "via",
    "new", "critical", "high", "cve", "vulnerability", "flaw", "bug", "attack",
}

def _normalize_title(title: str) -> str:
    """
    Collapse a title to a comparable fingerprint: lowercase, drop punctuation,
    strip common filler words, sort the remaining tokens. This makes near-dupes
    like "New Critical RCE in Foo" and "Foo RCE Vulnerability (Critical)" hash
    to the same key while keeping genuinely different stories apart.
    """
    t = re.sub(r"[^a-z0-9 ]+", " ", (title or "").lower())
    tokens = [w for w in t.split() if w and w not in _STOPWORDS]
    if not tokens:
        tokens = t.split()
    return " ".join(sorted(set(tokens)))[:120]

def _canonical_url(url: str) -> str:
    """Strip scheme, www, tracking params and trailing slash for URL dedup."""
    if not url:
        return ""
    u = url.strip().lower()
    u = re.sub(r"^https?://", "", u)
    u = re.sub(r"^www\.", "", u)
    u = u.split("?")[0].split("#")[0].rstrip("/")
    return u

# Higher rank wins a dedup collision. Primary vendor/government advisories
# beat aggregators, which beat news rewrites of the same story.
_SOURCE_AUTHORITY = {
    "NVD": 100, "CISA": 95, "MSRC": 90, "GitHub Advisories": 85, "ZDI": 85,
    "VMware": 80, "Fedora": 75, "Gentoo": 75, "Arch Linux": 75,
    "Amazon Linux": 75, "CentOS": 70, "Mitre CWE": 70,
    "PoC-in-GitHub": 65, "Ransomware.live": 60, "AlienVault OTX": 60,
    "ThreatFox": 60, "URLhaus": 60, "Feodo Tracker": 60, "Spamhaus": 60,
}


def _source_rank(source: str) -> int:
    return _SOURCE_AUTHORITY.get(source, 10)


def sort_for_dedup(items: list[dict]) -> list[dict]:
    """Order items so that ``deduplicate()``'s "first occurrence wins" rule
    keeps the RIGHT copy: most authoritative source first, then newest.

    Sorts in place and returns the list. The key is deliberately un-negated —
    ``reverse=True`` already gives descending order, and negating the rank on
    top of that silently inverted the whole thing, so the least authoritative
    copy of a story survived dedup and the NVD/CISA record was discarded.
    """
    items.sort(key=lambda x: (_source_rank(x.get("source", "")),
                              x.get("published", "")), reverse=True)
    return items


def deduplicate(items: list[dict]) -> list[dict]:
    """
    Drop duplicates by (a) same CVE from the same source, (b) identical
    canonical URL, or (c) fuzzy-normalized title. First occurrence wins, so the
    published-desc sort upstream keeps the newest copy.
    """
    seen_titles, seen_urls, seen_cve_src = set(), set(), set()
    unique = []
    for item in items:
        title_key = _normalize_title(item.get("title", ""))
        url_key   = _canonical_url(item.get("url", ""))
        cve       = (item.get("cve_id") or "").upper()
        src       = item.get("source", "")
        cve_src_key = f"{cve}|{src}" if cve else None

        if title_key and title_key in seen_titles:
            continue
        if url_key and url_key in seen_urls:
            continue
        if cve_src_key and cve_src_key in seen_cve_src:
            continue

        if title_key:
            seen_titles.add(title_key)
        if url_key:
            seen_urls.add(url_key)
        if cve_src_key:
            seen_cve_src.add(cve_src_key)
        unique.append(item)
    return unique


def item_key(item: dict) -> str:
    """Stable identity for an item across runs — prefers CVE, then URL, then title."""
    cve = (item.get("cve_id") or "").upper()
    if cve:
        return f"cve:{cve}"
    url = _canonical_url(item.get("url", ""))
    if url:
        return f"url:{url}"
    return f"title:{_normalize_title(item.get('title', ''))}"


def _load_previous_keys() -> set:
    """Keys present in the most recent archive snapshot (excluding today's)."""
    if not ARCHIVE_DIR.exists():
        return set()
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    snapshots = sorted(
        (f for f in ARCHIVE_DIR.glob("*.json") if f.stem != today),
        key=lambda f: f.stem, reverse=True,
    )
    if not snapshots:
        return set()
    try:
        with open(snapshots[0], encoding="utf-8") as f:
            prev = json.load(f)
        return {item_key(i) for i in prev.get("items", [])}
    except Exception as e:
        log.warning(f"Could not read previous archive for diff: {e}")
        return set()


def mark_new_since_last(items: list[dict]) -> int:
    """
    Set ``item["is_new"] = True`` for items whose key was absent from the
    previous archive snapshot. This is a real "new since yesterday" signal,
    independent of the item's own (often stale) published timestamp.
    """
    previous = _load_previous_keys()
    # First ever run (no prior snapshot): don't flood every card with NEW.
    if not previous:
        for item in items:
            item["is_new"] = False
        return 0
    count = 0
    for item in items:
        is_new = item_key(item) not in previous
        item["is_new"] = is_new
        if is_new:
            count += 1
    return count

# ── Main Pipeline ────────────────────────────────────────────────────────────

# ── Source orchestration ──────────────────────────────────────────────────────

# Non-RSS fetchers, run in order. Each entry is (display-name, callable).
API_SOURCES = [
    ("NVD",            fetch_nvd_cves),
    ("Reddit/netsec",  fetch_reddit_netsec),
    ("AlienVault OTX", fetch_otx_pulse),
    ("URLhaus",        fetch_urlhaus),
    ("Spamhaus",       fetch_spamhaus_drop),
    ("Feodo Tracker",  fetch_feodo),
    ("AbuseIPDB",      fetch_abuseipdb),
    ("PhishTank",      fetch_phishtank),
    ("MalwareBazaar",  fetch_malwarebazaar),
    ("ThreatFox",      fetch_threatfox),
    ("SSL Blacklist",  fetch_sslbl),
    ("MSRC",           fetch_msrc),
    ("Fedora",         fetch_fedora),
    ("Gentoo",         fetch_gentoo),
    ("Arch Linux",     fetch_archlinux),
    ("Amazon Linux",   fetch_amazon_linux),
    ("CentOS",         fetch_centos),
    ("Mitre CWE",      fetch_mitre_cwe),
    ("VMware",         fetch_vmware),
    ("GitHub Advisories", fetch_ghsa),
    ("PoC-in-GitHub",  fetch_poc_github),
    ("ZDI",            fetch_zdi),
    ("Ransomware.live", fetch_ransomware_live),
]

if fetch_leak_site_posts:
    API_SOURCES.append(("RansomLook", fetch_leak_site_posts))

def _median_age_days(items: list[dict]) -> float | None:
    """Median age of an item batch, in days. None when nothing parses."""
    now = datetime.now(timezone.utc)
    ages = []
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
        ages.append((now - published).total_seconds() / 86400.0)
    if not ages:
        return None
    ages.sort()
    mid = len(ages) // 2
    return round(ages[mid] if len(ages) % 2 else (ages[mid - 1] + ages[mid]) / 2, 1)


def run_source(name: str, fetcher, health: dict) -> list[dict]:
    """
    Invoke a single fetcher, capturing timing + outcome into ``health`` so a
    silently-dead feed becomes visible in the output instead of just vanishing.
    Never raises — a broken source can't abort the run.

    Health is FRESHNESS-aware, not just count-aware. The previous version set
    `ok` whenever a fetcher returned anything, so Threatpost — shut down in
    2023, still serving its 2022 archive — reported green every single hour.
    A feed whose median item is older than CONFIG.source_stale_days is `stale`.
    """
    started = time.monotonic()
    try:
        items = fetcher() or []
        elapsed = round(time.monotonic() - started, 2)
        median_age = _median_age_days(items)
        if not items:
            status = "empty"
        elif median_age is not None and median_age > CONFIG.source_stale_days:
            status = "stale"
            log.warning(f"Source '{name}' is STALE — median item age {median_age:.0f} days")
        else:
            status = "ok"
        health[name] = {"status": status, "count": len(items), "elapsed_s": elapsed,
                        "median_age_days": median_age, "error": None}
        return items
    except Exception as e:
        elapsed = round(time.monotonic() - started, 2)
        log.error(f"Source '{name}' failed: {e}")
        health[name] = {"status": "error", "count": 0, "elapsed_s": elapsed,
                        "median_age_days": None, "error": str(e)[:200]}
        return []


def main():
    log.info("═" * 60)
    log.info("OPENTHREAT v4.0 — Starting intel pipeline")
    log.info("═" * 60)

    all_items = []
    source_health: dict[str, dict] = {}
    _lock = threading.Lock()
    _load_feed_meta()

    def _collect(name: str, fetcher) -> None:
        items = run_source(name, fetcher, source_health)
        with _lock:
            all_items.extend(items)

    # 1. RSS feeds — each tracked individually by feed name.
    futures = []
    with ThreadPoolExecutor(max_workers=8) as pool:
        for source in RSS_SOURCES:
            fut = pool.submit(_collect, source["name"], lambda s=source: fetch_rss(s))
            futures.append(fut)
        for fut in as_completed(futures):
            pass  # exceptions handled inside run_source / _collect
    log.info(f"RSS phase complete — {len(all_items)} items so far")

    # 2. API / custom fetchers (parallelized).
    futures = []
    with ThreadPoolExecutor(max_workers=8) as pool:
        for name, fetcher in API_SOURCES:
            fut = pool.submit(_collect, name, fetcher)
            futures.append(fut)
        for fut in as_completed(futures):
            pass
    log.info(f"API phase complete — {len(all_items)} items so far")

    # ── Attacker map (independent of items; aggregated server-side) ─────────
    # Fetches the attacker-infrastructure feeds, geolocates every IP against the
    # DB-IP corpus, and collapses ~160k addresses into a per-country/category
    # summary. The IPs never leave this process — only the counts do.
    attack_map = None
    if collect_attacker_infrastructure and CONFIG.enable_attacker_map:
        try:
            geo = GeoIP.load() if GeoIP else None
            attack_map = collect_attacker_infrastructure(geo)
            if attack_map:
                log.info(f"✓ Attacker map: {attack_map['distinct_ips']} IPs across "
                         f"{len(attack_map['countries'])} countries")
        except Exception as e:
            log.error(f"Attacker map generation failed: {e}")

    # ── Dark-web leak-site rollup ──────────────────────────────────────────
    darkweb = None
    if build_darkweb_summary:
        try:
            darkweb = build_darkweb_summary()
            if darkweb:
                log.info(f"✓ Dark web: {darkweb['recent_posts']} recent posts across "
                         f"{darkweb['distinct_groups_active']} groups, "
                         f"{darkweb['tracked_leak_sites']} leak sites tracked")
        except Exception as e:
            log.warning(f"Dark-web summary failed: {e}")

    darkweb_index = None
    darkweb_watch_hits = []
    sector_benchmark = None
    if build_darkweb_index and CONFIG.enable_darkweb_index:
        try:
            darkweb_index = build_darkweb_index()
            if darkweb_index:
                log.info(f"✓ Dark-web index: {darkweb_index['count']} victim listings "
                         f"({darkweb_index['from']} → {darkweb_index['to']})")
                if check_watchlist:
                    darkweb_watch_hits = check_watchlist(darkweb_index)
                    if darkweb_watch_hits:
                        log.warning(f"  {len(darkweb_watch_hits)} watchlist term(s) matched")
                if build_sector_benchmark:
                    sector_benchmark = build_sector_benchmark(darkweb_index)
                    if sector_benchmark:
                        log.info(f"  Sector benchmark: {sector_benchmark['current_total']} "
                                 f"listings this window vs "
                                 f"{sector_benchmark['previous_total']} previous")
        except Exception as e:
            log.warning(f"Dark-web index build failed: {e}")

    # -- Your own estate: credential exposure and external attack surface ----
    exposure = None
    breach_catalogue = None
    attack_surface = None
    domains = CONFIG.domain_list
    if build_exposure and domains:
        try:
            exposure = build_exposure(domains)
        except Exception as e:
            log.warning(f"Exposure check failed: {e}")
    if build_breach_catalogue:
        try:
            breach_catalogue = build_breach_catalogue()
            if breach_catalogue:
                log.info(f"Breach catalogue: {breach_catalogue['total_breaches']} breaches, "
                         f"{breach_catalogue['total_accounts']:,} accounts")
        except Exception as e:
            log.warning(f"Breach catalogue failed: {e}")
    if build_attack_surface and domains:
        try:
            attack_surface = build_attack_surface(domains)
        except Exception as e:
            log.warning(f"Attack-surface discovery failed: {e}")

    # ── Roll up source health ───────────────────────────────────────────────
    # Replaces the append-only source_health_history.jsonl, which had grown to
    # 1.8 MB, was committed on every one of 24 daily runs, and was fetched in
    # full by the dashboard on every page load. All the UI ever needed was
    # "when did this source last return data", so store exactly that.
    try:
        summary = {}
        if CONFIG.health_summary_path.exists():
            summary = json.loads(CONFIG.health_summary_path.read_text(encoding="utf-8"))
        sources = summary.setdefault("sources", {})
        stamp = now_utc()
        for name, h in source_health.items():
            entry = sources.setdefault(name, {})
            entry["last_status"] = h["status"]
            entry["last_count"] = h["count"]
            entry["median_age_days"] = h.get("median_age_days")
            if h["status"] == "ok" and h["count"] > 0:
                entry["last_ok"] = stamp
            entry["last_checked"] = stamp
            # 30-day rolling success rate, cheap to keep and genuinely useful.
            hist = entry.setdefault("recent", [])
            hist.append(1 if h["status"] == "ok" else 0)
            del hist[:-720]                      # ~30 days at hourly cadence
            entry["uptime_30d"] = round(sum(hist) / len(hist), 3)
        summary["updated"] = stamp
        CONFIG.health_summary_path.parent.mkdir(parents=True, exist_ok=True)
        CONFIG.health_summary_path.write_text(
            json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    except Exception as e:
        log.warning(f"Could not write source health summary: {e}")

    degraded = [f"{n}({h['status']})" for n, h in source_health.items() if h["status"] != "ok"]
    if degraded:
        log.warning(f"Degraded sources this run: {', '.join(degraded)}")

    # ── Sort, THEN deduplicate ──────────────────────────────────────────────
    # Order matters and used to be wrong. Items arrive in thread-completion
    # order, so running dedup first meant "first occurrence wins" picked
    # whichever HTTP request happened to finish first — the authoritative NVD
    # record and a blog rewrite of it were equally likely to survive, and the
    # winner changed between runs. Sorting first makes it deterministic;
    # ranking by source authority makes it correct.
    # The ordering itself lives in sort_for_dedup() so the regression is
    # actually testable — see TestDeduplication.test_authoritative_copy_survives.
    sort_for_dedup(all_items)
    before_dedup = len(all_items)
    all_items = deduplicate(all_items)
    log.info(f"Deduplicated {before_dedup} → {len(all_items)} items")
    all_items.sort(key=lambda x: x.get("published", ""), reverse=True)

    # ── Map MITRE ATT&CK TTPs ──────────────────────────────────────────────
    log.info("Mapping MITRE ATT&CK TTPs...")
    for item in all_items:
        item["ttps"] = map_ttps(item.get("title", "") + " " + item.get("description", ""))
    ttp_total = sum(len(i["ttps"]) for i in all_items)
    log.info(f"  Mapped {ttp_total} TTP associations across {len(all_items)} items")

    # ── Extract IOCs (source-aware; see extract_iocs) ───────────────────────
    log.info("Extracting indicators...")
    ioc_items = 0
    for item in all_items:
        text = f"{item.get('title', '')} {item.get('description', '')}"
        found = extract_iocs(text, source=item.get("source", ""), own_url=item.get("url", ""))
        existing = item.get("iocs") or {}
        # Anything a fetcher set explicitly (the indicator feeds) wins.
        for k, v in found.items():
            if k not in existing:
                existing[k] = v
        if existing:
            item["iocs"] = existing
            ioc_items += 1
    log.info(f"  Indicators on {ioc_items} items")

    # ── Fetch EPSS scores ──────────────────────────────────────────────────
    cve_ids = [item["cve_id"] for item in all_items if item.get("cve_id")]
    if cve_ids:
        epss_scores = fetch_epss_scores(cve_ids)
        for item in all_items:
            if item.get("cve_id"):
                item["epss_score"] = epss_scores.get(item["cve_id"].upper())
        log.info("  Applied EPSS scores")

    # ── CISA KEV (skip if no CVEs in feed this run) ────────────────────────
    cisa_kev = fetch_cisa_kev() if cve_ids else set()
    if cisa_kev:
        kev_count = 0
        for item in all_items:
            if item.get("cve_id") and item["cve_id"].upper() in cisa_kev:
                item["cisa_kev"] = True
                kev_count += 1
        log.info(f"  Marked {kev_count} CVEs from CISA KEV")

    # ── Public PoC availability (PoC-in-GitHub) ────────────────────────────
    poc_map = build_poc_map()
    if poc_map:
        poc_count = 0
        for item in all_items:
            cve = (item.get("cve_id") or "").upper()
            if cve and cve in poc_map and not item.get("has_poc"):
                item["has_poc"] = True
                item["poc_url"] = poc_map[cve]
                poc_count += 1
        log.info(f"  Marked {poc_count} items with public PoC availability")

    # ── Detect threat actors ───────────────────────────────────────────────
    log.info("Detecting threat actors...")
    actor_count = 0
    for item in all_items:
        text = item.get("title", "") + " " + item.get("description", "")
        actors = detect_threat_actors(text)
        # Ransomware.live provides the group name directly.
        for hint in item.pop("threat_actors_hint", []):
            if hint and hint not in actors:
                actors.append(hint)
        if actors:
            item["threat_actors"] = actors
            actor_count += 1
    log.info(f"  Detected threat actors in {actor_count} items")

    # Leak-site fetchers hand us the crew's own spelling, so one run carried
    # 'Qilin' and 'qilin' as two actors and split every count that keys on the
    # name. Collapse case variants before anything downstream counts them.
    if canonical_actor_names:
        renamed = canonical_actor_names(all_items)
        if renamed:
            log.info(f"  Collapsed {renamed} threat-actor case variant(s)")

    # ── ATT&CK knowledge base + malware family entities ────────────────────
    attack_kb = {}
    malware_families = {}
    if load_attack_kb and CONFIG.enable_entity_graph:
        try:
            attack_kb = load_attack_kb() or {}
        except Exception as e:
            log.warning(f"ATT&CK knowledge base unavailable: {e}")
    if load_families:
        try:
            malware_families = load_families()
        except Exception as e:
            log.warning(f"Malpedia family table unavailable: {e}")
    if annotate_malware and (attack_kb or malware_families):
        try:
            tagged = annotate_malware(all_items, attack_kb, malware_families)
            log.info(f"  Named malware families on {tagged} items")
        except Exception as e:
            log.warning(f"Malware tagging failed: {e}")

    # ── Detection coverage (SigmaHQ) ───────────────────────────────────────
    sigma_index = {}
    if load_sigma_index and CONFIG.enable_sigma:
        try:
            sigma_index = load_sigma_index() or {}
            if sigma_index and annotate_detections:
                covered = annotate_detections(all_items, sigma_index)
                log.info(f"  Detection rules available for {covered} items "
                         f"({sigma_index.get('rules_indexed', 0)} Sigma rules indexed)")
        except Exception as e:
            log.warning(f"Sigma index unavailable: {e}")

    # ── CISA Vulnrichment SSVC decision points ─────────────────────────────
    ssvc_map = fetch_vulnrichment(cve_ids) if cve_ids else {}
    if ssvc_map:
        ssvc_applied = 0
        for item in all_items:
            cve = (item.get("cve_id") or "").upper()
            data = ssvc_map.get(cve)
            if not data:
                continue
            if data.get("exploitation"):
                item["ssvc_exploitation"] = data["exploitation"]
            if data.get("automatable"):
                item["ssvc_automatable"] = data["automatable"]
            if data.get("technical_impact"):
                item["ssvc_technical_impact"] = data["technical_impact"]
            if data.get("cwe"):
                item["cwe"] = data["cwe"]
                item["cwe_name"] = data.get("cwe_name", "")
            # Only fill CVSS where the CNA left it blank.
            if item.get("cvss_score") is None and data.get("cvss") is not None:
                item["cvss_score"] = data["cvss"]
                item["cvss_source"] = "CISA-ADP"
            ssvc_applied += 1
        log.info(f"  Applied SSVC to {ssvc_applied} items")

    # ── Prioritisation (CVSS + EPSS + KEV + PoC + SSVC) ────────────────────
    prioritized = 0
    for item in all_items:
        priority = compute_priority(item)
        if priority:
            item["priority_score"]     = priority["score"]
            item["priority_label"]     = priority["label"]
            item["priority_rationale"] = priority["rationale"]
            item["action"]             = priority["action"]
            item["action_detail"]      = priority["action_detail"]
            # The per-term arithmetic, so the dashboard can open the score up
            # instead of reimplementing the scorer in JavaScript.
            item["priority_components"] = priority["components"]
            prioritized += 1
    log.info(f"  Scored priority for {prioritized} items")

    # ── Flag items not seen in the previous run (accurate "NEW") ───────────
    new_count = mark_new_since_last(all_items)
    log.info(f"  Flagged {new_count} items as new since last run")

    # ── Sector segregation (confidence-laddered; see sectors.py) ────────────
    sector_breakdown = {}
    if annotate_sectors:
        try:
            sector_breakdown = annotate_sectors(all_items)
            log.info(f"  Tagged sectors on {sum(sector_breakdown.values())} items "
                     f"across {len(sector_breakdown)} sectors")
        except Exception as e:
            log.warning(f"Sector tagging failed: {e}")

    # ── Provenance: who authored each item (see provenance.py) ─────────────
    provenance_breakdown = {}
    if annotate_provenance:
        try:
            provenance_breakdown = annotate_provenance(all_items)
            human = sum(1 for i in all_items if i.get("human_authored"))
            log.info(f"  Provenance tagged: {human}/{len(all_items)} human-authored")
        except Exception as e:
            log.warning(f"Provenance tagging failed: {e}")

    # ── Geopolitics (suspected actor origin × target; see geopolitics.py) ───
    geopolitics = None
    if build_geopolitics:
        try:
            geopolitics = build_geopolitics(all_items)
            log.info(f"  Geopolitics: {len(geopolitics['suspected_origins'])} origins, "
                     f"{len(geopolitics['attributions'])} attributed actors")
        except Exception as e:
            log.warning(f"Geopolitics build failed: {e}")

    # ── AI Enrichment ──────────────────────────────────────────────────────
    try:
        all_items = enrich_with_ai(all_items)
    except Exception as e:
        # Rule-based defaults are already on every item, so a total AI failure
        # degrades the feed rather than emptying it.
        log.error(f"AI enrichment failed, keeping rule-based defaults: {e}")

    # ── Daily brief (one model call over the whole feed) ───────────────────
    daily_brief = None
    try:
        daily_brief = build_daily_brief(all_items)
        if daily_brief:
            log.info(f"✓ Daily brief: {daily_brief['headline'][:80]}")
    except Exception as e:
        log.warning(f"Daily brief generation failed: {e}")

    # ── Connected intelligence: graph, malware view, detections, campaigns ──
    # These all run on the finished item list, so they see every enrichment.
    entity_graph = None
    if build_entity_graph and CONFIG.enable_entity_graph:
        try:
            entity_graph = build_entity_graph(all_items, attack_kb, malware_families,
                                              CONFIG.graph_max_nodes)
            if entity_graph:
                c = entity_graph["counts"]
                log.info(f"✓ Entity graph: {c['actors']} actors, {c['software']} software, "
                         f"{c['techniques']} techniques, {c['edges']} edges "
                         f"({c['known_edges']} from ATT&CK, {c['observed_edges']} observed)")
        except Exception as e:
            log.warning(f"Entity graph build failed: {e}")

    malware_view = None
    if build_malware_view:
        try:
            malware_view = build_malware_view(all_items, malware_families,
                                              attack_kb.get("software", {}))
            if malware_view:
                log.info(f"✓ Malware families: {malware_view['count']} named this run "
                         f"(of {malware_view['corpus_size']} known)")
        except Exception as e:
            log.warning(f"Malware view failed: {e}")

    detections = None
    if build_detection_view and sigma_index:
        try:
            detections = build_detection_view(
                all_items, sigma_index, attack_kb.get("technique_names", {}))
            if detections:
                log.info(f"✓ Detections: {detections['coverage_pct']}% of observed "
                         f"technique activity has a public Sigma rule "
                         f"({detections['techniques_uncovered']} techniques uncovered)")
        except Exception as e:
            log.warning(f"Detection view failed: {e}")

    campaign_view = None
    if build_campaigns and CONFIG.enable_campaigns:
        try:
            campaign_view = build_campaigns(all_items)
        except Exception as e:
            log.warning(f"Campaign clustering failed: {e}")

    # ── Research: does the score work, which sources matter, how long do you
    #    actually have? All three read the archive and the KEV dates, so they
    #    cost one already-cached fetch and some arithmetic.
    kev_records = {}
    try:
        kev_records = load_kev_catalog()
    except Exception as e:
        log.warning(f"KEV catalogue unavailable for research modules: {e}")

    backtest_result = None
    if build_backtest and CONFIG.enable_backtest and kev_records:
        try:
            backtest_result = build_backtest(ARCHIVE_DIR, kev_records)
        except Exception as e:
            log.warning(f"Backtest failed: {e}")

    reliability = None
    if build_source_reliability and CONFIG.enable_source_reliability and kev_records:
        try:
            reliability = build_source_reliability(ARCHIVE_DIR, kev_records)
        except Exception as e:
            log.warning(f"Source reliability failed: {e}")

    lag = None
    if build_exploit_lag and CONFIG.enable_exploit_lag and kev_records:
        try:
            from exploit_lag import backfill_published_dates, seed_published_dates
            seeded = seed_published_dates(all_items)
            if seeded:
                log.info(f"  Seeded {seeded} CVE publication date(s) from NVD items")
            backfill_published_dates(list(kev_records))
            poc_dates = {}
            for poc in _fetch_recent_pocs():
                cve = (poc.get("cve_id") or "").upper()
                created = poc.get("created_at") or ""
                if cve and created and cve not in poc_dates:
                    poc_dates[cve] = created.replace(" ", "T")
            lag = build_exploit_lag(kev_records, poc_dates)
        except Exception as e:
            log.warning(f"Exploitation-lag build failed: {e}")

    # ── Source breakdown ───────────────────────────────────────────────────

    # =====================================================================
    # v5 STAGE: THE LIBRARY AND THE HUNT BENCH
    # =====================================================================
    # Everything below runs on the finished item list and on corpora that are
    # cached for days or weeks, so the marginal cost per hourly run is a few
    # joins over data already in memory. Each block is guarded independently:
    # the Library degrading to "ATT&CK only" is a much better failure than the
    # feed not publishing.

    # How often each technique was actually seen this window. Several v5
    # features are only interesting because of this number -- it is what makes
    # a hunt pack timely rather than encyclopedic.
    technique_counts = Counter()
    for _item in all_items:
        for _tid in item_technique_ids(_item):
            technique_counts[_tid] += 1
    actor_counts = Counter()
    for _item in all_items:
        for _actor in _item.get("threat_actors") or []:
            actor_counts[_actor] += 1

    galaxy = {}
    if load_galaxy:
        try:
            galaxy = load_galaxy() or {}
            if galaxy:
                log.info(f"OK MISP galaxy: {len(galaxy)} entities")
        except Exception as e:
            log.warning(f"MISP galaxy unavailable: {e}")

    orkl_index = {}
    if load_orkl:
        try:
            orkl_index = load_orkl() or {}
            if orkl_index:
                log.info(f"OK ORKL: {orkl_index.get('count', 0)} reports indexed")
        except Exception as e:
            log.warning(f"ORKL unavailable: {e}")

    d3fend_table = {}
    if load_d3fend:
        try:
            d3fend_table = load_d3fend() or {}
        except Exception as e:
            log.warning(f"D3FEND unavailable: {e}")

    control_frameworks = {}
    if load_control_mappings:
        try:
            control_frameworks = load_control_mappings() or {}
        except Exception as e:
            log.warning(f"Control mappings unavailable: {e}")

    atomics_table = {}
    if load_atomics:
        try:
            atomics_table = load_atomics() or {}
        except Exception as e:
            log.warning(f"Atomic Red Team unavailable: {e}")

    leak_view = None
    if load_leak_sites:
        try:
            leak_view = load_leak_sites()
            if leak_view:
                log.info(f"OK Leak sites: {leak_view['window_claims']} claims in "
                         f"{leak_view['window_days']}d from "
                         f"{leak_view['active_groups']} groups")
        except Exception as e:
            log.warning(f"Leak-site view failed: {e}")

    telegram_view = None
    if load_telegram:
        try:
            telegram_view = load_telegram()
        except Exception as e:
            log.warning(f"Telegram watch failed: {e}")

    knowledge = None
    if build_knowledge_base:
        try:
            knowledge = build_knowledge_base(
                attack_kb, galaxy, malware_families, orkl_index, d3fend_table,
                control_frameworks, sigma_index, atomics_table, leak_view,
                all_items)
            if knowledge:
                log.info(f"OK Library: {knowledge['count']} entities, "
                         f"{knowledge['described']} with prose, "
                         f"{len(knowledge['aliases'])} searchable names")
        except Exception as e:
            log.warning(f"Knowledge base build failed: {e}")

    hunt_packs = None
    if build_hunt_packs:
        try:
            hunt_packs = build_hunt_packs(
                dict(technique_counts), sigma_index, attack_kb, atomics_table,
                d3fend_table, control_frameworks, fetch_rule_bodies)
        except Exception as e:
            log.warning(f"Hunt packs failed: {e}")

    hunt_queue = None
    if build_hunt_queue:
        try:
            hunt_queue = build_hunt_queue(all_items, dict(technique_counts),
                                          attack_kb, sigma_index,
                                          dict(actor_counts))
        except Exception as e:
            log.warning(f"Hunt queue failed: {e}")

    detection_diff = None
    if build_detection_diff and sigma_index:
        try:
            detection_diff = build_detection_diff(
                sigma_index, dict(technique_counts),
                attack_kb.get("technique_names", {}))
        except Exception as e:
            log.warning(f"Detection diff failed: {e}")

    control_focus = None
    if build_control_focus and control_frameworks:
        try:
            control_focus = build_control_focus(dict(technique_counts),
                                                control_frameworks)
            if control_focus:
                log.info(f"OK Control focus over {control_focus['techniques_considered']} "
                         f"active techniques")
        except Exception as e:
            log.warning(f"Control focus failed: {e}")

    source_counter = Counter(i.get("source", "Unknown") for i in all_items)

    # ── Write output ───────────────────────────────────────────────────────
    ai_enriched = sum(1 for i in all_items if i.get("ai_provider") not in (None, "rule"))
    output = {
        "last_updated": now_utc(),
        "total_items": len(all_items),
        "pipeline_version": "5.0.0",
        # Honest counts. The old `sources_fetched` included a stub that
        # returned [] by design, and `sources_ok` counted any source that
        # returned anything, however stale.
        "sources_configured": len(RSS_SOURCES) + len(API_SOURCES),
        "sources_ok":      sum(1 for h in source_health.values() if h["status"] == "ok"),
        "sources_stale":   sum(1 for h in source_health.values() if h["status"] == "stale"),
        "sources_empty":   sum(1 for h in source_health.values() if h["status"] == "empty"),
        "sources_error":   sum(1 for h in source_health.values() if h["status"] == "error"),
        "ai_provider_configured": bool(GROQ_API_KEY) or bool(GEMINI_API_KEY),
        "ai_enriched_count": ai_enriched,
        "new_since_last": new_count,
        "brief": daily_brief,
        "source_breakdown": dict(source_counter.most_common()),
        "source_health": source_health,
        "attack_map": attack_map,
        "darkweb": darkweb,
        "darkweb_watch": darkweb_watch_hits,
        "sector_benchmark": sector_benchmark,
        "exposure": exposure,
        "breach_catalogue": breach_catalogue,
        "attack_surface": attack_surface,
        "sector_breakdown": sector_breakdown,
        "sector_labels": SECTOR_LABELS,
        # Canonical ATT&CK kill-chain order, so the matrix can lay tactics out
        # left-to-right as the framework intends instead of alphabetically.
        "tactic_order": TACTIC_ORDER,
        "geopolitics": geopolitics,
        "provenance_breakdown": provenance_breakdown,
        "provenance_labels": PROVENANCE_LABELS,
        "provenance_notes": PROVENANCE_NOTES,
        "provenance_order": PROVENANCE_ORDER,
        # The weights the scores above were computed with. Published so the
        # dashboard's score breakdown can name them, and so an archived
        # snapshot stays interpretable after the weights are retuned.
        "priority_weights": {
            "cvss": CONFIG.priority_cvss_weight,
            "epss": CONFIG.priority_epss_weight,
            "kev": CONFIG.priority_kev_bonus,
            "poc": CONFIG.priority_poc_bonus,
            "ssvc_active": CONFIG.priority_ssvc_active_bonus,
            "ssvc_automatable": CONFIG.priority_ssvc_auto_bonus,
            "ssvc_total_impact": CONFIG.priority_ssvc_total_bonus,
        },
        # Big derived artifacts are published as their own endpoints (see
        # exports.write_exports) and only summarised here, so intel.json does
        # not grow by a few hundred KB that most visitors never look at.
        "research_available": {
            "graph": bool(entity_graph),
            "malware": bool(malware_view),
            "detections": bool(detections),
            "campaigns": bool(campaign_view),
            "backtest": bool(backtest_result),
            "source_reliability": bool(reliability),
            "exploit_lag": bool(lag),
            "library": bool(knowledge),
            "hunt_packs": bool(hunt_packs),
            "hunt_queue": bool(hunt_queue),
            "detection_diff": bool(detection_diff),
            "control_focus": bool(control_focus),
            "leak_sites": bool(leak_view),
            "telegram": bool(telegram_view),
        },
        # Small headline counts so the nav can show a badge without fetching
        # any of the large lazily-loaded endpoints.
        "library_summary": ({"count": knowledge["count"],
                             "by_kind": knowledge["by_kind"],
                             "names": len(knowledge["aliases"])}
                            if knowledge else None),
        "hunt_summary": ({"packs": hunt_packs["count"],
                          "with_queries": hunt_packs["with_queries"],
                          "backends": [b["label"] for b in hunt_packs["backends"]],
                          "queue": (hunt_queue or {}).get("count", 0),
                          "uncovered": (hunt_queue or {}).get("uncovered", 0)}
                         if hunt_packs else None),
        "leak_summary": ({"window_days": leak_view["window_days"],
                          "claims": leak_view["window_claims"],
                          "groups": leak_view["active_groups"]}
                         if leak_view else None),
        "campaign_summary": ({"count": campaign_view["count"],
                              "high_confidence": sum(
                                  1 for c in campaign_view["campaigns"]
                                  if c["confidence"] == "high")}
                             if campaign_view else None),
        "detection_summary": ({"coverage_pct": detections["coverage_pct"],
                               "rules_indexed": detections["rules_indexed"],
                               "uncovered": detections["techniques_uncovered"]}
                              if detections else None),
        # Written into the export step, not into intel.json.
        "entity_graph": entity_graph,
        "malware_view": malware_view,
        "detections": detections,
        "campaigns": campaign_view,
        "backtest": backtest_result,
        "source_reliability": reliability,
        "exploit_lag": lag,
        "knowledge_base": knowledge,
        "hunt_packs": hunt_packs,
        "hunt_queue": hunt_queue,
        "detection_diff": detection_diff,
        "control_focus": control_focus,
        "leak_sites": leak_view,
        "telegram": telegram_view,
        "items": all_items,
    }

    today_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    # ── Split the payload: feed vs research artifacts ──────────────────────
    # The graph, the malware view, the Sigma coverage table, the campaigns and
    # the three research reports together run to ~600 KB. They are published as
    # separate lazily-fetched endpoints, so they are removed from what goes
    # into intel.json and into the daily archive — otherwise every visitor
    # downloads all of it to read a list of headlines, and 90 archived copies
    # of a backtest that is recomputed from those very archives get stored.
    _RESEARCH_KEYS = ("entity_graph", "malware_view", "detections", "campaigns",
                      "backtest", "source_reliability", "exploit_lag",
                      # v5. knowledge_base is the big one: several thousand
                      # entities, sharded to its own files by
                      # knowledge_base.write_entity_shards.
                      "knowledge_base", "hunt_packs", "hunt_queue",
                      "detection_diff", "control_focus", "leak_sites",
                      "telegram")
    feed_output = {k: v for k, v in output.items() if k not in _RESEARCH_KEYS}

    # ── Archive once per day, not 24x ───────────────────────────────────────
    # The daily snapshot was rewritten every hour and only the final write
    # survived, costing ~430 KB of git objects per run for no added history.
    archive_path = ARCHIVE_DIR / f"{today_str}.json"
    ARCHIVE_DIR.mkdir(parents=True, exist_ok=True)
    archive_age_h = None
    if archive_path.exists():
        archive_age_h = (time.time() - archive_path.stat().st_mtime) / 3600.0
    if archive_age_h is None or archive_age_h >= 20:
        with open(archive_path, "w", encoding="utf-8") as f:
            json.dump(feed_output, f, indent=2, ensure_ascii=False)
        log.info(f"✓ Archived to {archive_path}")
    else:
        log.info(f"Archive for {today_str} is {archive_age_h:.1f}h old — skipping rewrite")

    # ── Write intel.json atomically (tmp → rename) ────────────────────────
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = OUTPUT_PATH.with_suffix(f".{os.getpid()}.tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(feed_output, f, indent=2, ensure_ascii=False)
    tmp.replace(OUTPUT_PATH)   # atomic on POSIX, near-atomic on Windows
    log.info(f"✓ Wrote {len(all_items)} items to {OUTPUT_PATH}")

    # ── Prune old archives ─────────────────────────────────────────────────
    if ARCHIVE_DIR.exists():
        cutoff = datetime.now(timezone.utc) - timedelta(days=ARCHIVE_RETENTION_DAYS)
        pruned = 0
        for fpath in ARCHIVE_DIR.glob("*.json"):
            try:
                fdate = datetime.strptime(fpath.stem, "%Y-%m-%d").replace(tzinfo=timezone.utc)
                if fdate < cutoff:
                    fpath.unlink()
                    pruned += 1
            except ValueError:
                continue
        if pruned:
            log.info(f"  Pruned {pruned} old archives (> {ARCHIVE_RETENTION_DAYS} days)")

    # ── Machine-readable exports (STIX / CSV / JSON IOCs + RSS feed) ────────
    if write_exports:
        try:
            written = write_exports(output, CONFIG.export_dir,
                                    darkweb_index=darkweb_index)
            log.info(f"✓ Wrote exports: {', '.join(written)}")
        except Exception as e:
            log.error(f"Export generation failed: {e}")

    # ── /.well-known/security.txt ─────────────────────────────────────────
    # Generated rather than committed: RFC 9116 makes `Expires` mandatory and
    # tells readers to ignore the file once it has passed, so a committed one
    # silently expires on a date nobody wrote down. See scripts/wellknown.py.
    if write_wellknown:
        try:
            write_wellknown(CONFIG.data_dir / "wellknown")
        except Exception as e:
            log.warning(f"security.txt generation failed: {e}")

    # ── Time machine: publish a slim snapshot per archived day ─────────────
    # data/archive/ has held 90 days of history that no page could ever open,
    # because the archives are not published and a full snapshot is ~270 KB.
    # This writes a ~60 KB reduced copy per day plus an index, which is what
    # the date slider and the day-to-day diff read.
    if publish_timeline and CONFIG.enable_timeline:
        try:
            tl = publish_timeline(ARCHIVE_DIR, CONFIG.data_dir / "api", feed_output)
            arch = tl.get("archive", {})
            if arch.get("days", 0) < min(30, ARCHIVE_RETENTION_DAYS):
                log.warning(
                    f"Archive holds only {arch.get('days', 0)} day(s). Trends, the "
                    f"sector benchmark and the backtest all read it, so a cache "
                    f"eviction shows up here first.")
        except Exception as e:
            log.error(f"Timeline publish failed: {e}")

    # ── Historical trends (aggregated from the archive) ────────────────────
    if build_trends:
        try:
            trends = build_trends(ARCHIVE_DIR, CONFIG.trends_path)
            log.info(f"✓ Wrote trends over {trends.get('days_covered', 0)} days")
        except Exception as e:
            log.error(f"Trends build failed: {e}")

    # ── Alerting (critical / KEV items, deduped against prior alerts) ───────
    if send_alerts and CONFIG.webhook_url:
        try:
            sent = send_alerts(output, CONFIG)
            log.info(f"✓ Dispatched {sent} new alert(s)")
            if send_watch_alerts:
                watched = send_watch_alerts(output, CONFIG)
                if watched:
                    log.warning(f"✓ Dispatched {watched} dark-web watchlist alert(s)")
        except Exception as e:
            log.error(f"Alert dispatch failed: {e}")

    _save_feed_meta()

    log.info("═" * 60)
    log.info(f"OPENTHREAT — Complete. {len(all_items)} items from {len(source_counter)} sources.")
    for src, cnt in source_counter.most_common():
        log.info(f"  {src}: {cnt}")
    log.info("═" * 60)


if __name__ == "__main__":
    main()
