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
  - Arch Linux            → Arch security issues (JSON)
  - Amazon Linux          → ALAS advisories (RSS)
  - CentOS Stream         → CentOS blog (RSS)
  - VMware                → Broadcom advisories (JSON API)
  - Mitre CWE             → CWE taxonomy (API)
  - IOC Extraction        → Regex-based from all item descriptions
  - AI Enrichment         → Gemini (primary) with Groq fallback

Output: data/intel.json  +  data/archive/YYYY-MM-DD.json
"""

import json
import os
import re
import threading
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed


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
    from lifecycle import load_lifecycle
except Exception:
    load_lifecycle = None
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
    from webhook_post import send_alerts, send_estate_report, send_watch_alerts
except Exception:
    send_alerts = None
    send_estate_report = None
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
URLHAUS_API_KEY   = CONFIG.urlhaus_api_key

GROQ_MODEL_PRIMARY  = CONFIG.groq_model_primary
GROQ_MODEL_FALLBACK = CONFIG.groq_model_fallback
GEMINI_MODEL        = CONFIG.gemini_model
VULNCHECK_API_KEY   = CONFIG.vulncheck_api_key
AI_BATCH_SIZE       = CONFIG.ai_batch_size

HEADERS = {"User-Agent": CONFIG.http_user_agent}

# The sources themselves: the RSS feed list, every API fetcher, and the See sources.py.
from sources import (                                   # noqa: E402,F401
    RSS_SOURCES,
    _FEED_META,
    _FEED_META_LOCK,
    _load_feed_meta,
    _save_feed_meta,
    fetch_rss,
    _feed_cache_path,
    _store_cached_feed,
    _replay_cached_feed,
    fetch_nvd_cves,
    fetch_reddit_netsec,
    fetch_otx_pulse,
    SourceDisabled,
    fetch_urlhaus,
    fetch_spamhaus_drop,
    fetch_abuseipdb,
    fetch_phishtank,
    fetch_malwarebazaar,
    _THREATFOX_TYPE_MAP,
    _threatfox_ioc,
    fetch_sslbl,
    fetch_threatfox,
    _RSS_SOURCE_CONFIG,
    _fetch_rss_source,
    fetch_msrc,
    fetch_fedora,
    fetch_archlinux,
    fetch_amazon_linux,
    fetch_debian,
    fetch_cisco,
    fetch_paloalto,
    fetch_vmware,
    fetch_ghsa,
    _fetch_recent_pocs,
    _fetch_pocs_raw,
    build_poc_map,
    fetch_poc_github,
    fetch_zdi,
    fetch_ransomware_live,
    API_SOURCES,
    _median_age_days,
    run_source,
)

# Small helpers every fetcher uses: dates, HTML stripping and JSON/text GETs. See feedutil.py.
from feedutil import (                                   # noqa: E402,F401
    now_utc,
    parse_date,
    _TAG_RE,
    clean_html,
    make_request,
    make_request_text,
)

# Model-written summaries and the daily brief, with the cross-run cache See ai_enrich.py.
from ai_enrich import (                                   # noqa: E402,F401
    _ENRICH_ITEM_SCHEMA,
    _ENRICH_BATCH_SCHEMA,
    _BRIEF_SCHEMA,
    build_batch_prompt,
    _call_gemini_json,
    _call_groq_json,
    _GROQ_MODELS_LOGGED,
    _log_groq_models,
    apply_enrichment,
    rule_based_enrich,
    _AI_CACHE_NAME,
    _AI_CACHE_FIELDS,
    _load_ai_cache,
    _save_ai_cache,
    _cache_enrichment,
    _apply_cached_enrichment,
    _UNSCORED_SEVERITY_RANK,
    select_enrichment_candidates,
    enrich_with_ai,
    build_daily_brief,
    _BRIEF_CACHE_NAME,
    _brief_signature,
    _load_cached_brief,
    _save_cached_brief,
)

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


# What an item IS, inferred from its text: threat actors named in it, See classify.py.
from classify import (                                   # noqa: E402,F401
    THREAT_ACTORS,
    _ACTOR_PATTERNS,
    detect_threat_actors,
    _SEVERITY_KEYWORDS,
    _CATEGORY_KEYWORDS,
    _compile_keyword_matcher,
    _SEVERITY_MATCHERS,
    _CATEGORY_MATCHERS,
    infer_severity,
    infer_category,
    extract_cve_id,
    _CVE_EXACT,
    valid_cve_id,
)

# The priority score: how urgently an item needs acting on, and why. See scoring.py.
from scoring import (                                   # noqa: E402,F401
    cvss_to_severity,
    _SSVC_EXPLOITATION_WEIGHT,
    _ACTION_BY_LABEL,
    compute_priority,
)

# Indicator extraction: IPs, domains, hashes and URLs pulled out of item text, See iocs.py.
from iocs import (                                   # noqa: E402,F401
    IOC_PATTERNS,
    IOC_SOURCES,
    _DOMAIN_DENYLIST,
    _CODE_TLD_DENYLIST,
    _DEFANG_HINT,
    _plausible_domain,
    _is_private_ip,
    extract_iocs,
)

# Deduplication: one item per story, keeping the most authoritative copy. See dedup.py.
from dedup import (                                   # noqa: E402,F401
    _STOPWORDS,
    _normalize_title,
    _canonical_url,
    _SOURCE_AUTHORITY,
    _source_rank,
    sort_for_dedup,
    deduplicate,
    item_key,
)

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

# ── Own-estate findings ──────────────────────────────────────────────────────
# What the pipeline learned about YOUR domains and watch terms. intel.json is
# the public feed and every daily archive is a copy of it, so none of this may
# ride in there: for a while it did, which meant PUBLISH_OWN_ESTATE=0 withheld
# the per-view API files while the same findings shipped in the main payload.
_OWN_ESTATE_KEYS = {"exposure": None, "attack_surface": None, "darkweb_watch": []}


def split_own_estate(feed: dict) -> tuple[dict, dict]:
    """Return (public feed, private findings).

    The keys stay in the public feed with empty values so its shape does not
    change; only the content moves. With PUBLISH_OWN_ESTATE=1 the feed is
    returned untouched - that is the explicit opt-in for a private dashboard.
    """
    private = {k: feed[k] for k in _OWN_ESTATE_KEYS if feed.get(k)}
    if CONFIG.publish_own_estate:
        return feed, private
    public = dict(feed)
    for key, empty in _OWN_ESTATE_KEYS.items():
        if key in public:
            public[key] = empty
    return public, private


def write_own_estate(private: dict) -> None:
    """Keep the findings in a local file the run summary can read.

    It is gitignored, never copied into the site and not part of the state
    tarball. A run with nothing to report removes it, so a stale file cannot
    be mistaken for a current finding.
    """
    path = CONFIG.own_estate_path
    try:
        if private:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(private, ensure_ascii=False), encoding="utf-8")
        elif path.exists():
            path.unlink()
    except OSError as e:
        log.warning(f"Could not update the own-estate file: {e}")


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

    degraded = [f"{n}({h['status']})" for n, h in source_health.items()
                if h["status"] not in ("ok", "disabled")]
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

    lifecycle_view = None
    if load_lifecycle:
        try:
            lifecycle_view = load_lifecycle()
            if lifecycle_view:
                counts = lifecycle_view["counts"]
                log.info(f"OK Lifecycle: {counts['products']} products "
                         f"({counts['products_with_eol']} with an EOL cycle), "
                         f"{counts['releases']} releases")
        except Exception as e:
            log.warning(f"Lifecycle view failed: {e}")

    # The KEV catalogue is already loaded for the research modules. Publishing
    # it as its own endpoint costs one more write and turns 1,600 records the
    # pipeline was already holding into a browsable table.
    kev_view = None
    if CONFIG.enable_kev_table and kev_records:
        rows = []
        for cve, rec in kev_records.items():
            rows.append({"cve": cve, **{k: rec.get(k) for k in
                                        ("added", "due", "vendor", "product",
                                         "ransomware", "name", "desc", "action")}})
        rows.sort(key=lambda r: (r.get("added") or "", r.get("cve")), reverse=True)
        kev_view = {
            "built": now_utc(),
            "count": len(rows),
            "ransomware_linked": sum(1 for r in rows if r.get("ransomware")),
            "entries": rows,
            "source": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        }
        log.info(f"OK KEV table: {len(rows)} entries, "
                 f"{kev_view['ransomware_linked']} ransomware-linked")

    # A slim summary for the front page, carried in intel.json's metadata.
    #
    # The full catalogue is a separate 880 KB endpoint, which is right for a
    # browsable table and far too heavy for a rail that every visitor loads.
    # Fourteen rows is about 2 KB on a payload that is already ~500 KB, so
    # the rail costs no extra request and no meaningful bytes -- the same
    # bargain library_summary and leak_summary already make.
    kev_recent = None
    if kev_view:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=7)).strftime("%Y-%m-%d")
        recent = kev_view["entries"][:CONFIG.kev_recent_count]
        kev_recent = {
            "total": kev_view["count"],
            "ransomware_linked": kev_view["ransomware_linked"],
            "added_7d": sum(1 for r in kev_view["entries"]
                            if (r.get("added") or "") >= cutoff),
            "entries": [{k: r.get(k) for k in
                         ("cve", "added", "vendor", "product", "ransomware")}
                        for r in recent],
        }

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
        # Switched off for want of an API key. Not a fault, so not counted
        # among the degraded - but not live either.
        "sources_disabled": sum(1 for h in source_health.values() if h["status"] == "disabled"),
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
        "lifecycle": lifecycle_view,
        "kev_table": kev_view,
        # Slim; rides along in intel.json rather than costing a request.
        "kev_recent": kev_recent,
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
                      # v6. kev_table is ~1,600 records and lifecycle is 44
                      # products x 8 cycles; neither belongs in the feed
                      # payload or in 90 archived copies of it.
                      "telegram", "lifecycle", "kev_table")
    feed_output = {k: v for k, v in output.items() if k not in _RESEARCH_KEYS}
    feed_output, own_estate = split_own_estate(feed_output)
    write_own_estate(own_estate)

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
            if send_estate_report and send_estate_report(output, CONFIG):
                log.info("✓ Dispatched the own-estate report")
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
