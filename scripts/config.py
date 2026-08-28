"""
OPENTHREAT — config.py
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
    # Dark-web monitoring: ransomware leak-site activity, via the clearnet
    # mirror of a Tor crawler (we cannot reach .onion from a CI runner).
    enable_darkweb         = _bool("ENABLE_DARKWEB", True)
    darkweb_ttl_hours      = _int("DARKWEB_TTL_HOURS", 3)
    # CASM-style standing watch: comma-separated names checked against the
    # leak-site index every run. Hits are logged, surfaced and alertable.
    #   DARKWEB_WATCH="Acme Corp,Acme Ltd,acme.com"
    darkweb_watch          = _str("DARKWEB_WATCH", "")
    # The searchable index is published separately and lazily loaded by the
    # dashboard, so it never inflates intel.json.
    enable_darkweb_index   = _bool("ENABLE_DARKWEB_INDEX", True)
    # Cap on published index size. The full corpus is ~14.7k listings / 1.6 MB,
    # which is a lot to hand a phone even lazily. Newest-first, so the cap drops
    # the oldest listings - the least useful for exposure monitoring.
    darkweb_index_max      = _int("DARKWEB_INDEX_MAX", 9000)

    # ── Your own exposure (CASM) ───────────────────────────────────────────
    # Domains you own. Drives infostealer-exposure checks and Certificate
    # Transparency subdomain discovery.
    #   MY_DOMAINS="example.com,example.co.uk"
    my_domains             = _str("MY_DOMAINS", "")
    enable_exposure        = _bool("ENABLE_EXPOSURE", True)
    exposure_ttl_hours     = _int("EXPOSURE_TTL_HOURS", 12)
    enable_attack_surface  = _bool("ENABLE_ATTACK_SURFACE", True)
    attack_surface_ttl_hours = _int("ATTACK_SURFACE_TTL_HOURS", 24)
    attack_surface_max_hosts = _int("ATTACK_SURFACE_MAX_HOSTS", 300)
    # Own-estate findings are NOT published by default. The dashboard deploys to
    # a public URL, and an inventory of your own dev/staging/vpn hostnames plus
    # credential-exposure counts is precisely the reconnaissance an attacker
    # would otherwise have to do themselves. The data still reaches you through
    # the run summary and webhook alerts; it just does not get a public URL.
    # Set PUBLISH_OWN_ESTATE=1 only if the dashboard is genuinely private.
    publish_own_estate     = _bool("PUBLISH_OWN_ESTATE", False)
    # Cap per-feed rows parsed, as a guard against a feed ballooning. 0 = no cap.
    attacker_feed_max_rows = _int("ATTACKER_FEED_MAX_ROWS", 0)

    # ── Entity graph (MITRE CTI relationships) ─────────────────────────────
    # enterprise-attack.json is 48 MB and changes a few times a year. Only the
    # DERIVED graph (~1 MB of names, aliases and edges) is cached; see
    # entity_graph._derive_kb.
    enable_entity_graph    = _bool("ENABLE_ENTITY_GRAPH", True)
    attack_kb_ttl_hours    = _int("ATTACK_KB_TTL_HOURS", 24 * 30)
    graph_max_nodes        = _int("GRAPH_MAX_NODES", 400)

    # ── Malware family entities (Malpedia) ─────────────────────────────────
    enable_malware_families = _bool("ENABLE_MALWARE_FAMILIES", True)
    malpedia_ttl_hours      = _int("MALPEDIA_TTL_HOURS", 24 * 7)

    # ── Detection engineering (SigmaHQ) ────────────────────────────────────
    # The packaged release zip is ~3 MB and is cut roughly monthly.
    enable_sigma       = _bool("ENABLE_SIGMA", True)
    sigma_ttl_hours    = _int("SIGMA_TTL_HOURS", 24 * 7)
    sigma_rules_per_technique = _int("SIGMA_RULES_PER_TECHNIQUE", 12)

    # ── Research: scoring backtest + source reliability ────────────────────
    # Does the blended score actually predict exploitation? Answered against
    # the daily archive, so it costs nothing to fetch. The horizon is how long
    # a scored CVE is given to show up in KEV before it counts as a miss.
    enable_backtest        = _bool("ENABLE_BACKTEST", True)
    backtest_horizon_days  = _int("BACKTEST_HORIZON_DAYS", 30)
    backtest_min_samples   = _int("BACKTEST_MIN_SAMPLES", 20)
    enable_source_reliability = _bool("ENABLE_SOURCE_RELIABILITY", True)

    # ── Exploitation lag (published → PoC → KEV) ───────────────────────────
    # CVE publication dates are filled in incrementally from the CVE Program
    # API, a few per run, and cached permanently. A cold start therefore takes
    # several runs to converge rather than hammering a free API once.
    enable_exploit_lag       = _bool("ENABLE_EXPLOIT_LAG", True)
    cve_date_lookups_per_run = _int("CVE_DATE_LOOKUPS_PER_RUN", 40)

    # ── Campaign clustering ────────────────────────────────────────────────
    enable_campaigns     = _bool("ENABLE_CAMPAIGNS", True)
    campaign_window_days = _int("CAMPAIGN_WINDOW_DAYS", 14)
    campaign_min_items   = _int("CAMPAIGN_MIN_ITEMS", 3)

    # ── Time machine (slim per-day snapshots the dashboard can load) ───────
    # data/archive/*.json are full snapshots (~270 KB each, 24 MB for 90 days)
    # and are never published as loose files. The timeline publishes a reduced
    # copy per day so the dashboard can show any past day without downloading
    # a full archive.
    enable_timeline    = _bool("ENABLE_TIMELINE", True)
    timeline_days      = _int("TIMELINE_DAYS", 90)

    # ══════════════════════════════════════════════════════════════════════
    # v5 — THE LIBRARY (encyclopedia), THE HUNT BENCH, LEAK-SITE TRACKING
    # ══════════════════════════════════════════════════════════════════════

    # ── Knowledge base / entity pages ──────────────────────────────────────
    # The encyclopedia. ATT&CK prose + MISP galaxy + Malpedia are merged into
    # one canonical entity per actor / malware / technique / campaign, then
    # SHARDED to data/api/entity/<slug>.json. Sharding is not an optimisation
    # here, it is the only thing that makes this fit: the merged corpus is
    # ~4,800 entities and several MB, and a single blob would be downloaded in
    # full by every visitor who wanted to read one page.
    enable_knowledge_base   = _bool("ENABLE_KNOWLEDGE_BASE", True)
    kb_shard_dir            = _str("KB_SHARD_DIR", "entity")
    # The search index carries id/name/aliases/kind only, and is the ONE file
    # loaded up front. Cap it so a galaxy growth spurt cannot silently turn a
    # 300 KB download into 3 MB.
    kb_index_max_entities   = _int("KB_INDEX_MAX_ENTITIES", 12000)
    kb_description_chars    = _int("KB_DESCRIPTION_CHARS", 4000)

    # ── MISP galaxy (threat-actor, ransomware, tool, rat, banker clusters) ──
    # Keyless JSON in a git repo. This is the alias corpus that makes name
    # deconfliction work: "Midnight Blizzard" -> APT29.
    enable_misp_galaxy   = _bool("ENABLE_MISP_GALAXY", True)
    misp_galaxy_ttl_hours = _int("MISP_GALAXY_TTL_HOURS", 24 * 7)

    # ── ORKL (threat-report library) ───────────────────────────────────────
    # ORKL returns the FULL report text in list responses -- ~2.3 MB per 100
    # rows -- so the page budget is a bandwidth decision, not a taste one.
    # 1,500 reports is ~35 MB once a week, reduced on the fly to ~250 KB of
    # citations. Raising the cap raises the transfer linearly.
    enable_orkl        = _bool("ENABLE_ORKL", True)
    orkl_ttl_hours     = _int("ORKL_TTL_HOURS", 24 * 7)
    orkl_max_reports   = _int("ORKL_MAX_REPORTS", 1500)

    # ── MITRE D3FEND (countermeasures) ─────────────────────────────────────
    enable_d3fend      = _bool("ENABLE_D3FEND", True)
    d3fend_ttl_hours   = _int("D3FEND_TTL_HOURS", 24 * 30)

    # ── ATT&CK <-> NIST 800-53 / CIS control mappings ──────────────────────
    enable_control_mappings = _bool("ENABLE_CONTROL_MAPPINGS", True)
    control_map_ttl_hours   = _int("CONTROL_MAP_TTL_HOURS", 24 * 30)

    # ── CISA advisories + historical incident corpus ───────────────────────
    enable_advisories       = _bool("ENABLE_ADVISORIES", True)
    advisories_ttl_hours    = _int("ADVISORIES_TTL_HOURS", 12)
    enable_historical       = _bool("ENABLE_HISTORICAL", True)
    historical_ttl_hours    = _int("HISTORICAL_TTL_HOURS", 24 * 7)

    # ── Threat hunting ─────────────────────────────────────────────────────
    # A hunt pack is one technique's Sigma rules + Atomic Red Team tests +
    # queries compiled for the SIEMs people actually run. Compilation needs
    # pySigma and its backends; when they are absent the pack still publishes
    # with the raw Sigma, which is why the backends are an optional extra
    # rather than a hard dependency (see hunt_packs._compile).
    enable_hunt_packs       = _bool("ENABLE_HUNT_PACKS", True)
    hunt_packs_max          = _int("HUNT_PACKS_MAX", 220)
    hunt_pack_rules_max     = _int("HUNT_PACK_RULES_MAX", 8)
    enable_sigma_compile    = _bool("ENABLE_SIGMA_COMPILE", True)
    sigma_compile_budget    = _int("SIGMA_COMPILE_BUDGET", 900)
    enable_atomics          = _bool("ENABLE_ATOMICS", True)
    atomics_ttl_hours       = _int("ATOMICS_TTL_HOURS", 24 * 7)
    enable_hunt_queue       = _bool("ENABLE_HUNT_QUEUE", True)
    hunt_queue_max          = _int("HUNT_QUEUE_MAX", 40)

    # ── Detection diff (what SigmaHQ added since the last run) ─────────────
    enable_detection_diff   = _bool("ENABLE_DETECTION_DIFF", True)

    # ── Ransomware leak sites ──────────────────────────────────────────────
    # ransomware.live and ransomwatch aggregate what onion leak sites publish.
    # We read the aggregators rather than running Tor in CI: see
    # ransomware_leaks.py for why that is a deliberate choice and not laziness.
    enable_leak_sites       = _bool("ENABLE_LEAK_SITES", True)
    leak_sites_ttl_hours    = _int("LEAK_SITES_TTL_HOURS", 6)
    leak_victims_max        = _int("LEAK_VICTIMS_MAX", 6000)
    leak_recent_days        = _int("LEAK_RECENT_DAYS", 120)
    # How many months of ransomware.live victim data to assemble. Each month is
    # one request of roughly 800 KB; closed months are cached for 30 days, so
    # the recurring cost is the current month only.
    leak_history_months     = _int("LEAK_HISTORY_MONTHS", 5)

    # ── Telegram public-channel previews ───────────────────────────────────
    # t.me/s/<channel> is the ordinary public web preview. No API key, no
    # login, nothing private.
    #
    # THE DEFAULT LIST, AND WHAT IS DELIBERATELY NOT ON IT
    # ----------------------------------------------------
    # v5 shipped this off with an empty list, on the grounds that choosing
    # channels is editorial rather than technical. That was the right caution
    # and the wrong default: an editorial choice made by nobody is still a
    # choice, and it was "watch nothing".
    #
    # So there is a list, and the criteria are written down. Every entry was
    # verified to have a live public preview with real posts before it was
    # added. Nine report on threats; one is an adversary channel, because
    # hacktivist crews announce on Telegram before anything reaches a leak
    # site and that lead time is the entire point of this source.
    #
    # NOT included, as a standing rule: credential-dump, stealer-log and
    # carding channels. They are the most-recommended channels in every "top
    # dark web Telegram" listicle, and they are exactly the ones this project
    # must not ingest — their posts ARE victim data. Pulling them into a
    # public static site would republish other people's credentials and
    # personal information, at scale, with no way to take it back. The
    # scrubber in telegram_watch.py is a second line of defence for material
    # that slips through a channel that is normally fine, not a licence to
    # subscribe to channels whose whole purpose is dumping.
    enable_telegram         = _bool("ENABLE_TELEGRAM", True)
    telegram_channels       = _str("TELEGRAM_CHANNELS", ",".join([
        # `it_secur`, not the `infosecurity` vanity alias: t.me serves the
        # preview under either, but every post is stamped with the CANONICAL
        # username, and telegram_watch rejects posts whose channel does not
        # match the one it asked for (that check is what stops a forwarded or
        # crafted post being attributed here). Configured by the alias, the
        # channel fetches fine and yields zero posts, silently.
        "it_secur",                # infosec - 61K, general security news
        "Cyber_Security_Channel",  # Cyber Security News - 56K
        "vxunderground",           # vx-underground - 52K, malware research
        "CTINOW",                  # Cyber Threat Intelligence - 38K, CTI feed
        "Hacker_News_Feed",        # Hacker News - 29K
        "cvenotify",               # CVE Notify - 20K, vulnerability alerts
        "cyber_anarchy_squad",     # hacktivist claims - 13K, ADVERSARY channel
        "BleepingComputer",        # BleepingComputer - 12K, vendor newsroom
        "secharvester",            # Security Harvester - 9.6K, aggregator
        "CVEfeed",                 # CVE & Vulnerability RSS Feed
    ]))
    telegram_ttl_hours      = _int("TELEGRAM_TTL_HOURS", 4)
    telegram_max_posts      = _int("TELEGRAM_MAX_POSTS", 40)

    # ── MISP ───────────────────────────────────────────────────────────────
    enable_misp_export = _bool("ENABLE_MISP_EXPORT", True)
    misp_org_name      = _str("MISP_ORG_NAME", "OpenThreat")

    # ── Identity and contact ───────────────────────────────────────────────
    # One address, used everywhere something needs a human: security.txt, the
    # contact page, the STIX identity, the MISP organisation and the RSS
    # editor fields. It was hardcoded in none of those places before, which is
    # why the RSS channel link pointed at "https://github.com/".
    #
    # This address is PUBLISHED. That is the point of it — a site that reports
    # other people's vulnerabilities with no way to report one to it is not
    # arguing in good faith — but it does mean it will be scraped.
    contact_email     = _str("CONTACT_EMAIL", "priyanshu@openthreat.in")
    contact_name      = _str("CONTACT_NAME", "OpenThreat")
    discussions_url   = _str("DISCUSSIONS_URL",
                             "https://github.com/priyanshu965/OpenThreat/discussions")
    repo_url          = _str("REPO_URL", "https://github.com/priyanshu965/OpenThreat")
    # RFC 9116 requires an Expires date and readers are expected to ignore a
    # stale file, so it is regenerated on every run rather than committed.
    security_txt_months = _int("SECURITY_TXT_MONTHS", 12)

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
    dashboard_url = _str("DASHBOARD_URL", "https://openthreat.in/")
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

    http_user_agent = _str("HTTP_USER_AGENT", "OpenThreat/5.0 (+https://github.com/priyanshu965/OpenThreat)")

    @property
    def domain_list(self) -> list:
        return [d.strip() for d in self.my_domains.split(",") if d.strip()]

    @property
    def alert_severity_set(self) -> set:
        return {s.strip() for s in self.alert_severities.split(",") if s.strip()}


CONFIG = Config()
