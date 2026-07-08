"""
CYBERWATCH DASHBOARD — fetch_intel.py
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

import json, os, re, sys, time, logging, threading
from datetime import datetime, timezone, timedelta
from pathlib import Path
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed

import csv, io
import requests
import feedparser

# ── Local modules (support both `python scripts/x.py` and package import) ─────
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
    from webhook_post import send_alerts
except Exception:
    send_alerts = None

# ── Logging ───────────────────────────────────────────────────────────────────
class _StructuredAdapter(logging.LoggerAdapter):
    """Minimal structured logging: extra kwargs become space-separated key=val."""
    def process(self, msg, kwargs):
        extra = kwargs.pop("extra", {})
        if extra:
            ctx = " ".join(f"{k}={v}" for k, v in sorted(extra.items()))
            msg = f"{msg}  [{ctx}]"
        return msg, kwargs

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S"
)
log = _StructuredAdapter(logging.getLogger("cyberwatch"), {})

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
GROQ_SLEEP_SECS     = CONFIG.groq_sleep_secs
GEMINI_SLEEP_SECS   = CONFIG.gemini_sleep_secs

HEADERS = {"User-Agent": CONFIG.http_user_agent}

DEFAULT_WORKFLOW_GRAPH = (
    "graph LR\n"
    "    A([Threat Actor]):::actor -->|Recon| B[Initial Access]:::tactic\n"
    "    B -->|Exploit| C[Execution]:::tactic\n"
    "    C -->|Persist| D[Impact]:::tactic\n"
    "    classDef actor fill:#1a0e2e,stroke:#a78bfa,color:#c9d8e8\n"
    "    classDef tactic fill:#0d2038,stroke:#4da6ff,color:#c9d8e8"
)

# ── RSS Feed Sources (15 total) ───────────────────────────────────────────────
RSS_SOURCES = [
    {"name": "CISA",             "url": "https://www.cisa.gov/cybersecurity-advisories/ics-advisories.xml", "category": "advisory", "severity": "high"},
    {"name": "The Hacker News",  "url": "https://feeds.feedburner.com/TheHackersNews",            "category": "news",     "severity": "medium"},
    {"name": "Bleeping Computer","url": "https://www.bleepingcomputer.com/feed/",                 "category": "news",     "severity": "medium"},
    {"name": "Krebs on Security","url": "https://krebsonsecurity.com/feed/",                      "category": "news",     "severity": "medium"},
    {"name": "SANS ISC",         "url": "https://isc.sans.edu/rssfeed_full.xml",                  "category": "news",     "severity": "low"},
    {"name": "TheRecord Media",  "url": "https://therecord.media/feed",                           "category": "news",     "severity": "high"},
    {"name": "Dark Reading",     "url": "https://www.darkreading.com/rss.xml",                    "category": "news",     "severity": "medium"},
    {"name": "SecurityWeek",     "url": "https://www.securityweek.com/feed/",                     "category": "news",     "severity": "medium"},
    {"name": "Threatpost",       "url": "https://threatpost.com/feed/",                           "category": "news",     "severity": "medium"},
    {"name": "Cisco Talos",      "url": "https://blog.talosintelligence.com/feed",                "category": "news",     "severity": "high"},
    {"name": "Unit 42",          "url": "https://feeds.feedburner.com/Unit42",                    "category": "news",     "severity": "high"},
    {"name": "Graham Cluley",    "url": "https://grahamcluley.com/feed/",                         "category": "news",     "severity": "medium"},
    {"name": "ESET WeLiveSecurity","url": "https://welivesecurity.com/feed/",                     "category": "news",     "severity": "medium"},
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
        for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d"):
            try:
                return datetime.strptime(date_str, fmt).replace(tzinfo=timezone.utc).isoformat()
            except ValueError:
                continue
    except Exception:
        pass
    return now_utc()

def clean_html(text: str) -> str:
    if not text:
        return ""
    text = re.sub(r"<[^>]+>", "", text)
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

def ai_score_to_severity(score: float) -> str:
    if score >= 9.0: return "critical"
    if score >= 7.0: return "high"
    if score >= 4.0: return "medium"
    return "low"

# ── AI Prompt Builder ─────────────────────────────────────────────────────────

def build_prompt(item: dict) -> str:
    ttp_str = ", ".join(
        f"{t['id']} ({t['name']})" for t in item.get("ttps", [])[:6]
    ) or "None detected"
    return f"""You are a senior threat intelligence analyst. Analyze this cybersecurity threat and respond with ONLY a valid JSON object — no markdown, no code fences, no preamble.

Return exactly this structure:
{{
  "ai_summary": "4-5 sentences: detailed technical breakdown of the vulnerability/exploit, affected systems/versions, real-world impact with specific examples, threat actor attribution if mentioned, and specific actionable remediation steps for defenders.",
  "severity_score": 7.5,
  "workflow_graph": "graph LR\\n    A([Threat Actor]):::actor -->|T1566| B[Initial Access]:::tactic\\n    B -->|T1059.001| C[Execution]:::tactic\\n    C -->|T1041| D[Command and Control]:::tactic\\n    D -->|T1486| E[Impact]:::tactic\\n    classDef actor fill:#1a0e2e,stroke:#a78bfa,color:#c9d8e8\\n    classDef tactic fill:#0d2038,stroke:#4da6ff,color:#c9d8e8"
}}

RULES:
- ai_summary: 4-5 sentences. Be DETAILED and SPECIFIC.
- severity_score: 0.0 to 10.0 float. 9-10=critical, 7-8=high, 4-6=medium, 1-3=low.
- workflow_graph: valid Mermaid "graph LR" string with \\n for newlines, 4-6 nodes, edge labels = REAL TTP IDs.

THREAT ITEM:
Title: {item.get('title', '')[:200]}
Description: {item.get('description', '')[:500]}
Category: {item.get('category', '')}
TTPs Detected: {ttp_str}
CVE ID: {item.get('cve_id') or 'N/A'}
CVSS Score: {item.get('cvss_score') or 'N/A'}"""

# ── AI Response Parser ────────────────────────────────────────────────────────

def parse_ai_response(raw: str) -> dict:
    """
    Best-effort parse of an LLM's JSON reply.

    LLMs frequently wrap JSON in code fences, add a preamble, emit trailing
    commas, or leave the object unterminated when truncated by max_tokens. We
    try progressively harder to recover a dict and only raise ``ValueError`` if
    nothing usable survives — that signals the caller to fall back to the next
    provider rather than accepting a half-empty enrichment.
    """
    if not raw or not raw.strip():
        raise ValueError("empty AI response")

    text = raw.strip()
    # Strip ```json ... ``` fences.
    text = re.sub(r"^```(?:json)?\s*\n?", "", text, flags=re.MULTILINE)
    text = re.sub(r"\n?```\s*$", "", text, flags=re.MULTILINE)
    text = text.strip()

    # Narrow to the outermost {...} span.
    start = text.find("{")
    end   = text.rfind("}")
    if start != -1 and end != -1 and end > start:
        candidate = text[start:end + 1]
    else:
        candidate = text

    # 1) Straight parse.
    try:
        return json.loads(candidate)
    except (json.JSONDecodeError, TypeError):
        pass

    # 2) Repair common issues: control chars + trailing commas.
    repaired = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", " ", candidate)
    repaired = re.sub(r",\s*([}\]])", r"\1", repaired)
    try:
        return json.loads(repaired)
    except (json.JSONDecodeError, TypeError):
        pass

    # 3) Truncated object (ran out of tokens): balance braces and retry.
    if candidate.count("{") > candidate.count("}"):
        balanced = repaired + "}" * (candidate.count("{") - candidate.count("}"))
        try:
            return json.loads(balanced)
        except (json.JSONDecodeError, TypeError):
            pass

    # 4) Last resort: pull individual fields out with regex so we still get the
    #    human-readable summary even when the graph JSON is malformed.
    salvaged = {}
    m = re.search(r'"ai_summary"\s*:\s*"((?:[^"\\]|\\.)*)"', candidate, re.DOTALL)
    if m:
        salvaged["ai_summary"] = m.group(1).encode().decode("unicode_escape", "ignore")
    m = re.search(r'"severity_score"\s*:\s*([0-9]+(?:\.[0-9]+)?)', candidate)
    if m:
        salvaged["severity_score"] = float(m.group(1))
    if salvaged:
        return salvaged

    raise ValueError("could not parse AI response as JSON")

def postprocess_graph(raw_graph: str) -> str:
    if not raw_graph or not raw_graph.strip():
        return DEFAULT_WORKFLOW_GRAPH
    graph = raw_graph.replace("\\n", "\n").strip()
    if not re.match(r'^graph\s+(LR|TD|TB|RL|BT)', graph, re.IGNORECASE):
        graph = "graph LR\n" + graph
    lines = [l for l in graph.split("\n") if not l.strip().startswith("classDef")]
    graph = "\n".join(lines).rstrip()
    graph += (
        "\n    classDef actor fill:#1a0e2e,stroke:#a78bfa,color:#c9d8e8"
        "\n    classDef tactic fill:#0d2038,stroke:#4da6ff,color:#c9d8e8"
    )
    return graph

# ── Groq API Caller ───────────────────────────────────────────────────────────

def call_groq(prompt: str) -> tuple[str | None, str | None]:
    if not GROQ_API_KEY:
        return None, None
    headers = {"Authorization": f"Bearer {GROQ_API_KEY}", "Content-Type": "application/json"}
    for model in [GROQ_MODEL_PRIMARY, GROQ_MODEL_FALLBACK]:
        try:
            body = {
                "model": model, "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.1, "max_tokens": 700,
                "response_format": {"type": "json_object"},
            }
            resp = requests.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers=headers, json=body, timeout=REQUEST_TIMEOUT
            )
            if resp.status_code == 429:
                log.warning(f"Groq rate limit on {model}, trying fallback...")
                time.sleep(5)
                continue
            resp.raise_for_status()
            data = resp.json()
            raw = data["choices"][0]["message"]["content"]
            return raw, model
        except Exception as e:
            log.warning(f"Groq error ({model}): {e}")
    return None, None

# ── Gemini API Caller ─────────────────────────────────────────────────────────

def call_gemini(prompt: str) -> tuple[str | None, str | None]:
    if not GEMINI_API_KEY:
        return None, None
    try:
        import google.generativeai as genai
        genai.configure(api_key=GEMINI_API_KEY)
        model = genai.GenerativeModel(GEMINI_MODEL)
        response = model.generate_content(prompt)
        return response.text.strip(), GEMINI_MODEL
    except Exception as e:
        log.warning(f"Gemini call failed: {e}")
        return None, None

# ── AI Enrichment ─────────────────────────────────────────────────────────────

def apply_parsed(item: dict, parsed: dict, provider: str, model: str) -> None:
    item["ai_summary"] = str(parsed.get("ai_summary", "")).strip() or "AI analysis pending"
    raw_graph = str(parsed.get("workflow_graph", "")).strip()
    item["workflow_graph"] = postprocess_graph(raw_graph)
    raw_score = parsed.get("severity_score", None)
    try:
        score = float(raw_score)
        score = max(0.0, min(10.0, score))
    except (TypeError, ValueError):
        score = 5.0
    item["severity_score"] = round(score, 1)
    item["severity"] = ai_score_to_severity(score)
    item["ai_provider"] = provider
    item["ai_model"] = model

def set_fallback(item: dict) -> None:
    item.setdefault("ai_summary", "AI analysis pending")
    item.setdefault("workflow_graph", DEFAULT_WORKFLOW_GRAPH)
    item.setdefault("severity_score", None)
    item.setdefault("ai_provider", "none")
    item.setdefault("ai_model", "none")

_RULE_GRAPHS = {
    "cve": (
        "graph LR\n"
        "    A([Threat Actor]):::actor -->|CVE-Exploit| B[Initial Access]:::tactic\n"
        "    B -->|Execution| C[Impact]:::tactic\n"
        "    classDef actor fill:#1a0e2e,stroke:#a78bfa,color:#c9d8e8\n"
        "    classDef tactic fill:#0d2038,stroke:#4da6ff,color:#c9d8e8"
    ),
    "incident": (
        "graph LR\n"
        "    A([Threat Actor]):::actor -->|Attack| B[Intrusion]:::tactic\n"
        "    B -->|Breach| C[Impact]:::tactic\n"
        "    classDef actor fill:#1a0e2e,stroke:#a78bfa,color:#c9d8e8\n"
        "    classDef tactic fill:#0d2038,stroke:#4da6ff,color:#c9d8e8"
    ),
    "advisory": (
        "graph LR\n"
        "    A([Vendor]):::actor -->|Advisory| B[Patch]:::tactic\n"
        "    B -->|Mitigation| C[Remediation]:::tactic\n"
        "    classDef actor fill:#1a0e2e,stroke:#a78bfa,color:#c9d8e8\n"
        "    classDef tactic fill:#0d2038,stroke:#4da6ff,color:#c9d8e8"
    ),
}

_SEVERITY_SCORE_MAP = {
    "critical": 9.0,
    "high": 7.5,
    "medium": 5.0,
    "low": 2.5,
}

def rule_based_enrich(item: dict) -> None:
    """Fill summary, severity, and graph from the item's own fields — zero API cost."""
    title = item.get("title", "") or ""
    desc = item.get("description", "") or ""
    iocs = item.get("iocs") or {}

    # Summary: first ~3 sentences of description, or title fallback.
    summary = ""
    if desc:
        sentences = re.split(r"(?<=[.!?])\s+", desc.strip())
        summary = " ".join(sentences[:3])
    if not summary:
        summary = title[:300]
    summary = (summary or "No description available")[:500]

    # Append IOC counts.
    ioc_counts = {k: len(v) for k, v in iocs.items() if v}
    if ioc_counts:
        ioc_str = "; ".join(f"{k}: {c}" for k, c in sorted(ioc_counts.items()))
        summary += f" [IOCs: {ioc_str}]"

    # Severity via keyword matching.
    text = title + " " + desc
    sev = infer_severity(text)
    score = _SEVERITY_SCORE_MAP.get(sev, 5.0)

    # Category-appropriate workflow graph.
    cat = infer_category(text, "news")
    graph = _RULE_GRAPHS.get(cat, DEFAULT_WORKFLOW_GRAPH)

    item["ai_summary"] = summary
    item["workflow_graph"] = graph
    item["severity_score"] = score
    item["severity"] = sev
    item["ai_provider"] = "rule"
    item["ai_model"] = "rule-based"

def enrich_with_ai(items: list[dict]) -> list[dict]:
    # Phase 1: rule-based pre-fill on EVERY item so the dashboard never shows
    # empty summaries. AI will overwrite the highest-priority items in phase 2.
    log.info("Applying rule-based enrichment to all items...")
    for item in items:
        rule_based_enrich(item)
    log.info(f"  Rule-based summary set on {len(items)} items")

    if not GROQ_API_KEY and not GEMINI_API_KEY:
        log.info("No AI keys set — skipping AI enrichment")
        return items

    groq_available = bool(GROQ_API_KEY)
    gemini_available = bool(GEMINI_API_KEY)
    log.info(f"AI enrichment: gemini={gemini_available} groq={groq_available}")

    # Priority-sort: items with a priority_score get enriched first.
    candidates = [item for item in items if item.get("ai_provider") == "rule"]
    candidates.sort(key=lambda i: i.get("priority_score") or 0, reverse=True)
    to_enrich = candidates[:AI_ENRICH_LIMIT]
    log.info(f"  Enriching top {len(to_enrich)} priority items via AI...")

    for i, item in enumerate(to_enrich):
        prompt = build_prompt(item)
        enriched = False

        # Try Gemini first (more generous free tier).
        if gemini_available:
            raw, model = call_gemini(prompt)
            if raw:
                try:
                    parsed = parse_ai_response(raw)
                    apply_parsed(item, parsed, "gemini", model)
                    log.info(f"  [{i+1}/{len(to_enrich)}] Gemini ✓")
                    enriched = True
                except Exception as e:
                    log.warning(f"Gemini parse error: {e}")
        if not enriched and groq_available:
            time.sleep(3)
            raw, model = call_groq(prompt)
            if raw:
                try:
                    parsed = parse_ai_response(raw)
                    apply_parsed(item, parsed, "groq", model)
                    log.info(f"  [{i+1}/{len(to_enrich)}] Groq ✓")
                    enriched = True
                except Exception as e:
                    log.warning(f"Groq parse error: {e}")
        if not enriched:
            log.info(f"  [{i+1}/{len(to_enrich)}] AI skipped — keeping rule-based summary")
        if i < len(to_enrich) - 1:
            time.sleep(GROQ_SLEEP_SECS)

    ai_count = sum(1 for i in to_enrich if i.get("ai_provider") not in ("rule", "none"))
    log.info(f"AI enrichment complete: {ai_count}/{len(to_enrich)} overwritten by AI, "
             f"{len(items) - ai_count} using rule-based")
    return items

# ── RSS Fetcher ───────────────────────────────────────────────────────────────

def fetch_rss(source: dict) -> list[dict]:
    log.info(f"Fetching RSS: {source['name']}")
    items = []
    hdrs = {**HEADERS, **source.get("headers", {})}
    try:
        resp = requests.get(source["url"], headers=hdrs, timeout=15)
        resp.raise_for_status()
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
                "iocs": extract_iocs(text),
            })
    except Exception as e:
        log.error(f"Unexpected error {source['name']}: {e}")
    log.info(f"  Got {len(items)} items from {source['name']}")
    return items

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
            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}", "cve_id": cve_id,
            "source": "NVD", "category": "cve", "severity": severity,
            "cvss_score": cvss_score, "published": parse_date(cve.get("published", "")),
            "iocs": extract_iocs(description),
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
                "iocs": extract_iocs(title + " " + desc),
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
            "iocs": extract_iocs(name + " " + description),
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
            "url": f"https://www.spamhaus.org/drop/", "cve_id": None,
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

# ── OSV Vulnerability Fetcher (covers 25+ sources) ───────────────────────────

# OSV removed — the API no longer supports listing vulnerabilities per
# ecosystem without a specific package name, so it always returns 400.

def fetch_osv() -> list[dict]:
    log.info("OSV requires package names per ecosystem — no standalone listing API available, skipping.")
    return []

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
            iocs = {}
            if ":" in ioc and ioc.count(".") == 3:
                iocs["ipv4"] = [ioc.split(":")[0]]
            elif ioc.startswith("http"):
                iocs["url"] = [ioc]
            elif "." in ioc and " " not in ioc:
                iocs["domain"] = [ioc.lower()]
            else:
                iocs = extract_iocs(ioc)
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
                "iocs": extract_iocs(desc),
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
                    "description": clean_html(desc) or f"Fedora security update",
                    "url": update.get("url") or f"https://bodhi.fedoraproject.org/updates/{update_id}",
                    "cve_id": extract_cve_id(title + " " + desc), "source": "Fedora",
                    "category": "advisory", "severity": infer_severity(title, "medium"),
                    "cvss_score": None, "published": pub,
                    "iocs": extract_iocs(desc),
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
                desc = issue.get("issue_type", "") + ": " + issue.get("severity", "")
                pub = parse_date(issue.get("created_at", ""))
                items.append({
                    "title": f"Arch Linux: {title[:120]}",
                    "description": f"Type: {issue.get('issue_type','')} | Severity: {issue.get('severity','')} | Package: {issue.get('package','')}",
                    "url": f"https://security.archlinux.org/{issue.get('id','')}",
                    "cve_id": cve_id, "source": "Arch Linux",
                    "category": "advisory", "severity": infer_severity(title, "medium"),
                    "cvss_score": None, "published": pub,
                    "iocs": extract_iocs(title),
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
                        "iocs": extract_iocs(desc),
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
                "url": adv.get("url", adv.get("link", f"https://support.broadcom.com/web/ecx/security-advisory?segment=VC")),
                "cve_id": cve_id, "source": "VMware",
                "category": "advisory", "severity": infer_severity(title, "high"),
                "cvss_score": None, "published": pub,
                "iocs": extract_iocs(desc),
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
                    "iocs": extract_iocs(desc),
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
                "cve_id": adv.get("cve_id"),
                "source": "GitHub Advisories", "category": "cve",
                "severity": sev if sev in ("critical", "high", "medium", "low") else "medium",
                "cvss_score": cvss,
                "published": parse_date(adv.get("published_at", "")),
                "iocs": extract_iocs(desc),
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
            "cve_id": cve if cve.startswith("CVE-") else None,
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
            })
    except Exception as e:
        log.warning(f"Ransomware.live failed: {e}")
    log.info(f"  Got {len(items)} from Ransomware.live")
    return items

# ── Cached external data ──────────────────────────────────────────────────────
# EPSS scores and CISA KEV change at most daily. Cache them on disk so we don't
# re-fetch the same ~200 KB payloads every single pipeline run.

_CACHE_DIR = CONFIG.data_dir / ".cache"

def _cache_path(name: str) -> Path:
    _CACHE_DIR.mkdir(parents=True, exist_ok=True)
    return _CACHE_DIR / name

def _cached_fetch(name: str, ttl_hours: int, fetcher) -> str | None:
    """Return cached content (decoded text) if fresh, else call ``fetcher()``
    and cache the result atomically (write to tmp, then rename). ``fetcher``
    must return ``(content_str, None)`` on success or ``(None, error_str)``
    on failure."""
    path = _cache_path(name)
    # Check freshness.
    if path.exists():
        age = time.time() - path.stat().st_mtime
        if age < ttl_hours * 3600:
            log.info(f"  Cache HIT for {name} ({(age / 3600):.1f}h old)")
            return path.read_text(encoding="utf-8")
    # Fetch.
    content, err = fetcher()
    if content is not None:
        # Atomic write: temp file → rename to avoid partial reads.
        tmp = path.with_suffix(f".{os.getpid()}.tmp")
        tmp.write_text(content, encoding="utf-8")
        tmp.replace(path)
        return content
    # Fetch failed; try stale cache as fallback.
    if path.exists():
        log.warning(f"  Fetch failed for {name}, using stale cache: {err}")
        return path.read_text(encoding="utf-8")
    log.warning(f"  Fetch failed for {name} (no cache): {err}")
    return None

# ── EPSS Scoring ──────────────────────────────────────────────────────────────

def fetch_epss_scores(cve_ids: list[str]) -> dict[str, float]:
    if not cve_ids:
        return {}
    log.info(f"Fetching EPSS scores for {len(cve_ids)} CVEs...")
    cached = _cached_fetch("epss.json", 24, lambda: _fetch_epss_raw(cve_ids))
    if cached is None:
        return {}
    try:
        scores = json.loads(cached)
        log.info(f"  Got EPSS scores for {len(scores)} CVEs")
        return scores
    except Exception as e:
        log.warning(f"EPSS cache parse failed: {e}")
        return {}

def _fetch_epss_raw(cve_ids: list[str]) -> tuple[str | None, str | None]:
    try:
        cve_str = ",".join(cve_ids)
        resp = requests.get(
            f"https://api.first.org/data/v1/epss?cve={cve_str}",
            headers=HEADERS, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
        scores = {}
        for entry in data.get("data", []):
            cve = entry.get("cve", "")
            epss = entry.get("epss")
            if cve and epss is not None:
                scores[cve.upper()] = float(epss)
        return json.dumps(scores), None
    except Exception as e:
        return None, str(e)

# ── CISA KEV ──────────────────────────────────────────────────────────────────

def fetch_cisa_kev() -> set[str]:
    log.info("Fetching CISA KEV catalog...")
    cached = _cached_fetch("cisa_kev.json", 24, _fetch_cisa_kev_raw)
    if cached is None:
        return set()
    try:
        cves = set(json.loads(cached))
        log.info(f"  Got {len(cves)} CVEs in CISA KEV")
        return cves
    except Exception as e:
        log.warning(f"CISA KEV cache parse failed: {e}")
        return set()

def _fetch_cisa_kev_raw() -> tuple[str | None, str | None]:
    try:
        resp = requests.get(
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
        cves = [v.get("cveID", "").upper() for v in data.get("vulnerabilities", []) if v.get("cveID")]
        return json.dumps(cves), None
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

def compute_priority(item: dict) -> dict | None:
    """
    Blend CVSS (impact), EPSS (probability of exploitation) and CISA KEV
    (confirmed in-the-wild exploitation) into a single 0–100 "act on this first"
    score. Returns a small dict the frontend can badge/sort on, or None when the
    item has no CVE signal at all (so we don't score plain news items).

        score = cvss_weight * (cvss/10)
              + epss_weight * epss
              + kev_bonus       (only if CISA KEV)

    KEV items are additionally floored at 90 — a vuln CISA has confirmed is being
    exploited should always sort to the top regardless of its CVSS/EPSS.
    """
    cvss = item.get("cvss_score")
    epss = item.get("epss_score")
    kev  = bool(item.get("cisa_kev"))
    poc  = bool(item.get("has_poc"))

    if cvss is None and epss is None and not kev and not poc:
        return None

    try:
        cvss_val = float(cvss) if cvss is not None else 0.0
    except (TypeError, ValueError):
        cvss_val = 0.0
    try:
        epss_val = float(epss) if epss is not None else 0.0
    except (TypeError, ValueError):
        epss_val = 0.0

    cvss_val = max(0.0, min(10.0, cvss_val))
    epss_val = max(0.0, min(1.0, epss_val))

    score = (CONFIG.priority_cvss_weight * (cvss_val / 10.0)
             + CONFIG.priority_epss_weight * epss_val)
    if poc:
        # Public exploit code exists — weaponization is one git clone away.
        score += CONFIG.priority_poc_bonus
        score = max(score, 70.0)
    if kev:
        score += CONFIG.priority_kev_bonus
        score = max(score, 90.0)

    score = round(max(0.0, min(100.0, score)), 1)

    if score >= 90:   label = "urgent"
    elif score >= 70: label = "elevated"
    elif score >= 40: label = "moderate"
    else:             label = "low"

    # Human-readable driver of the score, shown in a tooltip.
    reasons = []
    if kev:
        reasons.append("CISA KEV (actively exploited)")
    if poc:
        reasons.append("Public PoC on GitHub")
    if epss is not None:
        reasons.append(f"EPSS {epss_val * 100:.1f}%")
    if cvss is not None:
        reasons.append(f"CVSS {cvss_val:.1f}")

    return {"score": score, "label": label, "rationale": " · ".join(reasons)}

def infer_severity(text: str, default: str = "medium") -> str:
    t = text.lower()
    if any(kw in t for kw in ["critical","zero-day","0-day","actively exploited","rce","remote code execution","unauthenticated","wormable"]):
        return "critical"
    if any(kw in t for kw in ["high","privilege escalation","authentication bypass","ransomware","data breach","nation-state","apt"]):
        return "high"
    if any(kw in t for kw in ["medium","xss","csrf","injection","phishing","malware"]):
        return "medium"
    if any(kw in t for kw in ["low","informational","advisory","guide"]):
        return "low"
    return default

def infer_category(text: str, default: str = "news") -> str:
    t = text.lower()
    if any(kw in t for kw in ["cve-","vulnerability","patch","exploit","nvd"]):
        return "cve"
    if any(kw in t for kw in ["breach","attack","ransomware","hack","intrusion","stolen","compromised","leaked","incident"]):
        return "incident"
    if any(kw in t for kw in ["advisory","alert","directive","guidance","warning","cisa","recommendation","patch tuesday"]):
        return "advisory"
    return default

def extract_cve_id(text: str) -> str | None:
    match = re.search(r"CVE-\d{4}-\d{4,7}", text, re.IGNORECASE)
    return match.group(0).upper() if match else None

# ── IOC Extraction Engine ─────────────────────────────────────────────────────

IOC_PATTERNS = {
    'sha256': re.compile(r'\b[a-fA-F0-9]{64}\b'),
    'sha1':   re.compile(r'\b[a-fA-F0-9]{40}\b'),
    'md5':    re.compile(r'\b[a-fA-F0-9]{32}\b'),
    'ipv4':   re.compile(r'(?<![0-9])(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?![0-9])'),
    'domain': re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'),
    'url':    re.compile(r'https?://[^\s<>"\'{}|\\^`\[\]]+', re.I),
    'cve':    re.compile(r'CVE-\d{4}-\d{4,7}', re.I),
    'cidr':   re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b'),
    'email':  re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'),
}

def extract_iocs(text: str) -> dict[str, list[str]]:
    if not text:
        return {k: [] for k in IOC_PATTERNS}
    result = {}
    text_clean = text.replace('[.]', '.').replace('hxxp', 'http').replace('hxxps', 'https').replace('[at]', '@')
    for ioc_type, pattern in IOC_PATTERNS.items():
        matches = pattern.findall(text_clean)
        seen = set()
        unique = []
        for m in matches:
            m = m.strip().lower()
            if m not in seen and len(m) > 2:
                # Filter private IPs for ipv4
                if ioc_type == 'ipv4':
                    parts = m.split('.')
                    if parts[0] in ('10', '127') or (parts[0] == '172' and 16 <= int(parts[1]) <= 31) or (parts[0] == '192' and parts[1] == '168'):
                        continue
                seen.add(m)
                unique.append(m)
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
    ("OSV",            fetch_osv),
    ("MalwareBazaar",  fetch_malwarebazaar),
    ("ThreatFox",      fetch_threatfox),
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

def run_source(name: str, fetcher, health: dict) -> list[dict]:
    """
    Invoke a single fetcher, capturing timing + outcome into ``health`` so a
    silently-dead feed (0 items or an exception) becomes visible in the output
    instead of just vanishing. Never raises — a broken source can't abort the run.
    """
    started = time.monotonic()
    try:
        items = fetcher() or []
        elapsed = round(time.monotonic() - started, 2)
        status = "ok" if items else "empty"
        health[name] = {"status": status, "count": len(items), "elapsed_s": elapsed, "error": None}
        return items
    except Exception as e:
        elapsed = round(time.monotonic() - started, 2)
        log.error(f"Source '{name}' failed: {e}")
        health[name] = {"status": "error", "count": 0, "elapsed_s": elapsed, "error": str(e)[:200]}
        return []


def main():
    log.info("═" * 60)
    log.info("CYBERWATCH v2.3 — Starting intel pipeline")
    log.info("═" * 60)

    all_items = []
    source_health: dict[str, dict] = {}
    _lock = threading.Lock()

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

    # ── Persist source health history ─────────────────────────────────────
    try:
        health_path = CONFIG.data_dir / "source_health_history.jsonl"
        health_record = json.dumps({
            "timestamp": now_utc(), "health": source_health,
        })
        with open(health_path, "a", encoding="utf-8") as f:
            f.write(health_record + "\n")
    except Exception as e:
        log.warning(f"Could not write source health history: {e}")

    dead = [n for n, h in source_health.items() if h["status"] != "ok"]
    if dead:
        log.warning(f"Sources with no data this run: {', '.join(dead)}")

    # ── Deduplicate + sort ──────────────────────────────────────────────────
    before_dedup = len(all_items)
    all_items = deduplicate(all_items)
    log.info(f"Deduplicated {before_dedup} → {len(all_items)} items")
    all_items.sort(key=lambda x: x.get("published", ""), reverse=True)
    log.info(f"Total raw items after dedup: {len(all_items)}")

    # ── Map MITRE ATT&CK TTPs ──────────────────────────────────────────────
    log.info("Mapping MITRE ATT&CK TTPs...")
    for item in all_items:
        item["ttps"] = map_ttps(item.get("title", "") + " " + item.get("description", ""))
    ttp_total = sum(len(i["ttps"]) for i in all_items)
    log.info(f"  Mapped {ttp_total} TTP associations across {len(all_items)} items")

    # ── Fetch EPSS scores ──────────────────────────────────────────────────
    cve_ids = [item["cve_id"] for item in all_items if item.get("cve_id")]
    if cve_ids:
        epss_scores = fetch_epss_scores(cve_ids)
        for item in all_items:
            if item.get("cve_id"):
                item["epss_score"] = epss_scores.get(item["cve_id"].upper())
        log.info(f"  Applied EPSS scores")

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

    # ── CVE prioritization score (CVSS + EPSS + CISA KEV + public PoC) ─────
    prioritized = 0
    for item in all_items:
        priority = compute_priority(item)
        if priority:
            item["priority_score"] = priority["score"]
            item["priority_label"] = priority["label"]
            item["priority_rationale"] = priority["rationale"]
            prioritized += 1
    log.info(f"  Scored priority for {prioritized} items")

    # ── Flag items not seen in the previous run (accurate "NEW") ───────────
    new_count = mark_new_since_last(all_items)
    log.info(f"  Flagged {new_count} items as new since last run")

    # ── AI Enrichment ──────────────────────────────────────────────────────
    try:
        all_items = enrich_with_ai(all_items)
    except Exception as e:
        log.error(f"AI enrichment failed: {e}")
        for item in all_items:
            set_fallback(item)

    # ── Source breakdown ───────────────────────────────────────────────────
    source_counter = Counter(i.get("source", "Unknown") for i in all_items)

    # ── Write output ───────────────────────────────────────────────────────
    output = {
        "last_updated": now_utc(),
        "total_items": len(all_items),
        "pipeline_version": "2.4.0",
        "sources_fetched": len(RSS_SOURCES) + len(API_SOURCES),
        "sources_ok": sum(1 for h in source_health.values() if h["status"] == "ok"),
        "ai_provider_configured": bool(GROQ_API_KEY) or bool(GEMINI_API_KEY),
        "source_breakdown": dict(source_counter.most_common()),
        "source_health": source_health,
        "items": all_items,
    }

    today_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    # ── Archive first (crash-safe: if this fails, intel.json is untouched) ──
    archive_path = ARCHIVE_DIR / f"{today_str}.json"
    ARCHIVE_DIR.mkdir(parents=True, exist_ok=True)
    with open(archive_path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    log.info(f"✓ Archived to {archive_path}")

    # ── Write intel.json atomically (tmp → rename) ────────────────────────
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = OUTPUT_PATH.with_suffix(f".{os.getpid()}.tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
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
            written = write_exports(output, CONFIG.export_dir)
            log.info(f"✓ Wrote exports: {', '.join(written)}")
        except Exception as e:
            log.error(f"Export generation failed: {e}")

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
        except Exception as e:
            log.error(f"Alert dispatch failed: {e}")

    log.info("═" * 60)
    log.info(f"CYBERWATCH — Complete. {len(all_items)} items from {len(source_counter)} sources.")
    for src, cnt in source_counter.most_common():
        log.info(f"  {src}: {cnt}")
    log.info("═" * 60)


if __name__ == "__main__":
    main()
