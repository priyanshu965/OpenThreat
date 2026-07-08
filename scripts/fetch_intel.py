"""
CYBERWATCH DASHBOARD — fetch_intel.py
======================================
Fetches threat intelligence from multiple free sources:
  - 16 RSS feeds          → News, advisories, incident reports
  - NVD (NIST) CVE API    → Latest vulnerabilities
  - Reddit r/netsec       → Community intel (public/403)
  - AlienVault OTX API    → Threat pulses (API key)
  - URLhaus               → Malware URLs & payload hashes (keyless)
  - Spamhaus DROP         → Malicious IP ranges (keyless)
  - Feodo Tracker         → C2 server IPs (keyless)
  - AbuseIPDB             → IP blacklist (API key)
  - PhishTank             → Phishing URLs (API key)
  - OSV (Open Source Vulns) → 25+ ecosystem databases (keyless)
  - MalwareBazaar         → Malware samples (keyless)
  - ThreatFox             → C2 IOCs (keyless)
  - MSRC                  → Microsoft advisories (RSS)
  - Fedora Bodhi          → Fedora security updates (API)
  - Gentoo GLSA           → Gentoo advisories (RSS)
  - Arch Linux            → Arch security issues (JSON)
  - Oracle Linux          → Oracle advisories (RSS)
  - Amazon Linux          → ALAS advisories (RSS)
  - CentOS                → CentOS announcements (RSS)
  - VMware                → VMware security advisories (RSS)
  - Mitre CWE             → CWE taxonomy (API)
  - IOC Extraction        → Regex-based from all item descriptions
  - AI Enrichment         → Groq (primary) with Gemini fallback

Output: data/intel.json  +  data/archive/YYYY-MM-DD.json
"""

import json, os, re, sys, time, logging
from datetime import datetime, timezone, timedelta
from pathlib import Path
from collections import Counter

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
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S"
)
log = logging.getLogger("cyberwatch")

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
OTX_API_KEY      = CONFIG.otx_api_key
GROQ_API_KEY     = CONFIG.groq_api_key
GEMINI_API_KEY   = CONFIG.gemini_api_key
ABUSEIPDB_KEY    = CONFIG.abuseipdb_api_key
PHISHTANK_KEY    = CONFIG.phishtank_api_key

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
    {"name": "CISA",             "url": "https://www.cisa.gov/news.xml",                         "category": "advisory", "severity": "high"},
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
    {"name": "GBHackers",        "url": "https://gbhackers.com/feed/",                            "category": "news",     "severity": "medium"},
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

def enrich_with_ai(items: list[dict]) -> list[dict]:
    if not GROQ_API_KEY and not GEMINI_API_KEY:
        log.info("No AI keys set — skipping enrichment")
        for item in items:
            set_fallback(item)
        return items
    groq_available = bool(GROQ_API_KEY)
    gemini_available = bool(GEMINI_API_KEY)
    log.info(f"AI enrichment: groq={groq_available} gemini={gemini_available}")
    items_to_process = [item for item in items if item.get("ai_summary", "") in ("", "AI analysis pending")][:AI_ENRICH_LIMIT]
    log.info(f"  Enriching {len(items_to_process)} items via AI...")
    for i, item in enumerate(items_to_process):
        prompt = build_prompt(item)
        enriched = False
        if groq_available:
            raw, model = call_groq(prompt)
            if raw:
                try:
                    parsed = parse_ai_response(raw)
                    apply_parsed(item, parsed, "groq", model)
                    log.info(f"  [{i+1}/{len(items_to_process)}] Groq ✓")
                    enriched = True
                except Exception as e:
                    log.warning(f"Groq parse error: {e}")
        if not enriched and gemini_available:
            time.sleep(6)
            raw, model = call_gemini(prompt)
            if raw:
                try:
                    parsed = parse_ai_response(raw)
                    apply_parsed(item, parsed, "gemini", model)
                    log.info(f"  [{i+1}/{len(items_to_process)}] Gemini ✓")
                    enriched = True
                except Exception as e:
                    log.warning(f"Gemini parse error: {e}")
        if not enriched:
            set_fallback(item)
            log.warning(f"  [{i+1}/{len(items_to_process)}] AI failed — fallback")
        if i < len(items_to_process) - 1:
            time.sleep(GROQ_SLEEP_SECS)
    enriched_count = sum(1 for i in items_to_process if i.get("ai_provider") not in ("", "none"))
    log.info(f"AI enrichment complete: {enriched_count}/{len(items_to_process)} enriched")
    return items

# ── RSS Fetcher ───────────────────────────────────────────────────────────────

def fetch_rss(source: dict) -> list[dict]:
    log.info(f"Fetching RSS: {source['name']}")
    items = []
    try:
        resp = requests.get(source["url"], headers=HEADERS, timeout=15)
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
    data = make_request("https://services.nvd.nist.gov/rest/json/cves/2.0", params={
        "pubStartDate": start_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate": end_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": MAX_ITEMS_PER_SOURCE,
    })
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
        items.append({
            "title": f"{cve_id}: {description[:80]}...", "description": description,
            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}", "cve_id": cve_id,
            "source": "NVD", "category": "cve", "severity": severity,
            "cvss_score": cvss_score, "published": parse_date(cve.get("published", "")),
            "iocs": extract_iocs(description),
        })
    log.info(f"  Got {len(items)} CVEs from NVD")
    return items

# ── Reddit r/netsec Fetcher ───────────────────────────────────────────────────

def fetch_reddit_netsec() -> list[dict]:
    log.info("Fetching Reddit r/netsec...")
    items = []
    data = make_request("https://www.reddit.com/r/netsec.json?limit=15",
                        headers={**HEADERS, "User-Agent": "CyberWatch/2.0 (macOS)"})
    if not data:
        return items
    for post in data.get("data", {}).get("children", []):
        p = post.get("data", {})
        if p.get("stickied"):
            continue
        title = p.get("title", "Untitled")
        created = p.get("created_utc")
        published = datetime.fromtimestamp(created, tz=timezone.utc).isoformat() if created else now_utc()
        items.append({
            "title": title, "description": clean_html(p.get("selftext", "")) or f"Reddit (score: {p.get('score',0)})",
            "url": p.get("url", ""), "cve_id": extract_cve_id(title),
            "source": "Reddit/netsec", "category": infer_category(title, "news"),
            "severity": infer_severity(title, "low"), "cvss_score": None, "published": published,
            "iocs": extract_iocs(title + " " + p.get("selftext","")),
        })
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

OSV_ECOSYSTEMS = [
    "Debian", "Ubuntu", "Alpine", "Red Hat", "SUSE", "openSUSE",
    "AlmaLinux", "Rocky Linux", "Azure Linux", "Chainguard", "Wolfi",
    "PyPI", "RubyGems", "crates.io", "Packagist", "Go", "npm",
    "Maven", "NuGet", "GitHub Actions", "OSS-Fuzz", "Linux Kernel",
    "Android", "Homebrew", "VSCode", "Haskell", "Hex", "Pub",
]

def fetch_osv() -> list[dict]:
    log.info("Fetching OSV vulnerabilities...")
    items = []
    for eco in OSV_ECOSYSTEMS:
        try:
            resp = requests.post(
                "https://api.osv.dev/v1/query",
                json={"ecosystem": eco, "page_size": 10},
                headers=HEADERS, timeout=15
            )
            resp.raise_for_status()
            data = resp.json()
            for vuln_id in data.get("vulns", []):
                try:
                    detail = requests.get(f"https://api.osv.dev/v1/vulns/{vuln_id['id']}", headers=HEADERS, timeout=10)
                    detail.raise_for_status()
                    v = detail.json()
                except:
                    continue
                title = v.get("summary", v.get("id", "Unknown"))
                desc = v.get("details", "")[:500]
                aliases = v.get("aliases", [])
                cve_id = next((a for a in aliases if a.startswith("CVE-")), None)
                severity = "medium"
                if v.get("database_specific", {}).get("severity"):
                    severity = v["database_specific"]["severity"].lower()
                items.append({
                    "title": f"[{eco}] {title[:150]}",
                    "description": clean_html(desc),
                    "url": f"https://osv.dev/vulnerability/{v['id']}",
                    "cve_id": cve_id, "source": "OSV",
                    "category": "cve", "severity": severity,
                    "cvss_score": None,
                    "published": parse_date(v.get("published", "")),
                    "iocs": extract_iocs(title + " " + desc),
                    "ecosystem": eco,
                })
            time.sleep(0.5)
        except Exception as e:
            log.warning(f"OSV ecosystem '{eco}' failed: {e}")
    log.info(f"  Got {len(items)} vulns from OSV ({len(OSV_ECOSYSTEMS)} ecosystems)")
    return items

# ── MalwareBazaar Fetcher (keyless) ──────────────────────────────────────────

def fetch_malwarebazaar() -> list[dict]:
    log.info("Fetching MalwareBazaar recent samples...")
    items = []
    try:
        resp = requests.post(
            "https://mb-api.abuse.ch/api/v1/",
            data={"query": "get_recent", "selector": "time"},
            headers=HEADERS, timeout=15
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
    log.info("Fetching ThreatFox recent IOCs...")
    items = []
    try:
        resp = requests.post(
            "https://threatfox-api.abuse.ch/api/v1/",
            json={"query": "recent", "limit": MAX_ITEMS_PER_SOURCE},
            headers=HEADERS, timeout=15
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

# ── MSRC Fetcher (RSS) ───────────────────────────────────────────────────────

def fetch_msrc() -> list[dict]:
    log.info("Fetching MSRC advisories...")
    items = []
    try:
        resp = requests.get("https://msrc.microsoft.com/update-guide/rss", headers=HEADERS, timeout=15)
        resp.raise_for_status()
        feed = feedparser.parse(resp.text)
        for entry in feed.entries[:MAX_ITEMS_PER_SOURCE]:
            title = entry.get("title", "MSRC Advisory")
            link = entry.get("link", "")
            desc = clean_html(entry.get("summary", ""))[:500]
            pub = parse_date(entry.get("published_parsed"))
            items.append({
                "title": title, "description": desc, "url": link,
                "cve_id": extract_cve_id(title + " " + desc), "source": "MSRC",
                "category": "advisory", "severity": infer_severity(title, "high"),
                "cvss_score": None, "published": pub,
                "iocs": extract_iocs(title + " " + desc),
            })
    except Exception as e:
        log.warning(f"MSRC failed: {e}")
    log.info(f"  Got {len(items)} from MSRC")
    return items

# ── Fedora Bodhi Fetcher ────────────────────────────────────────────────────

def fetch_fedora() -> list[dict]:
    log.info("Fetching Fedora updates...")
    items = []
    try:
        data = make_request("https://bodhi.fedoraproject.org/updates/?limit=10&status=stable&type=security")
        if data:
            for update in data.get("updates", [])[:MAX_ITEMS_PER_SOURCE]:
                title = update.get("title", update.get("updateid", "Fedora Update"))
                desc = update.get("notes", "")[:400]
                pub = parse_date(update.get("date_submitted", ""))
                items.append({
                    "title": f"Fedora: {title[:100]}",
                    "description": clean_html(desc) or f"Fedora security update",
                    "url": f"https://bodhi.fedoraproject.org/updates/{title}",
                    "cve_id": extract_cve_id(title + " " + desc), "source": "Fedora",
                    "category": "advisory", "severity": infer_severity(title, "medium"),
                    "cvss_score": None, "published": pub,
                    "iocs": extract_iocs(desc),
                })
    except Exception as e:
        log.warning(f"Fedora failed: {e}")
    log.info(f"  Got {len(items)} from Fedora")
    return items

# ── Gentoo GLSA Fetcher (RSS) ──────────────────────────────────────────────

def fetch_gentoo() -> list[dict]:
    log.info("Fetching Gentoo GLSAs...")
    items = []
    try:
        resp = requests.get("https://security.gentoo.org/glsa/rss/", headers=HEADERS, timeout=15)
        resp.raise_for_status()
        feed = feedparser.parse(resp.text)
        for entry in feed.entries[:MAX_ITEMS_PER_SOURCE]:
            title = entry.get("title", "Gentoo GLSA")
            link = entry.get("link", "")
            desc = clean_html(entry.get("summary", ""))[:400]
            pub = parse_date(entry.get("published_parsed"))
            items.append({
                "title": title, "description": desc, "url": link,
                "cve_id": extract_cve_id(title + " " + desc), "source": "Gentoo",
                "category": "advisory", "severity": infer_severity(title, "medium"),
                "cvss_score": None, "published": pub,
                "iocs": extract_iocs(desc),
            })
    except Exception as e:
        log.warning(f"Gentoo failed: {e}")
    log.info(f"  Got {len(items)} from Gentoo")
    return items

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

# ── Oracle Linux Fetcher ───────────────────────────────────────────────────

def fetch_oracle_linux() -> list[dict]:
    log.info("Fetching Oracle Linux advisories...")
    items = []
    try:
        resp = requests.get("https://linux.oracle.com/security/oval/", headers=HEADERS, timeout=15)
        resp.raise_for_status()
        feed = feedparser.parse(resp.text)
        for entry in feed.entries[:MAX_ITEMS_PER_SOURCE]:
            title = entry.get("title", "Oracle Advisory")
            link = entry.get("link", "")
            desc = clean_html(entry.get("summary", ""))[:400]
            pub = parse_date(entry.get("published_parsed"))
            items.append({
                "title": title, "description": desc, "url": link,
                "cve_id": extract_cve_id(title + " " + desc), "source": "Oracle Linux",
                "category": "advisory", "severity": infer_severity(title, "medium"),
                "cvss_score": None, "published": pub,
                "iocs": extract_iocs(desc),
            })
    except Exception as e:
        log.warning(f"Oracle Linux failed: {e}")
    log.info(f"  Got {len(items)} from Oracle Linux")
    return items

# ── Amazon Linux Fetcher ───────────────────────────────────────────────────

def fetch_amazon_linux() -> list[dict]:
    log.info("Fetching Amazon Linux advisories...")
    items = []
    try:
        for alas_type in ["ALAS-2025", "ALAS2-2025"]:
            resp = requests.get(f"https://alas.aws.amazon.com/alas/{alas_type}.xml", headers=HEADERS, timeout=15)
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
    except Exception as e:
        log.warning(f"Amazon Linux failed: {e}")
    log.info(f"  Got {len(items)} from Amazon Linux")
    return items

# ── CentOS Announce Fetcher ────────────────────────────────────────────────

def fetch_centos() -> list[dict]:
    log.info("Fetching CentOS announcements...")
    items = []
    try:
        resp = requests.get("https://lists.centos.org/pipermail/centos-announce/", headers=HEADERS, timeout=15)
        resp.raise_for_status()
        feed = feedparser.parse(resp.text)
        for entry in feed.entries[:MAX_ITEMS_PER_SOURCE]:
            title = entry.get("title", "CentOS Announce")
            link = entry.get("link", "")
            desc = clean_html(entry.get("summary", ""))[:400]
            pub = parse_date(entry.get("published_parsed"))
            items.append({
                "title": title, "description": desc, "url": link,
                "cve_id": extract_cve_id(title + " " + desc), "source": "CentOS",
                "category": "advisory", "severity": infer_severity(title, "medium"),
                "cvss_score": None, "published": pub,
                "iocs": extract_iocs(desc),
            })
    except Exception as e:
        log.warning(f"CentOS failed: {e}")
    log.info(f"  Got {len(items)} from CentOS")
    return items

# ── VMware Security Fetcher ───────────────────────────────────────────────

def fetch_vmware() -> list[dict]:
    log.info("Fetching VMware security advisories...")
    items = []
    try:
        resp = requests.get("https://www.vmware.com/security/advisories/rss.xml", headers=HEADERS, timeout=15)
        resp.raise_for_status()
        feed = feedparser.parse(resp.text)
        for entry in feed.entries[:MAX_ITEMS_PER_SOURCE]:
            title = entry.get("title", "VMware Advisory")
            link = entry.get("link", "")
            desc = clean_html(entry.get("summary", ""))[:400]
            pub = parse_date(entry.get("published_parsed"))
            items.append({
                "title": title, "description": desc, "url": link,
                "cve_id": extract_cve_id(title + " " + desc), "source": "VMware",
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
        data = make_request("https://cwe-api.mitre.org/api/v1/cwe/weaknesses?limit=10&offset=0")
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

# ── EPSS Scoring ──────────────────────────────────────────────────────────────

def fetch_epss_scores(cve_ids: list[str]) -> dict[str, float]:
    if not cve_ids:
        return {}
    log.info(f"Fetching EPSS scores for {len(cve_ids)} CVEs...")
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
        log.info(f"  Got EPSS scores for {len(scores)} CVEs")
        return scores
    except Exception as e:
        log.warning(f"EPSS fetch failed: {e}")
        return {}

# ── CISA KEV ──────────────────────────────────────────────────────────────────

def fetch_cisa_kev() -> set[str]:
    log.info("Fetching CISA KEV catalog...")
    try:
        resp = requests.get(
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
        cves = set()
        for vuln in data.get("vulnerabilities", []):
            cve_id = vuln.get("cveID", "")
            if cve_id:
                cves.add(cve_id.upper())
        log.info(f"  Got {len(cves)} CVEs in CISA KEV")
        return cves
    except Exception as e:
        log.warning(f"CISA KEV fetch failed: {e}")
        return set()

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

    if cvss is None and epss is None and not kev:
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
    ("Oracle Linux",   fetch_oracle_linux),
    ("Amazon Linux",   fetch_amazon_linux),
    ("CentOS",         fetch_centos),
    ("Mitre CWE",      fetch_mitre_cwe),
    ("VMware",         fetch_vmware),
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

    # 1. RSS feeds — each tracked individually by feed name.
    for source in RSS_SOURCES:
        all_items.extend(run_source(source["name"], lambda s=source: fetch_rss(s), source_health))
        time.sleep(CONFIG.inter_source_sleep)

    # 2. API / custom fetchers.
    for name, fetcher in API_SOURCES:
        all_items.extend(run_source(name, fetcher, source_health))
        time.sleep(1)

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

    # ── CISA KEV ───────────────────────────────────────────────────────────
    cisa_kev = fetch_cisa_kev()
    if cisa_kev:
        kev_count = 0
        for item in all_items:
            if item.get("cve_id") and item["cve_id"].upper() in cisa_kev:
                item["cisa_kev"] = True
                kev_count += 1
        log.info(f"  Marked {kev_count} CVEs from CISA KEV")

    # ── Detect threat actors ───────────────────────────────────────────────
    log.info("Detecting threat actors...")
    actor_count = 0
    for item in all_items:
        text = item.get("title", "") + " " + item.get("description", "")
        actors = detect_threat_actors(text)
        if actors:
            item["threat_actors"] = actors
            actor_count += 1
    log.info(f"  Detected threat actors in {actor_count} items")

    # ── CVE prioritization score (blend of CVSS + EPSS + CISA KEV) ─────────
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
        "pipeline_version": "2.3.0",
        "sources_fetched": len(RSS_SOURCES) + len(API_SOURCES),
        "sources_ok": sum(1 for h in source_health.values() if h["status"] == "ok"),
        "ai_provider_configured": bool(GROQ_API_KEY) or bool(GEMINI_API_KEY),
        "source_breakdown": dict(source_counter.most_common()),
        "source_health": source_health,
        "items": all_items,
    }

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    log.info(f"✓ Wrote {len(all_items)} items to {OUTPUT_PATH}")

    today_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    archive_path = ARCHIVE_DIR / f"{today_str}.json"
    ARCHIVE_DIR.mkdir(parents=True, exist_ok=True)
    with open(archive_path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    log.info(f"✓ Archived to {archive_path}")

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
