"""
CYBERWATCH DASHBOARD — fetch_intel.py
======================================
Fetches threat intelligence from multiple free sources:
  - 15 RSS feeds          → News, advisories, incident reports
  - NVD (NIST) CVE API    → Latest vulnerabilities
  - Reddit r/netsec       → Community intel
  - AlienVault OTX API    → Threat pulses (API key)
  - URLhaus               → Malware URLs & payload hashes (keyless)
  - Spamhaus DROP         → Malicious IP ranges (keyless)
  - Feodo Tracker         → C2 server IPs (keyless)
  - AbuseIPDB             → IP blacklist (API key)
  - PhishTank             → Phishing URLs (API key)
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

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S"
)
log = logging.getLogger("cyberwatch")

# ── Configuration ─────────────────────────────────────────────────────────────
PROJECT_ROOT         = Path(__file__).resolve().parent.parent
OUTPUT_PATH          = PROJECT_ROOT / "data/intel.json"
ARCHIVE_DIR          = PROJECT_ROOT / "data/archive"
MAX_ITEMS_PER_SOURCE = 10
NVD_LOOKBACK_DAYS    = 10
REQUEST_TIMEOUT      = 30
AI_ENRICH_LIMIT      = 15
ARCHIVE_RETENTION_DAYS = 90

# API keys (set as environment variables)
OTX_API_KEY      = os.environ.get("OTX_API_KEY", "")
GROQ_API_KEY     = os.environ.get("GROQ_API_KEY", "")
GEMINI_API_KEY   = os.environ.get("GEMINI_API_KEY", "")
ABUSEIPDB_KEY    = os.environ.get("ABUSEIPDB_API_KEY", "")
PHISHTANK_KEY    = os.environ.get("PHISHTANK_API_KEY", "")

GROQ_MODEL_PRIMARY  = "llama-3.3-70b-versatile"
GROQ_MODEL_FALLBACK = "llama-3.1-8b-instant"
GEMINI_MODEL        = "gemini-2.5-flash-lite"
GROQ_SLEEP_SECS     = 3
GEMINI_SLEEP_SECS   = 6

HEADERS = {"User-Agent": "CyberWatch/2.0 (macOS dashboard)"}

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
    raw = raw.strip()
    raw = re.sub(r"^```(?:json)?\s*\n?", "", raw, flags=re.MULTILINE)
    raw = re.sub(r"\n?```\s*$", "", raw, flags=re.MULTILINE)
    raw = raw.strip()
    json_match = re.search(r'\{.*\}', raw, re.DOTALL)
    if json_match:
        raw = json_match.group(0)
    return json.loads(raw)

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
        })
    log.info(f"  Got {len(items)} phishing URLs from PhishTank")
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

def detect_threat_actors(text: str) -> list[str]:
    text_lower = text.lower()
    actors = []
    for actor, keywords in THREAT_ACTORS.items():
        for kw in keywords:
            if kw in text_lower:
                actors.append(actor)
                break
    return list(set(actors))

# ── Intel Inference Helpers ───────────────────────────────────────────────────

def cvss_to_severity(score) -> str:
    if score is None: return "medium"
    if score >= 9.0: return "critical"
    if score >= 7.0: return "high"
    if score >= 4.0: return "medium"
    return "low"

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

def deduplicate(items: list[dict]) -> list[dict]:
    seen, unique = set(), []
    for item in items:
        key = item["title"].lower().strip()[:80]
        if key not in seen:
            seen.add(key)
            unique.append(item)
    return unique

# ── Main Pipeline ────────────────────────────────────────────────────────────

def main():
    log.info("═" * 60)
    log.info("CYBERWATCH v2.1 — Starting intel pipeline (16 RSS + 7 API sources)")
    log.info("═" * 60)

    all_items = []

    # 1. RSS feeds (15 sources)
    for source in RSS_SOURCES:
        try:
            all_items.extend(fetch_rss(source))
        except Exception as e:
            log.error(f"Failed {source['name']}: {e}")
        time.sleep(0.5)

    # 2. NVD CVE API
    try:
        all_items.extend(fetch_nvd_cves())
    except Exception as e:
        log.error(f"NVD failed: {e}")
    time.sleep(1)

    # 3. Reddit r/netsec
    try:
        all_items.extend(fetch_reddit_netsec())
    except Exception as e:
        log.error(f"Reddit failed: {e}")
    time.sleep(1)

    # 4. AlienVault OTX
    try:
        all_items.extend(fetch_otx_pulse())
    except Exception as e:
        log.error(f"OTX failed: {e}")
    time.sleep(1)

    # 5. URLhaus (keyless)
    try:
        all_items.extend(fetch_urlhaus())
    except Exception as e:
        log.error(f"URLhaus failed: {e}")
    time.sleep(1)

    # 6. Spamhaus DROP (keyless)
    try:
        all_items.extend(fetch_spamhaus_drop())
    except Exception as e:
        log.error(f"Spamhaus failed: {e}")
    time.sleep(1)

    # 7. Feodo Tracker (keyless)
    try:
        all_items.extend(fetch_feodo())
    except Exception as e:
        log.error(f"Feodo failed: {e}")
    time.sleep(1)

    # 8. AbuseIPDB (API key)
    try:
        all_items.extend(fetch_abuseipdb())
    except Exception as e:
        log.error(f"AbuseIPDB failed: {e}")
    time.sleep(1)

    # 9. PhishTank (API key)
    try:
        all_items.extend(fetch_phishtank())
    except Exception as e:
        log.error(f"PhishTank failed: {e}")

    # ── Deduplicate + sort ──────────────────────────────────────────────────
    all_items = deduplicate(all_items)
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
        "pipeline_version": "2.1.0",
        "sources_fetched": len(RSS_SOURCES) + 7,
        "ai_provider_configured": bool(GROQ_API_KEY) or bool(GEMINI_API_KEY),
        "source_breakdown": dict(source_counter.most_common()),
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

    log.info("═" * 60)
    log.info(f"CYBERWATCH — Complete. {len(all_items)} items from {len(source_counter)} sources.")
    for src, cnt in source_counter.most_common():
        log.info(f"  {src}: {cnt}")
    log.info("═" * 60)


if __name__ == "__main__":
    main()
