# CyberWatch

A free, self-updating cybersecurity threat intelligence dashboard. Aggregates
CVEs, advisories, incidents, and news from 15+ sources into a single interface.
Runs daily via GitHub Actions — zero infrastructure needed.

## Features

- **15+ data sources** — NVD, CISA, MSRC, OSV, Gentoo, Oracle Linux, CentOS,
  VMware, AlienVault OTX, The Hacker News, Bleeping Computer, Krebs, SANS,
  Reddit r/netsec, TheRecord
- **Rule-based enrichment** on every item — 3‑sentence summary, IOC extraction
  (IPs, hashes), severity inference, category-appropriate Mermaid graphs
- **AI enrichment** — Gemini (primary) or Groq (fallback) overwrites rule data
  for top‑priority items (configurable limit, default 10)
- **Priority scoring** — blends CVSS + EPSS + CISA KEV into a 0–100 "act first"
  score with urgency badges (urgent/elevated/moderate/low)
- **Trends** — 30‑day volume, severity, actor, and CVE trend charts
- **STIX exports** — `iocs.csv`, `iocs.json`, `stix.json`, `feed.xml` written
  every run
- **Webhook alerts** — Slack, Discord, Telegram, or Email for high‑severity
  items with persistent dedup (no repeat alerts for same CVE)
- **Source health tracking** — per‑run status logged to JSONL time series
- **MITRE ATT&CK mapping** — 14 tactics, 504 techniques/sub‑techniques,
  ~2,800 keywords; scanned at fetch time
- **Dashboard** — dark terminal theme, infinite scroll, watchlist, sort toggle,
  MITRE matrix heatmap, priority badges, Mermaid threat graphs
- **Parallelised fetching** — RSS + API sources fetched concurrently
  (ThreadPoolExecutor, configurable workers)
- **Docker support** — multi‑stage build with version labels

## Project Structure

```
.
├── .github/
│   ├── workflows/
│   │   └── update.yml            ← GitHub Actions: hourly schedule
│   └── dependabot.yml            ← Weekly pip & GHA updates
├── scripts/
│   ├── fetch_intel.py            ← Pipeline: fetch → enrich → export
│   ├── config.py                 ← Central config (env‑overridable)
│   ├── webhook_post.py           ← Slack / Discord / Telegram / Email alerts
│   ├── trends.py                 ← 30‑day trend builder
│   ├── exports.py                ← STIX / CSV / JSON / RSS exports
│   └── mitre_ttps.py             ← MITRE ATT&CK database (504 entries)
├── data/
│   ├── intel.json                ← Auto‑generated daily
│   ├── archive/                  ← Daily snapshots (pruned after N days)
│   ├── trends.json               ← 30‑day trend data
│   ├── exports/                  ← STIX, CSV, JSON, RSS
│   ├── .alert_state.json         ← Webhook dedup memory
│   ├── .cache/                   ← EPSS / CISA KEV (24h TTL)
│   └── source_health_history.jsonl ← Health time‑series
├── tests/
│   └── test_pipeline.py          ← Unit tests for pipeline helpers
├── index.html                    ← Dashboard UI
├── style.css                     ← Dark terminal theme
├── app.js                        ← Feed, matrix, search, filter, trends
├── requirements.txt              ← Runtime dependencies
├── requirements-dev.txt          ← Dev dependencies (pytest, ruff)
├── Dockerfile                    ← Multi‑stage: frontend + fetcher
└── nginx.conf                    ← Nginx config for frontend
```

## Quick Start

### GitHub Pages (zero setup)

1. Fork this repo
2. Enable GitHub Pages on `main` root
3. The workflow runs hourly — your dashboard will be live at
   `https://<user>.github.io/Cyberwatch/`

### Docker

```bash
# Build with version label
VERSION=$(git rev-parse --short HEAD)
docker build --build-arg VERSION=$VERSION -t cyberwatch .

# Run the fetcher
docker run --rm cyberwatch python scripts/fetch_intel.py
```

### Local

```bash
pip install -r requirements.txt         # runtime deps only
pip install -r requirements-dev.txt     # includes pytest, ruff
python scripts/fetch_intel.py           # generates data/intel.json
```

### Tests

```bash
python -m unittest tests/test_pipeline.py -v
```

## Configuration

All settings in `scripts/config.py` are overridable via environment variables:

| Variable | Default | Description |
|---|---|---|
| `GROQ_API_KEY` | — | Groq API key for AI enrichment (fallback) |
| `GEMINI_API_KEY` | — | Gemini API key for AI enrichment (primary) |
| `AI_ENRICH_LIMIT` | `10` | Items enriched per run via AI |
| `WEBHOOK_URL` | — | Webhook URL for alerts |
| `WEBHOOK_TYPE` | `slack` | `slack`, `discord`, `telegram`, or `email` |
| `SMTP_HOST` | — | SMTP server (for email alerts) |
| `SMTP_TO` | — | Recipient address (for email alerts) |
| `ALERT_SEVERITIES` | `critical,high` | Minimum severity for alerting |
| `THREATFOX_API_KEY` | — | API key for ThreatFox IOCs |
| `MB_API_KEY` | — | API key for MalwareBazaar |
| `PRIORITY_CVSS_WEIGHT` | `40` | CVSS weight in priority score |
| `PRIORITY_EPSS_WEIGHT` | `40` | EPSS weight in priority score |
| `PRIORITY_KEV_BONUS` | `20` | CISA KEV flat bonus |

## Customization

**Add an RSS source:**

Edit `RSS_SOURCES` in `scripts/fetch_intel.py`:
```python
{
    "name": "Dark Reading",
    "url":  "https://www.darkreading.com/rss.xml",
    "category": "news",
    "severity": "medium",
},
```

**Change the update schedule:**

Edit the cron in `.github/workflows/update.yml`:
```yaml
- cron: '0 */6 * * *'   # every 6 hours
```

## Data Sources

| Source | Type | Key? |
|---|---|---|
| NVD (NIST) | CVEs | No |
| CISA Alerts | Advisories | No |
| OSV.dev | Open‑Source Vulns | No |
| MSRC | Microsoft Vulns | No |
| Gentoo | Linux Vulns | No |
| Oracle Linux | Linux Vulns | No |
| CentOS | Linux Vulns | No |
| VMware | Virtualisation Vulns | No |
| AlienVault OTX | Threat Pulses | Yes |
| The Hacker News | News | No |
| Bleeping Computer | Incidents | No |
| Krebs on Security | News | No |
| SANS ISC | Threat Diaries | No |
| Reddit r/netsec | Community | No |
| TheRecord | News | No |

## How It Works

1. **Fetch** — RSS feeds & API sources are fetched in parallel (8 workers)
2. **Enrich (rule)** — Every item gets a description summary, IOC scan, severity
   inference, category, and Mermaid graph
3. **Prioritise** — Items with CVSS/EPSS/KEV data are scored and sorted first
4. **Enrich (AI)** — Top N items (default 10) are sent to Gemini for deeper
   analysis; Groq is the fallback if Gemini is unavailable
5. **Export** — Writes `intel.json`, trends, archives, and STIX/CSV/RSS exports
6. **Alert** — New high‑severity items trigger webhooks (Slack/Discord/Telegram/Email)
7. **Commit** — The GitHub Action commits all output back to the repo

## Tips

- Works even if some sources fail — uses whatever data was fetched
- EPSS & CISA KEV are cached for 24h (reduces API calls)
- `data/.alert_state.json` is in `.gitignore` — CI force‑adds it to persist
  dedup across runs
- No API keys are needed for basic operation (only AI enrichment and AlienVault
  require keys)

---

*Built with GitHub Actions, Python, and vanilla JS.*
