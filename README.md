<div align="center">

# 🛡️ CyberWatch

**A free, self-updating cybersecurity threat intelligence dashboard**  
*Aggregates CVEs, advisories, incidents & news from 15+ sources. Runs hourly via GitHub Actions — zero infrastructure.*

[![GitHub Actions](https://img.shields.io/badge/Updates-Hourly-00ADD8?logo=githubactions&logoColor=white)](https://github.com/priyanshu965/Cyberwatch/actions)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?logo=python&logoColor=white)](https://python.org)
[![Dashboard](https://img.shields.io/badge/Dashboard-GitHub%20Pages-222222?logo=githubpages&logoColor=white)](https://priyanshu965.github.io/Cyberwatch/)
[![AI](https://img.shields.io/badge/AI-Gemini%20%2F%20Groq-8E44AD?logo=googleai&logoColor=white)](https://ai.google.dev)

</div>

---

## ✨ What It Does

| Capability | Detail |
|---|---|
| **🔍 15+ Sources** | NVD, CISA, MSRC, OSV, Gentoo, Oracle, CentOS Stream, VMware/Broadcom, AlienVault OTX, THN, Bleeping Computer, Krebs, SANS, Reddit r/netsec, TheRecord, ThreatFox, MalwareBazaar, URLhaus, Spamhaus, Feodo, Arch, Fedora, Amazon Linux, Dark Reading, SecurityWeek, Cisco Talos, Unit 42 … |
| **🤖 AI Enrichment** | Gemini (primary) / Groq (fallback) writes detailed summaries, severity scores & Mermaid attack graphs for top-priority items |
| **⚡ Priority Scoring** | Blends CVSS + EPSS + CISA KEV into a 0–100 "act-first" score with badges (`URGENT` / `ELEVATED` / `MODERATE` / `LOW`) |
| **📊 Trends & Exports** | 30-day charts (volume, severity, actors, CVEs) + STIX/CSV/JSON/RSS exports every run |
| **🔔 Webhook Alerts** | Slack / Discord / Telegram / Email for high-severity items — persistent dedup so you never see the same CVE twice |
| **🩺 Source Health** | Per-run status + JSONL time-series — know instantly when a feed goes dark |
| **🗺️ MITRE ATT&CK** | 14 tactics, 504 techniques, ~2,800 keywords mapped at fetch time with a heatmap matrix |
| **⚡ Parallel Fetching** | RSS feeds & API sources fetched concurrently (ThreadPoolExecutor) — full pipeline in ~90 seconds |
| **🧪 Tested** | Unit tests for pipeline helpers (extraction, inference, scoring) |

---

## 🏗️ Architecture

```
┌─────────────┐    ┌──────────────┐    ┌──────────────┐    ┌─────────────┐
│ 15+ Sources │───▶│ fetch_intel  │───▶│ enrich + AI  │───▶│  intel.json │
│ (RSS + API)  │    │ (parallel)   │    │ (rules→Gemini)│    │  + archive  │
└─────────────┘    └──────────────┘    └──────────────┘    └──────┬──────┘
                                                                  │
                    ┌──────────────────────────────────────────────┘
                    ▼
┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐
│ Webhook     │  │ Trends &    │  │ STIX / CSV  │  │ GitHub      │
│ Alert       │  │ Charts      │  │ / RSS       │  │ Pages       │
│ (Slack/Disc)│  │ (30d)       │  │ Exports     │  │ Dashboard   │
└─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘
```

---

## 🚀 Quick Start

### 🌐 GitHub Pages — 30 seconds

```bash
# 1. Fork the repo
# 2. Settings → Pages → Deploy from main / (root)
# 3. Done. Your dashboard at https://<user>.github.io/Cyberwatch/
```

### 🐳 Docker

```bash
VERSION=$(git rev-parse --short HEAD)
docker build --build-arg VERSION=$VERSION -t cyberwatch .
docker run --rm cyberwatch python scripts/fetch_intel.py
```

### 🐍 Local

```bash
pip install -r requirements.txt
python scripts/fetch_intel.py          # generates data/intel.json
```

### 🧪 Run Tests

```bash
pip install -r requirements-dev.txt
python -m unittest tests/test_pipeline.py -v
```

---

## ⚙️ Configuration

All settings in `scripts/config.py` — overridable via environment variables:

| Variable | Default | What It Does |
|---|---|---|
| `GEMINI_API_KEY` | — | Primary AI enrichment (recommended) |
| `GROQ_API_KEY` | — | Fallback AI enrichment |
| `AI_ENRICH_LIMIT` | `10` | Items enriched per run |
| `WEBHOOK_URL` / `WEBHOOK_TYPE` | — / `slack` | Alert destination (`slack`, `discord`, `telegram`, `email`) |
| `SMTP_HOST` / `SMTP_TO` | — | Email alert config |
| `ALERT_SEVERITIES` | `critical,high` | Minimum severity to trigger alert |
| `OTX_API_KEY` | — | AlienVault OTX threat pulses |
| `THREATFOX_API_KEY` | — | ThreatFox C2 IOCs |
| `MB_API_KEY` | — | MalwareBazaar samples |
| `PRIORITY_CVSS_WEIGHT` | `40` | CVSS weight (0–100 score) |
| `PRIORITY_EPSS_WEIGHT` | `40` | EPSS weight |
| `PRIORITY_KEV_BONUS` | `20` | CISA KEV flat bonus |

---

## 📦 Project Map

```
📁 .github/workflows/update.yml        ← Hourly scheduler
📁 scripts/
├── fetch_intel.py                     ← Pipeline: fetch → enrich → export
├── config.py                          ← Central config (env‑overridable)
├── webhook_post.py                    ← Slack / Discord / Telegram / Email
├── trends.py                          ← 30‑day trend builder
├── exports.py                         ← STIX / CSV / JSON / RSS
└── mitre_ttps.py                      ← MITRE ATT&CK (504 techniques)
📁 tests/test_pipeline.py              ← Unit tests
📄 index.html  +  style.css  +  app.js ← Dashboard (dark terminal theme)
📄 Dockerfile                          ← Multi‑stage build
📄 requirements.txt  +  requirements-dev.txt
```

---

## 🔌 Data Sources

| 🟢 Always Free | 🔑 Optional API Key | 🚫 No Longer Available |
|---|---|---|
| NVD, CISA, MSRC, OSV, Gentoo | AlienVault OTX | (replaced with working alternatives) |
| Oracle Linux, CentOS Stream | ThreatFox | |
| VMware/Broadcom, Amazon Linux | MalwareBazaar | |
| The Hacker News, Bleeping Computer | AbuseIPDB | |
| Krebs, SANS, Reddit r/netsec | PhishTank | |
| TheRecord, Dark Reading, SecurityWeek | | |
| Threatpost, Cisco Talos, Unit 42 | | |
| Graham Cluley, ESET, CyberSecurity News | | |
| GBHackers, Fedora, Arch Linux | | |
| URLhaus, Spamhaus DROP, Feodo Tracker | | |

---

## 🔄 Pipeline

```
1️⃣  FETCH ──── Parallel RSS + API (8 workers, ~90s)
      │
2️⃣  ENRICH ─── Rule-based (every item): summary, IOCs, severity, category, Mermaid graph
      │
3️⃣  PRIORITISE ── CVSS + EPSS + KEV → 0–100 score → sort
      │
4️⃣  AI ENRICH ── Top N items → Gemini (primary) / Groq (fallback)
      │
5️⃣  EXPORT ──── intel.json + archive + trends + STIX/CSV/RSS
      │
6️⃣  ALERT ───── High-severity items → Slack / Discord / Telegram / Email
      │
7️⃣  COMMIT ──── GitHub Action commits everything back to the repo
```

---

## 💡 Tips

- **No API keys? No problem.** Core features work without any keys — only AI enrichment and a few threat-feed APIs need them
- **EPSS & CISA KEV** are cached for 24 h — no redundant API calls
- **Dedup is persistent** — `data/.alert_state.json` survives across runs (force-added in CI)
- **Partial failure is fine** — the pipeline never crashes on a dead source; it logs and moves on
- **All output is static** — `intel.json` + HTML + CSS + JS → serves perfectly from GitHub Pages

---

<div align="center">

Built with ❤️ using **GitHub Actions**, **Python**, and **vanilla JS**  
*Stay safe out there.*

</div>
