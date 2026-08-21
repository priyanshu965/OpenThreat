<div align="center">

# 🛡️ CyberWatch

**A free, self-updating cybersecurity threat intelligence dashboard**
*Aggregates CVEs, advisories, incidents & IOCs, then tells you which handful actually need action today. Runs hourly on GitHub Actions — zero infrastructure.*

[![CI](https://github.com/priyanshu965/Cyberwatch/actions/workflows/ci.yml/badge.svg)](https://github.com/priyanshu965/Cyberwatch/actions/workflows/ci.yml)
[![Hourly Update](https://img.shields.io/badge/Updates-Hourly-00ADD8?logo=githubactions&logoColor=white)](https://github.com/priyanshu965/Cyberwatch/actions)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?logo=python&logoColor=white)](https://python.org)
[![Dashboard](https://img.shields.io/badge/Dashboard-GitHub%20Pages-222222?logo=githubpages&logoColor=white)](https://priyanshu965.github.io/Cyberwatch/)

</div>

---

## ✨ What It Does

| Capability | Detail |
|---|---|
| **🎯 Tells you what to do** | Every scored item carries an action — *Patch now* / *Patch this week* / *Next patch cycle* / *Monitor* — derived from CVSS + EPSS + CISA KEV + public PoC + **SSVC** |
| **🩺 SSVC decision points** | CISA Vulnrichment supplies Exploitation (`none`/`poc`/`active`), Automatable, and Technical Impact. Free, no API key |
| **🔍 28 live sources** | NVD, CISA, MSRC, GHSA, ZDI, Gentoo, Fedora, Arch, Amazon Linux, CentOS, VMware/Broadcom, OTX, THN, Bleeping Computer, Krebs, SANS, r/netsec, TheRecord, ThreatFox, MalwareBazaar, URLhaus, Spamhaus, Feodo, Dark Reading, SecurityWeek, Cisco Talos, Unit 42, Ransomware.live |
| **🤖 AI where it earns its keep** | Batched Gemini calls extract affected **vendor/product** (feeds stack matching) and write a one-line *why this matters*; one call per run produces the daily brief |
| **⚡ Priority scoring** | 0–100 blended score with a rationale you can read, not a black box |
| **📊 Trends & exports** | 30-day charts + STIX / CSV / JSON / RSS, plus pre-rendered static JSON API endpoints |
| **🔔 Alerts & digest** | Slack / Discord / Telegram / Email with persistent dedup |
| **⌨️ Keyboard triage** | `j`/`k`/`e`/`x`/`s`/`w`, a `Ctrl-K` command palette, and dismiss state — "inbox zero" for 250 items |
| **🔄 Live updates** | The page polls for new intel and offers it, rather than reshuffling under you |
| **🗺️ MITRE ATT&CK** | 504 techniques, whole-token matched, with a heatmap matrix |

---

## 🏗️ Architecture

```
28 sources ──▶ fetch_intel.main()
  (RSS + API)          │
                       ├─ deduplicate()          authority-ranked, deterministic
                       ├─ map_ttps()             ATT&CK, one compiled regex pass
                       ├─ extract_iocs()         source-gated (indicator feeds only)
                       ├─ fetch_epss_scores()    full daily corpus, cached 24h
                       ├─ fetch_cisa_kev()       + optional VulnCheck KEV superset
                       ├─ fetch_vulnrichment()   SSVC decision points
                       ├─ compute_priority()     score ──▶ ACTION
                       ├─ enrich_with_ai()       batched, schema-constrained
                       └─ build_daily_brief()    one call over the whole feed
                                 │
      ┌───────────────┬──────────┼───────────────┬────────────────┐
  intel.json      archive/    exports/        data/api/       webhook
  (current)       (daily)     STIX·CSV·RSS    static JSON     alert + digest
```

---

## 🚀 Quick Start

### 🌐 GitHub Pages

```bash
# 1. Fork the repo
# 2. Settings → Pages → Deploy from main / (root)
# 3. Add GEMINI_API_KEY under Settings → Secrets → Actions (optional but recommended)
```

### 🐍 Local

```bash
pip install -r requirements.txt
python scripts/fetch_intel.py          # writes data/intel.json
python -m http.server 8000             # open http://localhost:8000
```

### 🐳 Docker

```bash
docker compose up -d                   # dashboard on :8080
docker compose run --rm fetcher        # one-off intel fetch
```

### 🧪 Tests

```bash
pip install -r requirements-dev.txt
python -m unittest discover -s tests -v          # 45 unit tests
RUN_LIVE_TESTS=1 python -m unittest tests.test_integration -v   # live source checks
```

---

## ⚙️ Configuration

All settings live in `scripts/config.py` and are environment-overridable.

### Keys (all optional)

| Variable | What it unlocks |
|---|---|
| `GEMINI_API_KEY` | AI enrichment + daily brief. Gemini 3.x Flash-Lite is free-tier |
| `GROQ_API_KEY` | Failover only — Groq's free tier is 100–2,000 req/day |
| `VULNCHECK_API_KEY` | VulnCheck KEV superset (free signup) |
| `NVD_API_KEY` | Higher NVD rate limits |
| `OTX_API_KEY` / `THREATFOX_API_KEY` / `MB_API_KEY` | Extra indicator feeds |
| `WEBHOOK_URL` / `WEBHOOK_TYPE` | `slack` · `discord` · `telegram` · `email` |
| `TELEGRAM_CHAT_ID` | **Required** when `WEBHOOK_TYPE=telegram` |
| `SMTP_HOST` / `SMTP_TO` / … | Email alerts |

> **CISA Vulnrichment, the EPSS corpus and CISA KEV need no key at all.**
> Never commit a key. Use GitHub Actions secrets, or a local `.env` (already gitignored).
> CI fails the build if a credential-shaped string is found in the tree.

### Tuning

| Variable | Default | Effect |
|---|---|---|
| `AI_ENRICH_LIMIT` | `40` | Items enriched per run (batched, so this is cheap) |
| `AI_BATCH_SIZE` | `10` | Items per model call |
| `MAX_ITEMS_PER_SOURCE` | `10` | Per-source cap |
| `SOURCE_STALE_DAYS` | `30` | Median item age above which a feed is reported `stale` |
| `ALERT_SEVERITIES` | `critical` | Severities that trigger an alert (KEV/SSVC-active always do) |
| `ALERT_MIN_PRIORITY` | `0` | Priority floor for alerts; `0` disables |
| `PRIORITY_CVSS_WEIGHT` | `40` | Score weights… |
| `PRIORITY_EPSS_WEIGHT` | `40` | |
| `PRIORITY_KEV_BONUS` | `20` | |
| `PRIORITY_POC_BONUS` | `15` | |
| `PRIORITY_SSVC_ACTIVE_BONUS` | `25` | SSVC `Exploitation: active` |
| `PRIORITY_SSVC_AUTO_BONUS` | `10` | SSVC `Automatable: yes` |

---

## 📦 Project Map

```
📁 .github/workflows/
├── ci.yml               ← tests + lint + secret scan + frontend checks (every PR)
├── update.yml           ← hourly pipeline
├── daily-digest.yml     ← daily rollup
└── source-health.yml    ← live source validation
📁 scripts/
├── fetch_intel.py       ← the pipeline
├── config.py            ← central config
├── mitre_ttps.py        ← ATT&CK (504 techniques)
├── trends.py            ← 30-day rollup
├── exports.py           ← STIX / CSV / RSS + static JSON API
└── webhook_post.py      ← alerts AND digest
📁 tests/                ← 45 unit + 18 integration tests, importing real code
📄 index.html · style.css · app.js
```

---

## 📡 Static JSON API

No server. `write_exports()` pre-renders these on every run — cacheable on any CDN.

| Endpoint | Contents |
|---|---|
| `data/intel.json` | Full feed |
| `data/api/stats.json` | Counts by severity, category, source, priority |
| `data/api/urgent.json` | Items labelled urgent or elevated |
| `data/api/exploited.json` | CISA KEV or SSVC `active` |
| `data/api/brief.json` | Today's brief |
| `data/api/health.json` | Per-source health |
| `data/exports/feed.xml` | RSS |
| `data/exports/stix.json` | STIX 2.1 bundle |

---

## ⌨️ Keyboard

| Key | Action |
|---|---|
| `j` / `k` | Next / previous item |
| `e` | Expand |
| `x` | Dismiss |
| `s` | Star |
| `w` | Copy as markdown for a ticket |
| `o` | Open source link |
| `/` | Search · `Ctrl-K` palette · `?` help |

---

## 💡 Notes

- **Source health is freshness-aware.** A feed still returning items but whose median age exceeds `SOURCE_STALE_DAYS` reports `stale`, not `ok`.
- **IOC extraction is source-gated.** Indicators come from indicator feeds (URLhaus, ThreatFox, Feodo, Spamhaus, MalwareBazaar, OTX) or from defanged text. Prose in a news article is not a threat feed.
- **Partial failure is fine.** A dead source is recorded in `source_health` and the run continues.
- **All output is static** — GitHub Pages serves it directly.

---

<div align="center">

Built with **GitHub Actions**, **Python** and **vanilla JS**
*Stay safe out there.*

</div>
