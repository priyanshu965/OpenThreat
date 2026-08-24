<div align="center">

# 🛡️ CyberWatch

**A self-updating threat intelligence pipeline and dashboard.**

Pulls CVEs, vendor advisories, incident reporting and indicator feeds from 35 configured sources every hour, scores each item against how likely it is to actually be exploited, and renders the result as a static dashboard.

[![CI](https://github.com/priyanshu965/Cyberwatch/actions/workflows/ci.yml/badge.svg)](https://github.com/priyanshu965/Cyberwatch/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?logo=python&logoColor=white)](https://python.org)

**[Live dashboard](https://priyanshu965.github.io/Cyberwatch/)**

</div>

---

## Architecture

The whole system is one Python process that runs on a schedule, plus a static frontend that reads its output. There is no database, no server and no runtime backend. State between runs is limited to what the next run genuinely cannot recompute.

```
                      ┌──────────────────────────────────────┐
   13 RSS feeds  ────▶ │                                      │
   22 JSON APIs  ────▶ │   fetch_intel.main()                 │
                      │   ThreadPoolExecutor(max_workers=8)  │
                      └──────────────────┬───────────────────┘
                                         │  raw items
                    ┌────────────────────▼────────────────────┐
                    │  NORMALISE                              │
                    │    sort_for_dedup()   authority ranking │
                    │    deduplicate()      URL + title + CVE │
                    └────────────────────┬────────────────────┘
                                         │
                    ┌────────────────────▼────────────────────┐
                    │  ENRICH                                 │
                    │    map_ttps()          ATT&CK, 504 tech │
                    │    extract_iocs()      source-gated     │
                    │    fetch_epss_scores() full daily corpus│
                    │    fetch_cisa_kev()    + VulnCheck KEV  │
                    │    fetch_vulnrichment()SSVC points      │
                    │    build_poc_map()     PoC-in-GitHub    │
                    └────────────────────┬────────────────────┘
                                         │
                    ┌────────────────────▼────────────────────┐
                    │  SCORE                                  │
                    │    compute_priority()  0-100 + ACTION   │
                    │    enrich_with_ai()    batched, cached  │
                    │    build_daily_brief() one call per day │
                    └────────────────────┬────────────────────┘
                                         │
         ┌──────────────┬────────────────┼──────────────┬──────────────┐
    intel.json      archive/        exports/        data/api/       webhook
    (full feed)   (daily snapshot)  STIX·CSV·RSS   static JSON    Slack/Discord
```

## Ingestion

Sources are declared as data, not code. Feeds live in `RSS_SOURCES` and per-source fetchers are registered in `API_SOURCES`, and both are fanned out across a thread pool. Every fetcher is wrapped in `run_source()`, which catches anything it throws and records a health entry instead of letting one bad feed abort the run. A source that returns nothing, errors, or serves stale content is reported in `source_health` and the pipeline continues.

Around 28 of the 35 typically return data on a given run; the remainder need an optional API key or are degraded that hour, and the run reports which.

Health is freshness aware rather than count aware. A feed that reliably returns ten items whose median age is four years is reported `stale`, not `ok`, which is how a long dead source gets caught instead of quietly padding the feed.

HTTP goes through a single pooled `requests.Session` with a retry adapter, so all sources share connections and get uniform backoff on 429 and 5xx. Per feed ETag and Last-Modified values are stored between runs, so unchanged feeds cost a conditional request rather than a full download.

## Normalisation

The same story arrives from several places at once, so items are collapsed on three keys: canonical URL (scheme, `www`, tracking parameters and trailing slash removed), a fuzzy title fingerprint (lowercased, punctuation stripped, filler words dropped, remaining tokens sorted), and CVE paired with source.

Which copy survives is not arbitrary. Items are sorted by source authority before deduplication, so an NVD or CISA record beats an aggregator, which beats a news rewrite of the same advisory. Because dedup keeps the first occurrence, the sort is what makes the outcome both correct and deterministic across runs.

## Enrichment

| Signal | Source | Notes |
|---|---|---|
| EPSS | FIRST.org daily corpus | The full gzipped CSV is downloaded once and looked up locally, so every CVE gets a score rather than only those in a cached query |
| KEV | CISA catalogue | Optional VulnCheck superset when a key is configured |
| SSVC | CISA Vulnrichment | Exploitation, Automatable and Technical Impact, fetched per CVE and cached for 14 days |
| Public PoC | PoC-in-GitHub index | Contributes to the score without dominating it |
| ATT&CK | `mitre_ttps.py` | 504 techniques matched in one compiled regex pass |
| IOCs | Indicator feeds only | See below |

Keyword matching across severity, category and ATT&CK is whole token. Substring matching is the obvious way to write this and it is wrong: `rce` is a substring of `source`, `force` and `resource`, which is enough to mislabel a third of everything marked critical.

IOC extraction is gated by source. Indicators are taken from feeds that exist to publish indicators (URLhaus, ThreatFox, Feodo, Spamhaus, MalwareBazaar, OTX) or from text that is explicitly defanged. Running a regex over prose in a news article produces the article's own domain, the vendor's domain and the author's email address, none of which are indicators of anything.

## Prioritisation

Each item with any exploitability signal gets a blended 0 to 100 score:

```
score = 40 × (cvss / 10)              impact
      + 40 × epss                     probability of exploitation
      + 25 × ssvc_exploitation        active = 1.0, poc = 0.45, none = 0
      + 10 if automatable
      +  5 if technical_impact == total
      + 15 if a public PoC exists
      + 20 if listed in CISA KEV

floor of 90 when KEV or SSVC exploitation is active
```

The score maps to a band, and the band maps to a plain instruction, which is the actual output of the pipeline:

| Score | Band | Action |
|---|---|---|
| 90+ | urgent | Patch now, within 24h |
| 70 to 89 | elevated | Patch this week |
| 40 to 69 | moderate | Next patch cycle |
| below 40 | low | Monitor |

Every score ships with a readable rationale (`CISA KEV (actively exploited) · EPSS 42.1% · CVSS 9.8`) so the number can be argued with. Weights are environment overridable through `PRIORITY_*`.

Confirmed exploitation floors the score because a CVSS 6.5 that is being used in the wild today outranks a theoretical 9.8. A public PoC only adds to the score. It deliberately does not floor it, since the PoC index carries a lot of empty scaffold repositories, and flooring collapsed the ordering by tying every low impact item at one value.

## AI layer

Language models are used in the two places regex cannot reach: pulling the affected vendor and product out of prose (which drives stack matching), and writing a one line judgement of why an item matters. A single call per run produces the daily brief, which is a genuine judgement over the whole feed.

Calls are batched, with a JSON schema attached so the model cannot return malformed output. Results are cached across runs keyed by item identity, because an enrichment is a property of the item and the feed turns over slowly. The daily brief is regenerated only when it ages out or the set of urgent items changes, so a newly listed KEV entry still forces a rewrite within the hour.

Gemini is primary with Groq as failover, and rule based defaults are applied to every item first. If no key is configured, or every provider fails, the run degrades rather than empties.

## Frontend

Vanilla JavaScript, no build step, no framework. `app.js` fetches `intel.json`, filters in memory and renders cards directly to the DOM. Everything sourced from a feed goes through `escapeHTML()`, and the page sets a CSP without `unsafe-inline` for scripts, enforced in CI by a check that rejects inline handlers.

Mermaid is loaded on demand rather than up front. It is 3.3 MB, and only a minority of visitors ever expand an attack flow diagram, so it is fetched on first use with an SRI hash pinning exactly which bytes are allowed to execute.

The page polls for new data and offers it through a toast instead of reshuffling the list under whoever is reading. Triage state (dismissed, starred, watchlist, stack) persists in `localStorage`, and the current view is encoded in the URL so a filtered dashboard can be shared.

## Configuration

Everything tunable lives in [`scripts/config.py`](scripts/config.py) and can be overridden by environment variable. All API keys are optional, and CISA Vulnrichment, the EPSS corpus and CISA KEV need no key at all.

| Variable | Default | Effect |
|---|---|---|
| `GEMINI_API_KEY` | none | Enables AI enrichment and the daily brief |
| `GROQ_API_KEY` | none | Failover provider |
| `WEBHOOK_URL`, `WEBHOOK_TYPE` | none | Alert destination; unset disables alerting |
| `ALERT_SEVERITIES` | `critical` | What justifies a push; KEV and SSVC active always alert |
| `MAX_ITEMS_PER_SOURCE` | `10` | Per source cap |
| `AI_ENRICH_LIMIT` | `40` | Scored items enriched per run |
| `SOURCE_STALE_DAYS` | `30` | Median age above which a feed is reported stale |

## Static JSON API

Pre-rendered on every run and served with the dashboard. Paths are relative to the dashboard URL.

| Endpoint | Contents |
|---|---|
| `data/intel.json` | Full feed with all enrichment |
| `data/api/stats.json` | Counts by severity, category, source and priority band |
| `data/api/urgent.json` | Items scored urgent or elevated |
| `data/api/exploited.json` | CISA KEV or SSVC exploitation active |
| `data/api/brief.json` | Current brief |
| `data/exports/stix.json` | STIX 2.1 bundle |
| `data/exports/feed.xml` | RSS |

---

<div align="center">

MIT licensed. Built with GitHub Actions, Python and vanilla JavaScript.

</div>
