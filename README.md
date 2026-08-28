<div align="center">

# 🛡️ OpenThreat

**A self-updating threat intelligence pipeline, encyclopedia, hunt bench and research bench.**

Pulls CVEs, vendor advisories, incident reporting and indicator feeds from 43 configured sources every hour and scores each item against how likely it is to actually be exploited. Then it does three things most feeds do not: it merges nine public corpora into **one page per threat actor, malware family, ATT&CK technique and campaign** — with every vendor's alias resolving to the same entry — it turns each technique into a **hunt pack** carrying paste-ready queries for six SIEMs and the Atomic Red Team tests that prove they fire, and it **checks its own scoring against what really happened** and publishes the result even when the result is unflattering.

[![CI](https://github.com/priyanshu965/OpenThreat/actions/workflows/ci.yml/badge.svg)](https://github.com/priyanshu965/OpenThreat/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?logo=python&logoColor=white)](https://python.org)

**[Live dashboard](https://priyanshu965.github.io/OpenThreat/)**

</div>

---

## What it answers

Most threat feeds answer *what happened*. This one is built to answer **what do I do today**, and then to show its working:

| Question | Where |
|---|---|
| What needs action today? | Feed, defaulting to **Verdicts** — the handful of items the tool has an opinion about |
| Why is this item ranked here? | Click the score. It opens the arithmetic, term by term |
| Who is behind it, and with what? | **Graph** — actors → malware → techniques → sectors |
| Are these separate stories or one operation? | **Campaigns** |
| Can I detect it? | **Detections** — ATT&CK activity crossed with SigmaHQ rules, and the gaps |
| Does the score actually work? | **Research → Scoring backtest** |
| Which of my 43 feeds are worth reading? | **Research → Source reliability** |
| How long is the patch window, really? | **Research → Exploitation lag** |
| What did the board look like the day this dropped? | **Time machine**, over 90 days of archives |
| What changed since yesterday? | **Diff**, two dates side by side |
| Who *is* Midnight Blizzard? | **Library** — and it is the same page as APT29, Cozy Bear, Nobelium and UNC2452 |
| What should I hunt for today? | **Hunt → Queue** — hypotheses generated from what is active right now, with a finish line |
| How do I actually run that hunt? | **Hunt → Packs** — Sigma rules compiled for Splunk, ES\|QL, Lucene, EQL and both KQL dialects |
| Would my detection even fire? | The Atomic Red Team test is on the same page |
| What do I change so it stops working? | D3FEND countermeasures, ATT&CK mitigations, and NIST 800-53 / CCM / Azure / AWS controls |
| Which controls matter *this week*? | **Hunt → Controls**, ranked by observed activity rather than audit order |
| Who is getting extorted? | **Landscape → Leak sites** |

---

## Architecture

One Python process on a schedule, plus a static frontend that reads its output. No database, no server, no runtime backend. State between runs is limited to what the next run genuinely cannot recompute.

```
                      ┌──────────────────────────────────────┐
   19 RSS feeds  ────▶ │                                      │
   24 JSON APIs  ────▶ │   fetch_intel.main()                 │
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
                    │    fetch_cisa_kev()    + dates          │
                    │    fetch_vulnrichment()SSVC points      │
                    │    build_poc_map()     PoC-in-GitHub    │
                    │    annotate_malware()  ATT&CK+Malpedia  │
                    │    annotate_detections() SigmaHQ        │
                    └────────────────────┬────────────────────┘
                                         │
                    ┌────────────────────▼────────────────────┐
                    │  SCORE                                  │
                    │    compute_priority()  0-100 + ACTION   │
                    │                        + components     │
                    │    enrich_with_ai()    batched, cached  │
                    │    build_daily_brief() one call per day │
                    └────────────────────┬────────────────────┘
                                         │
                    ┌────────────────────▼────────────────────┐
                    │  CONNECT + MEASURE                      │
                    │    build_entity_graph()  known+observed │
                    │    build_campaigns()     clustering     │
                    │    build_backtest()      does it work?  │
                    │    build_source_reliability()           │
                    │    build_exploit_lag()   patch window   │
                    │    publish_timeline()    90 slim days   │
                    └────────────────────┬────────────────────┘
                                         │
   ┌───────────┬──────────┬──────────────┼───────────┬──────────┬─────────┐
intel.json  archive/  api/day/*     exports/      data/api/   webhook  state.tar.gz
(feed only) (snapshot)(time machine)STIX·MISP·CSV static JSON  Slack   (durability)
```

`intel.json` carries the **feed**. Everything large and occasional — the graph, the Sigma coverage table, the three research reports — is published as its own endpoint and fetched only when someone opens that view. Folding them into the feed payload would roughly triple what a visitor downloads to read a list of headlines.

---

## Ingestion

Sources are declared as data, not code. Feeds live in `RSS_SOURCES` and per-source fetchers are registered in `API_SOURCES`, and both are fanned out across a thread pool. Every fetcher is wrapped in `run_source()`, which catches anything it throws and records a health entry instead of letting one bad feed abort the run.

Health is freshness aware rather than count aware. A feed that reliably returns ten items whose median age is four years is reported `stale`, not `ok`, which is how a long-dead source gets caught instead of quietly padding the feed.

HTTP goes through a single pooled `requests.Session` with a retry adapter, so all sources share connections and get uniform backoff on 429 and 5xx. Per-feed ETag and Last-Modified values are stored between runs, so unchanged feeds cost a conditional request rather than a full download.

That session and the on-disk cache live in [`scripts/fetchlib.py`](scripts/fetchlib.py), which every module imports. They used to live in `fetch_intel` and be reached for like this:

```python
try:
    from fetch_intel import _SESSION, _cached_fetch, log
except Exception:
    ...build a private session, set _cached_fetch = None...
```

That import can never succeed. `fetch_intel` imports `darkweb` around line 78 and defines `_SESSION` around line 179, so the name does not exist yet; and when the pipeline runs as `python scripts/fetch_intel.py` the module is `__main__`, so the import would load a *second* copy of the whole module. The fallback always fired, which meant the dark-web fetcher ran with caching **disabled** and re-downloaded RansomLook on all 24 daily runs.

---

## Normalisation

The same story arrives from several places at once, so items are collapsed on three keys: canonical URL (scheme, `www`, tracking parameters and trailing slash removed), a fuzzy title fingerprint, and CVE paired with source.

Which copy survives is not arbitrary. Items are sorted by source authority before deduplication, so an NVD or CISA record beats an aggregator, which beats a news rewrite of the same advisory.

Threat-actor names are then collapsed **case-insensitively**. Leak-site fetchers hand us the crew's own spelling, so one run carried `Qilin`, `qilin`, `SafePay`, `safepay`, `Dark Project` and `dark project` as six distinct actors — splitting every count that keys on the name, across trends, geopolitics and the graph.

---

## Enrichment

| Signal | Source | Notes |
|---|---|---|
| EPSS | FIRST.org daily corpus | The full gzipped CSV is downloaded once and looked up locally |
| KEV | CISA catalogue | Now with `dateAdded`, which is what makes the backtest and the lag timeline possible |
| SSVC | CISA Vulnrichment | Exploitation, Automatable and Technical Impact, cached 14 days |
| Public PoC | PoC-in-GitHub index | Contributes to the score without dominating it |
| ATT&CK | `mitre_ttps.py` | 504 techniques matched in one compiled regex pass |
| Relationships | MITRE CTI bundle | intrusion-set → uses → malware → technique. 48 MB, reduced to ~380 KB, refreshed monthly |
| Malware families | Malpedia | ~3,700 families with curated aliases and attribution, refreshed weekly |
| Detections | SigmaHQ release | 2,876 ATT&CK-tagged rules across 378 techniques, refreshed weekly |
| IOCs | Indicator feeds only | See below |

Keyword matching across severity, category, sectors and ATT&CK is **whole token**. Substring matching is the obvious way to write this and it is wrong: `rce` is a substring of `source`, `force` and `resource`, which was enough to mislabel a third of everything marked critical.

The same trap appears in malware naming, and it bites harder. ATT&CK ships software genuinely called *Expand*, *Route*, *Chaos*, *Embargo* and *Royal*, so matching family names against prose tagged a story about a shipping embargo as ransomware. Ordinary-English collisions are denylisted; security-distinctive tool names (Mimikatz, Impacket, Rclone, Cobalt Strike) are deliberately kept, because in a security corpus those words really do mean the tool.

IOC extraction is gated by source. Indicators are taken from feeds that exist to publish indicators, or from text that is explicitly defanged. Running a regex over prose in a news article produces the article's own domain, the vendor's domain and the author's email address, none of which are indicators of anything.

---

## Prioritisation

Each item with any exploitability signal gets a blended 0-100 score:

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

| Score | Band | Action |
|---|---|---|
| 90+ | urgent | Patch now, within 24h |
| 70 to 89 | elevated | Patch this week |
| 40 to 69 | moderate | Next patch cycle |
| below 40 | low | Monitor |

Every score now ships with its **components** — the points each term contributed — so clicking the number on a card opens the arithmetic instead of a summary of it:

```
Impact (CVSS)                9.8/10 x 40 weight          +39.2
Exploit probability (EPSS)   1.5% x 40 weight             +0.6
SSVC exploitation: active    25 x 1                      +25.0
Public PoC on GitHub                                     +15.0
CISA KEV listing             confirmed exploitation      +20.0
Confirmed-exploitation floor                             +24.4
─────────────────────────────────────────────────────────────
Priority score                                              90
```

The floor and the 100-cap are shown as their own terms rather than silently absorbing 40 points, because a score whose largest contributor is invisible is not interrogable.

---

## Does the score work?

This is the part most threat-intel projects do not do, and it is the reason the archive exists.

There are ~90 daily snapshots carrying a score for every CVE **on the day it was scored**, and CISA KEV records the date each CVE was added. That is enough to ask whether the score saw exploitation coming.

**The method, and the one detail that makes or breaks it:**

- A CVE enters the cohort on the first archived day it was scored.
- It is **excluded if it was already in KEV that day.** Without this the experiment is circular — the score adds 20 points and floors at 90 for KEV membership, so "high score predicts KEV" would be measuring the arithmetic, not the world.
- CVEs first scored fewer than `BACKTEST_HORIZON_DAYS` ago are **censored**, not counted as failures. They have not had their chance yet.
- Average precision is reported rather than ROC-AUC, because the positive class is ~2% of the cohort and ROC-AUC flatters a ranker on data that imbalanced.

**The current result is not flattering, which is the point:**

| Scoring method | Avg precision | Lift over base rate |
|---|---|---|
| Blended priority score | 0.031 | 1.7× |
| CVSS alone | 0.019 | 1.0× |
| **EPSS alone** | **0.103** | **5.6×** |
| Public PoC alone | 0.025 | 1.3× |

On 544 evaluable CVEs with a 1.8% base rate, **EPSS alone outperforms the blend by more than 3×**, and a coarse grid search over the CVSS/EPSS weights puts the optimal CVSS weight at **zero**. The flat bonuses appear to be diluting a ranking that EPSS was already doing well.

That is a finding about this project's own scoring, published by the project, in the project. The weights are environment variables (`PRIORITY_CVSS_WEIGHT`, `PRIORITY_EPSS_WEIGHT`, …) precisely so the answer can change the tool rather than just being noted.

**Caveats are shipped with the result**, not buried: KEV listing is a proxy for exploitation, not exploitation itself; a CVE exploited quietly and never listed counts here as a miss; and 90 days is a signal, not a finding.

---

## Which sources are worth reading?

The same archive, the same outcome variable, applied to the 43 feeds. The important distinction is between **coverage** and **early warning**:

- `precision` — of the CVEs a source carried, how many are in KEV at all.
- `ahead_precision` — the same, restricted to CVEs it carried **before** the listing date.

Only the second is a forecast. Run together they mislead badly: a news site that writes up every KEV addition the day it lands scored a 0.81 "precision" for predicting an announcement it was merely reporting. The first version of this module did exactly that, and the fix is why both numbers are now reported side by side, with median lead time next to them.

A source is ranked by how often it was **first in the whole corpus** to carry a CVE that was later listed, and carried it early. Volume never ranks a source up. Noise ratio — items with no CVE, no score, no actor, no technique and no indicator — is reported next to it, so a feed that publishes steadily and contributes nothing enrichable is visible.

---

## How long is the patch window?

Three dated events per CVE:

```
published ─────────▶ public PoC ─────────▶ CISA KEV listing
          (days)                 (days)
          └──────────── total window ─────────────┘
```

Publication dates come from the CVE Program API by **incremental backfill** — there is no free bulk feed that is not the entire NVD corpus, so a bounded number of lookups run each hour and every answer is cached permanently. A cold start converges in a couple of days of runs, and the module reports its own coverage instead of pretending.

Current corpus: **1,577 KEV entries with dates (100% coverage)**. The headline median is skewed by old CVEs listed years after disclosure, so the by-quarter trend is the real signal — and it is **shortening**: a median of **8.8 days** across the two most recent quarters against **30.5 days** in the two before them. A 30-day patch SLA written against the older figure no longer describes reality.

---

## Connected intelligence

Every item already carried threat actors, ATT&CK techniques and a target sector, but *independently* — nothing said the APT28 on one row and the T1071 on another were the same story. MITRE's CTI bundle ships the missing half as explicit relationship objects, so the edges cost nothing to obtain:

```
APT28 ──uses──▶ X-Agent ──implements──▶ T1071 ──seen in──▶ 4 items this week
  │                                        │
  └──targets──▶ Government ◀───────────────┘
```

Two kinds of edge, kept visibly apart because conflating them would be the most misleading thing this project could do:

- **KNOWN** — from MITRE ATT&CK. A curated claim about the world. Drawn solid.
- **OBSERVED** — from this feed, this window. Actor→sector, technique→item counts. Drawn dashed.

The graph is laid out in columns (actors → malware → techniques → sectors) rather than as a force-directed hairball: the relationships have a natural direction, a spring simulation throws that away, and a deterministic layout does not rearrange itself between visits.

**Campaigns** cluster the feed into operations. Actors seed a cluster; a shared malware family seeds one when no actor is named; and overlapping techniques plus a shared sector may only **extend** an existing cluster, never create one. That last constraint is load-bearing — unconstrained it merges half the feed, because T1566 Phishing and "corporate" co-occur constantly and mean nothing together. Confidence counts independent **sources**, not rows: five items from one feed is one observation repeated.

**Malware families** come from Malpedia, and curated attribution is reported separately from what this feed happened to see alongside a family. They are different kinds of claim.

---

## Detection engineering

Mapping to ATT&CK and stopping there is the least useful place to stop: knowing a technique is active tells a defender nothing they can deploy. SigmaHQ publishes ~2,900 vendor-neutral rules tagged with the same technique ids, so the join turns

> T1566 Phishing — seen 29 times

into

> T1566 Phishing — seen 29 times · 12 detection rules available

The headline number is honest about what it measures: **what share of this week's observed technique activity has a public detection rule behind it** (currently 89%). The **gaps** list — techniques seen in the feed with no public rule at all — is the half worth reading.

Rules are parsed with a small line scanner rather than a YAML library: the four fields needed are flat top-level scalars, and adding a dependency to read four fields is a poor trade. Nothing is extracted to disk, so the classic zip-slip traversal cannot apply.

---

## The Library

By v4 this project held four entity corpora and had no entities. ATT&CK knew APT29's techniques. Malpedia knew what WellMess is. MISP galaxy knew that Midnight Blizzard, Cozy Bear, Nobelium and UNC2452 are one organisation. The feed knew APT29 had been mentioned four times this week. None of those facts could reach any of the others, so "tell me about APT29" returned a filtered list of headlines.

The Library merges them into **8,800+ entities**: threat actors, malware families, tools, every ATT&CK technique, campaigns and mitigations.

| Corpus | What it contributes |
|---|---|
| MITRE ATT&CK CTI | Descriptions, detection strategies and analytics, techniques, campaigns, mitigations, sub-technique structure |
| MISP galaxy | ~4,400 entities and the synonym corpus that makes name deconfliction work |
| Malpedia | ~3,800 malware families with attribution |
| ORKL | A bibliography of published threat reports per actor |
| MITRE D3FEND | ~3,900 countermeasure links across 392 techniques |
| CTID mappings | NIST 800-53 rev5, CSA CCM, Azure and AWS security capabilities |
| SigmaHQ | Detection coverage per technique |
| Atomic Red Team | 2,300 validation tests across 341 techniques |
| The feed itself | What was seen this week, and when |

**ATT&CK's own prose was already being downloaded and thrown away.** v4 pulled the 48 MB CTI bundle, extracted the relationship edges, and discarded the descriptions, the detection content, the mitigations and the campaigns — which are exactly what an entity page is made of. The bundle now yields 176 actors, 825 software entries, 697 techniques, 44 mitigations and 56 campaigns *with their text*.

### Detection, from where ATT&CK actually keeps it

ATT&CK v18 replaced the old free-text `x_mitre_detection` field with an object graph:

```
x-mitre-detection-strategy --detects--> attack-pattern
      -> x-mitre-analytic  (the detection logic)
            -> x-mitre-data-component  ("auditd:SYSCALL", channel "execve")
```

The first cut of this read the old fields, which no longer exist — so all 697 techniques published an empty "how to see it" section and nothing reported a problem. Reading the graph instead gives **697 strategies over 1,758 analytics**, each naming the log source and channel it needs:

```
T1486  Data Encrypted for Impact
  WinEventLog:Sysmon (EventCode=1) · WinEventLog:Sysmon (EventCode=11)
  auditd:SYSCALL (openat, write, rename, unlink)
```

That is the difference between "monitor for suspicious encryption" and knowing whether you are collecting the telemetry to try.

### Name deconfliction

Vendors do not coordinate actor naming and never will. Typing any of these lands on the same page:

```
Midnight Blizzard · Cozy Bear · Nobelium · UNC2452 · The Dukes · BlueBravo · G0016  →  APT29
```

16,500 names resolve to 8,800 entities. Where a name legitimately belongs to two things — "Emotet" is both a malware family and the crew that runs it — the page says so and links to the other reading rather than silently picking one.

### One skeleton, always the same order

```
identity  →  summary  →  timeline  →  relationships  →  defence  →  sources
```

After two entity pages you know where to look on the third without hunting. That consistency is worth more than any amount of styling.

Where prose comes from more than one corpus, the page names the one it is showing you (`via MITRE ATT&CK`, `via MISP galaxy`) rather than blending two voices into one.

---

## The hunt bench

Everything above tells you something. This is the part that hands you an instrument.

### Hunt packs

One technique, fully equipped, precomputed in CI:

```
T1486  Data Encrypted for Impact
  what it is       ATT&CK prose + its detection strategies and analytics
  detections       the Sigma rules that cover it
  queries          each rule compiled for Splunk SPL, Elastic ES|QL, Lucene,
                   EQL, Sentinel KQL and Defender XDR KQL — paste-ready
  validation       Atomic Red Team tests, with prerequisites and cleanup
  telemetry        the data sources you need to be collecting
  countermeasures  D3FEND, ATT&CK mitigations, and your control framework
```

220 packs, 153 of them carrying compiled queries. That is roughly twenty minutes of tab-shuffling per technique, done once instead of independently by everyone who reads the same advisory.

**Compilation is optional on purpose.** pySigma and its backends are a fast-moving family with tight inter-version constraints, and this pipeline runs unattended 24 times a day. Pinning them into the critical path of the hourly job would trade the entire feed for a convenience feature, so they live in `requirements-hunt.txt`, are installed best-effort, and each backend is probed independently at import. With none of them present the packs still publish with their rules, atomics and countermeasures, and say plainly that queries are unavailable.

### The hunt queue

The chain had been sitting in the data since v4 and nothing walked it:

```
actor active this week → techniques ATT&CK attributes to them
  → Sigma rules that cover those → hunts to run today
```

Each row carries its own justification and a stop condition, so it is a task somebody can pick up and finish. A technique with **no** public rule still appears — that is the finding, not an omission.

### Coverage

Paste your rule inventory (Sigma UUIDs, ATT&CK ids, any format) and get a heatmap of what you cover against what is active, exportable as an ATT&CK Navigator layer.

It stays in your browser. There is no backend to send it to and the CSP has no endpoint that would accept it — that is a property of the architecture, not a promise.

---

## Dark web

Ransomware leak-site activity, from the aggregators rather than from Tor.

Running a Tor daemon in CI to scrape onion sites directly is the obvious implementation and the wrong one: leak sites are deliberately flaky and half sit behind a captcha, routing Actions traffic through Tor to scrape criminal infrastructure is not a fight worth having with a CI provider, and ransomware.live and ransomwatch already run that infrastructure with better uptime than this project could manage. Reading them is the same data, more reliably.

**Freshness is measured, not assumed.** The first cut of this paired ransomwatch's history with a single 100-row "recent" call, and published *99 claims in 120 days* — which read as a quiet quarter for ransomware and was actually an artefact: ransomwatch's newest post was ten months old. The current window is now assembled month by month, and every source reports the age of its newest record on the page. A feed that quietly stops updating shows up as a number rather than as a wrong conclusion.

The victims' extortion prose is **not** published. The analytical value of a leak-site post is entirely in its structured fields — who claimed it, when, what sector, which country — and republishing the note would make this dashboard another amplification channel for criminal claims about a named, frequently small, organisation.

An optional Telegram watch reads public `t.me/s/<channel>` previews. It is off by default: which channels to follow is an editorial choice, and shipping a default list would mean this project deciding whose propaganda gets a feed on your dashboard.

---

## Frontend

Vanilla JavaScript, no build step, no framework. `app.js` plus three sibling modules (`js/query.js`, `js/research.js`, `js/timetravel.js`) loaded as classic scripts. Everything sourced from a feed goes through `escapeHTML()` or `textContent`, every URL through `safeUrl()`, and CI rejects `innerHTML`, inline handlers and any widening of the CSP.

### Five modes, not thirteen buttons

v4 put every view in one row, which made "THREAT MAP" and "MALWARE" look like the same kind of choice when one is a picture of the world and the other is an encyclopedia. Views are now grouped by the question they answer:

```
FEED       what changed      ·  the triage list
LIBRARY    what is known     ·  entities, graph, ATT&CK matrix, campaigns, malware
HUNT       what to do        ·  queue, packs, coverage, controls, new rules
LANDSCAPE  the world         ·  threat map, geopolitics, leak sites, dark web, exposure
RESEARCH   what is proven    ·  backtest, source reliability, exploitation lag, trends
```

A second row switches views *inside* the active mode, and hides itself when a mode holds only one.

*(The design note that prompted this proposed four modes. A fifth was needed: the situational and own-estate views have no honest home under "what is proven", and filing them there would repeat the conflation the split exists to remove.)*

### Views are not filters

The previous build had **sixteen identically-styled buttons in one strip**. Nine narrowed the feed in place; seven replaced the entire screen. Clicking `NEWS` filtered a list, clicking `THREAT MAP` threw the list away, and nothing in the UI distinguished them. Worse, the sector and severity filters stayed armed while a map was on screen, where they meant nothing.

They are now two different pieces of chrome:

- **Views** (Feed · Map · Landscape · ATT&CK · Graph · Campaigns · Detections · Malware · Geopolitics · Dark Web · Exposure · Trends · Research) — a top-level tab strip attached to the header.
- **Feed filters** — smaller pills, rendered **only inside Feed**, and they leave with it.

### Opening on the nine, not the 320

A typical run collects 315 items, scores 66 of them and marks 4 urgent. The other **249 carry no verdict at all — 79% of the feed**, and on top of that the old NEW badge fired on roughly two-thirds of everything, because it meant "not in the previous hourly run". The tool's whole thesis is "here is the handful that needs action today", and that handful was buried.

- The feed **defaults to Verdicts**: only items the tool has an opinion about, ordered *Patch now → this week → next cycle → monitor*. The rest stay one click away and stop being the front page.
- **NEW means new to you.** `lastVisit` was already being written to `localStorage` and never read; it is read now. The old badge meant "not in the previous hourly run", which is why it fired on 64% of the feed. A visit is a *session*, so reloading three times in ten minutes does not empty it.
- **Compact by default.** At 224px per card the old feed put roughly two items on a screen, making 320 items about 160 screens long. One scannable row carries severity, action and title; everything else is behind expansion.
- **Triage has an end.** `4 of 9 reviewed`, a progress bar, a *next unreviewed* jump, and a real done screen. Nine actionable items is a finishable list; an infinite feed never lets you finish.
- **"Why am I seeing this?"** — one line per card naming the filter that surfaced it (`matches your stack: Fortinet`).

### A real query layer

```
epss > 0.5 and not kev and stack and age <= 7d
```

Fields (`epss`, `cvss`, `score`, `age`, `sigma`, `kev`, `poc`, `exploited`, `stack`, `sector`, `actor`, `malware`, `technique`, …), comparison operators, `AND`/`OR`/`NOT`, parentheses and quoted phrases — evaluated in the browser over the loaded corpus.

On top of it, a natural-language front end rewrites English into that language before parsing:

> *actively exploited things affecting VPNs this week* → `exploited AND "vpn" AND age <= 7d`

**Why this is local and not a model call.** The obvious implementation is one Gemini call per query — the pipeline already pays for Gemini. It cannot be done here. This is a static site with no backend, so calling a model API from the page means shipping the API key to every visitor, where it would be extracted and billed to the project within a day. The alternative is a proxy, and a proxy is a server; the entire architecture of this project is that there is no server. A phrase-rewriting front end handles the vocabulary this domain actually uses, runs in under a millisecond, works offline, costs nothing and cannot leak a key. When it does not understand something it returns `null` and the box falls back to substring search, so it can only ever add.

Ordered rewrite rules have a specific failure mode — a later rule eats a token an earlier one produced, silently, returning a plausible wrong answer — so `tests/query.test.js` pins every one that was found by hand, including a filler rule that deleted the `kev` in *"no KEV listing"* and left a dangling `NOT` that attached itself to the time window, inverting the query.

### The rest

- **Time machine.** 90 days of daily snapshots the dashboard could never open, because archives are not published and a full snapshot is ~270 KB. A reduced ~60 KB copy per day is published instead, with an index, a date slider and a volume sparkline. A past day shows the scores that item carried **then**. Days that predate priority scoring say so rather than showing an empty feed.
- **Diff.** Two dates side by side: what arrived, what left, and what changed underneath — with **escalations** (gained a KEV listing, moved up a band) sorted to the top, because that is the part worth reading.
- **Saved investigations.** Name a filter combination and come back to it. URL state already made one shareable; this is the half that was missing.
- **Analyst notes** per item, exportable with the item.
- **Confidence surfacing.** `sector_confidence`, `ai_confidence` and CVSS provenance were computed everywhere and shown nowhere; they are pills on the card now.
- **Light theme.** Three states — auto follows the OS, light and dark are explicit. The sheet was already fully tokenised, so this is a second token block rather than a restyle.
- **Semantic colour.** Cyan used to mean active state, links, counts and highlights simultaneously. When one hue means four things it stops meaning any of them. Four roles, four tokens: `--ui-active`, `--ui-link`, `--ui-count`, `--ui-accent`.
- **Three breakpoints** (640 / 900 / 1200), chosen rather than accumulated — the sheet had grown five across twelve media queries, none corresponding to anything in particular.
- **Mobile.** The header stat pills used to be `display: none` below 640px, removing the only always-visible count of what needs doing.

---

## Configuration

Everything tunable lives in [`scripts/config.py`](scripts/config.py) and can be overridden by environment variable. All API keys are optional. Every corpus the Library and the hunt bench are built from is keyless: CISA Vulnrichment, EPSS, CISA KEV, MITRE CTI, D3FEND, the CTID control mappings, MISP galaxy, Malpedia, SigmaHQ, Atomic Red Team, ORKL, ransomware.live and ransomwatch.

| Variable | Default | Effect |
|---|---|---|
| `GEMINI_API_KEY` | none | Enables AI enrichment and the daily brief |
| `GROQ_API_KEY` | none | Failover provider |
| `WEBHOOK_URL`, `WEBHOOK_TYPE` | none | Alert destination; unset disables alerting |
| `ALERT_SEVERITIES` | `critical` | What justifies a push; KEV and SSVC active always alert |
| `MAX_ITEMS_PER_SOURCE` | `10` | Per source cap |
| `AI_ENRICH_LIMIT` | `40` | Scored items enriched per run |
| `SOURCE_STALE_DAYS` | `30` | Median age above which a feed is reported stale |
| `ENABLE_ENTITY_GRAPH` | `1` | MITRE CTI relationship graph |
| `ATTACK_KB_TTL_HOURS` | `720` | ATT&CK bundle refresh (48 MB download, monthly) |
| `ENABLE_SIGMA` | `1` | SigmaHQ detection index |
| `SIGMA_TTL_HOURS` | `168` | Sigma release refresh |
| `ENABLE_MALWARE_FAMILIES` | `1` | Malpedia family entities |
| `ENABLE_BACKTEST` | `1` | Scoring backtest |
| `BACKTEST_HORIZON_DAYS` | `30` | Days a scored CVE gets to appear in KEV |
| `ENABLE_SOURCE_RELIABILITY` | `1` | Per-source signal measurement |
| `ENABLE_EXPLOIT_LAG` | `1` | Publication → PoC → KEV timeline |
| `CVE_DATE_LOOKUPS_PER_RUN` | `40` | Bounded publication-date backfill |
| `ENABLE_CAMPAIGNS` | `1` | Campaign clustering |
| `CAMPAIGN_WINDOW_DAYS` | `14` | Clustering window |
| `ENABLE_TIMELINE` | `1` | Slim per-day snapshots for the time machine |
| `TIMELINE_DAYS` | `90` | Days published |
| `ENABLE_MISP_EXPORT` | `1` | MISP event export |
| `PUBLISH_OWN_ESTATE` | `0` | Whether your own exposure/attack-surface findings are published |
| `ENABLE_KNOWLEDGE_BASE` | `1` | The Library: merged entity pages |
| `ENABLE_MISP_GALAXY` | `1` | MISP galaxy alias/actor corpus |
| `ENABLE_ORKL` | `1` | ORKL threat-report bibliography |
| `ORKL_MAX_REPORTS` | `1500` | Page budget — ORKL returns full report text, ~2.3 MB per 100 rows |
| `ENABLE_D3FEND` | `1` | D3FEND countermeasures |
| `ENABLE_CONTROL_MAPPINGS` | `1` | ATT&CK → NIST 800-53 / CCM / Azure / AWS |
| `ENABLE_HUNT_PACKS` | `1` | Hunt packs |
| `HUNT_PACKS_MAX` | `220` | How many techniques get a pack |
| `ENABLE_SIGMA_COMPILE` | `1` | Compile Sigma to SIEM queries (needs `requirements-hunt.txt`) |
| `SIGMA_COMPILE_BUDGET` | `900` | Rules compiled per weekly refresh |
| `ENABLE_ATOMICS` | `1` | Atomic Red Team validation tests |
| `ENABLE_HUNT_QUEUE` | `1` | Generated hunt hypotheses |
| `ENABLE_DETECTION_DIFF` | `1` | What SigmaHQ added since last run |
| `ENABLE_LEAK_SITES` | `1` | Ransomware leak-site tracking |
| `LEAK_HISTORY_MONTHS` | `5` | Months of victim data assembled (~800 KB each, closed months cached 30d) |
| `ENABLE_TELEGRAM` | `0` | Public channel watch — **off by default**, you choose the channels |
| `TELEGRAM_CHANNELS` | none | Comma-separated public channel names |

---

## Situational awareness

Beyond the feed:

- **Threat map.** Current attacker infrastructure by country of origin, from 8 keyless feeds, categorised by observed behaviour. ~160k hosts are geolocated and aggregated server-side into a ~28 KB country summary; the raw IPs never reach the browser.
- **Landscape.** Urgent/KEV/PoC counts, threat-actor momentum, ATT&CK technique frequency, targeted-sector heat, KEV velocity.
- **Sectors.** Every item tagged with a target sector on a confidence ladder: explicit when the source names it, inferred from whole-token keyword rules otherwise, never guessed.
- **Geopolitics.** Suspected actor origin crossed with target country and sector, over 72 tracked groups. Attribution is version-controlled, every origin cites its source, and nothing is asserted: "suspected" unless a government has formally attributed the actor.
- **Provenance.** Who produced each item: vendor research, independent researcher, journalism, government, vendor advisory, adversary-authored, or automated feed. Ransomware leak-site posts are the attacker's own words and get their own stream.

---

## Static JSON API

Pre-rendered on every run and served with the dashboard. Paths are relative to the dashboard URL.

| Endpoint | Contents |
|---|---|
| `data/intel.json` | Full feed with all enrichment |
| `data/api/stats.json` | Counts by severity, category, source and priority band |
| `data/api/urgent.json` | Items scored urgent or elevated |
| `data/api/exploited.json` | CISA KEV or SSVC exploitation active |
| `data/api/brief.json` | Current brief |
| `data/api/attack_map.json` | Attacker infrastructure by country and category |
| `data/api/graph.json` | Entity graph: nodes and known/observed edges |
| `data/api/malware.json` | Malware families named this run |
| `data/api/sigma.json` | Detection coverage and gaps by technique |
| `data/api/campaigns.json` | Clustered campaigns with their evidence |
| `data/api/backtest.json` | Scoring backtest: curves, precision@k, weight search |
| `data/api/source_reliability.json` | Per-source coverage, early warning, noise |
| `data/api/exploit_lag.json` | Publication → PoC → KEV latency by quarter |
| `data/api/timeline.json` | Archive index with per-day counts and digests |
| `data/api/day/YYYY-MM-DD.json` | One reduced daily snapshot |
| `data/api/entity_index.json` | Library search index: 8,800 entities, 16,500 names |
| `data/api/entity/<slug>.json` | One full entity record (~2 KB) |
| `data/api/hunt_packs.json` | Hunt pack index: technique, counts, available SIEMs |
| `data/api/hunt/<technique>.json` | One full hunt pack (~20 KB) |
| `data/api/hunt_queue.json` | Generated hunt hypotheses with their justification |
| `data/api/control_focus.json` | Controls ranked by this window's observed activity |
| `data/api/detection_diff.json` | Sigma rules added since the last refresh |
| `data/api/leak_sites.json` | Leak-site claims, groups, sectors, geography, freshness |
| `data/api/telegram.json` | Public channel watch (only when enabled) |
| `data/exports/stix.json` | STIX 2.1 bundle |
| `data/exports/misp_event.json` | MISP event — the other half of the ecosystem |
| `data/exports/feed.xml` | RSS |

The Library and the hunt packs are **sharded**, and that is not an optimisation — it is what makes them fit. The merged corpus is 8,883 entities and 17 MB; the packs are 4.7 MB across 220 files. Served as single blobs, every visitor would download all of it to read one page, which is precisely the mistake v4 fixed for the research artifacts. The index is loaded once (540 KB gzipped) and one record costs ~2 KB.

STIX is what you hand a commercial platform; MISP is what most CERTs and sharing communities actually run. Emitting only one of them makes the project standalone in practice. Both use deterministic `uuid5` ids, so re-importing updates in place instead of creating a duplicate every hour. In the MISP event, `to_ids` — "safe to turn into a detection rule" — is set **only** for indicator feeds: a hash mentioned in a news article is context, and pushing it into an IDS is how false positives reach someone's SOC.

---

## Archive durability

Trends, the sector benchmark, the backtest and the source-reliability report all read `data/archive/`, and it lives in the Actions cache, which is evicted after 7 days without a read. Three things guard it:

1. The **published tarball** (`data/state.tar.gz`) carries the archive, the health summary and the four expensive derived corpora (ATT&CK, Malpedia, Sigma, CVE dates). A run that misses the cache pulls it back from its own last deployment. Named files only — never `data/.cache` wholesale, because that directory also holds your estate's credential exposure and subdomain inventory, and the tarball is public. CI asserts that no own-estate file reached it.
2. The **timeline index** records a size and SHA-256 per day and reports gaps, so silent truncation is visible in the UI and in the run log rather than showing up as trends quietly computed from three days of data.
3. The deploy step **refuses to publish** a site missing any required asset, and checks that every `?v=` reference in `index.html` resolves to a file that shipped.

---

## Development

```bash
python -m unittest discover -s tests      # 290 Python tests
node --test tests/query.test.js           # query-language tests
ruff check scripts tests
python scripts/fetch_intel.py             # full run
```

Individual modules run standalone for a quick look:

```bash
python scripts/backtest.py
python scripts/source_reliability.py
python scripts/exploit_lag.py
python scripts/entity_graph.py
python scripts/timeline.py
```

CI additionally verifies that every view button has a container **and** a route, that every cross-module function `app.js` calls actually exists in `js/`, that no `innerHTML` sink or inline handler has appeared, and that the CSP has not been widened to reach a model API.

---

<div align="center">

MIT licensed. Built with GitHub Actions, Python and vanilla JavaScript.

ATT&CK data © MITRE · malware families © [Malpedia](https://malpedia.caad.fkie.fraunhofer.de) · detection rules © [SigmaHQ](https://github.com/SigmaHQ/sigma) · IP geolocation by [DB-IP](https://db-ip.com) (CC BY 4.0)

</div>
