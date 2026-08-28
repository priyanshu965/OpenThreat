<div align="center">

# 🛡️ OpenThreat

**A self-updating threat intelligence pipeline, encyclopedia and hunt bench.**

[![CI](https://github.com/priyanshu965/OpenThreat/actions/workflows/ci.yml/badge.svg)](https://github.com/priyanshu965/OpenThreat/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?logo=python&logoColor=white)](https://python.org)

**[openthreat.in](https://openthreat.in/)**

</div>

---

Roughly every hour, a GitHub Actions job pulls CVEs, advisories, incident reporting and indicator
feeds from 43 sources, scores each item on how likely it is to actually be exploited, and
publishes a static site. No server, no database, no backend at runtime.

*Roughly*, because GitHub's `schedule` event is best-effort: it runs on a shared queue, is
routinely delayed, and is **dropped** outright under load. Measured over 44 runs, this workflow
never once started on time — median 31 minutes late — and the gap between runs decayed to as much
as 11 hours during a busy period. The cron is now twice an hour at off-peak minutes, which makes
hourly likely but cannot make it guaranteed. The dashboard shows the real age of the data rather
than the intended cadence.

Three things it does that a feed does not:

- **One page per threat.** Nine public corpora merged into 8,800 entities — actors, malware,
  every ATT&CK technique, campaigns — with 16,500 vendor aliases resolving to the same entry.
  Midnight Blizzard, Cozy Bear, Nobelium, UNC2452 and APT29 are one page.
- **Hunt packs.** Each technique ships Sigma rules compiled for six SIEMs, the Atomic Red Team
  tests that prove they fire, the telemetry you need to be collecting, and the D3FEND / NIST
  800-53 countermeasures that stop it.
- **It grades its own scoring** against what really happened, and publishes the result even when
  the result is unflattering. See below.
- **Tools you can point at one thing** — passive recon over DNS and RDAP, an IOC pivot launcher,
  phishing triage, and a k-anonymity password check. All in your browser; nothing reaches this
  site, because there is no endpoint here that could receive it.

## The six modes

| Mode | Answers | Views |
|---|---|---|
| **Feed** | what changed | the triage list, defaulting to items with a verdict |
| **Library** | what is known | entities, graph, ATT&CK matrix, campaigns, malware, CVE browser |
| **Hunt** | what to do | queue, packs, coverage, controls, new rules |
| **Landscape** | the world | threat map, geopolitics, leak sites, dark web, KEV, lifecycle, exposure |
| **Research** | what is proven | scoring backtest, source reliability, exploitation lag, trends |
| **Tools** | check one thing | passive recon, IOC lookup, phishing triage, credentials |

**Tools runs in your browser, not in the pipeline.** Its input arrives after
the pipeline has finished, and there is no server here to forward it to — so
every provider it uses had to be keyless *and* CORS-open, both verified before
anything was built. That is why live TLS cipher inspection and technology
fingerprinting are absent rather than faked: JavaScript cannot see a TLS
handshake, and reading a target's HTML is blocked by that target's own CORS
policy. Doing either server-side would make this an active scanner.

## How it works

```
19 RSS + 24 JSON sources ─▶ fetch_intel.main()   ThreadPoolExecutor(8)
                                   │
   NORMALISE   dedupe on canonical URL + title fingerprint + CVE,
               keeping the most authoritative copy
                                   │
   ENRICH      EPSS · CISA KEV · SSVC · public PoC · ATT&CK (504 techniques)
               · Malpedia families · SigmaHQ rules · source-gated IOCs
                                   │
   SCORE       compute_priority() → 0-100 + action band + components
               enrich_with_ai()   → batched, cached (optional)
                                   │
   CONNECT     entity graph · campaign clustering · backtest
   + MEASURE   · source reliability · exploit lag · 90-day timeline
                                   │
   ┌───────────┬──────────┬────────┴───────┬──────────┬─────────────┐
intel.json  archive/  api/day/*        exports/    data/api/   state.tar.gz
 (feed)    (snapshot)(time machine)  STIX·MISP·CSV static JSON  (durability)
```

`intel.json` carries only the feed. The graph, the coverage tables and the research reports are
separate endpoints, fetched when someone opens that view — folding them in would triple what a
visitor downloads to read a list of headlines.

## The priority score

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
| 70–89 | elevated | Patch this week |
| 40–69 | moderate | Next patch cycle |
| < 40 | low | Monitor |

Every score ships with its **components** — the points each term contributed, the floor and the
cap included — so clicking the number on a card opens the arithmetic instead of a summary of it.

## Does the score work?

~90 daily snapshots record what each CVE scored *on the day it was scored*; CISA KEV records when
each CVE was added. That is enough to ask whether the score saw exploitation coming. CVEs already
in KEV on their first scored day are excluded (otherwise the experiment just measures the +20 and
the floor), recent CVEs are censored rather than counted as failures, and average precision is
reported instead of ROC-AUC because the positive class is ~2%.

| Scoring method | Avg precision | Lift over base rate |
|---|---|---|
| Blended priority score | 0.031 | 1.7× |
| CVSS alone | 0.019 | 1.0× |
| **EPSS alone** | **0.103** | **5.6×** |
| Public PoC alone | 0.025 | 1.3× |

**EPSS alone beats the blend by more than 3×**, and a grid search puts the optimal CVSS weight at
zero. The weights are environment variables precisely so this can change the tool. Caveats ship
with the result: KEV listing is a proxy for exploitation, and 90 days is a signal, not a finding.

The same archive drives **source reliability** (a source ranks on how often it was first to carry
a CVE that was later listed — never on volume) and the **exploitation lag** timeline (publication
→ public PoC → KEV, currently shortening from a 30.5-day median to 8.8).

## Static JSON API

Pre-rendered every run, relative to the dashboard URL. Everything below is CORS-open and keyless.

| Endpoint | Contents |
|---|---|
| `data/intel.json` | Full feed with all enrichment |
| `data/api/stats.json` · `urgent.json` · `exploited.json` · `brief.json` | Feed slices |
| `data/api/graph.json` · `campaigns.json` · `malware.json` · `sigma.json` | Connected intelligence |
| `data/api/backtest.json` · `source_reliability.json` · `exploit_lag.json` | The research reports |
| `data/api/timeline.json` · `day/YYYY-MM-DD.json` | Time machine index and daily snapshots |
| `data/api/entity_index.json` · `entity/<slug>.json` | Library: 8,800 entities, one record ≈ 2 KB |
| `data/api/hunt_packs.json` · `hunt/<technique>.json` | Hunt packs: index and one full pack |
| `data/api/hunt_queue.json` · `control_focus.json` · `detection_diff.json` | Hunt bench |
| `data/api/leak_sites.json` | Leak-site claims, groups, sectors, freshness |
| `data/api/kev.json` | The full CISA KEV catalogue, with dates and required actions |
| `data/api/lifecycle.json` | End-of-life status per product, plus latest tooling releases |
| `data/api/telegram.json` | Ten monitored public channels, scrubbed of credentials |
| `data/exports/stix.json` · `misp_event.json` · `feed.xml` | STIX 2.1, MISP event, RSS |

The Library and hunt packs are **sharded** because the merged corpus is 17 MB — served whole,
every visitor would download all of it to read one page. Both exports use deterministic `uuid5`
ids so re-importing updates in place rather than duplicating hourly.

## Configuration

Everything tunable lives in [`scripts/config.py`](scripts/config.py) and can be overridden by
environment variable. **All API keys are optional** — every corpus the Library and hunt bench are
built from is keyless. The ones worth knowing:

| Variable | Default | Effect |
|---|---|---|
| `GEMINI_API_KEY` / `GROQ_API_KEY` | none | AI summaries and the daily brief; failover provider |
| `WEBHOOK_URL`, `WEBHOOK_TYPE` | none | Alert destination; unset disables alerting |
| `ALERT_SEVERITIES` | `critical` | What justifies a push; KEV and SSVC active always alert |
| `PRIORITY_CVSS_WEIGHT`, `PRIORITY_EPSS_WEIGHT`, … | see table above | The scoring weights |
| `PUBLISH_OWN_ESTATE` | `0` | Whether your own exposure findings are published |
| `TELEGRAM_CHANNELS` | 10 verified channels | Public channel watch. Credential-dump channels are excluded on principle: their posts *are* victim data |
| `ENABLE_*` | `1` | One switch per module (Library, hunt packs, backtest, leak sites, …) |

Every `ENABLE_*` module degrades to "unavailable" rather than failing the run, so a missing
dependency or a dead upstream costs you one section, not the feed.

## Development

```bash
python -m unittest discover -s tests      # 358 Python tests
node --test tests/query.test.js           # query-language tests
ruff check scripts tests
python scripts/fetch_intel.py             # full run
```

Individual modules run standalone — `python scripts/backtest.py`, `source_reliability.py`,
`exploit_lag.py`, `entity_graph.py`, `timeline.py`.

CI additionally verifies that every view has a container *and* a route, that every cross-module
function `app.js` calls exists in `js/`, that no `innerHTML` sink or inline handler has appeared,
that the CSP has not been widened to reach a model API, and that no own-estate data reached the
public state tarball.

## Further reading

[**docs/design-notes.md**](docs/design-notes.md) — why each module works the way it does, and the
bugs that shaped it: the substring match that mislabelled a third of everything critical, the
alias collision that silently overwrote 25 ATT&CK techniques, the ATT&CK v18 restructure that
emptied every detection section without raising anything, and the leak-site feed that had been
stale for ten months while reporting a quiet quarter.

---

<div align="center">

MIT licensed. Built with GitHub Actions, Python and vanilla JavaScript.

ATT&CK data © MITRE · malware families © [Malpedia](https://malpedia.caad.fkie.fraunhofer.de) · detection rules © [SigmaHQ](https://github.com/SigmaHQ/sigma) · IP geolocation by [DB-IP](https://db-ip.com) (CC BY 4.0)

</div>
