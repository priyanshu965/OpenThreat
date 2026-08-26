# CyberWatch — Efficiency, UI & Feature Roadmap

**Written:** 2026-08-20 · Companion to `CODE_ANALYSIS.md`
All numbers below are measured from your committed `data/intel.json`, `data/exports/`, and `source_health`.

> ### ⚠ Status: superseded in large part by v4.0 (2026-08-26)
>
> This document is kept as the dated analysis it is — the measurements in it
> describe the tree as it stood on 2026-08-20 and are **not** current. Most of
> what it asks for has since shipped; see [Appendix — what v4.0 shipped](#appendix--what-v40-shipped)
> at the end for the mapping, and `README.md` for how it actually works now.
>
> The framing in Part 0 did survive, and drove the v4 redesign:
> *"make the front page answer what are the 3 things I should do today"* is
> now literally the default view.

---

## Part 0 — The framing problem

Before any feature list, the honest diagnosis:

> **CyberWatch is currently an aggregator that shows you everything. To be useful it has to become a triage tool that tells you what matters.**

Right now a run produces **251 items**. A human cannot read 251 items an hour. And of those 251:

| | |
|---|---|
| Items marked `critical` | 51 — of which **16 are false** (the `rce`-in-`source` bug) |
| Items with any AI analysis | **3** |
| Distinct "AI attack flow" diagrams | **7** across 251 items (4 boilerplate templates cover 248) |
| Items from sources contributing fresh data | 28 of 37 declared sources |
| Threatpost items | 10 — **median age 1,456 days** (site shut down in 2023, feed still serves the 2022 archive) |
| STIX indicators that are real IOCs | ~0 of 36 |

Every feature idea below is judged against one question: **does it reduce the number of things the user has to look at, or does it add more?** Features that add more noise are in the cut list (Part 5), no matter how impressive they sound.

The single most valuable change you could make is not a feature. It's this: **make the front page answer "what are the 3 things I should do today?"** Everything else is supporting infrastructure.

---

# Part 1 — Efficiency

## 1.1 Payload: 33% of what you ship the browser is redundant

`intel.json` is **358 KB**. Measured breakdown:

```
workflow_graph   62 KB (17%)  ← 60 KB is byte-identical duplication
ai_summary       58 KB (16%)  ← 246 of 248 are a prefix of `description`, already in the payload
iocs             27 KB  (8%)  ← ~100% false positives (see CODE_ANALYSIS §3)
ttps             19 KB  (5%)
```

### Fix A — dedupe the graphs (saves 60 KB, 30 min work)

You have 251 items and **7 distinct graphs**. 91 items share one string, 87 share another, 67 share a third. Emit a template ID instead:

```python
# fetch_intel.py — instead of item["workflow_graph"] = graph
item["graph_template"] = cat          # "cve" | "incident" | "advisory" | "default"
# AI-enriched items keep the real thing:
item["workflow_graph"] = postprocess_graph(raw)   # only when AI actually produced one

output["graph_templates"] = _RULE_GRAPHS          # emitted once, not 251 times
```

Frontend: `const graph = item.workflow_graph || GRAPH_TEMPLATES[item.graph_template];`

### Fix B — stop shipping rule summaries at all (saves 58 KB)

246 of 248 rule-based `ai_summary` values are literally the first three sentences of `description`, which is **already in the same JSON object**. You are transmitting the same prose twice. Delete the field for rule-based items and derive it client-side:

```js
const summary = item.ai_summary || item.description.split(/(?<=[.!?])\s+/).slice(0,3).join(' ');
```

This also makes the `ai_provider === 'rule'` case honest — right now the UI renders a header that says **"AI THREAT ANALYSIS"** above a mechanical string slice, for 99% of cards.

### Fix C — split the feed

Ship a light index for first paint, load detail on expand:

```
data/feed.json      ~90 KB   title, source, severity, priority, cve, published, ttp ids
data/items/<id>.json         description, iocs, graph, ai_summary, references
```

**Combined result: 358 KB → ~110 KB, a 70% reduction**, with the heavy content loaded only for cards the user actually opens. On GitHub Pages (which serves gzip automatically) that's roughly 90 KB → 25 KB on the wire.

## 1.2 Pipeline speed: you're optimising the wrong phase

Your `source_health` timings show fetching is **not** the bottleneck:

```
sum of all 37 sources:  30.8 CPU-seconds
slowest single source:   4.5 s  (Amazon Linux)
with 8 workers, wall clock for both fetch phases: ~8-10 s
```

The README claims "full pipeline in ~90 seconds". Fetching is ~10s of that. The rest is **AI enrichment, which is the one un-parallelised phase**:

```python
for i, item in enumerate(to_enrich):     # sequential
    call_gemini(prompt)                  # ~2-4 s each
    ...
    time.sleep(GROQ_SLEEP_SECS)          # + 3 s
    # gemini_sleep_secs=6 is defined but never used
```

10 items × (3s call + 3s sleep) = **60-90 seconds to enrich 4% of the feed**.

**Three fixes, in order of leverage:**

1. **Batch the prompt.** Send 10 items in one call asking for an array of 10 results. One request instead of ten. ~5s total instead of 90s, and 10× fewer requests against your rate limit. This alone lets you raise `AI_ENRICH_LIMIT` from 10 to 50 within the same quota.
2. **Use `asyncio` + a semaphore** if you keep per-item calls. `asyncio.Semaphore(4)` with `google-genai`'s async client respects rate limits without blocking sleeps.
3. **Delete the unconditional `time.sleep()`.** Sleep on 429 only, with backoff. Right now you pay the sleep even when the API is happy.

## 1.3 Network efficiency: conditional GET

You re-download every RSS feed in full, every hour, 24 times a day. Most feeds publish a handful of times per day. Store `ETag`/`Last-Modified` per source and send `If-None-Match`:

```python
_SESSION = requests.Session()
_SESSION.mount("https://", HTTPAdapter(
    pool_connections=16, pool_maxsize=16,
    max_retries=Retry(total=2, backoff_factor=0.5,
                      status_forcelist=[429,500,502,503,504])))

def fetch_rss(source):
    meta = _feed_meta.get(source["url"], {})
    hdrs = {**HEADERS}
    if meta.get("etag"):     hdrs["If-None-Match"] = meta["etag"]
    if meta.get("modified"): hdrs["If-Modified-Since"] = meta["modified"]
    r = _SESSION.get(source["url"], headers=hdrs, timeout=15)
    if r.status_code == 304:
        return _cached_items(source["url"])      # unchanged, zero parse cost
```

Two wins beyond speed: you stop hammering free feeds 24×/day (several of your sources have already started 403ing automated clients — GBHackers is already commented out for exactly this reason), and you get a real signal for source health.

Also note: **`requests.Session` is not currently used anywhere.** Every one of ~37 fetches opens a fresh TCP+TLS connection. Connection pooling alone is worth ~2-3 seconds.

## 1.4 Compute: `map_ttps` does 530,000 substring scans per run

```python
for tech_id, tech in MITRE_TECHNIQUES.items():   # 504 techniques
    for kw in tech["keywords"]:                  # 2,123 keywords total
        if kw in t:                              # × 251 items = ~530k scans
```

Replace with one compiled alternation (which also fixes the word-boundary bug from `CODE_ANALYSIS.md` §2 in the same change):

```python
import re
_KW_TO_TECH = {kw: tid for tid, t in MITRE_TECHNIQUES.items() for kw in t["keywords"]}
_TTP_RE = re.compile(
    r"(?<![0-9A-Za-z])(" + "|".join(sorted(map(re.escape, _KW_TO_TECH), key=len, reverse=True)) + r")(?![0-9A-Za-z])",
    re.IGNORECASE)

def map_ttps(text):
    hits = {_KW_TO_TECH[m.group(1).lower()] for m in _TTP_RE.finditer(text)}
    ...
```

One pass over the text instead of 2,123. Roughly **50-100× faster** and correct.

## 1.5 Repo bloat: you are committing ~20 MB/day

```
24 commits/day × (430 KB intel.json rewrite + 430 KB archive rewrite) ≈ 20 MB/day
source_health_history.jsonl: 1.8 MB, appended hourly, never truncated, committed every run
data/archive/ at 90-day retention × ~420 KB ≈ 38 MB in the working tree
```

`update.yml` also does `fetch-depth: 0` — a **full history clone, every hour**. Within a year this workflow will take longer to clone than to run.

Fixes, in order:

1. **`fetch-depth: 1`** in the checkout. You never use history in the job. One-line change, immediate win.
2. **Archive once per day, not every hour.** `data/archive/YYYY-MM-DD.json` is rewritten 24 times a day and only the last write survives. Write it on the first run after 00:00 UTC and skip the other 23.
3. **Roll up `source_health_history.jsonl` daily.** You only need per-source last-seen-with-data; you're storing 24 records/day forever, and **the browser downloads all 1.8 MB of it on every page load** (`app.js:1231`). Collapse to `data/source_health_summary.json` — one object, a few KB.
4. **Move data to an orphan branch** (`data`) that Pages reads, so the code repo's history stays clean. `git checkout --orphan data` once, then push data commits there. This is the standard pattern for self-committing dashboards.

## 1.6 Efficiency summary

| Change | Effort | Win |
|---|---|---|
| `fetch-depth: 1` | 1 line | Removes an ever-growing clone from every run |
| Dedupe `workflow_graph` | 30 min | −60 KB payload |
| Drop rule `ai_summary` | 30 min | −58 KB payload |
| Roll up health JSONL | 1 h | −1.8 MB per page load |
| Batch the AI prompt | 2 h | 90 s → 5 s; enables 5× more enrichment on the same quota |
| Compiled TTP regex | 1 h | 50-100× faster, fixes correctness |
| `Session` + conditional GET | 3 h | ~3 s faster, stops feed abuse, real staleness signal |
| Split feed/detail JSON | 4 h | 358 KB → ~110 KB |

---

# Part 2 — Making it genuinely more helpful

Efficiency is table stakes. This is the part that changes whether anyone uses it twice.

## 2.1 Replace "severity" with "should I act"

`severity` is inferred by keyword matching on headlines. It is the weakest signal you have, and it drives everything — the badges, the sidebar chart, the alerting threshold. Meanwhile you already compute `priority_score` (CVSS + EPSS + KEV + PoC), which is a genuinely defensible number, and you bury it in a small `⚑ P87` tag.

**Invert this.** Sort and badge by `priority_score` by default; keep `severity` as a secondary tag for news items that have no CVE. `sortMode` already supports `'priority'` — make it the default and consider removing `'latest'` as the primary view entirely. Latest-first is what a feed reader does; priority-first is what a security tool does.

## 2.2 Add SSVC — the highest-value data addition available to you

CISA's **Vulnrichment** program publishes free, per-CVE JSON with three decision points that are exactly what a defender needs, and which you cannot derive from CVSS:

- **Exploitation**: `none` / `poc` / `active`
- **Automatable**: can an attacker exploit this at scale, unattended?
- **Technical Impact**: `partial` / `total`

That converts your score from "this is scary" into "**patch this in 24h / 7d / next cycle**", which is a decision, not a number. It's raw JSON in a public GitHub repo (`cisagov/vulnrichment`, laid out as `2026/12xxx/CVE-2026-12345.json`) — no key, no rate limit, and you can fetch just the CVEs in your feed.

This is the single best ROI item in this document. Detail in Part 6.2.

## 2.3 Ship a "Today's Brief" that's actually a brief

You have `renderDailySummary()` already, and it renders a stat strip. Make it a real editorial summary:

> **3 things today** — CVE-2026-12345 (Fortinet, KEV, PoC public, matches your stack) · Salt Typhoon activity reported by 3 independent sources · Chrome 0-day patched, update now

This is the one place AI is genuinely worth spending tokens on — see Part 6.1. One call per run, ~500 tokens, produces the thing a human actually reads.

## 2.4 Make "My Stack" the centre of the product, not a sidebar box

`matchesStack()` currently does a substring check against title+description. That's the right idea, badly implemented. Upgrade it to match against **CPE vendor/product strings from NVD** (you already fetch NVD data and could pull `configurations[].cpeMatch`). Then:

- Default view = items matching your stack, everything else behind a tab
- Email/Slack digest scoped to your stack only
- "0 items affect your stack today" is a **valuable, calming answer** — currently impossible to express

A dashboard that says "nothing you run is affected today" is more useful than one that says "251 threats detected."

## 2.5 Fix source health to measure freshness, not just count

Right now: `status = "ok" if items else "empty"`. Threatpost returns 10 items every hour and reports **green**, and those items are from **August 2022**. CentOS Stream shows a median age of 252 days. A feed that has been dead for four years is indistinguishable from a live one in your UI.

```python
ages = [(now - parse(i["published"])).days for i in items]
median_age = statistics.median(ages) if ages else None
status = ("ok"    if items and median_age is not None and median_age <= 30 else
          "stale" if items else
          "empty")
health[name] = {..., "median_age_days": median_age}
```

Then surface `stale` as amber in the sidebar. This turns a vanity metric ("30/37 live!") into an operational one.

## 2.6 Be honest about the source count

`sources_fetched: 37` counts `fetch_osv`, which is a **stub that logs a message and returns `[]`** — with the README still claiming "OSV (covers 25+ sources)". 7 sources return zero. 2 more return only stale data. The honest number is **28 sources contributing fresh intel**.

28 working sources is genuinely impressive. Claiming 37 when 9 are dead makes the whole dashboard less trustworthy — and source health is a feature you're advertising. Report the real number, and let the health panel show the rest as degraded.

---

# Part 3 — Dynamic UI

You asked specifically for this. Current state: `app.js` renders all cards into a container on load, filters by rebuilding the list, and has pagination at 40 with an IntersectionObserver. It's a static render with client-side filtering. Here's how to make it feel alive, ranked by **value ÷ effort**.

## Tier 1 — do these first

### 3.1 Live updates without a reload ⭐ highest impact

The pipeline runs hourly; the page shows whatever was there when it loaded. Poll for change and animate new items in:

```js
let lastETag = null;
async function pollForUpdates() {
  const r = await fetch('data/feed.json', { method: 'HEAD' });
  const etag = r.headers.get('etag');
  if (lastETag && etag !== lastETag) {
    const fresh = await (await fetch('data/feed.json')).json();
    const newKeys = diffKeys(allItems, fresh.items);
    showToast(`${newKeys.length} new items`, () => mergeAndHighlight(fresh, newKeys));
  }
  lastETag = etag;
}
setInterval(pollForUpdates, 120_000);
```

Key detail: **don't reshuffle the page under the user.** Show a toast — "12 new items · click to load" — and let them opt in. Then insert with a highlight flash and a `prefers-reduced-motion` guard. This is the single change that makes a dashboard feel like a live console instead of a static page.

### 3.2 Command palette (Cmd/Ctrl-K)

You already have `/` for search and `Esc` to close. A palette generalises it: type to jump to a CVE, filter by actor, switch views, toggle watchlist, open the matrix. ~150 lines, no dependency, and it makes every other feature discoverable without adding chrome to the page. For a keyboard-heavy audience (security people) this is disproportionately loved.

### 3.3 Keyboard triage: `j` / `k` / `e` / `x` / `w`

Gmail/Superhuman-style navigation over the card list — next, previous, expand, dismiss, add to watchlist. Combined with 3.2 you get a tool someone can actually work through 251 items with. Pair it with a persistent `dismissed` set in `localStorage` so the list shrinks as they triage. **"Inbox zero" for threat intel** is a genuinely differentiated product idea and you're two evenings away from it.

### 3.4 Make the sidebar interactive

The severity bars, source list, and category list are currently read-only decoration. Every one should be a filter control: click "CRITICAL 51" → filter. Click a source → filter. Shift-click → add to selection. You already have `filterByCategory` and `filterByThreatActor` as globals; wire up the rest. **~1 hour, and it removes the need for several separate UI controls.**

### 3.5 Real charts on the Trends tab

You built `trends.json` — 30 days of daily counts, severity mix, top actors, top TTPs, trending CVEs — and then render it with `renderBarList()`, which draws `<div>`s with percentage widths. The data deserves better:

- **Stacked area chart**: daily volume by severity over 30 days
- **Sparklines** in the source-health rows: is this feed trending down before it dies?
- **Calendar heatmap**: 90 days × item count, spot the Patch Tuesday spikes
- **Slope chart**: this week's top actors vs last week's

Use `uPlot` (~45 KB, no dependencies, extremely fast) or hand-rolled SVG. **Do not add Chart.js or D3** — both are heavier than your entire app.

> Note: adding a CDN for a chart library means updating your CSP `script-src`. Prefer vendoring the file into the repo so `'self'` still covers it.

## Tier 2 — strong additions

### 3.6 Relationship graph

You have the edges already: item → CVE, item → threat_actors, item → ttps, item → source. A force-directed graph of *"Salt Typhoon → T1190 → CVE-2026-x → 3 sources"* is the view that shows a campaign rather than a list of headlines. This is the one place a graph visualisation earns its keep — unlike the current per-item Mermaid diagrams, which show the same 4 pictures 248 times.

Reuse the Mermaid dependency you already load, or use `d3-force` for interactivity.

### 3.7 Shareable view state in the URL

You persist filters to `localStorage`. Put them in the URL hash instead (`#severity=critical&source=NVD&q=fortinet`) so a view can be **sent to a colleague**. You already have hash routing for `#cve-...`; extend the same handler. Cheap, and turns the dashboard into something teams pass around.

### 3.8 "What changed since I last looked"

You have `is_new` from the pipeline and `markAsSeen()` in localStorage. Combine into a real diff view: *"Since your last visit (6h ago): 14 new · 3 escalated to KEV · 1 PoC published."* An escalation feed is more actionable than a new-items feed, because a CVE going from `poc` to `active` is the moment your priority changes.

### 3.9 Density toggle + virtual scrolling

At 251 items, a compact mode (one line per item: severity dot, title, source, priority) makes scanning far faster than cards. Add a comfortable/compact toggle. If you later scale past ~1,000 items, swap the 40-item pagination for a virtual list (`@tanstack/virtual` or ~80 lines by hand).

### 3.10 Skeleton loading

Replace the spinner with skeleton cards matching the final layout. Perceived performance improves measurably and it removes the layout jump when content arrives.

## Tier 3 — nice, later

- **Comparison mode**: diff two archive dates side by side (the archive data already supports it)
- **Toast for new criticals** while the tab is open, with the Notification API behind an explicit opt-in
- **Light theme** — the dark terminal aesthetic is good, but some people present this on a projector
- **Per-item "copy as IOC / copy as markdown"** for pasting into a ticket
- **Print/PDF stylesheet** for the daily brief

## 3.11 Should you leave vanilla JS?

`app.js` is 1,612 lines with manual `innerHTML` string building and manual DOM sync. That's near the ceiling for maintainable vanilla, and features like 3.1 (live merge) and 3.9 (virtual list) get painful without reactivity.

| Option | Size | Verdict |
|---|---|---|
| **Stay vanilla, add a tiny store** | 0 KB | **Recommended.** ~50 lines of pub/sub over your state + a `render()` that diffs by key gets you 80% of the benefit. Your CSP stays simple, no build step, GitHub Pages stays trivial. |
| **Alpine.js** | 15 KB | Good fit for sprinkles, but `x-` attributes need CSP `unsafe-eval`. **Avoid** given your CSP. |
| **Preact + htm** | 12 KB | Real components, no build step, no `unsafe-eval`. The right choice **if** you commit to the rewrite. |
| **Svelte** | ~5 KB runtime | Smallest output, but adds a build step and a CI job. Only worth it if the app keeps growing. |

**Recommendation: stay vanilla now.** Fix the payload and the data quality first — those change what the product *is*. Revisit the framework question only when you hit a feature you genuinely can't build (probably the virtual list). Rewriting the view layer while the underlying data is 31% mislabelled is optimising the wrong thing.

---

# Part 4 — Features worth adding

## Tier 1 — build these

| Feature | Why | Effort |
|---|---|---|
| **SSVC decision column** (Vulnrichment) | Turns a score into an action. Free data. | M |
| **Batched AI daily brief** | The 3-line answer people actually want. 1 API call/run. | S |
| **Stack-scoped everything** | "Nothing you run is affected" is the killer feature | M |
| **Escalation feed** (`poc`→`active`, new KEV) | Change is more actionable than volume | M |
| **Triage state** (dismiss / snooze / star, localStorage) | Makes 251 items tractable | S |
| **Freshness-aware source health** | Stops reporting 4-year-old feeds as green | S |

## Tier 2 — worth it once Tier 1 lands

| Feature | Why | Effort |
|---|---|---|
| **Cross-source corroboration** ("3 sources report this") | Best noise filter available; the dedup keys already exist | M |
| **Campaign clustering** (group items by actor + TTP + time) | 251 items → ~15 stories | L |
| **Real per-item attack chains** from mapped TTPs | Replaces 4 fake diagrams with something derived from data | M |
| **RSS/Atom per filter** (`feed.xml?severity=critical`) | Meets people in the reader they already use | S |
| **Weekly digest** (better cadence than daily for most) | Higher signal, lower fatigue | S |
| **Vendor/product landing pages** (`#/vendor/fortinet`) | SEO + genuinely useful pivot | M |

## Tier 3 — speculative

- **VEX consumption** — filter out CVEs your vendors have declared not-affected
- **SBOM upload** → match CVEs against actual dependencies (this is where "My Stack" logically ends up)
- **Slack bot with slash commands** rather than one-way webhooks
- **Historical "what did we know when"** replay from the archive
- **Public API with an OpenAPI spec** — but see Part 5 on `rest_api.py`

---

# Part 5 — Features to cut or stop investing in

Being ruthless here is worth more than any addition.

### 5.1 Per-item Mermaid attack diagrams — **cut**

251 items, **7 distinct graphs**, 4 templates covering 248 of them. They cost 62 KB of payload (17%), a 45 KB CDN dependency, a CSP entry, and lazy-render complexity — to show the same picture 91 times under a header that says "AI THREAT ANALYSIS". They are decorative at best and actively misleading at worst.

**Keep the Mermaid dependency only if you build 3.6 (the relationship graph)**, where one real graph per *campaign* would earn its place. Otherwise drop it entirely.

### 5.2 `rest_api.py` — **cut, or repurpose**

222 lines implementing a REST API that **cannot be reached in the deployed architecture** — the site is static on GitHub Pages; nothing runs this server. It duplicates what `data/intel.json` already provides (a static JSON file *is* a public read API, cacheable on a CDN, infinitely scalable, free). It also carries real bugs: unvalidated `int()` parsing that 500s with a traceback, single-threaded `HTTPServer`, a `0.0.0.0` default bind with `CORS: *`, and a `/api/stats` field (`exploit_available`) the pipeline never sets, so it reports 0 forever.

If you want an API, generate **static JSON endpoints** at build time — `data/api/critical.json`, `data/api/by-source/nvd.json`, `data/api/stats.json`. Same benefit, zero runtime, zero attack surface.

### 5.3 STIX export in its current form — **cut until §3 of the analysis is fixed**

It currently publishes `gmail.com`, `redhat.com`, `cern.ch` and two named maintainers' work email addresses as `indicator_types: ["malicious-activity"]`. Shipping this is worse than shipping nothing. Turn it off today; re-enable only for IOCs from sources that actually publish IOCs.

### 5.4 `severity_score` (the AI 0-10 float) — **cut**

You have CVSS (authoritative), EPSS (empirical), KEV (confirmed), and a blended `priority_score`. A fifth number, hallucinated by an LLM from a headline, adds no information and creates disagreement between badges on the same card. Drop it; keep the AI for prose.

### 5.5 `sw.js` — **delete**

Dead file. Only `service-worker.js` is registered. Two service worker implementations side by side is a trap.

### 5.6 `utils.py` — **delete or actually use**

Nothing imports it. Its docstring claims otherwise. See `CODE_ANALYSIS.md` §6.

### 5.7 `daily_digest.py` as a separate system — **merge**

241 lines duplicating `webhook_post.py`'s payload builders and retry logic, with its own state file and workflow. Its Slack footer renders a **local filesystem path** as a link (`</app/data/index.html|Open Dashboard>`), which proves it hasn't been used. Merge into `webhook_post.py` with a `--mode digest` flag.

### 5.8 Dead and stale sources — **prune**

| Source | Status |
|---|---|
| Threatpost | **Delete.** Shut down 2023; median item age 1,456 days |
| OSV | **Delete the stub** or implement it properly — it returns `[]` by design while the README credits it with "25+ sources" |
| CISA, AbuseIPDB, PhishTank, MalwareBazaar, ThreatFox, Mitre CWE | Returning 0. Fix or remove — a permanently amber row trains people to ignore the health panel |
| CentOS Stream | Median 252 days old. Low value, keep only if cheap |

Chasing source *count* is a trap. **28 fresh sources well-deduplicated beats 37 with 9 dead.**

### 5.9 LinkedIn badge — **reconsider**

It costs two CSP entries (`script-src platform.linkedin.com`, `frame-src`, plus two `img-src` domains), an external script on every page load, and third-party tracking on a security tool. A plain text link costs nothing. Your call — it's your portfolio piece — but be aware of what it's buying.

---

# Part 6 — AI and data source recommendations

## 6.1 AI: what to use and, more importantly, what to use it *for*

### Your current setup is two versions behind

```
requirements.txt:  google-generativeai==0.8.3    ← legacy SDK, superseded by `google-genai`
config.py:         gemini-2.5-flash-lite         ← current line is Gemini 3.x
                   llama-3.3-70b-versatile (Groq)
```

Gemini 3.x Flash and Flash-Lite are on the **free tier**, so upgrading is a strict improvement at zero cost: better instruction-following, better JSON adherence, larger context.

### Recommended stack

| Role | Choice | Why |
|---|---|---|
| **Primary** | `gemini-3.5-flash-lite` (free tier) | Cheapest capable model, generous free RPD, native structured output |
| **Quality tier** | `gemini-3-flash` for the daily brief only | One call/run — worth the better model |
| **Fallback** | Groq (`openai/gpt-oss` or Llama) | Keep, but see the caveat below |
| **SDK** | `google-genai` | The `google-generativeai` package is the deprecated path |

**Caveat on Groq:** its free tier is **100–2,000 requests/day and 3.6K–500K tokens/day depending on model** — tight for per-item enrichment. It's fine as a failover for a handful of calls, not as a primary. If you want a second real provider, **Cerebras** and **Together** both have usable free tiers, or run `qwen3` locally via Ollama for zero marginal cost.

### Use structured output — it deletes 60 lines of your code

`parse_ai_response()` is a four-stage recovery ladder (strip fences → repair trailing commas → balance braces → regex-salvage fields) for malformed LLM JSON. **That entire function becomes unnecessary** with a response schema:

```python
from google import genai
from pydantic import BaseModel, Field

class Enrichment(BaseModel):
    summary: str = Field(description="4-5 sentence technical analysis")
    why_it_matters: str = Field(description="One sentence: who should act and how fast")
    affected_products: list[str]
    confidence: float

client = genai.Client(api_key=CONFIG.gemini_api_key)
resp = client.interactions.create(
    model="gemini-3.5-flash-lite",
    input=prompt,
    response_format={"type": "text", "mime_type": "application/json",
                     "schema": Enrichment.model_json_schema()},
)
```

The model is constrained at the decoding level — it *cannot* emit invalid JSON. Delete the ladder, keep one `try/except`.

> Verify the exact call shape against the current SDK docs before committing — Google renamed these parameters when moving to `google-genai`.

### Batch the calls

One request with 10 items and an array schema instead of 10 requests. 90s → ~5s, 10× fewer requests against your quota, and it lets you raise `AI_ENRICH_LIMIT` to 50+ on the same free tier. For genuinely non-urgent work, Gemini's **Batch API is 50% cheaper** — though on the free tier you're already at zero.

### **The most important point: change what you ask the AI to do**

Right now the AI writes a summary of an article that already has a summary, and draws a diagram of a threat model it doesn't know. Both are low value. LLMs are bad at facts you already have and good at judgement and synthesis. Spend the tokens on:

| Instead of | Ask for |
|---|---|
| "Summarise this article" (`description` already says it) | **"Given these 251 headlines, which 5 matter most and why?"** — one call, produces the daily brief |
| A hallucinated 0-10 severity score | **"Which of these 30 items are the same story?"** — semantic dedup your regex can't do |
| A boilerplate Mermaid diagram | **"Given this user's stack (Fortinet, VMware, Ubuntu), which of today's items affect them?"** |
| Nothing | **"Extract affected vendor/product/version as structured data"** — this is what LLMs are genuinely best at, and it feeds "My Stack" |

That last row is the highest-value use of an LLM in this entire project. Vendor/product extraction from unstructured advisory text is hard for regex, easy for a model, and it's the missing piece that makes stack-matching work.

**Cheaper alternative worth knowing:** for semantic dedup and clustering specifically, **embeddings beat generation** — `gemini-embedding-001` or a local `sentence-transformers` model, then cosine similarity. Far cheaper, faster, deterministic, and no hallucination risk. For "are these two articles the same story", embeddings are the right tool.

## 6.2 Data sources worth adding

### Tier 1 — add these

**CISA Vulnrichment** — *free, no key, highest value*
`github.com/cisagov/vulnrichment`, laid out as `<year>/<N>xxx/CVE-<id>.json`. Provides SSVC decision points (Exploitation none/poc/active, Automatable, Technical Impact), plus CWE and CVSS where the CNA omitted them. Fetch only the CVEs in your feed; cache aggressively (records rarely change). **This is the enrichment that makes your priority score defensible.**

**VulnCheck Community** — *free key, generous*
- **VulnCheck KEV** — a superset of CISA KEV, typically listing exploited vulnerabilities *earlier* and including many CISA never adds. A drop-in upgrade to `fetch_cisa_kev()`.
- **NVD++** — mirrors NVD with restored CPE data. Notably, **CISA stopped adding CPE strings to Vulnrichment in Dec 2024**, so this is your best route to reliable product matching for "My Stack".
- **XDB** — an index of PoC exploit code in public git repos. More authoritative than the single `PoC-in-GitHub` repo you scrape today.

**EPSS full daily CSV** — *free, fixes a real bug*
`epss.cyber.ir/data/current` publishes the entire scored corpus daily as gzipped CSV. Download once per day into a dict. This **eliminates the stale-cache bug** from `CODE_ANALYSIS.md` §4 (14 of your 69 CVEs currently have no EPSS score) and removes a per-run API dependency entirely.

**CIRCL Vulnerability-Lookup** — *free*
`vulnerability.circl.lu` aggregates CVE, GHSA, PySec, CSAF and several KEV sources (CIRCL, CISA, ENISA, Shadowserver) behind one API, with sightings data. Good coverage-per-integration ratio. Check current rate limits before depending on it.

### Tier 2 — worth it later

- **GitHub Security Advisory GraphQL API** — richer than the REST endpoint you use in `fetch_ghsa()`, with proper package/version ranges (good for SBOM matching). Uses your existing GitHub token.
- **OSV batch API** — `POST /v1/querybatch` takes up to 1,000 package queries at once. This is the correct way to use OSV, and it makes your stubbed `fetch_osv()` real — but it needs package names, so it only works *after* you have SBOM/stack input. The current stub is honest about this; the README isn't.
- **Shadowserver** — free daily reports, but scoped to your own netblocks. Only relevant if you add an org-specific mode.
- **inthewild.io** — community-reported exploitation sightings, free API. Another `Exploitation: active` signal.

### Tier 3 — probably not

- **Commercial TI** (Recorded Future, Mandiant, Intel 471) — no free tier, wrong shape for this project
- **VirusTotal** — free tier is 4 req/min, far too slow for pipeline use
- **Shodan / Censys** — great data, but for asset discovery, not intel aggregation. Different product.

### Sources to fix rather than add

Before adding anything, get to 100% on what you have: **CISA, AbuseIPDB, PhishTank, MalwareBazaar, ThreatFox, and Mitre CWE all return zero items.** CISA in particular is your flagship advisory source and it's dark — the ICS advisory feed URL in `RSS_SOURCES` is the likely culprit. Fixing six broken integrations is worth more than adding six new ones.

---

# Part 7 — Suggested sequencing

**Phase 1 — Truth (1 week).** Nothing else matters if the data is wrong.
1. Word-boundary matching (`infer_severity`, `infer_category`, `map_ttps`) — fixes 31% of your criticals
2. Turn off the STIX/CSV export until IOC extraction is scoped to IOC sources
3. Freshness-aware source health; delete Threatpost and the OSV stub
4. Make the tests import production code; add a PR CI workflow

**Phase 2 — Efficiency (1 week).**
5. `fetch-depth: 1`; roll up the health JSONL; archive daily not hourly
6. Dedupe `workflow_graph`; drop rule-based `ai_summary`
7. Batch the AI prompt; upgrade to `google-genai` + Gemini 3.x + structured output
8. Compiled TTP regex; `requests.Session` + conditional GET

**Phase 3 — Value (2 weeks).**
9. Vulnrichment SSVC integration
10. EPSS daily CSV (kills the cache bug)
11. VulnCheck KEV + NVD++ for CPE
12. AI daily brief (one call/run) + LLM vendor/product extraction

**Phase 4 — UI (2 weeks).**
13. Live update toast + merge
14. Interactive sidebar; priority-first default sort
15. Command palette + keyboard triage + dismiss state
16. Real charts on the Trends tab

**Phase 5 — Cut.**
17. Delete `sw.js`, `utils.py`, `rest_api.py`, per-item Mermaid, `severity_score`
18. Merge `daily_digest.py` into `webhook_post.py`

---

## The one-paragraph version

Your infrastructure is good — the concurrency, failure isolation, atomic writes and caching are all done properly. The problems are that the **inference layer is wrong** (31% of criticals are a substring bug), the **exports are unusable** (and publish two people's email addresses as malicious), the **AI does the wrong job** (rewriting summaries that already exist instead of telling you what matters), and the **product shows 251 items when a human needs 5**. Fix correctness first, cut the four features that add noise, spend your AI budget on judgement instead of prose, add SSVC so the score means something, and only then make the UI dynamic — because a live-updating view of mislabelled data is just a faster way to be wrong.

---

# Appendix — what v4.0 shipped

**2026-08-26.** Everything below landed after this document was written. Where a
roadmap item was implemented differently from the sketch above, the reason is
given — the sketch was working from measurements, not from having tried it.

## The framing problem (Part 0) — addressed

The diagnosis was right and the fix is now the default: the feed opens on
**Verdicts**, the 66 of 315 items the tool has an opinion about, ordered
*Patch now → this week → next cycle → monitor*. The other 249 are one click
away and are no longer the front page.

Two supporting changes that mattered as much as the filter itself:

- **NEW now means new to you.** It meant "not in the previous hourly run",
  which is why it fired on two-thirds of the feed and therefore meant nothing.
  `lastVisit` was already in `localStorage`, written and never read.
- **Triage has an end.** Progress counter, next-unreviewed jump, and a real
  done screen. Nine actionable items is a finishable list; the old feed never
  acknowledged the end of anything.

## Navigation — the item this document did not catch

The sixteen-button strip mixed nine feed filters with seven full-screen views,
styled identically. Clicking `NEWS` narrowed a list; clicking `THREAT MAP`
discarded it. Sector and severity filters also stayed armed while a map was on
screen, where they meant nothing. Views and filters are now separate chrome,
and filters render only inside Feed.

## Research — new, and the reason the archive exists

None of this was on the roadmap. It is the part that turns 90 days of archives
from storage into evidence.

| Shipped | What it answers |
|---|---|
| `scripts/backtest.py` | Does the blended score predict exploitation? (Currently: **no** — EPSS alone beats it 3×) |
| `scripts/source_reliability.py` | Which of the 43 feeds carry things that later mattered, and which were merely early to report the announcement |
| `scripts/exploit_lag.py` | Median publication → PoC → KEV latency, by quarter. **Shortening: 8.8 days recent vs 30.5 earlier** |

The backtest excludes CVEs already in KEV when first scored; without that the
experiment measures its own arithmetic rather than the world.

## Entity graph, campaigns, malware, detections

| Roadmap item | Shipped as |
|---|---|
| 3.6 Relationship graph | `scripts/entity_graph.py` — MITRE CTI relationships, laid out in columns rather than as a force-directed hairball, with **known** (ATT&CK) and **observed** (this feed) edges drawn differently |
| — | `scripts/campaigns.py` — actor/malware-anchored clustering; technique+sector overlap may only *extend* a cluster, never create one |
| — | `scripts/malware.py` — Malpedia family entities, curated attribution kept separate from co-occurrence |
| — | `scripts/sigma_rules.py` — intel → detection, plus the coverage **gaps**, which is the half worth reading |

## Time travel and diff

| Roadmap item | Shipped as |
|---|---|
| 3.8 "What changed since I last looked" | A first-class **Diff** view over any two archived days, with escalations sorted to the top — not just an `is_new` flag |
| — | **Time machine**: `scripts/timeline.py` publishes a reduced ~60 KB snapshot per archived day. The archives existed for 90 days and no page could open them, because they are not published and a full snapshot is ~270 KB |

## UI items from Part 3

| Roadmap item | Status |
|---|---|
| 3.9 Density toggle | Shipped, and **compact is now the default** — comfortable put ~2 cards on a screen, making 320 items ~160 screens long |
| 3.7 Shareable URL state | Shipped, plus **saved investigations** (name a filter set and return to it), which is the half URL state did not cover |
| 3.4 Interactive sidebar | Shipped, then **removed from the layout**: eight always-on cards competed with the content and several duplicated the nav. They are a summoned slide-over with collapsible sections now |
| — | A real **query layer** (`js/query.js`): `epss > 0.5 and not kev and stack and age <= 7d`, with an English front end on top |
| — | **Light theme**, three states, as a second token block |
| — | **Semantic colour**: cyan meant active state, links, counts and highlights simultaneously. Four roles, four tokens |
| — | **Three breakpoints** (640/900/1200) replacing five accumulated ones |
| — | **Score interrogability**: click the number, get the arithmetic term by term |
| — | **"Why am I seeing this?"** per card |
| — | **Confidence surfacing** — `sector_confidence`, `ai_confidence`, CVSS provenance were computed and never shown |

## Interoperability and durability

- **MISP export** alongside STIX. STIX is what you hand a commercial platform;
  MISP is what most CERTs actually run. `to_ids` is set only for indicator
  feeds — a hash from a news article is context, not a detection rule.
- **Archive durability**: the published `state.tar.gz` now also carries the four
  expensive derived corpora, the timeline index records a SHA-256 and size per
  day and reports gaps, and the deploy step refuses to publish an incomplete
  site. CI asserts no own-estate data reaches the public tarball.

## Defects found and fixed along the way

Listed because they are the kind that a green test suite does not catch:

1. **Satellite modules never shared the session or the cache.** `darkweb`,
   `geoip`, `exposure`, `attacker_feeds` and `attack_surface` all did
   `try: from fetch_intel import _SESSION, _cached_fetch except: ...`, an import
   that can never succeed — `fetch_intel` imports them *before* defining those
   names, and running it as a script makes it `__main__` anyway. Every one ran
   with caching disabled. Extracted to `scripts/fetchlib.py`.
2. **`priority_components` never reached the published item.** The scorer
   emitted it correctly; `main()` copied five named fields and dropped it.
   Found by checking the artifact, not the unit test.
3. **The service worker defeated its own cache-busting.** `ignoreSearch: true`
   collapsed `app.js?v=4.0.0` and `?v=4.0.1` onto one entry, so a returning
   visitor kept the old code against new data.
4. **Threat-actor case variants split every count.** `Qilin`/`qilin`,
   `SafePay`/`safepay` counted as four actors.
5. **Malware naming matched ordinary English.** ATT&CK ships tools called
   *Expand*, *Route*, *Chaos* and *Embargo*; a shipping-embargo story was
   tagged as ransomware.
6. **Source reliability conflated coverage with prediction.** A news site
   scored 0.81 "precision" for reporting KEV additions the day they landed.
7. **Five query-language bugs**, including a filler rule that deleted the `kev`
   in "no KEV listing" and left a dangling `NOT` that attached to the time
   window — inverting the query. All pinned in `tests/query.test.js`.
