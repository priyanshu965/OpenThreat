/**
 * OPENTHREAT DASHBOARD — app.js
 *
 * Architecture notes (this replaced a 1,612-line render-everything-on-load file):
 *
 *  - A tiny pub/sub store replaces manual DOM syncing, so live merges and filter
 *    changes go through one render path instead of ad-hoc mutations.
 *  - NO inline event handlers anywhere. The page CSP sets script-src without
 *    'unsafe-inline', so every inline handler attribute in the old markup
 *    was silently dead code in the browser.
 *  - URLs are scheme-checked before they reach an href. escapeHTML() neutralises
 *    <>"'& but NOT `javascript:`, so a feed item could previously ship a working
 *    payload behind a card title.
 *  - Attack-flow graphs come from document-level templates, not 251 duplicated
 *    copies of the same four strings.
 */

'use strict';

// ─── Constants ────────────────────────────────────────────────────────────────
const DATA_URL      = 'data/intel.json';
const HEALTH_URL    = 'data/source_health_summary.json';
const TRENDS_URL    = 'data/trends.json';
// The pipeline publishes hourly, so a 2-minute poll spent ~30 requests an hour
// per open tab to discover nothing. Ten minutes still surfaces a new run well
// inside the hour it lands in.
const POLL_INTERVAL = 600000;
const PAGE_SIZE     = 40;

const LS = {
  filter: 'ot_filter', severity: 'ot_severity', sort: 'ot_sort',
  watchlist: 'ot_watchlist', watchlistOnly: 'ot_watchlistOnly',
  stack: 'ot_stack', dismissed: 'ot_dismissed', starred: 'ot_starred',
  density: 'ot_density', lastVisit: 'ot_lastVisit', darkwebWatch: 'ot_darkwebWatch', notes: 'ot_notes',
  view: 'ot_view', reviewed: 'ot_reviewed', saved: 'ot_saved', theme: 'ot_theme',
  lastSeen: 'ot_lastSeen',
};

// Endpoints published by the pipeline, fetched on demand. Every one of these is
// its own file precisely so opening the feed does not download the graph, the
// Sigma coverage table and three research reports nobody asked for.
const API = {
  graph:       'data/api/graph.json',
  malware:     'data/api/malware.json',
  detections:  'data/api/sigma.json',
  campaigns:   'data/api/campaigns.json',
  backtest:    'data/api/backtest.json',
  reliability: 'data/api/source_reliability.json',
  lag:         'data/api/exploit_lag.json',
  timeline:    'data/api/timeline.json',
  day:         (date) => `data/api/day/${date}.json`,
  // v5. entityIndex is the ONE file loaded up front for the Library; the full
  // record for a single entity is its own small shard.
  entityIndex:    'data/api/entity_index.json',
  entity:         (slug) => `data/api/entity/${slug}.json`,
  huntPacks:      'data/api/hunt_packs.json',
  // One pack is ~20 KB and there are 220 of them; the index above
  // carries only what the list view renders.
  huntPack:       (tid) => `data/api/hunt/${tid}.json`,
  huntQueue:      'data/api/hunt_queue.json',
  detectionDiff:  'data/api/detection_diff.json',
  controlFocus:   'data/api/control_focus.json',
  leaks:          'data/api/leak_sites.json',
  telegram:       'data/api/telegram.json',
  // v6
  kev:            'data/api/kev.json',
  lifecycle:      'data/api/lifecycle.json',
};

// VIEWS replace the screen. FEED FILTERS narrow the list in place. Keeping the
// two in separate vocabularies is the whole point of the v4 navigation: the old
// build had them in one 16-button strip where clicking NEWS filtered a list and
// clicking THREAT MAP discarded it.
const VIEWS = ['feed', 'map', 'landscape', 'matrix', 'graph', 'campaigns',
  'detections', 'malware', 'geopol', 'darkweb', 'exposure', 'trends',
  'research', 'about', 'diff',
  // v5
  'library', 'hunt', 'leaks',
  // v6 tools
  'recon', 'creds', 'ioc', 'phish',
  // v6 catalogs
  'kev', 'lifecycle', 'cve',
  // v6 — 'contact' is a route, not a mode: it answers no question about
  // threats, so putting it in the mode nav would dilute what the modes mean.
  'contact'];

// Views grouped by the QUESTION they answer. The top nav switches MODE; the
// strip beneath switches views WITHIN the active mode, and hides itself when a
// mode holds only one. This is the whole point of the v5 navigation: the v4
// build put thirteen buttons in one row, so choosing an encyclopedia and
// choosing a picture of the world looked like the same kind of decision.
const MODE_VIEWS = {
  feed:      [['feed', 'FEED']],
  library:   [['library', 'BROWSE'], ['graph', 'GRAPH'], ['matrix', 'ATT&CK'],
              ['campaigns', 'CAMPAIGNS'], ['malware', 'MALWARE'],
              ['cve', 'CVE']],
  hunt:      [['hunt', 'BENCH'], ['detections', 'COVERAGE MAP']],
  landscape: [['map', 'THREAT MAP'], ['landscape', 'LANDSCAPE'],
              ['geopol', 'GEOPOLITICS'], ['leaks', 'LEAK SITES'],
              ['darkweb', 'DARK WEB'], ['kev', 'KEV'],
              ['lifecycle', 'LIFECYCLE'], ['exposure', 'EXPOSURE']],
  research:  [['research', 'EVIDENCE'], ['trends', 'TRENDS']],
  // A sixth mode, because these answer a different KIND of question. The other
  // five report on the world from data this project published; these take an
  // artifact you have and query third-party APIs live from your browser.
  // Filing them under HUNT would repeat the conflation the split removed.
  tools:     [['recon', 'RECON'], ['ioc', 'IOC LOOKUP'],
              ['phish', 'PHISHING'], ['creds', 'CREDENTIALS']],
};

const MODES = Object.keys(MODE_VIEWS);

// view -> mode, derived so the two can never drift apart.
const VIEW_MODE = {};
Object.entries(MODE_VIEWS).forEach(([mode, views]) => {
  views.forEach(([view]) => { VIEW_MODE[view] = mode; });
});

function modeOf(view) {
  return VIEW_MODE[view] || 'feed';
}

const FEED_FILTERS = ['verdicts', 'all', 'fresh', 'exploited', 'stack', 'cve',
  'incident', 'advisory', 'news', 'iocs', 'starred', 'urgent'];

// Verdict bands, in the order a triage list should present them. This ordering
// IS the product: "what do I do today", not "what happened".
const BAND_ORDER = { urgent: 0, elevated: 1, moderate: 2, low: 3 };

// A visit is a session. Reloading the page three times in ten minutes is one
// visit, so NEW must not reset each time — see rollVisit().
const VISIT_GAP_MS = 30 * 60 * 1000;

// Severity is ORDINAL (low -> critical), so it takes a one-hue sequential ramp
// rather than four categorical hues. The previous four-hue set failed the
// normal-vision separation floor: #f5c518 (medium) against #ff8c42 (high) sat at
// deltaE 14.4, below the 15 threshold — hard to tell apart even with full colour
// vision. This ramp passes all four ordinal checks against the #0d1117 surface
// (monotone lightness, deltaL gaps >= 0.06, light-end contrast, 9-degree hue
// spread). Severity is never encoded by colour alone: every mark carries a text
// label or a legend entry.
const SEVERITY_RAMP = {
  low: '#8c4a5c', medium: '#b9455f', high: '#e04365', critical: '#ff7a91',
};
const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low'];

// Nominal categorical bars (sources, actors) are ONE series, so every bar takes
// the same slot-1 hue. Colouring nominal bars by their value would spend the
// identity channel re-encoding what bar length already shows.
const SERIES_1 = '#3987e5';

const CATEGORIES = ['cve', 'incident', 'advisory', 'news'];

// ─── Store ────────────────────────────────────────────────────────────────────
const store = {
  items: [], filtered: [], meta: {}, brief: null,
  health: {}, staleness: {}, trends: null,
  view: 'feed',
  // "Verdicts" is the default because it is the answer to the question the tool
  // exists to answer. On a typical run 251 of 320 items carry no verdict at
  // all, so an unfiltered feed buries the 9 things that need doing today under
  // 78% noise.
  filter: 'verdicts', severity: null, query: '', sort: 'priority',
  renderLimit: PAGE_SIZE, cursor: -1, density: 'compact',
  watchlist: [], watchlistOnly: false, stack: [],
  dismissed: new Set(), starred: new Set(), showDismissed: false,
  reviewed: new Set(),
  lastVisit: null, stamp: null,
  mapCat: null, sector: null, mapPaused: false,
  darkwebIndex: null, darkwebQuery: '', darkwebWatch: [], casm: {}, provenance: null, humanOnly: false,
  notes: {}, saved: [], theme: 'auto',
  // Time machine. `day` is null when looking at today; otherwise it holds the
  // date string being displayed and `liveItems` keeps today's feed aside.
  day: null, liveItems: null, timeline: null, dayCache: {},
  diffFrom: null, diffTo: null,
  // Parsed structured query (js/query.js). Null when the search box holds
  // plain text or is empty.
  parsedQuery: null,
  research: {},          // lazily-fetched endpoint cache, keyed by API name
};

// ─── Safe DOM helpers ─────────────────────────────────────────────────────────
function escapeHTML(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#039;');
}

/**
 * Scheme allowlist for anything that reaches an href.
 *
 * escapeHTML alone does NOT stop `javascript:alert(1)`, and item URLs come from
 * third-party feeds (Reddit posts, OTX pulses) that anyone can submit to. The
 * control-character strip matters because "java\tscript:" is parsed as
 * javascript: by some engines.
 */
function safeUrl(url) {
  if (!url) return '';
  const trimmed = String(url).trim();
  const normalised = trimmed.replace(/[\u0000-\u0020]/g, '').toLowerCase();
  return /^https?:\/\//.test(normalised) ? trimmed : '';
}

/**
 * A mailto: URL, built from parts.
 *
 * safeUrl() deliberately allows http(s) ONLY, because every URL it sees came
 * from one of 43 third-party feeds and the scheme allowlist is what stops a
 * `javascript:` href reaching an anchor. Widening it to admit mailto: would
 * weaken that check for all of those feeds in order to serve a handful of
 * first-party links, which is a bad trade.
 *
 * So this is separate and much narrower: the address must look like an address
 * and carry no CR/LF (a newline in a mailto is how you inject extra headers),
 * and the subject and body are percent-encoded here rather than by the caller.
 * It is only ever called with constants defined in this codebase.
 */
function safeMailto(address, subject, body) {
  const addr = String(address || '').trim();
  if (!/^[^\s@<>,;:"'\\]+@[^\s@<>,;:"'\\]+\.[a-z]{2,}$/i.test(addr)) return '';
  const params = [];
  if (subject) params.push('subject=' + encodeURIComponent(String(subject)));
  if (body) params.push('body=' + encodeURIComponent(String(body)));
  return 'mailto:' + addr + (params.length ? '?' + params.join('&') : '');
}

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function $(id) { return document.getElementById(id); }

// ─── localStorage ─────────────────────────────────────────────────────────────
// Keys were prefixed `cw_` / `cw.` when the project was called CyberWatch. They
// are now `ot_` / `ot.`.
//
// The rename has to carry the old values across, because these keys are not
// bookkeeping — they hold analyst notes, starred and dismissed items, saved
// investigations, the watchlist, the stack and the pasted detection inventory.
// Renaming the keys without moving the values would have silently wiped all of
// it the first time anyone loaded the page after the rename, with no error and
// no way back.
//
// Runs once: after the copy, a marker stops it re-reading old keys the user may
// since have deliberately cleared.
const LS_MIGRATION_MARKER = 'ot_migrated_from_cw';

function migrateLegacyKeys() {
  try {
    if (localStorage.getItem(LS_MIGRATION_MARKER)) return;
    let moved = 0;
    for (let i = 0; i < localStorage.length; i += 1) {
      const key = localStorage.key(i);
      if (!key || !/^cw[_.]/.test(key)) continue;
      const next = key.replace(/^cw([_.])/, 'ot$1');
      if (localStorage.getItem(next) === null) {
        localStorage.setItem(next, localStorage.getItem(key));
        moved += 1;
      }
    }
    localStorage.setItem(LS_MIGRATION_MARKER, '1');
    if (moved) console.info(`OpenThreat: carried ${moved} saved setting(s) over from the old key names.`);
  } catch (_) { /* private mode, quota, or storage disabled — nothing to do */ }
}

function readLS(key, fallback) {
  try {
    const raw = localStorage.getItem(key);
    return raw === null ? fallback : JSON.parse(raw);
  } catch (_) { return fallback; }
}

function writeLS(key, value) {
  try { localStorage.setItem(key, JSON.stringify(value)); } catch (_) {}
}

// ─── Item helpers ─────────────────────────────────────────────────────────────
function canonicalUrl(url) {
  return String(url || '').toLowerCase()
    .replace(/^https?:\/\//, '').replace(/^www\./, '')
    .split('?')[0].split('#')[0].replace(/\/$/, '');
}

function itemKey(item) {
  if (item.cve_id) return `cve:${item.cve_id.toUpperCase()}`;
  const url = canonicalUrl(item.url);
  if (url) return `url:${url}`;
  return `title:${(item.title || '').toLowerCase().slice(0, 100)}`;
}

/**
 * Display summary. Rule-based items no longer ship an `ai_summary` — 246 of 248
 * were a prefix of `description`, which is already in the same object, so the
 * payload carried the same prose twice.
 */
function displaySummary(item) {
  if (item.ai_summary) return item.ai_summary;
  const desc = item.description || '';
  return desc.split(/(?<=[.!?])\s+/).slice(0, 3).join(' ') || item.title || '';
}

function matchesStack(item) {
  if (!store.stack.length) return false;
  const hay = [item.title, item.description,
    ...(item.vendors || []), ...(item.products || []),
    ...(item.affected_products || [])].join(' ').toLowerCase();
  return store.stack.some((term) => hay.includes(term.toLowerCase()));
}

function matchesWatchlist(item) {
  if (!store.watchlist.length) return false;
  const hay = `${item.title} ${item.description} ${item.cve_id || ''}`.toLowerCase();
  return store.watchlist.some((term) => hay.includes(term.toLowerCase()));
}

function timeAgo(date) {
  const diff = Date.now() - date;
  if (Number.isNaN(diff)) return '';
  const mins = Math.floor(diff / 60000);
  const hours = Math.floor(diff / 3600000);
  const days = Math.floor(diff / 86400000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  if (hours < 24) return `${hours}h ago`;
  if (days < 7) return `${days}d ago`;
  return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
}

// ─── URL state (shareable views) ──────────────────────────────────────────────
function readUrlState() {
  const hash = location.hash.slice(1);
  if (!hash || hash.startsWith('cve-')) return;
  const params = new URLSearchParams(hash);
  const view = params.get('view');
  if (view && VIEWS.includes(view)) store.view = view;
  const filter = params.get('filter');
  if (filter && FEED_FILTERS.includes(filter)) store.filter = filter;
  if (params.get('severity')) store.severity = params.get('severity');
  if (params.get('sector')) store.sector = params.get('sector');
  if (params.get('provenance')) store.provenance = params.get('provenance');
  if (params.get('q')) store.query = params.get('q');
  if (params.get('sort')) store.sort = params.get('sort');
  if (/^\d{4}-\d{2}-\d{2}$/.test(params.get('day') || '')) store.day = params.get('day');

  // v5 deep links. A library entry and a hunt tab are the two things people
  // will actually paste to a colleague, so they have to survive the URL.
  //
  // The slug is validated against the same charset knowledge_base.slugify can
  // produce. It is interpolated into a fetch path, so anything else -- a
  // traversal, a scheme, an absolute URL -- must never reach it.
  const slug = params.get('entity');
  if (slug && /^[a-z0-9-]{1,120}$/.test(slug) && typeof libState === 'object') {
    libState.open = slug;
  }
  const tab = params.get('tab');
  if (tab && typeof huntState === 'object'
      && HUNT_TABS.some((t) => t.key === tab)) {
    huntState.tab = tab;
  }
  const pack = params.get('pack');
  if (pack && /^T\d{4}(\.\d{3})?$/.test(pack) && typeof huntState === 'object') {
    huntState.openPack = pack;
  }
}

function urlStateParams() {
  const params = new URLSearchParams();
  if (store.view && store.view !== 'feed') params.set('view', store.view);
  if (store.filter && store.filter !== 'verdicts') params.set('filter', store.filter);
  if (store.severity) params.set('severity', store.severity);
  if (store.sector) params.set('sector', store.sector);
  if (store.provenance) params.set('provenance', store.provenance);
  if (store.query) params.set('q', store.query);
  if (store.sort !== 'priority') params.set('sort', store.sort);
  if (store.day) params.set('day', store.day);
  if (store.view === 'library' && typeof libState === 'object' && libState.open) {
    params.set('entity', libState.open);
  }
  if (store.view === 'hunt' && typeof huntState === 'object') {
    if (huntState.tab && huntState.tab !== 'queue') params.set('tab', huntState.tab);
    if (huntState.openPack) params.set('pack', huntState.openPack);
  }
  return params;
}

function writeUrlState() {
  const next = urlStateParams().toString();
  history.replaceState(null, '', next ? `#${next}` : location.pathname + location.search);
}

// ─── Data loading ─────────────────────────────────────────────────────────────
function ingest(data) {
  store.items = data.items || [];
  store.meta = data;
  store.brief = data.brief || null;
  store.health = data.source_health || {};
  store.items.forEach((item) => { item._key = itemKey(item); });
}

async function loadIntelData() {
  try {
    // `cache: 'no-cache'` revalidates instead of busting: the browser sends
    // If-None-Match and the host can answer 304. The old `?v=${Date.now()}`
    // made every single page load a fresh 184 KB download.
    const resp = await fetch(DATA_URL, { cache: 'no-cache' });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    store.stamp = resp.headers.get('etag') || resp.headers.get('last-modified');
    const data = await resp.json();
    // When the network is unreachable and nothing is cached, the service
    // worker answers with a SYNTHETIC 200 carrying {items: [], offline: true}
    // rather than letting the fetch reject. Without this check the dashboard
    // renders that as a perfectly successful load of an empty feed: no error,
    // no banner, just "TOTAL 0" and "No results match your filters" — which
    // reads as "quiet day" and is the single most misleading thing this page
    // can show. It is a failure, so it has to surface as one.
    if (data && data.offline) {
      throw new Error('Could not reach the network, and no cached feed was available.');
    }
    ingest(data);
    await loadHealthSummary();
    applyFilters();
    showContent();
    renderAll();
    return true;
  } catch (err) {
    console.error('Failed to load intel:', err);
    showError(err.message);
    return false;
  }
}

/**
 * Per-source last-seen data, for the staleness badges.
 *
 * This used to fetch data/source_health_history.jsonl — an append-only file that
 * had reached 1.8 MB and was downloaded IN FULL on every page load, purely to
 * compute one timestamp per source. The pipeline now rolls it up server-side.
 */
async function loadHealthSummary() {
  try {
    const resp = await fetch(HEALTH_URL, { cache: 'no-cache' });
    if (!resp.ok) return;
    const data = await resp.json();
    const now = Date.now();
    store.staleness = {};
    for (const [name, entry] of Object.entries(data.sources || {})) {
      if (entry.last_ok) {
        const ts = new Date(entry.last_ok).getTime();
        if (!Number.isNaN(ts)) store.staleness[name] = (now - ts) / 3600000;
      }
      if (entry.uptime_30d != null) store.staleness[`${name}__uptime`] = entry.uptime_30d;
    }
  } catch (_) { /* staleness is best-effort */ }
}

// ─── Live updates ─────────────────────────────────────────────────────────────
/**
 * Poll for a new intel.json and OFFER it, rather than reshuffling the page under
 * whoever is reading. A dashboard that silently reorders mid-sentence is worse
 * than a slightly stale one.
 */
function initLivePolling() {
  setInterval(async () => {
    if (document.hidden) return;
    // Never swap the feed out from under someone reading an archived day.
    // The toast would offer "12 new items" for a day three weeks ago.
    if (store.day) return;
    try {
      const head = await fetch(DATA_URL, { method: 'HEAD', cache: 'no-store' });
      const stamp = head.headers.get('etag') || head.headers.get('last-modified');
      if (!stamp || stamp === store.stamp) return;

      const known = new Set(store.items.map((i) => i._key));
      const fresh = await (await fetch(DATA_URL, { cache: 'no-cache' })).json();
      const incoming = (fresh.items || []).filter((i) => !known.has(itemKey(i)));
      store.stamp = stamp;

      if (!incoming.length) { ingest(fresh); return; }
      showToast(`${incoming.length} new item${incoming.length === 1 ? '' : 's'}`, 'Load', () => {
        ingest(fresh);
        store.items.forEach((i) => { if (!known.has(i._key)) i._justArrived = true; });
        applyFilters();
        renderAll();
      });
    } catch (_) { /* offline is fine */ }
  }, POLL_INTERVAL);
}

let toastTimer = null;
function showToast(message, actionLabel, onAction) {
  const host = $('toast-host');
  if (!host) return;
  host.replaceChildren();
  const toast = el('div', 'toast');
  toast.appendChild(el('span', 'toast-msg', message));
  if (actionLabel) {
    const btn = el('button', 'toast-action', actionLabel);
    btn.addEventListener('click', () => { onAction(); host.replaceChildren(); });
    toast.appendChild(btn);
  }
  const close = el('button', 'toast-close', '×');
  close.setAttribute('aria-label', 'Dismiss notification');
  close.addEventListener('click', () => host.replaceChildren());
  toast.appendChild(close);
  host.appendChild(toast);
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => host.replaceChildren(), 30000);
}

// ─── "New to you" ─────────────────────────────────────────────────────────────
/**
 * `is_new` from the pipeline means "not in the previous run", and the pipeline
 * runs hourly — which is why 205 of 320 items shipped with a NEW badge. Two
 * thirds of a feed shouting NEW is the same as none of it doing so.
 *
 * lastVisit was already being written to localStorage and then never read.
 * This is the read: new means published since YOUR last visit.
 */
function isNewToYou(item) {
  if (!store.lastVisit) return item.is_new === true;
  const published = Date.parse(item.published || '');
  if (Number.isNaN(published)) return false;
  return published > Date.parse(store.lastVisit);
}

/**
 * One line per card explaining why it is on screen. With stack matching,
 * watchlists, sectors, severity and a query all narrowing at once, an item's
 * presence stops being self-evident.
 */
function whyShown(item) {
  const reasons = [];
  if (store.filter === 'stack' || matchesStack(item)) {
    const hay = [item.title, item.description, ...(item.vendors || []),
      ...(item.products || []), ...(item.affected_products || [])].join(' ').toLowerCase();
    const hit = store.stack.find((t) => hay.includes(t.toLowerCase()));
    if (hit) reasons.push(`matches your stack: ${hit}`);
  }
  if (store.watchlistOnly || matchesWatchlist(item)) {
    const hay = `${item.title} ${item.description} ${item.cve_id || ''}`.toLowerCase();
    const hit = store.watchlist.find((t) => hay.includes(t.toLowerCase()));
    if (hit) reasons.push(`watchlist: ${hit}`);
  }
  if (store.filter === 'verdicts' && item.priority_label) {
    reasons.push(`scored ${item.priority_label} (P${Math.round(item.priority_score || 0)})`);
  }
  if (store.filter === 'exploited') {
    if (item.cisa_kev) reasons.push('listed in CISA KEV');
    else if (item.ssvc_exploitation === 'active') reasons.push('SSVC: exploitation active');
    else if (item.has_poc) reasons.push('public PoC exists');
  }
  if (store.filter === 'fresh') reasons.push('published since your last visit');
  if (store.sector && item.sector === store.sector) reasons.push(`sector: ${item.sector}`);
  if (store.severity) reasons.push(`severity: ${store.severity}`);
  if (store.provenance) reasons.push(`provenance: ${item.provenance}`);
  if (store.query && !store.parsedQuery) reasons.push(`matches "${store.query}"`);
  if (store.parsedQuery && typeof queryExplain === 'function') {
    const q = queryExplain(store.parsedQuery);
    if (q) reasons.push(q);
  }
  return reasons.slice(0, 3).join(' · ');
}

// ─── Filtering ────────────────────────────────────────────────────────────────
function applyFilters() {
  const q = store.query.trim().toLowerCase();
  let list = store.items;

  if (!store.showDismissed) list = list.filter((i) => !store.dismissed.has(i._key));
  if (store.watchlistOnly) list = list.filter(matchesWatchlist);

  if (store.filter === 'iocs') {
    list = list.filter((i) => i.iocs && Object.keys(i.iocs).length);
  } else if (store.filter === 'stack') {
    list = list.filter(matchesStack);
  } else if (store.filter === 'starred') {
    list = list.filter((i) => store.starred.has(i._key));
  } else if (store.filter === 'urgent') {
    list = list.filter((i) => i.priority_label === 'urgent');
  } else if (store.filter === 'verdicts') {
    // The 69 items the tool has an opinion about, not the 320 it collected.
    list = list.filter((i) => !!i.priority_label);
  } else if (store.filter === 'fresh') {
    list = list.filter(isNewToYou);
  } else if (store.filter === 'exploited') {
    list = list.filter((i) => i.cisa_kev || i.ssvc_exploitation === 'active' || i.has_poc);
  } else if (CATEGORIES.includes(store.filter)) {
    list = list.filter((i) => (i.category || 'news') === store.filter);
  }

  if (store.severity) {
    list = list.filter((i) => (i.severity || '').toLowerCase() === store.severity);
  }
  if (store.sector) {
    list = list.filter((i) => i.sector === store.sector);
  }
  if (store.provenance) {
    list = list.filter((i) => i.provenance === store.provenance);
  }
  if (store.humanOnly) {
    list = list.filter((i) => i.human_authored);
  }

  // A structured query (js/query.js) replaces the substring search entirely —
  // "epss > 0.5 and not kev" is not a phrase to look for in a title.
  if (store.parsedQuery && typeof queryMatches === 'function') {
    list = list.filter((i) => queryMatches(store.parsedQuery, i));
  } else if (q) {
    list = list.filter((i) => (
      `${i.title} ${i.description} ${i.cve_id || ''} ${i.source} `
      + `${(i.vendors || []).join(' ')} ${(i.malware || []).join(' ')} `
      + `${(i.threat_actors || []).join(' ')}`
    ).toLowerCase().includes(q));
  }

  list = list.slice();
  if (store.sort === 'priority') {
    // Band first, then score. Sorting by raw score alone put a P89 "elevated"
    // above nothing in particular; ordering by band makes the list read as
    // "patch now, then this week, then next cycle, then monitor", which is
    // the order a person actually works in.
    list.sort((a, b) => (
      (BAND_ORDER[a.priority_label] ?? 9) - (BAND_ORDER[b.priority_label] ?? 9)
      || (b.priority_score || 0) - (a.priority_score || 0)
      || String(b.published || '').localeCompare(String(a.published || ''))
    ));
  } else {
    list.sort((a, b) => String(b.published || '').localeCompare(String(a.published || '')));
  }

  store.filtered = list;
  store.renderLimit = PAGE_SIZE;
  // Keep the keyboard cursor across re-renders. Resetting it here meant that
  // after the first `x` the cursor was gone, so the next press had no current
  // item and silently did nothing — triage worked exactly once.
  store.cursor = store.cursor < 0 ? -1 : Math.min(store.cursor, list.length - 1);
  writeUrlState();
}

// ─── Card rendering ───────────────────────────────────────────────────────────
const IOC_LABELS = {
  ipv4: 'IP', domain: 'DOMAIN', url: 'URL', sha256: 'SHA256',
  sha1: 'SHA1', md5: 'MD5', cve: 'CVE', cidr: 'CIDR', email: 'EMAIL',
};

function buildIocSection(item) {
  const wrap = el('div', 'card-iocs');
  const ownCve = (item.cve_id || '').toUpperCase();
  for (const [type, values] of Object.entries(item.iocs || {})) {
    if (!values || !values.length) continue;
    // The `cve` indicator list usually just repeats item.cve_id, which the meta
    // row already shows. Only surface it when it names OTHER CVEs.
    if (type === 'cve') {
      const others = values.filter((v) => String(v).toUpperCase() !== ownCve);
      if (!others.length) continue;
      const pill = el('span', 'ioc-pill ioc-cve',
        `ALSO: ${others.length > 2 ? `${others[0]} +${others.length - 1}` : others.join(', ')}`);
      pill.title = others.join(', ');
      wrap.appendChild(pill);
      continue;
    }
    const label = IOC_LABELS[type] || type.toUpperCase();
    const shown = values.length > 2 ? `${values[0]} +${values.length - 1}` : values.join(', ');
    const pill = el('span', `ioc-pill ioc-${type}`, `${label}: ${shown}`);
    pill.title = values.join(', ');
    wrap.appendChild(pill);
  }
  return wrap;
}

/**
 * The score, opened up.
 *
 * priority_rationale reads "CISA KEV · EPSS 2.5% · CVSS 9.8" — the inputs, but
 * not what each was worth. The pipeline now emits `priority_components` with
 * the points every term contributed, so the arithmetic can be shown rather
 * than reimplemented in JavaScript (a second implementation of the scorer is a
 * second thing to drift).
 */
function buildScoreBreakdown(item) {
  const box = el('div', 'score-breakdown');
  const parts = item.priority_components || [];
  if (!parts.length) {
    box.appendChild(el('p', 'score-note',
      item.priority_rationale || 'No component breakdown was published for this item.'));
    return box;
  }
  const table = el('div', 'score-rows');
  parts.forEach((part) => {
    const row = el('div', 'score-row');
    row.appendChild(el('span', 'score-label', part.label));
    if (part.detail) row.appendChild(el('span', 'score-detail', part.detail));
    const pts = Number(part.points) || 0;
    row.appendChild(el('span', `score-points${pts < 0 ? ' is-negative' : ''}`,
      `${pts > 0 ? '+' : ''}${pts.toFixed(1)}`));
    table.appendChild(row);
  });
  const total = el('div', 'score-row score-total');
  total.appendChild(el('span', 'score-label', 'Priority score'));
  total.appendChild(el('span', 'score-points',
    String(Math.round(item.priority_score || 0))));
  table.appendChild(total);
  box.appendChild(table);

  const band = el('p', 'score-note',
    `${(item.priority_label || '').toUpperCase()} band → ${item.action || ''}. `
    + 'Bands: 90+ urgent, 70-89 elevated, 40-69 moderate, below 40 low.');
  box.appendChild(band);
  return box;
}

/** Small "how sure is this" pills. Computed everywhere, shown nowhere until now. */
function buildConfidence(item) {
  const wrap = el('div', 'card-confidence');
  let any = false;
  if (item.sector_confidence) {
    const pill = el('span', `conf-pill conf-${item.sector_confidence}`,
      `sector: ${item.sector_confidence}`);
    pill.title = item.sector_confidence === 'explicit'
      ? 'The source named the sector.'
      : 'Inferred from whole-token keyword rules — a signal, not a fact.';
    wrap.appendChild(pill); any = true;
  }
  if (item.ai_confidence != null) {
    const level = item.ai_confidence >= 0.75 ? 'high'
      : item.ai_confidence >= 0.45 ? 'medium' : 'low';
    const pill = el('span', `conf-pill conf-${level}`,
      `analysis: ${Math.round(item.ai_confidence * 100)}%`);
    pill.title = "The model's own stated confidence in its summary.";
    wrap.appendChild(pill); any = true;
  }
  if (item.cvss_source) {
    const pill = el('span', 'conf-pill conf-inferred', `CVSS via ${item.cvss_source}`);
    pill.title = 'The CNA left CVSS blank; this came from CISA ADP enrichment.';
    wrap.appendChild(pill); any = true;
  }
  if (item.provenance) {
    const labels = (store.meta && store.meta.provenance_labels) || {};
    const notes = (store.meta && store.meta.provenance_notes) || {};
    const pill = el('span', 'conf-pill prov-dot-' + item.provenance,
      labels[item.provenance] || item.provenance);
    pill.title = notes[item.provenance] || '';
    wrap.appendChild(pill); any = true;
  }
  return any ? wrap : null;
}

function buildCard(item, index) {
  const card = el('div', 'intel-card');
  card.dataset.key = item._key;
  card.dataset.index = String(index);
  card.dataset.category = item.category || 'news';

  const severity = (item.severity || 'medium').toLowerCase();
  const isNew = isNewToYou(item);
  if (isNew) card.classList.add('new-item');
  if (item._justArrived) card.classList.add('just-arrived');
  if (matchesWatchlist(item)) card.classList.add('watchlist-hit');
  if (store.starred.has(item._key)) card.classList.add('starred');
  if (store.dismissed.has(item._key)) card.classList.add('is-dismissed');
  if (store.reviewed.has(item._key)) card.classList.add('is-reviewed');

  // ── Scan row ────────────────────────────────────────────────────────────
  // One line carrying the three things a triage pass needs: how bad, what to
  // do, what it is. Everything else lives behind expansion. The old card was
  // 224px tall, which put two items on a screen and made a 320-item feed 160
  // screens long.
  const scan = el('div', 'card-scan');
  const band = item.priority_label || null;
  const rail = el('span', `card-rail prio-${band || severity}`);
  rail.setAttribute('aria-hidden', 'true');
  scan.appendChild(rail);

  const verdict = el('span', `card-verdict prio-${band || 'none'}`);
  verdict.textContent = band ? (item.action || band.toUpperCase()) : severity.toUpperCase();
  verdict.title = band
    ? (item.action_detail || item.priority_rationale || '')
    : 'No exploitability signal — severity inferred from headline keywords';
  scan.appendChild(verdict);

  const top = el('div', 'card-top');
  const title = el('p', 'card-title');
  const href = safeUrl(item.url);
  if (href) {
    const link = el('a', null, item.title || 'Untitled');
    link.href = href;
    link.target = '_blank';
    link.rel = 'noopener noreferrer';
    title.appendChild(link);
  } else {
    title.appendChild(document.createTextNode(item.title || 'Untitled'));
  }

  const badges = el('span', 'card-badges');
  if (isNew) {
    const badge = el('span', 'new-item-badge', 'NEW');
    badge.title = store.lastVisit
      ? `Published since your last visit (${new Date(store.lastVisit).toLocaleString()})`
      : 'New since the last pipeline run';
    badges.appendChild(badge);
  }
  if (item.cisa_kev) {
    const kev = el('span', 'cisa-kev-badge', 'KEV');
    kev.title = 'CISA Known Exploited Vulnerabilities catalogue';
    badges.appendChild(kev);
  }
  if (item.ssvc_exploitation === 'active' && !item.cisa_kev) {
    const ex = el('span', 'cisa-kev-badge', 'EXPLOITED');
    ex.title = 'CISA Vulnrichment SSVC: active exploitation observed';
    badges.appendChild(ex);
  }
  if (item.has_poc) {
    const poc = el('span', 'poc-badge');
    const pocHref = safeUrl(item.poc_url);
    // The old markup interpolated item.poc_url RAW into a title="" attribute,
    // so a double quote in the value broke out of it.
    poc.title = pocHref ? `Public PoC: ${item.poc_url}` : 'Public PoC on GitHub';
    if (pocHref) {
      const a = el('a', null, 'PoC');
      a.href = pocHref;
      a.target = '_blank';
      a.rel = 'noopener noreferrer';
      poc.appendChild(a);
    } else {
      poc.textContent = 'PoC';
    }
    badges.appendChild(poc);
  }
  if (matchesStack(item)) {
    const stack = el('span', 'stack-badge', 'STACK');
    stack.title = 'Matches your monitored stack';
    badges.appendChild(stack);
  }
  if (item.ai_provider && item.ai_provider !== 'rule') {
    const ai = el('span', 'ai-badge', String(item.ai_provider).toUpperCase());
    ai.title = `Enriched by ${item.ai_model || item.ai_provider}`;
    badges.appendChild(ai);
  }
  title.appendChild(badges);
  top.appendChild(title);
  scan.appendChild(top);

  // The score is a control, not a decoration: clicking it opens the arithmetic.
  if (item.priority_score != null) {
    const score = el('button', `card-score prio-${item.priority_label || 'low'}`,
      String(Math.round(item.priority_score)));
    score.type = 'button';
    score.dataset.act = 'score';
    score.title = `${item.priority_rationale || 'Blended priority score'}\nClick for the breakdown`;
    score.setAttribute('aria-label', `Priority ${Math.round(item.priority_score)} — show breakdown`);
    scan.appendChild(score);
  } else {
    const badge = el('span', `card-score sev-${severity}`, severity.slice(0, 3).toUpperCase());
    badge.title = 'Severity inferred from headline keywords — weaker than a priority score';
    scan.appendChild(badge);
  }
  card.appendChild(scan);

  // "Why am I seeing this?" — one line, only when filters are doing work.
  const why = whyShown(item);
  if (why) {
    const line = el('div', 'card-why');
    line.appendChild(el('span', 'why-ico', '↳'));
    line.appendChild(el('span', 'why-text', why));
    card.appendChild(line);
  }

  // ── Everything below is behind expansion ────────────────────────────────
  const detail = el('div', 'card-detail');

  if (item.action_detail) {
    const action = el('div', `card-action prio-${item.priority_label || 'low'}`);
    action.appendChild(el('span', 'action-verb', item.action || ''));
    action.appendChild(el('span', 'action-detail', item.action_detail));
    detail.appendChild(action);
  }

  if ((item.threat_actors && item.threat_actors.length)
      || (item.malware && item.malware.length)) {
    const actors = el('div', 'card-actors');
    (item.threat_actors || []).slice(0, 3).forEach((actor) => {
      const chip = el('span', 'threat-actor-badge', actor);
      chip.dataset.actor = actor;
      chip.title = `Open ${actor} in the entity graph`;
      actors.appendChild(chip);
    });
    (item.malware || []).slice(0, 4).forEach((family) => {
      const chip = el('span', 'malware-badge', family);
      chip.dataset.malware = family;
      chip.title = `Open the ${family} family`;
      actors.appendChild(chip);
    });
    detail.appendChild(actors);
  }

  if (item.description) detail.appendChild(el('p', 'card-description', item.description));

  const meta = el('div', 'card-meta');
  if (item.cve_id) {
    const cve = el('span', 'cve-id', item.cve_id);
    cve.dataset.cve = item.cve_id;
    cve.title = 'Open CVE details';
    meta.appendChild(cve);
  }
  const src = el('span', 'meta-tag meta-source', item.source || 'unknown');
  src.dataset.source = item.source || '';
  meta.appendChild(src);
  meta.appendChild(el('span', 'meta-tag meta-cat', item.category || 'news'));

  if (item.priority_score != null) {
    const prio = el('span', `meta-tag meta-priority prio-${item.priority_label || 'low'}`,
      `P${Math.round(item.priority_score)}`);
    prio.title = item.priority_rationale || 'Blended priority score';
    meta.appendChild(prio);
  }
  if (item.cvss_score != null) {
    meta.appendChild(el('span', 'meta-tag meta-cvss', `CVSS ${Number(item.cvss_score).toFixed(1)}`));
  }
  if (item.epss_score != null) {
    const epss = el('span', 'meta-tag meta-epss', `EPSS ${(item.epss_score * 100).toFixed(1)}%`);
    epss.title = `${(item.epss_score * 100).toFixed(2)}% chance of exploitation within 30 days`;
    meta.appendChild(epss);
  }
  if (item.ssvc_automatable === 'yes') {
    const auto = el('span', 'meta-tag meta-ssvc', 'AUTOMATABLE');
    auto.title = 'SSVC: an attacker can exploit this at scale, unattended';
    meta.appendChild(auto);
  }
  if (item.cwe) {
    const cwe = el('span', 'meta-tag meta-cwe', item.cwe);
    cwe.title = item.cwe_name || item.cwe;
    meta.appendChild(cwe);
  }
  if (item.detection_rule_count) {
    const det = el('span', 'meta-tag meta-detect',
      `${item.detection_rule_count} SIGMA`);
    det.dataset.act = 'detections';
    det.title = `${item.detection_rule_count} public Sigma rules cover this item's `
      + `techniques (${(item.detection_techniques || []).join(', ')}) — open Detections`;
    meta.appendChild(det);
  }
  if (item.published) meta.appendChild(el('span', 'meta-date', timeAgo(new Date(item.published))));
  detail.appendChild(meta);

  const confidence = buildConfidence(item);
  if (confidence) detail.appendChild(confidence);

  if (item.iocs && Object.keys(item.iocs).length) detail.appendChild(buildIocSection(item));

  const analysis = el('div', 'analysis-section');
  const header = el('div', 'analysis-header');
  const enriched = item.ai_provider && item.ai_provider !== 'rule';
  header.appendChild(el('span', 'analysis-label', enriched ? 'AI THREAT ANALYSIS' : 'SUMMARY'));
  if (item.ai_model) header.appendChild(el('span', 'analysis-model', item.ai_model));
  analysis.appendChild(header);
  analysis.appendChild(el('p', 'analysis-summary', displaySummary(item)));
  if (item.why_it_matters) analysis.appendChild(el('p', 'analysis-why', item.why_it_matters));
  analysis.appendChild(buildNoteEditor(item));
  detail.appendChild(analysis);

  // The score breakdown lives collapsed inside the card, revealed by the
  // score button rather than by expanding the whole row.
  const breakdown = el('div', 'card-score-panel');
  breakdown.style.display = 'none';
  breakdown.appendChild(buildScoreBreakdown(item));
  detail.appendChild(breakdown);

  const actions = el('div', 'card-actions');
  const star = el('button', 'card-btn', store.starred.has(item._key) ? '★ Starred' : '☆ Star');
  star.dataset.act = 'star';
  const review = el('button', 'card-btn',
    store.reviewed.has(item._key) ? '✓ Reviewed' : '○ Mark reviewed');
  review.dataset.act = 'review';
  review.title = 'Counts toward the triage progress bar';
  const dismiss = el('button', 'card-btn',
    store.dismissed.has(item._key) ? '↩ Restore' : '✕ Dismiss');
  dismiss.dataset.act = 'dismiss';
  const copy = el('button', 'card-btn', '⧉ Copy');
  copy.dataset.act = 'copy';
  copy.title = 'Copy as markdown for a ticket';
  actions.append(star, review, dismiss, copy);
  detail.appendChild(actions);

  card.appendChild(detail);
  card.appendChild(el('span', 'card-expand-hint', '▼'));

  return card;
}

/**
 * Triage progress.
 *
 * An item is REVIEWED when you act on it: star, dismiss, or mark it. The point
 * is that a verdict list is finishable — nine actionable items is a list you
 * can get to the end of, and a feed that never acknowledges the end is a feed
 * you never finish. This is the difference between a dashboard you glance at
 * and one you work.
 */
function triageProgress() {
  const list = store.filtered;
  const done = list.filter((i) => store.reviewed.has(i._key)
    || store.starred.has(i._key) || store.dismissed.has(i._key)).length;
  return { done, total: list.length };
}

function renderTriageBar() {
  const host = $('triage-bar');
  if (!host) return;
  const showFor = ['verdicts', 'urgent', 'exploited', 'stack', 'fresh'];
  if (store.view !== 'feed' || !showFor.includes(store.filter) || !store.filtered.length) {
    host.style.display = 'none';
    return;
  }
  const { done, total } = triageProgress();
  host.style.display = 'flex';
  host.replaceChildren();

  const label = el('span', 'triage-label', `${done} of ${total} reviewed`);
  const track = el('span', 'triage-track');
  const fill = el('span', 'triage-fill');
  fill.style.width = `${total ? (done / total) * 100 : 0}%`;
  track.appendChild(fill);
  host.append(label, track);

  if (done >= total && total > 0) {
    host.classList.add('is-complete');
  } else {
    host.classList.remove('is-complete');
    const next = el('button', 'triage-next', 'NEXT UNREVIEWED →');
    next.type = 'button';
    next.id = 'triage-next';
    host.appendChild(next);
  }
  if (done) {
    const reset = el('button', 'triage-reset', 'RESET');
    reset.type = 'button';
    reset.id = 'triage-reset';
    reset.title = 'Clear review marks for the items on screen';
    host.appendChild(reset);
  }
}

function renderTriageDone() {
  const host = $('triage-done');
  if (!host) return;
  const showFor = ['verdicts', 'urgent', 'exploited', 'stack', 'fresh'];
  const { done, total } = triageProgress();
  if (store.view !== 'feed' || !showFor.includes(store.filter)
      || total === 0 || done < total) {
    host.style.display = 'none';
    return;
  }
  host.style.display = 'block';
  host.replaceChildren();
  host.appendChild(el('div', 'done-mark', '✓'));
  host.appendChild(el('p', 'done-title', 'Triage complete'));
  host.appendChild(el('p', 'done-sub',
    `You have been through all ${total} item${total === 1 ? '' : 's'} the tool `
    + 'has an opinion about today.'));

  const rest = store.items.filter((i) => !i.priority_label
    && !store.dismissed.has(i._key)).length;
  const row = el('div', 'done-actions');
  const browse = el('button', 'done-btn', `Browse the other ${rest} items`);
  browse.type = 'button';
  browse.dataset.act = 'browse-rest';
  const research = el('button', 'done-btn ghost', 'Open Research');
  research.type = 'button';
  research.dataset.act = 'open-research';
  row.append(browse, research);
  host.appendChild(row);
}

function renderCards() {
  const container = $('cards-container');
  if (!container) return;
  const slice = store.filtered.slice(0, store.renderLimit);

  const frag = document.createDocumentFragment();
  slice.forEach((item, i) => frag.appendChild(buildCard(item, i)));
  container.replaceChildren(frag);
  container.setAttribute('aria-busy', 'false');
  container.dataset.density = store.density;

  const count = $('feed-count');
  if (count) {
    const total = store.filtered.length;
    const hidden = store.dismissed.size;
    const scope = store.day ? `${store.day} · ` : '';
    const verdictNote = store.filter === 'verdicts'
      ? ` · ${store.items.length - total} items with no verdict hidden` : '';
    count.textContent = total === 0
      ? 'No items match'
      : `${scope}Showing ${Math.min(store.renderLimit, total)} of ${total}`
        + (hidden && !store.showDismissed ? ` · ${hidden} dismissed` : '')
        + verdictNote;
  }
  const noResults = $('no-results');
  if (noResults) noResults.style.display = store.filtered.length ? 'none' : 'block';
  renderTriageBar();
  renderTriageDone();

  // Restore the keyboard cursor onto the freshly-rendered cards.
  if (store.cursor >= 0) {
    const cards = container.querySelectorAll('.intel-card');
    if (cards.length) {
      store.cursor = Math.min(store.cursor, cards.length - 1);
      cards[store.cursor].classList.add('cursor');
    } else {
      store.cursor = -1;
    }
  }
}

// ─── Daily brief ──────────────────────────────────────────────────────────────
function renderBrief() {
  const host = $('daily-brief');
  if (!host) return;
  const brief = store.brief;
  const urgent = store.items.filter((i) => i.priority_label === 'urgent').length;
  const exploited = store.items.filter(
    (i) => i.cisa_kev || i.ssvc_exploitation === 'active').length;

  host.replaceChildren();
  if (!brief && !urgent) { host.style.display = 'none'; return; }
  host.style.display = 'block';

  const inner = el('div', 'brief-inner');
  const head = el('div', 'brief-head');
  head.appendChild(el('span', 'brief-label', "TODAY'S BRIEF"));
  head.appendChild(el('span', 'brief-stats',
    `${urgent} urgent · ${exploited} actively exploited · ${store.items.length} total`));
  inner.appendChild(head);

  if (brief && brief.headline) inner.appendChild(el('p', 'brief-headline', brief.headline));

  const picks = (brief && brief.items) || store.items
    .filter((i) => i.priority_label === 'urgent')
    .slice(0, 3)
    .map((i) => ({ title: i.title, url: i.url, key: i._key, reason: i.action_detail || '' }));

  if (picks.length) {
    const list = el('ol', 'brief-list');
    picks.forEach((pick) => {
      const li = el('li', 'brief-item');
      const href = safeUrl(pick.url);
      if (href) {
        const a = el('a', 'brief-link', pick.title || '');
        a.href = href;
        a.target = '_blank';
        a.rel = 'noopener noreferrer';
        li.appendChild(a);
      } else {
        li.appendChild(el('span', 'brief-link', pick.title || ''));
      }
      if (pick.reason) li.appendChild(el('span', 'brief-reason', pick.reason));
      list.appendChild(li);
    });
    inner.appendChild(list);
  }
  host.appendChild(inner);
}

// ─── Sidebar ──────────────────────────────────────────────────────────────────
function renderSidebar() {
  renderSeverityChart();
  renderSourceList();
  renderCategoryList();
  renderSectorList();
  renderProvenanceList();
  renderSourceHealth();
  renderWatchlist();
  renderStack();
  updateHeaderStats();
}

function countBy(field) {
  const counts = {};
  store.items.forEach((item) => {
    const key = (item[field] || 'unknown').toString().toLowerCase();
    counts[key] = (counts[key] || 0) + 1;
  });
  return counts;
}

/**
 * Severity distribution. Every row carries its label and count as text, so the
 * ordinal ramp is a reinforcement of the ordering rather than the only cue.
 * Rows are buttons: the sidebar used to be read-only decoration.
 */
function renderSeverityChart() {
  const host = $('severity-chart');
  if (!host) return;
  const counts = countBy('severity');
  const max = Math.max(1, ...SEVERITY_ORDER.map((s) => counts[s] || 0));

  host.replaceChildren();
  SEVERITY_ORDER.forEach((sev) => {
    const value = counts[sev] || 0;
    const row = el('button', `sev-row${store.severity === sev ? ' active' : ''}`);
    row.type = 'button';
    row.dataset.severity = sev;
    row.setAttribute('aria-pressed', String(store.severity === sev));
    row.title = `Filter to ${sev} (${value})`;

    row.appendChild(el('span', `sev-label ${sev}`, sev.toUpperCase()));
    const track = el('span', 'sev-bar-wrap');
    const bar = el('span', 'sev-bar');
    bar.style.width = `${(value / max) * 100}%`;
    bar.style.background = SEVERITY_RAMP[sev];
    track.appendChild(bar);
    row.appendChild(track);
    row.appendChild(el('span', 'sev-count', String(value)));
    host.appendChild(row);
  });
}

function renderSourceList() {
  const host = $('source-list');
  if (!host) return;
  const counts = countBy('source');
  const rows = Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 14);
  const max = Math.max(1, ...rows.map((r) => r[1]));

  host.replaceChildren();
  rows.forEach(([name, value]) => {
    const original = store.items.find(
      (i) => (i.source || '').toLowerCase() === name)?.source || name;
    const row = el('button', 'src-row');
    row.type = 'button';
    row.dataset.source = original;
    row.title = `Filter to ${original} (${value})`;
    row.appendChild(el('span', 'src-name', original));
    const track = el('span', 'src-bar-wrap');
    const bar = el('span', 'src-bar');
    bar.style.width = `${(value / max) * 100}%`;
    // Nominal bars: one series, one hue.
    bar.style.background = SERIES_1;
    track.appendChild(bar);
    row.appendChild(track);
    row.appendChild(el('span', 'src-count', String(value)));
    host.appendChild(row);
  });
}

function renderCategoryList() {
  const host = $('cat-list');
  if (!host) return;
  const counts = countBy('category');
  host.replaceChildren();
  Object.entries(counts).sort((a, b) => b[1] - a[1]).forEach(([name, value]) => {
    const row = el('button', `cat-row${store.filter === name ? ' active' : ''}`);
    row.type = 'button';
    row.dataset.filter = name;
    row.appendChild(el('span', 'cat-name', name));
    row.appendChild(el('span', 'cat-count', String(value)));
    host.appendChild(row);
  });
}

function renderSectorList() {
  const host = $('sector-list');
  if (!host) return;
  const labels = (store.meta && store.meta.sector_labels) || {};
  // Count sectors over the whole feed, and note whether any tag was explicit.
  const counts = {};
  const hasExplicit = {};
  store.items.forEach((i) => {
    if (!i.sector) return;
    counts[i.sector] = (counts[i.sector] || 0) + 1;
    if (i.sector_confidence === 'explicit') hasExplicit[i.sector] = true;
  });
  host.replaceChildren();
  const entries = Object.entries(counts).sort((a, b) => b[1] - a[1]);
  if (!entries.length) {
    host.appendChild(el('p', 'sector-empty', 'No sectors identified in this run.'));
    return;
  }
  entries.forEach(([sector, value]) => {
    const row = el('button', `sector-row${store.sector === sector ? ' active' : ''}`);
    row.type = 'button';
    row.dataset.sector = sector;
    row.appendChild(el('span', 'sector-name', labels[sector] || sector));
    const meta = el('span', 'sector-meta');
    // A small mark distinguishes source-confirmed sectors from keyword guesses.
    if (hasExplicit[sector]) {
      const dot = el('span', 'sector-explicit');
      dot.title = 'Includes source-confirmed items';
      dot.textContent = '●';
      meta.appendChild(dot);
    }
    meta.appendChild(el('span', 'sector-count', String(value)));
    row.appendChild(meta);
    host.appendChild(row);
  });
}

function staleLabel(hours) {
  if (hours == null || hours < 48) return null;
  return `${Math.floor(hours / 24)}d silent`;
}

function renderSourceHealth() {
  const host = $('source-health');
  if (!host) return;
  const entries = Object.entries(store.health);
  if (!entries.length) {
    const card = host.closest('.sidebar-card');
    if (card) card.style.display = 'none';
    return;
  }
  const rank = (s) => (s === 'error' ? 0 : s === 'empty' ? 1 : s === 'stale' ? 2 : 3);
  entries.sort((a, b) => rank(a[1].status) - rank(b[1].status));

  const okCount = entries.filter(([, h]) => h.status === 'ok').length;
  const summary = $('source-health-summary');
  if (summary) summary.textContent = `${okCount}/${entries.length} live`;

  host.replaceChildren();
  entries.forEach(([name, h]) => {
    const row = el('div', `health-item health-${h.status}`);
    const detail = h.status === 'error'
      ? (h.error || 'error')
      : `${h.count} item${h.count === 1 ? '' : 's'}`;
    const age = h.median_age_days;
    const uptime = store.staleness[`${name}__uptime`];
    row.title = [detail,
      age != null ? `median age ${age}d` : null,
      uptime != null ? `${Math.round(uptime * 100)}% uptime (30d)` : null,
      staleLabel(store.staleness[name]),
    ].filter(Boolean).join(' · ');

    row.appendChild(el('span', `health-dot dot-${h.status}`));
    row.appendChild(el('span', 'health-name', name));
    // `stale` is a distinct state from `ok`: a feed serving a four-year-old
    // archive used to report green because health only counted items.
    if (h.status === 'stale') row.appendChild(el('span', 'health-stale-badge', 'STALE'));
    row.appendChild(el('span', 'health-count', h.status === 'error' ? '!' : String(h.count)));
    host.appendChild(row);
  });
}

function renderChips(hostId, values, removeAct) {
  const host = $(hostId);
  if (!host) return;
  host.replaceChildren();
  values.forEach((value) => {
    const chip = el('span', 'chip', value);
    const btn = el('button', 'chip-x', '×');
    btn.type = 'button';
    btn.dataset.act = removeAct;
    btn.dataset.value = value;
    btn.setAttribute('aria-label', `Remove ${value}`);
    chip.appendChild(btn);
    host.appendChild(chip);
  });
}

function renderWatchlist() {
  renderChips('watchlist-chips', store.watchlist, 'unwatch');
  const hits = store.items.filter(matchesWatchlist).length;
  const badge = $('watchlist-match-count');
  if (badge) badge.textContent = store.watchlist.length ? `${hits} hits` : '';
  const btn = $('watchlist-only-btn');
  if (btn) {
    btn.style.display = store.watchlist.length ? 'block' : 'none';
    btn.classList.toggle('active', store.watchlistOnly);
    btn.textContent = store.watchlistOnly ? '★ SHOWING WATCHLIST' : '☆ WATCHLIST ONLY';
  }
}

function renderStack() {
  renderChips('stack-chips', store.stack, 'unstack');
  const hits = store.items.filter(matchesStack).length;
  const badge = $('stack-match-count');
  if (badge) {
    // "0 items affect your stack today" is a valuable, calming answer that the
    // old UI had no way to express.
    badge.textContent = store.stack.length ? `${hits} affect you` : '';
    badge.classList.toggle('all-clear', store.stack.length > 0 && hits === 0);
  }
}

function updateHeaderStats() {
  const counts = countBy('severity');
  const set = (id, value) => { const node = $(id); if (node) node.textContent = value; };
  set('count-critical', counts.critical || 0);
  set('count-high', counts.high || 0);
  set('count-urgent', store.items.filter((i) => i.priority_label === 'urgent').length);
  set('count-total', store.items.length);

  const meta = store.meta;
  const updated = $('last-updated');
  if (updated && meta.last_updated) {
    const date = new Date(meta.last_updated);
    updated.textContent = `Updated ${timeAgo(date)} · ${meta.sources_ok || 0} sources live`
      + (meta.sources_stale ? ` · ${meta.sources_stale} stale` : '');
    updated.title = date.toUTCString();
  }
}

// ─── Charts (hand-rolled SVG; no charting dependency) ─────────────────────────
const SVG_NS = 'http://www.w3.org/2000/svg';
function svgEl(tag, attrs) {
  const node = document.createElementNS(SVG_NS, tag);
  for (const [k, v] of Object.entries(attrs || {})) node.setAttribute(k, String(v));
  return node;
}

/**
 * Stacked area: daily item volume split by severity over the trend window.
 * One ordinal ramp, a legend, a hover crosshair with a tooltip, and a table
 * view behind a toggle.
 */
function buildVolumeChart(daily) {
  const W = 720; const H = 220;
  const PAD = { top: 16, right: 12, bottom: 26, left: 40 };
  const plotW = W - PAD.left - PAD.right;
  const plotH = H - PAD.top - PAD.bottom;

  const figure = el('figure', 'chart-figure');
  figure.appendChild(el('figcaption', 'chart-title', 'Daily volume by severity'));

  const maxTotal = Math.max(1, ...daily.map(
    (d) => SEVERITY_ORDER.reduce((s, k) => s + (d[k] || 0), 0)));
  const x = (i) => PAD.left + (daily.length === 1 ? plotW / 2 : (i / (daily.length - 1)) * plotW);
  const y = (v) => PAD.top + plotH - (v / maxTotal) * plotH;

  const svg = svgEl('svg', {
    viewBox: `0 0 ${W} ${H}`, class: 'chart-svg', role: 'img',
    'aria-label': `Daily threat volume by severity over ${daily.length} days`,
  });

  // Recessive gridlines + axis labels.
  for (let g = 0; g <= 4; g += 1) {
    const gv = (maxTotal / 4) * g;
    svg.appendChild(svgEl('line', {
      x1: PAD.left, x2: W - PAD.right, y1: y(gv), y2: y(gv), class: 'chart-grid',
    }));
    const label = svgEl('text', { x: PAD.left - 6, y: y(gv) + 3, class: 'chart-axis-label', 'text-anchor': 'end' });
    label.textContent = Math.round(gv);
    svg.appendChild(label);
  }

  // Stack from the least severe upward so `critical` sits on top.
  const stackOrder = [...SEVERITY_ORDER].reverse();
  const running = new Array(daily.length).fill(0);
  stackOrder.forEach((sev) => {
    const lower = running.slice();
    daily.forEach((d, i) => { running[i] += d[sev] || 0; });
    const top = daily.map((_, i) => `${x(i)},${y(running[i])}`);
    const bottom = daily.map((_, i) => `${x(i)},${y(lower[i])}`).reverse();
    svg.appendChild(svgEl('polygon', {
      points: [...top, ...bottom].join(' '),
      fill: SEVERITY_RAMP[sev],
      // 2px surface gap between stacked segments, per the mark spec.
      stroke: '#0d1117',
      'stroke-width': 2,
      'stroke-linejoin': 'round',
    }));
  });

  // Date ticks: first, middle, last only — a label per day would collide.
  [0, Math.floor(daily.length / 2), daily.length - 1].forEach((i) => {
    if (!daily[i]) return;
    const t = svgEl('text', {
      x: x(i), y: H - 8, class: 'chart-axis-label',
      'text-anchor': i === 0 ? 'start' : i === daily.length - 1 ? 'end' : 'middle',
    });
    t.textContent = (daily[i].date || '').slice(5);
    svg.appendChild(t);
  });

  const crosshair = svgEl('line', {
    y1: PAD.top, y2: PAD.top + plotH, class: 'chart-crosshair', opacity: 0,
  });
  svg.appendChild(crosshair);

  const hit = svgEl('rect', {
    x: PAD.left, y: PAD.top, width: plotW, height: plotH, fill: 'transparent',
  });
  svg.appendChild(hit);
  figure.appendChild(svg);

  const tooltip = el('div', 'chart-tooltip');
  tooltip.style.opacity = '0';
  figure.appendChild(tooltip);

  hit.addEventListener('pointermove', (ev) => {
    const box = svg.getBoundingClientRect();
    const px = ((ev.clientX - box.left) / box.width) * W;
    const idx = Math.max(0, Math.min(daily.length - 1,
      Math.round(((px - PAD.left) / plotW) * (daily.length - 1))));
    const d = daily[idx];
    crosshair.setAttribute('x1', x(idx));
    crosshair.setAttribute('x2', x(idx));
    crosshair.setAttribute('opacity', 1);
    tooltip.replaceChildren();
    tooltip.appendChild(el('strong', null, d.date));
    SEVERITY_ORDER.forEach((sev) => {
      if (!d[sev]) return;
      const row = el('span', 'tt-row');
      const dot = el('span', 'tt-dot');
      dot.style.background = SEVERITY_RAMP[sev];
      row.append(dot, el('span', 'tt-name', sev), el('span', 'tt-val', String(d[sev])));
      tooltip.appendChild(row);
    });
    tooltip.style.opacity = '1';
    tooltip.style.left = `${Math.min(Math.max((x(idx) / W) * 100, 8), 82)}%`;
  });
  hit.addEventListener('pointerleave', () => {
    crosshair.setAttribute('opacity', 0);
    tooltip.style.opacity = '0';
  });

  // Legend: identity is never colour-alone.
  const legend = el('div', 'chart-legend');
  SEVERITY_ORDER.forEach((sev) => {
    const entry = el('span', 'legend-entry');
    const swatch = el('span', 'legend-swatch');
    swatch.style.background = SEVERITY_RAMP[sev];
    entry.append(swatch, el('span', null, sev));
    legend.appendChild(entry);
  });
  figure.appendChild(legend);
  return figure;
}

/** Nominal bars: one series, one hue, direct value labels. */
function buildBarChart(title, rows, nameKey, valKey) {
  const figure = el('figure', 'chart-figure');
  figure.appendChild(el('figcaption', 'chart-title', title));
  if (!rows || !rows.length) {
    figure.appendChild(el('p', 'chart-empty', 'No data yet'));
    return figure;
  }
  const max = Math.max(1, ...rows.map((r) => r[valKey] || 0));
  const list = el('div', 'bar-list');
  rows.slice(0, 10).forEach((row) => {
    const line = el('div', 'bar-row');
    line.appendChild(el('span', 'bar-name', String(row[nameKey])));
    const track = el('span', 'bar-track');
    const fill = el('span', 'bar-fill');
    fill.style.width = `${((row[valKey] || 0) / max) * 100}%`;
    fill.style.background = SERIES_1;
    track.appendChild(fill);
    line.appendChild(track);
    line.appendChild(el('span', 'bar-val', String(row[valKey] || 0)));
    list.appendChild(line);
  });
  figure.appendChild(list);
  return figure;
}

function buildDataTable(daily) {
  const details = el('details', 'chart-table');
  details.appendChild(el('summary', null, 'View as table'));
  const table = el('table');
  const thead = el('thead');
  const hrow = el('tr');
  ['Date', ...SEVERITY_ORDER.map((s) => s[0].toUpperCase() + s.slice(1)), 'Total']
    .forEach((h) => hrow.appendChild(el('th', null, h)));
  thead.appendChild(hrow);
  table.appendChild(thead);
  const tbody = el('tbody');
  daily.slice().reverse().forEach((d) => {
    const tr = el('tr');
    tr.appendChild(el('td', null, d.date));
    let total = 0;
    SEVERITY_ORDER.forEach((s) => { total += d[s] || 0; tr.appendChild(el('td', null, String(d[s] || 0))); });
    tr.appendChild(el('td', null, String(total)));
    tbody.appendChild(tr);
  });
  table.appendChild(tbody);
  details.appendChild(table);
  return details;
}

async function showTrendsView() {
  hideAllViews();
  const host = $('trends-view');
  if (!host) return;
  host.style.display = 'block';
  host.replaceChildren(el('p', 'chart-empty', 'Loading trends…'));

  if (!store.trends) {
    try {
      const resp = await fetch(`${TRENDS_URL}?v=${Date.now()}`);
      if (resp.ok) store.trends = await resp.json();
    } catch (_) { /* fall through */ }
  }
  const t = store.trends;
  host.replaceChildren();
  if (!t || !t.daily || !t.daily.length) {
    host.appendChild(el('p', 'chart-empty', 'No trend history yet — it builds from the daily archive.'));
    return;
  }

  const grid = el('div', 'chart-grid-layout');
  grid.appendChild(buildVolumeChart(t.daily));
  grid.appendChild(buildBarChart('Most active sources', t.top_sources || [], 'name', 'count'));
  grid.appendChild(buildBarChart('Most-seen threat actors', t.top_actors || [], 'name', 'count'));
  grid.appendChild(buildBarChart('Most-mapped ATT&CK techniques', t.top_ttps || [], 'id', 'count'));
  host.appendChild(grid);
  host.appendChild(buildDataTable(t.daily));
}

// ─── ATT&CK matrix ────────────────────────────────────────────────────────────
// --- ATT&CK matrix ----------------------------------------------------------
// Laid out as the kill chain actually runs: tactics left to right in canonical
// ATT&CK order, techniques stacked beneath, cells heat-shaded by how often the
// current feed touches them. The point is to see WHERE in the chain this run's
// activity concentrates, which an alphabetical grid of equal-weight boxes
// cannot show.

function tacticOrder() {
  const shipped = (store.meta && store.meta.tactic_order) || [];
  return shipped.length ? shipped.map((t) => t.name) : [];
}

function showMatrixView() {
  hideAllViews();
  const host = $('matrix-view');
  if (!host) return;
  host.style.display = 'block';

  const counts = {};
  const names = {};
  const tactics = new Map();
  store.items.forEach((item) => {
    (item.ttps || []).forEach((t) => {
      counts[t.id] = (counts[t.id] || 0) + 1;
      names[t.id] = t.name;
      if (!tactics.has(t.tactic)) tactics.set(t.tactic, new Set());
      tactics.get(t.tactic).add(t.id);
    });
  });

  const grid = $('matrix-grid');
  if (!grid) return;
  grid.replaceChildren();

  const legend = $('matrix-legend-host');
  if (legend) legend.replaceChildren();

  if (!tactics.size) {
    grid.appendChild(el('p', 'chart-empty', 'No techniques mapped in the current feed.'));
    return;
  }

  // Order columns by the canonical kill chain; anything unrecognised trails.
  const canonical = tacticOrder();
  const present = [...tactics.keys()];
  const ordered = canonical.filter((n) => tactics.has(n))
    .concat(present.filter((n) => !canonical.includes(n)).sort());

  const allCounts = Object.values(counts);
  const max = Math.max(1, ...allCounts);
  const totalHits = allCounts.reduce((s, n) => s + n, 0);

  // ---- summary strip: what the chain actually looks like this run ----------
  if (legend) {
    const sum = el('div', 'mx-summary');
    sum.appendChild(mxStat(Object.keys(counts).length, 'techniques observed'));
    sum.appendChild(mxStat(ordered.length, 'of ' + (canonical.length || 14) + ' tactics touched'));
    sum.appendChild(mxStat(totalHits, 'technique mentions'));
    const hottest = Object.entries(counts).sort((a, b) => b[1] - a[1])[0];
    if (hottest) {
      sum.appendChild(mxStat(hottest[0], 'most-mapped', names[hottest[0]]));
    }
    legend.appendChild(sum);

    // Kill-chain ribbon: every canonical tactic, lit where this run has data.
    const chain = el('div', 'mx-chain');
    (canonical.length ? canonical : ordered).forEach((name, i) => {
      const seg = el('div', 'mx-chain-seg' + (tactics.has(name) ? ' lit' : ''));
      const n = tactics.has(name)
        ? [...tactics.get(name)].reduce((s, id) => s + counts[id], 0) : 0;
      seg.style.setProperty('--seg-heat', tactics.has(name)
        ? String(Math.min(1, n / Math.max(1, totalHits / 3))) : '0');
      seg.appendChild(el('span', 'mx-chain-name', name));
      seg.appendChild(el('span', 'mx-chain-n', n ? String(n) : '·'));
      seg.title = name + (n ? ': ' + n + ' mention' + (n === 1 ? '' : 's') : ': not seen this run');
      chain.appendChild(seg);
      if (i < (canonical.length ? canonical.length : ordered.length) - 1) {
        chain.appendChild(el('span', 'mx-chain-link', ''));
      }
    });
    legend.appendChild(chain);

    const scale = el('div', 'mx-scale');
    scale.appendChild(el('span', 'mx-scale-label', 'Fewer'));
    const ramp = el('span', 'mx-scale-ramp');
    for (let i = 1; i <= 5; i++) {
      const sw = el('span', 'mx-scale-sw');
      sw.style.background = mxHeat(i / 5);
      ramp.appendChild(sw);
    }
    scale.appendChild(ramp);
    scale.appendChild(el('span', 'mx-scale-label', 'More items mapped'));
    scale.appendChild(el('span', 'mx-scale-hint', 'Click a technique to filter the feed'));
    legend.appendChild(scale);
  }

  // ---- the matrix ----------------------------------------------------------
  ordered.forEach((tactic) => {
    const ids = tactics.get(tactic);
    const col = el('div', 'tactic-col');
    const colTotal = [...ids].reduce((s, id) => s + counts[id], 0);

    const header = el('div', 'tactic-header');
    header.appendChild(el('span', 'tactic-name', tactic));
    header.appendChild(el('span', 'tactic-count', String(colTotal)));
    col.appendChild(header);

    [...ids].sort((a, b) => counts[b] - counts[a]).forEach((id) => {
      const n = counts[id];
      const heat = n / max;
      const cell = el('button', 'tech-cell');
      cell.type = 'button';
      cell.dataset.technique = id;
      cell.style.background = mxHeat(heat);
      cell.style.setProperty('--cell-heat', heat.toFixed(3));
      if (heat > 0.66) cell.classList.add('is-hot');
      cell.title = id + ' — ' + names[id] + ' (' + n + ' item' + (n === 1 ? '' : 's') + ')';
      cell.appendChild(el('span', 'tech-id', id));
      cell.appendChild(el('span', 'tech-name', names[id] || ''));
      cell.appendChild(el('span', 'tech-count', String(n)));
      const bar = el('span', 'tech-bar');
      bar.style.width = (heat * 100) + '%';
      cell.appendChild(bar);
      col.appendChild(cell);
    });
    grid.appendChild(col);
  });
}

function mxStat(value, label, sub) {
  const s = el('div', 'mx-stat');
  s.appendChild(el('span', 'mx-stat-val', String(value)));
  s.appendChild(el('span', 'mx-stat-label', label));
  if (sub) s.appendChild(el('span', 'mx-stat-sub', sub));
  return s;
}

// Sequential single-hue ramp. Heat is ORDINAL (few -> many), so it takes one
// hue with rising lightness/alpha rather than a categorical set.
function mxHeat(t) {
  const a = 0.10 + Math.min(1, Math.max(0, t)) * 0.72;
  return 'rgba(0, 173, 216, ' + a.toFixed(3) + ')';
}

// --- Attacker map -----------------------------------------------------------
// A CHOROPLETH of current attacker infrastructure by country of origin. Not a
// real-time animation of attacks in flight: we own no sensors, so arcs between
// countries would be invented data. What this shows is real and sourced --
// where the hosts currently scanning, brute-forcing, amplifying DDoS and
// exiting anonymity networks are located, refreshed every run.
//
// Countries are shaded by attacker volume; the top origins also carry an
// animated pulse so the view reads as live. The ranked table beside the map is
// the accessible content and works with no SVG at all.

// Country outlines: Natural Earth 110m (public domain), projected
// equirectangular into a 1000x500 viewBox, Douglas-Peucker simplified.
// 173 countries.
const WORLD_PATHS = {
  AE:"M643.3 182.7L650.0 183.0L655.8 177.6L656.3 178.6L656.7 180.8L655.2 180.8L655.5 183.0L652.8 187.5L644.4 186.1L643.3 182.7Z",
  AF:"M684.8 146.2L692.2 146.8L696.7 143.1L698.2 143.7L699.6 147.9L703.5 145.8L708.8 146.9L698.0 149.8L698.9 152.4L696.9 155.6L694.3 155.5L695.3 157.3L692.4 159.7L692.5 161.4L685.9 163.0L684.4 164.6L684.3 167.0L673.7 168.6L669.1 167.1L671.6 164.6L671.4 162.8L669.3 162.4L668.2 158.4L670.0 151.0L675.0 151.7L679.3 149.1L679.9 146.9L682.6 145.4L684.8 146.2Z",
  AL:"M558.4 136.5L556.0 139.9L553.9 138.2L553.6 132.8L554.8 131.4L557.0 132.7L557.2 135.9L558.4 136.5Z",
  AM:"M629.2 142.3L621.3 138.2L621.1 135.9L624.9 135.4L626.6 136.6L626.0 137.3L627.5 138.3L626.7 139.2L629.1 140.4L629.2 142.3Z",
  AO:"M536.1 263.3L533.8 266.1L533.1 264.0L535.1 262.3L536.1 263.3ZM534.2 266.9L545.4 266.3L548.5 272.4L552.8 272.2L553.9 269.9L555.8 269.3L560.4 270.3L561.5 280.8L565.2 280.2L566.7 281.2L566.7 285.9L560.9 285.8L560.8 294.7L564.5 298.7L559.4 299.8L552.7 299.4L550.7 298.1L539.1 298.4L537.4 297.1L532.6 298.1L533.8 290.1L538.2 281.4L534.2 266.9Z",
  AQ:"M364.8 466.8L370.4 466.2L378.0 468.0L379.6 472.3L359.8 475.1L349.5 474.0L350.0 472.8L358.4 471.2L364.8 466.8ZM315.9 472.9L328.1 473.3L331.6 471.2L334.5 472.3L332.9 475.0L320.9 474.8L315.9 472.9ZM294.7 448.0L299.8 447.8L300.7 443.1L304.9 441.3L310.2 448.4L308.9 450.5L302.6 451.4L298.9 451.3L300.3 450.3L293.9 451.0L291.8 450.2L291.6 449.1L294.7 448.0ZM215.7 449.7L231.1 449.9L232.8 451.4L220.0 451.4L215.7 449.7ZM159.4 454.6L160.0 453.7L170.2 454.1L166.0 455.8L159.4 454.6ZM146.4 454.1L148.4 453.5L155.5 455.2L146.4 454.1ZM45.2 468.3L46.9 467.3L52.1 467.7L57.8 470.8L52.4 471.2L45.2 468.3ZM1000.0 485.3L1000.0 500.0L0.0 500.0L0.0 485.3L2.6 483.7L7.6 484.6L11.6 483.7L15.6 484.8L27.9 483.0L36.0 484.9L60.9 487.1L68.9 486.4L87.4 487.8L102.5 486.2L103.1 484.9L83.2 484.2L73.4 482.5L75.9 479.0L75.4 477.9L64.3 475.3L81.5 475.9L93.3 473.2L84.6 470.4L68.5 469.6L61.0 466.7L60.1 463.6L64.0 464.7L72.9 464.1L75.2 465.3L79.6 465.0L94.2 462.4L93.1 460.4L93.9 459.4L99.1 459.8L124.4 456.4L163.7 457.0L183.5 454.8L188.1 457.5L190.9 456.7L201.2 458.8L220.4 459.2L221.9 458.0L218.7 456.1L215.2 455.9L212.0 451.7L224.6 452.5L232.4 454.5L249.8 453.7L252.1 451.6L254.4 452.8L273.7 455.1L277.0 453.1L292.0 455.2L312.9 451.3L313.2 449.0L309.6 443.7L312.7 439.3L311.8 437.0L323.3 430.3L339.4 425.8L341.0 426.5L336.0 428.8L327.7 430.0L326.0 431.9L327.4 433.9L322.9 434.7L317.6 438.8L324.5 442.3L328.3 446.4L331.4 453.2L331.0 454.7L321.2 459.1L303.9 462.9L285.4 463.1L295.4 466.4L283.5 467.7L283.3 469.9L290.7 472.9L334.2 478.8L338.3 481.2L361.8 477.0L381.1 478.0L386.7 476.0L420.7 473.2L417.5 470.2L401.0 470.7L400.6 467.6L419.8 463.0L437.6 461.4L451.3 458.7L456.4 456.9L457.2 455.9L454.3 455.2L457.1 453.2L465.9 451.1L471.4 448.0L479.4 449.2L480.9 447.0L487.9 448.5L498.2 447.9L499.4 449.0L521.5 444.1L526.5 444.5L530.0 446.8L537.3 444.4L542.0 445.6L553.5 444.1L559.6 444.6L562.7 446.4L575.3 445.7L588.9 443.5L594.1 440.3L607.4 443.8L616.6 440.6L631.8 438.1L643.9 434.0L651.5 432.8L656.5 433.3L663.2 436.9L670.6 438.8L677.9 437.2L691.4 438.7L693.5 442.3L693.2 443.6L688.4 445.3L688.7 446.4L691.9 446.3L688.7 449.6L694.1 450.7L697.3 450.2L705.2 444.1L715.7 443.0L719.8 439.8L729.9 436.7L741.0 436.5L744.4 433.9L749.1 436.5L766.1 437.2L777.0 436.8L785.6 432.1L794.9 435.9L806.2 435.3L815.6 433.0L821.1 435.3L832.9 436.9L842.3 434.7L857.8 435.4L874.3 433.9L875.2 431.4L879.5 435.5L881.8 436.0L904.1 435.9L907.4 438.6L913.4 440.0L923.6 441.3L928.6 440.4L942.2 443.3L948.8 446.1L964.7 446.8L975.6 449.2L970.2 454.6L961.4 456.6L954.4 461.8L954.1 464.1L957.6 467.2L962.8 467.6L963.9 468.8L949.4 469.9L943.9 474.8L954.7 478.9L969.2 481.5L970.6 482.8L1000.0 485.3Z",
  AR:"M309.3 396.2L311.8 399.6L319.3 401.9L318.1 403.3L315.4 403.5L309.4 402.4L309.3 396.2ZM339.9 333.9L337.5 345.6L341.0 348.0L340.7 349.9L342.4 351.1L342.3 352.5L339.6 356.1L335.5 357.6L326.8 357.9L327.4 363.0L325.7 364.0L319.1 364.1L319.5 366.8L321.4 367.7L322.9 366.8L323.7 368.2L318.9 370.8L317.9 375.1L313.1 376.5L312.3 378.6L317.7 381.2L316.7 383.7L313.4 385.3L311.6 388.5L307.9 390.9L310.7 395.4L300.2 394.5L299.1 390.8L296.3 389.9L296.1 387.0L299.1 384.0L300.9 374.9L302.2 374.4L300.6 372.8L301.5 371.6L299.6 367.4L300.7 366.8L300.2 363.4L301.6 358.1L303.3 357.1L302.4 351.8L304.5 350.0L306.1 345.0L304.1 337.1L305.8 334.3L306.5 329.1L310.3 324.7L310.0 318.1L313.0 316.7L313.6 313.2L315.9 310.6L319.5 311.3L321.2 313.3L322.3 311.1L325.4 311.2L331.0 316.3L339.5 319.9L339.9 321.1L337.2 325.3L345.3 326.1L349.6 321.0L351.0 324.8L339.9 333.9Z",
  AT:"M547.2 116.3L547.0 117.5L545.4 117.5L544.5 120.3L540.6 121.0L533.8 119.1L530.7 120.1L526.3 119.2L527.5 117.8L535.9 118.1L535.8 115.9L537.8 114.2L539.8 115.1L542.4 113.8L545.8 114.5L547.2 116.3Z",
  AU:"M910.2 363.4L911.9 363.5L910.9 370.0L909.9 369.3L908.0 371.2L905.7 371.0L902.1 363.1L906.6 364.3L910.2 363.4ZM850.4 339.5L845.1 341.6L843.5 344.1L833.0 344.4L827.8 347.4L824.0 347.3L819.5 345.0L819.6 343.4L821.4 342.4L821.7 339.5L819.6 331.8L814.8 322.5L816.1 323.7L815.1 321.2L817.3 323.1L815.0 317.7L815.9 312.4L817.1 310.4L817.3 312.5L818.5 310.6L824.2 307.5L835.7 304.7L839.6 300.5L839.8 297.9L841.7 295.6L842.9 298.0L844.1 297.4L843.1 296.1L843.9 294.8L845.2 295.4L845.5 293.2L849.1 289.5L853.0 288.4L856.6 291.3L860.1 291.6L859.5 290.1L862.8 284.8L868.3 283.7L868.2 282.2L866.2 281.3L867.7 280.9L875.8 284.0L879.1 282.9L880.4 284.3L877.7 287.0L876.4 291.7L889.5 299.2L891.3 298.2L892.4 295.5L893.6 284.5L895.9 279.6L899.8 290.4L901.6 289.4L903.8 291.6L906.6 302.7L913.5 306.6L915.8 312.1L918.7 312.2L919.2 315.2L924.6 320.2L926.6 328.1L924.7 337.9L917.6 349.1L916.7 354.0L912.0 355.0L906.4 358.4L902.4 356.7L902.9 355.3L898.9 357.8L890.7 355.6L887.7 350.4L883.7 348.9L884.6 347.6L883.9 345.5L882.6 347.4L880.1 347.9L883.0 343.4L882.8 341.4L877.7 346.9L875.6 345.8L873.0 340.6L864.8 337.5L850.4 339.5Z",
  AZ:"M628.9 133.7L632.8 135.7L635.0 133.9L640.0 138.2L637.7 138.4L635.8 143.6L633.4 142.2L634.3 140.9L633.5 140.0L629.2 142.3L629.1 140.4L626.7 139.2L627.5 138.3L624.9 135.4L629.2 135.9L628.9 133.7ZM628.2 142.4L626.3 142.0L624.4 139.7L627.1 140.4L628.2 142.4Z",
  BA:"M551.6 131.5L545.7 127.7L543.8 125.5L544.3 124.4L553.8 125.4L554.0 129.0L551.6 131.5Z",
  BD:"M757.4 188.8L756.6 192.6L753.9 186.8L751.4 186.7L750.8 189.3L747.3 188.7L746.4 182.7L744.7 181.9L747.0 179.9L745.0 178.4L746.0 176.5L749.5 177.9L749.8 179.8L756.6 180.6L753.2 184.7L754.7 186.2L756.0 184.4L757.4 188.8Z",
  BE:"M517.1 108.9L515.8 112.4L511.9 111.4L507.0 107.9L513.8 107.0L517.1 108.9Z",
  BF:"M485.0 221.2L485.5 217.5L488.1 213.3L497.0 208.4L501.0 208.5L502.8 214.3L506.0 214.9L505.4 217.7L502.5 219.5L491.8 219.5L492.1 223.2L488.0 223.3L485.0 221.2Z",
  BG:"M562.9 127.1L563.7 128.3L571.0 128.6L575.7 127.3L579.3 128.6L576.9 131.7L577.8 133.3L572.5 133.8L572.5 135.2L563.8 135.2L562.2 132.4L563.9 130.0L562.5 128.8L562.9 127.1Z",
  BI:"M584.6 256.7L585.4 259.3L581.5 262.5L580.6 257.9L584.6 256.7Z",
  BJ:"M507.5 232.6L505.2 232.9L504.6 224.6L502.1 220.9L504.0 217.9L507.9 216.0L510.0 217.6L510.5 220.2L507.6 226.4L507.5 232.6Z",
  BN:"M820.7 234.9L820.4 238.0L818.5 238.9L817.2 237.4L820.7 234.9Z",
  BO:"M306.9 280.4L310.4 280.6L314.9 277.6L318.5 277.1L318.3 282.1L321.3 284.6L331.9 288.3L332.9 295.2L338.2 295.3L338.1 298.0L340.3 300.5L339.3 305.5L338.4 306.0L335.8 303.8L328.4 304.5L325.9 311.8L322.3 311.1L321.2 313.3L319.5 311.3L315.9 310.6L311.6 313.5L309.0 306.6L309.9 303.9L306.7 298.8L308.4 295.8L307.4 291.5L309.3 284.9L306.9 280.4Z",
  BR:"M351.7 343.8L351.0 342.2L352.2 340.9L350.6 339.0L341.7 333.6L339.9 333.9L351.0 324.8L351.0 322.6L349.6 321.0L348.3 321.5L349.2 316.7L346.1 316.5L345.0 312.1L339.1 311.4L338.4 306.0L340.3 300.5L338.1 298.0L338.2 295.3L332.9 295.2L331.9 288.3L321.3 284.6L318.3 282.1L318.5 277.1L314.9 277.6L310.4 280.6L304.0 280.6L304.2 276.4L301.9 278.0L299.5 277.9L296.6 276.3L297.2 275.1L294.5 270.9L296.9 268.4L297.5 264.7L303.3 261.8L305.9 261.9L307.2 253.1L305.5 248.5L307.6 248.3L307.7 247.3L306.1 247.0L306.1 245.2L311.5 245.3L312.4 244.3L313.7 246.9L317.9 247.8L324.0 243.9L321.5 243.1L321.2 239.5L320.0 238.7L324.7 239.5L330.6 237.4L331.3 235.6L333.4 236.1L333.0 237.3L334.6 239.0L333.4 242.3L336.0 246.3L340.7 244.6L344.5 245.0L344.5 243.0L352.9 244.1L357.5 238.3L359.7 244.7L361.2 245.2L361.3 247.1L359.2 249.4L360.0 250.2L364.9 250.7L365.0 253.4L367.2 251.6L375.3 254.3L376.6 255.9L376.2 257.5L379.4 256.6L388.9 258.0L396.6 263.4L401.1 264.3L403.5 270.4L402.4 275.0L392.6 286.3L390.9 299.6L386.3 310.9L383.4 313.8L376.0 314.9L367.6 319.1L365.3 321.9L364.2 329.7L351.7 343.8Z",
  BS:"M283.9 174.9L286.1 176.1L285.6 178.1L283.9 174.9ZM282.8 180.0L284.6 184.0L282.2 181.7L282.8 180.0Z",
  BT:"M754.7 172.9L755.6 175.4L749.3 175.8L746.8 174.7L750.0 171.4L754.7 172.9Z",
  BW:"M581.8 311.4L575.3 315.5L571.3 320.8L567.3 321.3L564.8 320.2L560.0 324.2L558.0 324.5L557.7 321.9L555.3 318.8L555.3 310.7L558.0 310.6L558.1 300.7L564.4 299.6L565.5 300.8L570.2 299.3L572.7 303.6L577.0 306.9L577.8 309.7L581.8 311.4Z",
  BY:"M578.3 94.0L585.8 95.7L585.4 97.7L590.8 101.8L587.0 102.6L588.3 105.3L585.9 105.4L584.9 107.4L570.4 105.8L565.4 106.7L564.4 104.2L566.1 103.6L565.2 100.2L570.9 99.2L573.9 96.8L573.6 95.5L578.3 94.0Z",
  BZ:"M252.4 200.5L254.2 198.6L255.3 199.0L254.6 204.1L253.0 205.9L252.1 205.9L252.4 200.5Z",
  CA:"M158.8 113.9L146.0 108.8L144.5 106.3L144.9 104.6L141.3 103.5L140.8 101.2L137.5 99.2L138.9 94.7L134.1 92.9L129.6 87.7L123.7 83.9L118.2 86.4L113.8 83.3L108.3 82.5L108.4 56.4L120.8 58.6L126.6 56.6L130.8 56.9L139.5 55.0L141.4 56.2L144.1 54.2L150.7 57.0L154.4 55.1L154.8 57.2L162.6 56.1L179.9 58.6L183.6 60.0L179.7 61.4L184.7 62.0L194.6 61.2L197.6 62.8L200.6 61.4L197.7 60.2L199.5 59.3L205.1 58.9L210.2 61.1L218.2 62.1L226.5 61.7L226.2 60.0L228.7 59.5L233.0 60.4L233.0 63.1L234.8 60.9L237.0 60.9L238.2 58.1L232.0 55.3L232.2 52.2L235.5 50.2L242.0 51.9L245.8 55.0L243.3 56.4L248.5 57.0L248.5 59.8L252.2 57.6L255.5 59.4L254.7 61.5L257.4 63.3L262.3 58.9L262.4 55.9L270.5 56.5L274.2 57.9L274.4 59.3L272.3 60.7L274.3 62.2L273.9 63.6L268.5 65.5L261.8 65.1L257.4 70.1L248.0 73.3L247.9 75.1L244.6 75.5L238.2 80.8L237.0 86.3L241.1 86.7L243.6 91.4L247.5 90.9L263.9 96.4L271.5 96.8L271.9 102.0L273.9 105.1L278.0 107.8L280.2 106.9L281.7 104.0L280.2 99.6L278.3 98.1L282.7 96.8L287.4 93.0L285.3 88.7L281.9 86.7L285.2 83.7L283.0 76.9L294.9 76.5L301.7 80.2L306.7 80.4L307.5 86.2L312.1 88.3L316.1 86.8L320.6 82.4L329.5 91.8L328.3 93.5L340.7 98.3L341.8 100.6L345.1 102.0L345.3 105.1L333.2 110.4L315.6 110.5L309.7 113.7L302.5 119.9L304.8 119.5L309.3 115.8L319.3 113.2L321.7 114.6L319.1 116.5L320.9 121.6L324.5 122.9L329.1 122.5L331.9 119.4L332.1 121.4L333.9 122.4L318.4 129.0L316.3 128.8L316.2 126.5L321.0 124.2L313.5 124.6L311.7 123.0L311.7 119.3L307.7 118.2L303.7 123.7L301.4 125.0L292.0 125.0L286.6 128.8L281.3 128.8L280.1 129.3L280.7 130.9L271.0 134.2L269.1 133.4L271.8 129.0L270.7 124.0L264.2 119.7L254.5 115.8L245.4 116.3L238.0 114.8L236.6 112.8L235.7 113.9L158.8 113.9ZM266.7 76.5L268.7 75.2L272.6 75.3L269.3 77.3L266.7 76.5ZM278.4 47.8L275.3 46.3L275.5 45.3L283.2 45.4L288.2 47.7L278.4 47.8ZM276.9 77.5L279.8 77.3L278.7 78.8L276.9 77.5ZM240.0 41.7L238.5 42.8L231.1 41.9L236.5 39.9L240.0 41.7ZM231.2 31.2L234.6 32.2L229.7 33.7L227.4 33.1L226.0 30.9L231.2 31.2ZM255.1 43.4L243.3 42.1L242.0 39.2L239.2 38.0L230.2 36.8L231.3 35.7L245.5 36.7L247.9 37.6L247.3 38.7L252.3 40.0L274.6 39.7L278.2 41.9L272.4 43.2L255.1 43.4ZM190.9 32.9L194.8 33.3L188.7 35.0L184.6 34.1L190.9 32.9ZM191.8 31.1L195.4 31.7L187.4 32.2L191.8 31.1ZM345.6 107.5L342.2 111.6L344.0 110.7L345.9 111.3L344.9 112.3L351.5 113.2L350.6 115.2L352.5 114.8L353.8 118.0L352.6 120.4L349.5 120.0L349.3 117.4L346.1 119.8L344.5 119.7L346.4 118.4L343.7 117.7L335.4 117.8L334.9 116.9L336.7 116.0L335.5 115.2L340.7 109.1L344.8 106.6L346.1 106.7L345.6 107.5ZM267.0 69.1L277.5 73.0L275.0 73.9L269.1 71.9L262.4 74.9L261.5 73.2L257.7 73.5L260.1 72.1L261.4 67.4L267.0 69.1ZM281.2 49.0L283.8 47.9L293.8 50.6L294.2 51.9L299.3 51.2L302.2 53.0L308.9 54.1L314.0 57.8L308.9 59.1L319.8 61.5L323.8 64.1L328.2 64.3L327.3 66.2L322.4 69.4L314.7 65.6L311.1 65.9L310.7 67.5L318.6 71.2L320.4 73.9L319.4 75.9L308.9 72.9L316.2 78.0L308.7 76.9L292.1 70.3L292.2 71.1L284.1 71.6L281.8 70.6L283.6 68.6L294.6 68.2L293.6 67.2L294.6 65.8L298.2 63.1L296.4 60.9L286.5 58.6L288.3 57.9L280.7 55.1L274.2 56.3L253.7 54.4L251.4 53.4L254.3 52.2L250.3 52.2L249.4 49.3L254.4 45.7L261.6 45.0L259.5 46.8L261.7 48.5L264.3 46.3L271.3 45.1L276.1 48.0L275.7 49.8L281.2 49.0ZM237.5 44.1L248.6 44.8L238.1 49.9L235.0 49.8L233.3 46.0L237.5 44.1ZM158.7 38.6L169.2 34.7L177.2 34.3L176.8 36.5L174.7 37.4L162.5 39.2L158.7 38.6ZM131.4 99.9L134.0 99.7L133.2 102.8L135.6 105.1L130.4 101.6L130.1 99.5L131.4 99.9ZM207.0 29.7L219.9 31.1L223.1 33.6L207.8 32.3L210.5 31.5L207.2 30.8L207.0 29.7ZM156.9 115.2L151.0 114.4L147.1 111.6L144.3 111.1L143.4 109.0L150.7 110.3L156.9 115.2ZM162.4 43.2L173.5 43.9L179.1 45.9L168.8 48.6L165.4 50.5L165.4 51.7L158.1 53.1L150.2 50.4L155.7 45.3L153.0 43.6L162.4 43.2ZM200.5 39.3L205.9 39.0L206.4 40.3L204.7 41.7L188.3 43.3L184.0 43.3L183.7 42.4L189.5 41.2L173.0 41.0L179.4 37.6L197.0 40.4L193.1 37.7L195.6 36.7L198.5 37.0L200.5 39.3ZM204.1 47.0L207.2 48.1L209.8 52.8L219.5 55.5L219.2 56.7L214.6 56.9L216.4 58.0L215.5 59.0L205.7 57.8L185.2 59.6L183.7 58.3L177.5 57.9L174.1 55.7L187.7 54.5L172.5 54.1L171.0 53.0L177.5 51.9L168.3 51.2L172.6 48.0L180.0 46.3L182.9 46.9L181.5 48.2L187.7 47.3L191.5 48.7L194.7 47.3L197.2 48.2L199.5 51.0L200.9 49.8L198.9 47.0L204.1 47.0ZM221.0 48.0L217.9 46.2L221.2 44.9L229.5 45.1L230.2 45.9L227.6 47.2L231.8 48.4L231.3 50.9L226.8 52.0L215.3 48.6L215.3 47.7L221.0 48.0ZM203.9 45.6L209.7 46.1L207.3 47.9L202.9 45.9L203.9 45.6ZM226.4 36.9L228.5 38.2L227.3 41.7L222.8 42.0L219.8 41.5L219.8 39.9L215.3 40.1L215.1 38.0L226.4 36.9ZM233.3 26.1L238.1 25.1L236.8 24.4L243.3 24.3L256.1 26.9L261.6 29.6L252.7 32.5L242.0 32.4L239.0 31.2L241.3 29.5L236.2 29.5L231.4 27.3L233.3 26.1ZM245.6 22.5L262.5 20.4L268.9 21.3L271.1 19.8L279.7 19.1L297.7 18.8L328.2 20.5L312.1 23.6L318.1 23.6L307.0 26.1L302.3 28.3L286.4 29.7L290.2 30.0L288.3 30.5L290.6 31.9L278.4 35.5L283.6 36.7L276.2 38.4L251.4 37.6L251.1 36.2L256.2 35.6L254.8 33.6L264.0 34.6L255.7 32.3L263.6 29.6L258.5 27.1L268.3 27.5L272.6 26.5L256.7 26.3L245.6 22.5ZM291.1 62.7L286.1 63.6L285.5 62.3L286.6 60.7L289.2 60.3L291.3 61.1L291.1 62.7ZM232.6 57.0L234.3 58.0L232.6 59.0L222.8 57.2L227.2 55.2L232.6 57.0ZM320.8 111.5L325.4 111.9L328.3 113.6L320.8 111.5ZM322.2 119.3L323.2 120.7L327.7 121.0L325.3 122.3L321.8 121.1L321.1 120.2L322.2 119.3Z",
  CD:"M581.5 262.5L582.3 268.1L585.4 273.2L579.8 273.7L578.8 282.8L582.3 283.8L582.5 286.8L580.4 286.8L575.5 282.2L573.8 283.1L567.4 280.4L561.5 280.8L560.4 270.3L555.8 269.3L553.9 269.9L552.8 272.2L548.5 272.4L545.4 266.3L534.2 266.9L533.8 266.1L535.1 263.9L537.8 262.5L540.5 263.8L544.5 259.8L545.6 254.8L549.0 251.2L551.5 238.3L554.1 236.0L562.2 238.8L563.4 236.9L571.3 235.4L576.0 235.5L579.0 238.1L582.5 237.2L585.6 240.3L585.5 243.5L586.6 243.9L583.0 248.3L580.6 257.9L581.5 262.5Z",
  CF:"M576.0 235.5L567.8 235.8L563.4 236.9L562.2 238.8L554.1 236.0L551.5 238.3L551.3 240.3L547.6 239.6L544.5 243.7L540.2 236.9L540.2 234.9L542.4 229.4L549.9 228.1L552.5 226.0L552.3 225.0L558.3 223.7L560.3 220.6L563.5 219.0L565.4 222.0L565.2 225.1L569.8 228.3L576.0 235.5Z",
  CG:"M551.3 240.3L549.0 251.2L545.6 254.8L544.5 259.8L540.5 263.8L539.3 262.5L536.8 263.6L535.1 262.3L533.1 264.0L530.8 261.1L532.9 259.5L531.9 257.7L534.7 256.6L534.9 255.4L538.9 256.9L540.1 253.7L538.5 249.9L539.7 246.7L536.9 246.3L536.3 243.7L544.3 245.2L547.6 239.6L551.3 240.3Z",
  CH:"M526.7 118.0L526.3 119.2L529.0 119.7L528.8 120.9L520.2 122.8L518.1 121.0L516.7 121.5L518.7 117.9L523.7 117.1L526.7 118.0Z",
  CI:"M477.7 221.6L482.8 220.8L483.2 222.0L485.0 221.2L488.0 223.3L492.1 223.2L492.9 227.2L491.0 232.6L492.1 236.1L487.1 235.6L478.6 237.9L479.0 234.1L476.1 232.0L476.9 226.9L478.2 226.2L476.9 222.8L477.7 221.6Z",
  CL:"M309.3 396.2L309.4 402.4L314.0 402.5L310.7 404.5L302.8 402.9L292.6 396.8L302.5 400.2L304.8 397.0L309.3 396.2ZM306.7 298.8L309.9 303.9L309.0 306.6L311.6 313.5L313.9 313.9L313.0 316.7L310.0 318.1L310.3 324.7L306.5 329.1L305.8 334.3L304.1 337.1L306.1 345.0L304.5 350.0L302.4 351.8L303.3 357.1L301.6 358.1L300.2 363.4L300.7 366.8L299.6 367.4L301.5 371.6L300.6 372.8L302.2 374.4L300.9 374.9L299.1 384.0L296.1 387.0L296.3 389.9L299.1 390.8L300.2 394.5L309.5 395.3L303.2 396.9L302.8 399.5L301.6 399.6L291.8 395.2L290.0 385.2L291.2 382.5L294.1 380.4L289.9 379.6L292.5 377.1L293.5 372.5L296.6 373.5L298.0 367.7L296.1 367.0L295.3 370.5L293.5 370.1L296.6 359.1L295.6 353.2L296.8 353.1L301.6 340.1L301.4 330.2L303.0 326.8L305.3 309.4L304.5 301.0L306.7 298.8Z",
  CM:"M540.3 214.3L543.0 222.3L539.4 222.2L538.8 223.5L541.6 225.6L542.9 228.6L540.4 232.7L540.2 236.9L544.1 241.6L544.3 245.2L539.8 243.8L526.8 243.7L527.2 241.5L523.6 237.5L524.3 234.8L528.1 230.4L530.7 231.5L532.6 230.6L537.7 220.0L540.0 217.9L539.4 215.3L540.3 214.3Z",
  CN:"M804.1 199.5L801.8 198.6L801.7 196.2L807.7 194.2L808.4 195.3L806.5 198.1L804.1 199.5ZM722.9 132.4L722.7 130.8L724.6 130.1L722.1 125.2L729.1 123.5L731.1 118.5L736.6 119.4L738.1 118.2L738.2 115.4L743.8 113.1L744.5 115.0L750.8 117.5L752.7 119.8L751.6 123.0L752.6 124.2L759.7 125.1L764.7 127.1L767.6 131.3L780.1 131.5L791.6 134.5L803.5 131.9L810.6 128.5L809.3 126.5L810.8 124.7L815.2 125.5L826.2 120.4L832.4 120.3L832.7 119.3L828.0 116.5L821.5 117.4L820.8 116.3L824.1 111.4L827.4 112.5L831.4 110.7L835.4 105.7L835.3 104.1L833.8 103.5L839.6 101.6L849.9 103.4L854.6 111.8L859.4 112.7L862.7 114.6L863.9 117.2L875.1 115.3L869.7 124.6L864.0 125.1L864.3 130.8L862.9 130.8L862.9 132.2L861.1 130.6L860.0 132.2L855.7 133.3L856.1 134.8L852.4 133.8L845.2 139.1L836.3 142.0L839.4 137.7L837.9 136.3L826.5 142.4L832.5 146.8L835.6 144.8L839.9 146.0L840.3 147.4L836.4 148.2L831.0 153.0L834.0 154.6L838.6 162.0L838.6 164.0L836.8 164.8L839.1 167.1L838.0 171.6L836.5 171.8L829.6 181.8L821.9 186.7L817.1 188.3L816.1 187.4L807.7 190.6L806.8 193.5L805.2 193.7L805.2 190.6L797.3 189.4L796.0 188.3L796.5 186.7L792.6 185.1L782.4 188.0L782.8 191.2L781.3 191.1L781.0 189.3L778.9 190.1L775.7 188.6L776.5 186.3L774.7 185.7L774.1 183.2L771.1 183.6L771.5 180.3L774.1 178.0L774.1 173.6L772.0 171.3L767.4 171.1L768.3 169.9L767.0 168.2L765.0 169.4L762.7 168.7L757.0 172.5L750.0 171.4L746.7 174.2L746.5 172.0L738.4 171.7L718.7 162.5L717.9 159.4L719.9 159.8L720.0 158.3L719.2 154.7L716.2 151.4L711.6 150.3L708.3 146.1L708.0 143.4L705.4 143.0L704.7 140.5L707.7 137.9L712.6 137.7L713.6 135.9L717.2 135.6L722.9 132.4Z",
  CO:"M314.2 246.5L312.4 244.3L311.5 245.3L306.1 245.2L306.1 247.0L307.7 247.3L307.6 248.3L305.5 248.5L307.2 253.1L305.9 261.9L303.6 260.4L305.4 257.6L303.3 256.3L297.0 256.4L291.4 250.2L284.9 248.9L280.6 245.3L285.8 239.3L284.7 238.6L285.2 233.8L283.7 229.9L285.4 228.0L284.8 226.3L289.8 223.8L290.3 220.5L291.9 219.2L296.1 218.8L301.7 215.6L301.9 217.3L297.5 221.0L296.4 224.6L297.8 224.8L298.8 229.4L300.1 230.6L305.3 230.7L307.3 233.1L312.9 233.1L311.6 237.5L313.0 240.8L311.6 242.2L314.2 246.5Z",
  CR:"M270.7 223.4L269.6 223.7L269.5 227.2L264.0 222.0L263.6 223.5L262.1 222.4L261.3 219.7L262.3 218.8L267.6 219.6L270.7 223.4Z",
  CU:"M271.5 185.6L282.4 187.5L289.8 192.4L293.9 193.7L284.0 194.8L285.9 193.3L283.0 192.4L281.3 190.0L271.8 187.8L272.8 187.1L264.0 189.2L267.3 186.7L271.5 185.6Z",
  CY:"M590.9 152.4L594.5 152.8L591.6 154.0L589.6 152.5L590.9 152.4Z",
  CZ:"M541.7 108.0L546.4 110.5L548.8 110.1L552.4 112.5L547.1 115.0L542.4 113.8L539.8 115.1L534.8 112.4L534.0 110.4L541.7 108.0Z",
  DE:"M539.2 100.7L539.1 102.8L541.7 108.0L534.0 110.4L534.8 112.4L537.8 114.2L535.8 115.9L535.9 118.1L520.7 117.7L522.5 113.8L518.5 113.3L516.8 110.8L516.6 106.0L519.0 104.9L519.7 100.9L522.6 101.3L524.4 99.9L523.7 97.3L527.6 97.3L530.4 100.0L534.8 98.7L539.2 100.7Z",
  DJ:"M617.6 215.2L620.3 215.6L618.7 217.4L619.8 218.2L618.8 219.6L616.0 219.3L615.7 217.7L617.6 215.2Z",
  DK:"M527.6 97.3L523.7 97.3L522.5 92.9L523.7 91.4L529.4 89.6L528.5 92.0L530.3 93.2L526.8 95.9L527.6 97.3ZM534.4 94.1L535.3 95.5L533.6 97.8L530.7 96.2L530.3 95.1L534.4 94.1Z",
  DO:"M300.8 199.9L301.1 194.8L305.7 195.4L310.2 198.3L309.2 199.4L303.7 198.8L301.7 201.1L300.8 199.9Z",
  DZ:"M475.9 173.9L475.9 169.9L485.4 166.7L489.7 164.2L489.9 162.1L496.4 160.4L494.0 152.3L496.6 150.8L504.1 148.3L523.4 147.4L522.6 153.7L520.9 155.3L521.1 157.4L525.2 160.8L527.2 168.3L527.0 176.4L525.9 177.5L528.6 182.3L529.9 181.8L533.3 184.8L515.8 195.6L508.8 197.1L508.7 195.3L475.9 173.9Z",
  EC:"M290.6 250.4L290.2 254.3L287.1 257.2L283.8 258.3L281.6 262.6L280.0 263.8L278.8 262.4L276.5 262.3L278.4 257.4L277.8 256.2L276.8 257.5L275.1 256.2L275.2 252.9L277.5 247.9L281.0 246.2L284.9 248.9L288.1 248.8L290.6 250.4Z",
  EE:"M577.7 84.8L576.2 86.9L577.0 89.5L575.8 90.3L567.5 89.5L567.9 87.8L565.1 87.2L564.8 85.6L577.7 84.8Z",
  EG:"M602.4 188.9L569.4 188.9L568.6 166.5L569.9 162.3L580.3 164.2L586.0 162.3L588.8 164.1L589.4 163.2L595.2 163.3L597.0 168.1L594.9 172.7L592.0 171.1L589.8 167.3L599.1 183.5L598.7 185.8L602.4 188.9Z",
  EH:"M475.9 173.2L475.9 178.1L466.8 178.0L466.8 185.1L464.2 185.3L464.1 190.8L453.2 190.7L452.6 191.7L452.7 190.5L459.0 190.3L461.4 184.2L465.3 181.2L468.4 175.3L475.6 174.7L475.9 173.2Z",
  ER:"M601.2 209.9L602.4 202.9L606.7 200.0L609.1 205.8L619.7 214.7L617.6 215.2L611.2 209.7L607.0 209.7L605.3 208.4L604.4 210.5L601.2 209.9Z",
  ES:"M479.3 147.0L480.5 144.2L479.2 139.9L480.4 139.7L481.0 135.8L482.3 135.1L481.5 133.7L477.7 133.9L477.0 132.6L474.9 133.7L473.9 130.5L477.8 128.5L494.7 129.4L500.9 131.7L508.3 132.0L508.4 133.6L505.8 135.5L502.3 136.1L499.2 140.8L500.3 142.4L494.0 148.1L487.9 148.1L485.1 150.1L481.9 147.4L479.3 147.0Z",
  ET:"M632.7 227.8L624.9 236.1L621.3 236.2L616.3 239.1L613.2 238.2L609.9 240.5L600.4 237.6L596.4 231.7L591.5 228.4L594.0 226.7L595.2 220.5L599.6 215.1L601.2 209.9L604.4 210.5L605.3 208.4L607.0 209.7L611.2 209.7L615.6 212.6L617.6 215.2L615.7 217.7L616.0 219.3L618.8 219.6L618.2 220.6L621.3 224.5L632.7 227.8Z",
  FI:"M579.4 58.2L579.0 60.1L583.3 61.9L580.7 64.0L583.9 67.2L582.1 69.6L584.6 71.7L583.4 73.5L587.5 75.4L586.5 76.8L578.0 81.9L563.5 83.8L559.2 81.3L559.8 78.6L558.5 76.1L559.8 74.5L570.6 69.1L565.5 65.6L565.4 61.3L557.3 58.0L559.0 57.3L562.1 58.8L568.7 59.3L572.7 56.0L577.0 55.1L580.6 56.2L579.4 58.2Z",
  FJ:"M1000.0 294.6L1000.0 296.0L996.5 297.3L996.1 296.2L1000.0 294.6ZM994.8 298.6L996.4 299.0L996.0 300.4L992.7 300.5L993.5 298.3L994.8 298.6Z",
  FK:"M330.0 394.0L337.4 391.9L339.6 393.2L335.0 395.0L333.8 394.0L331.4 395.3L330.0 394.0Z",
  FR:"M356.5 238.5L352.9 244.1L348.5 243.6L350.0 239.9L348.7 236.4L350.1 234.0L353.1 235.0L356.5 238.5ZM517.2 112.6L522.5 113.8L520.7 117.7L518.7 117.9L516.8 120.2L516.7 121.5L518.1 121.0L519.0 122.2L519.7 124.1L518.7 124.9L519.5 127.1L521.0 127.4L520.7 128.6L518.1 130.2L512.7 129.4L508.6 130.3L508.3 132.0L505.1 132.4L494.7 129.4L496.2 127.7L496.7 122.2L491.8 117.9L487.5 116.8L487.2 114.8L495.5 114.9L494.6 111.7L497.3 112.9L503.7 110.8L504.6 108.5L507.0 107.9L511.9 111.4L517.2 112.6ZM524.3 131.6L526.1 130.5L525.6 135.1L524.4 134.5L524.3 131.6Z",
  GA:"M531.3 243.7L536.0 243.6L536.9 246.3L539.7 246.7L538.5 249.9L540.1 253.7L538.9 256.9L534.9 255.4L534.7 256.6L531.9 257.7L532.9 259.5L530.8 261.1L524.4 253.1L526.4 247.2L531.3 247.1L531.3 243.7Z",
  GB:"M482.8 100.4L479.0 99.8L479.0 96.9L484.3 98.5L482.8 100.4ZM491.4 101.7L491.8 100.0L489.9 98.3L485.9 97.1L486.9 95.8L486.0 95.0L484.5 96.4L484.3 93.7L482.9 92.3L486.1 87.1L491.7 87.1L488.7 90.1L494.6 89.8L491.3 94.5L494.2 94.7L496.9 98.3L498.8 98.7L501.3 103.0L504.7 103.5L502.9 106.1L504.0 107.5L501.5 109.0L484.0 110.7L490.5 107.1L486.2 106.7L485.4 105.6L488.3 104.7L486.7 103.2L487.3 101.4L491.4 101.7Z",
  GE:"M611.0 129.3L626.3 131.9L629.5 135.6L621.1 135.9L615.4 134.6L615.1 131.5L611.0 129.3Z",
  GH:"M500.1 219.4L502.9 233.5L494.5 236.9L492.1 236.1L491.0 232.6L492.9 227.2L491.8 219.5L500.1 219.4Z",
  GL:"M370.1 20.5L392.7 17.9L424.7 18.0L442.1 20.2L437.0 21.3L411.4 21.7L431.0 22.8L436.4 22.0L438.7 23.0L435.6 24.6L456.2 22.5L464.5 23.0L466.1 24.2L444.3 27.3L450.7 27.4L445.3 31.2L445.4 34.3L448.7 36.2L439.8 37.1L444.9 38.6L445.6 41.0L442.6 41.2L446.2 43.6L440.0 43.8L443.2 45.0L442.3 45.9L434.5 46.4L438.0 48.3L438.1 49.5L432.6 48.3L431.1 49.1L438.5 51.5L439.6 53.7L434.6 54.2L429.0 51.6L430.0 53.5L426.8 54.9L437.9 55.2L422.9 59.8L411.7 60.8L405.0 64.8L389.4 68.2L387.0 69.9L385.6 73.7L381.1 75.9L382.2 78.1L379.5 83.1L375.6 83.2L371.5 81.0L365.9 80.9L356.6 73.3L354.8 69.0L350.9 66.4L351.9 64.3L350.1 63.4L352.8 60.1L357.0 59.1L358.7 55.8L351.5 57.5L348.1 56.6L349.0 53.3L357.2 54.0L350.0 51.3L344.9 51.0L348.0 48.4L340.8 42.5L337.2 41.4L337.3 40.2L329.8 38.6L309.7 38.7L301.7 36.1L314.5 35.1L296.4 33.2L296.8 32.1L317.5 29.5L318.5 28.4L311.0 27.5L327.1 24.1L326.0 22.9L341.1 21.7L352.7 22.5L360.0 21.0L376.3 23.2L369.7 21.7L370.1 20.5Z",
  GM:"M453.6 212.2L458.1 211.5L461.5 212.5L453.2 213.5L453.6 212.2Z",
  GN:"M461.9 215.0L468.0 215.4L468.2 216.5L471.8 217.1L474.6 215.8L477.7 221.6L476.9 222.8L478.2 226.2L476.9 226.9L477.0 228.6L474.4 229.7L472.9 226.3L470.8 226.8L469.1 222.1L465.5 222.7L463.2 225.3L458.0 219.3L461.8 217.2L461.9 215.0Z",
  GQ:"M526.8 243.7L531.3 243.7L531.3 247.1L526.4 247.2L526.8 243.7Z",
  GR:"M573.0 151.9L568.7 153.0L565.3 152.0L565.8 150.8L573.0 151.9ZM563.8 135.2L572.5 135.2L572.5 133.8L573.9 134.5L572.4 136.6L565.9 137.0L567.8 138.5L562.9 138.2L564.9 141.1L563.8 141.7L566.7 143.8L566.8 145.4L564.2 144.7L565.0 146.1L563.3 146.4L564.3 148.8L562.5 148.9L560.2 147.7L556.0 139.9L558.4 136.5L563.8 135.2Z",
  GT:"M243.8 209.6L245.1 205.4L248.7 205.4L246.0 202.1L247.2 202.1L247.2 200.5L252.4 200.5L252.1 205.9L254.9 206.3L251.8 209.9L249.7 211.8L243.8 209.6Z",
  GW:"M453.7 215.6L461.9 215.0L461.8 217.2L458.0 219.3L453.7 215.6Z",
  GY:"M342.9 244.7L337.4 246.5L334.3 245.0L333.4 242.3L334.6 239.0L333.0 237.3L333.4 236.1L329.4 233.4L330.1 231.4L332.5 230.4L331.8 228.4L334.0 226.8L341.3 233.4L338.8 238.7L342.9 244.7Z",
  HN:"M269.0 208.3L264.1 208.9L257.5 213.9L255.9 211.4L251.8 209.9L252.3 208.1L255.8 205.9L263.9 205.6L269.0 208.3Z",
  HR:"M546.0 120.8L552.3 122.5L553.9 124.3L552.8 125.4L544.3 124.4L543.8 125.5L551.3 132.0L544.5 129.1L541.4 124.8L539.6 124.4L538.8 125.5L537.9 124.6L538.1 123.6L542.6 123.7L543.8 121.6L546.0 120.8Z",
  HT:"M300.8 195.2L300.8 199.9L293.2 199.0L293.4 198.2L299.1 198.1L297.8 195.9L296.1 195.4L296.7 194.7L300.8 195.2Z",
  HU:"M561.3 115.5L563.1 117.0L558.4 121.3L551.3 122.9L545.0 119.9L545.4 117.5L547.0 117.5L547.2 116.3L549.6 117.3L557.8 114.9L561.3 115.5Z",
  ID:"M891.7 257.2L891.8 275.3L889.3 273.0L882.3 273.4L885.2 270.3L883.1 265.0L871.3 259.8L869.4 261.4L868.8 259.2L866.6 257.8L871.4 256.2L867.3 256.1L862.6 252.6L867.7 251.0L872.2 252.2L873.4 257.7L876.3 259.4L881.8 254.7L891.7 257.2ZM847.1 274.7L847.5 276.1L845.7 278.2L842.9 278.4L844.4 275.8L847.1 274.7ZM872.8 269.2L873.6 265.1L874.2 267.3L872.8 269.2ZM827.5 238.5L825.9 241.0L827.9 243.6L827.4 244.9L830.5 247.5L827.3 247.8L826.4 252.2L823.8 254.1L822.6 261.1L822.2 260.2L819.1 261.4L818.0 259.7L814.6 258.7L811.3 259.7L810.3 258.3L806.2 258.2L805.8 254.4L803.0 251.3L802.6 248.8L804.6 244.4L807.0 247.9L813.5 245.8L816.1 246.6L818.4 246.0L821.8 238.0L827.5 238.5ZM859.4 257.8L862.4 258.6L863.4 260.7L855.3 259.4L855.9 257.9L859.4 257.8ZM852.4 260.5L850.0 258.8L852.8 258.7L853.5 259.6L852.4 260.5ZM855.4 244.0L857.5 246.9L857.3 249.3L855.9 249.0L855.8 252.5L853.9 247.2L855.4 244.0ZM841.5 247.6L847.9 246.1L845.7 248.8L843.6 249.3L833.8 249.3L833.4 251.4L835.9 253.9L842.6 251.7L842.4 253.0L841.2 252.6L837.5 255.3L840.2 258.9L842.1 264.8L840.6 265.7L839.5 264.7L840.9 262.4L838.2 263.5L837.5 262.7L837.8 261.6L835.8 260.0L836.0 257.3L834.2 258.1L834.5 265.4L832.8 265.8L831.6 264.9L831.9 259.7L829.9 257.8L832.8 249.6L835.8 246.4L841.5 247.6ZM834.2 278.5L830.5 276.5L833.1 276.0L835.5 277.7L834.2 278.5ZM837.1 273.7L841.4 272.5L841.0 274.0L833.1 274.5L833.1 273.5L835.3 272.9L837.1 273.7ZM828.5 273.2L830.2 273.0L830.9 274.2L824.3 275.1L827.5 272.5L828.5 273.2ZM801.4 267.8L801.7 268.8L807.1 269.1L807.7 268.0L812.8 269.3L813.8 271.1L821.4 273.3L818.2 274.3L800.8 271.6L792.7 269.0L794.6 266.4L801.4 267.8ZM789.9 253.0L791.4 256.5L793.4 256.7L794.7 258.5L793.9 266.3L790.9 266.3L785.0 261.7L775.7 249.5L773.9 244.9L764.7 234.8L770.8 235.4L779.6 244.2L782.4 244.2L784.7 246.1L788.4 249.7L787.3 252.0L789.9 253.0Z",
  IE:"M482.8 100.4L483.2 102.4L481.1 104.8L476.2 106.5L472.3 106.1L474.5 103.2L473.1 100.3L479.0 96.9L479.0 99.8L482.8 100.4Z",
  IL:"M599.2 159.1L597.2 161.5L597.0 162.9L598.3 162.5L598.4 163.6L597.0 168.1L595.2 163.3L597.5 158.1L599.5 157.6L599.2 159.1Z",
  IN:"M770.4 171.5L769.8 174.8L767.8 174.3L764.2 176.2L761.4 183.7L759.2 183.1L758.8 188.1L757.4 188.8L756.0 184.4L754.7 186.2L753.2 184.7L756.6 180.6L749.8 179.8L749.5 177.9L746.0 176.5L745.0 178.4L747.0 179.9L744.7 181.9L746.4 182.7L746.9 189.7L741.6 190.3L741.8 192.4L740.3 194.0L736.3 195.9L728.3 202.7L728.3 204.0L723.1 205.8L721.8 221.2L720.4 221.4L719.1 223.5L720.0 224.4L717.4 225.2L715.4 227.9L712.8 225.3L706.8 209.4L704.3 205.6L701.8 190.7L695.8 192.0L692.1 188.6L693.5 187.6L692.6 186.5L689.4 184.2L691.2 182.3L697.3 182.3L694.9 176.4L693.1 175.2L696.2 172.3L699.4 172.5L706.7 163.9L706.7 162.0L709.1 160.4L706.8 159.0L704.9 154.7L706.2 153.5L713.5 153.7L716.2 151.4L719.2 154.7L720.0 158.3L719.9 159.8L717.9 159.4L718.7 162.5L725.3 166.2L722.5 170.0L731.4 174.0L744.6 176.6L744.8 172.6L746.5 172.0L746.8 174.7L749.3 175.8L755.6 175.4L754.7 172.9L762.7 168.7L765.0 169.4L767.0 168.2L768.3 169.9L767.4 171.1L770.4 171.5Z",
  IQ:"M608.9 160.7L607.8 157.3L613.9 154.4L614.7 149.0L618.8 146.2L624.4 146.7L626.2 150.1L628.0 150.9L626.2 155.6L628.1 158.3L631.5 159.8L632.9 161.9L632.5 163.9L634.9 166.9L631.4 166.5L629.4 169.2L624.2 168.9L616.4 163.4L608.9 160.7Z",
  IR:"M634.9 166.9L632.5 163.9L632.9 161.9L631.5 159.8L628.1 158.3L626.2 155.6L628.0 150.9L626.2 150.1L622.8 144.5L622.5 140.5L624.4 139.7L626.3 142.0L628.2 142.4L633.5 140.0L634.3 140.9L633.4 142.2L635.8 143.6L636.7 145.6L641.2 147.6L649.5 147.3L657.3 144.1L669.8 148.6L668.1 156.5L669.3 156.9L668.2 158.4L669.3 162.4L671.4 162.8L671.6 164.6L669.1 167.1L674.2 171.5L674.3 173.9L675.9 175.7L671.9 177.1L670.8 180.3L659.4 178.5L658.3 175.1L652.0 176.4L648.6 175.5L643.1 172.6L639.2 166.3L635.9 165.8L634.9 166.9Z",
  IS:"M459.7 65.4L459.1 67.2L462.2 69.1L458.6 71.2L448.2 73.6L436.8 72.3L439.5 71.1L433.5 69.7L438.4 69.2L438.3 68.4L432.4 67.7L434.3 65.9L438.5 65.5L442.8 67.4L447.1 65.9L450.6 66.7L455.1 65.2L459.7 65.4Z",
  IT:"M529.0 119.7L533.8 119.1L538.4 120.8L538.7 123.4L534.2 123.9L535.0 127.5L542.1 133.5L544.2 133.4L544.1 134.6L551.0 137.9L550.8 139.4L546.9 137.7L545.7 139.5L547.7 140.5L547.4 141.9L543.6 144.7L544.7 141.8L542.8 138.8L531.1 132.3L528.3 128.0L524.7 126.8L520.7 128.6L521.0 127.4L519.5 127.1L518.7 124.9L519.7 124.1L519.0 122.2L524.9 122.1L525.5 121.0L528.8 120.9L529.0 119.7ZM541.0 144.0L543.1 143.8L541.9 148.3L534.5 145.5L534.9 144.1L541.0 144.0ZM524.2 136.4L525.6 135.5L527.2 137.5L526.9 141.2L524.5 141.9L522.7 136.2L524.2 136.4Z",
  JM:"M284.5 198.6L288.3 200.3L285.5 200.8L282.4 199.4L284.5 198.6Z",
  JO:"M598.7 160.0L599.2 159.1L602.3 160.2L607.8 157.3L608.9 160.7L602.8 162.5L605.6 165.3L600.2 168.9L597.0 168.1L598.7 160.0Z",
  JP:"M894.1 141.2L891.6 144.0L891.0 150.4L889.6 152.4L881.2 153.9L877.2 157.0L875.3 156.0L875.2 153.9L863.9 155.9L866.7 157.9L864.8 162.6L863.0 163.8L861.7 162.7L862.4 160.2L859.5 157.5L868.4 151.6L876.9 151.3L879.8 146.4L881.6 147.7L887.3 143.8L889.7 135.6L892.7 135.1L894.1 141.2ZM901.7 127.9L903.7 126.7L904.3 129.8L900.2 130.6L897.7 133.3L893.4 131.4L891.9 134.5L888.8 134.5L888.4 131.8L889.8 129.6L892.7 129.5L894.4 123.5L901.7 127.9ZM867.7 157.0L872.0 154.5L874.4 156.1L872.8 157.8L870.2 157.5L869.5 159.2L867.7 158.4L867.7 157.0Z",
  KE:"M608.9 263.0L604.9 260.2L604.7 258.6L594.2 252.6L594.1 249.7L597.3 244.7L594.5 238.2L598.1 234.7L599.5 235.2L600.4 237.6L605.9 240.0L609.9 240.5L613.2 238.2L616.3 239.1L613.8 242.3L613.9 252.4L615.5 254.7L611.8 257.1L608.9 263.0Z",
  KG:"M697.1 132.6L699.6 131.0L704.1 131.9L706.1 129.7L710.1 130.9L719.8 131.0L722.9 132.4L717.2 135.6L713.6 135.9L712.6 137.7L707.7 137.9L704.7 140.5L693.0 140.2L693.2 138.6L699.4 138.5L702.9 136.5L695.6 134.7L697.9 132.9L697.1 132.6Z",
  KH:"M785.0 216.1L784.3 212.8L786.1 210.5L789.7 210.0L794.6 211.4L795.8 209.5L798.3 210.5L798.9 212.4L798.6 215.7L793.9 217.9L795.1 219.6L787.5 220.5L785.0 216.1Z",
  KP:"M862.9 132.2L860.2 134.4L860.3 136.4L854.3 139.6L853.8 141.1L856.1 143.4L848.0 145.4L846.4 144.1L848.3 140.6L845.2 139.1L847.4 137.3L852.4 133.8L856.1 134.8L855.7 133.3L860.0 132.2L861.1 130.6L862.9 132.2Z",
  KR:"M850.5 145.1L856.5 142.7L859.6 147.8L858.6 152.5L851.3 154.5L850.3 148.0L852.4 147.5L850.5 145.1Z",
  KW:"M633.3 166.7L634.5 170.7L629.4 169.2L631.4 166.5L633.3 166.7Z",
  KZ:"M742.7 113.3L738.2 115.4L738.1 118.2L736.6 119.4L731.1 118.5L729.1 123.5L722.1 125.2L724.6 130.1L722.7 130.8L722.9 132.4L719.8 131.0L710.1 130.9L706.1 129.7L704.1 131.9L697.7 131.4L690.6 137.0L688.8 135.7L685.3 135.6L684.8 133.4L683.4 133.3L683.6 130.6L680.3 128.5L672.3 129.2L662.5 123.4L655.4 125.0L655.5 135.3L650.2 132.4L645.8 133.9L645.8 131.1L642.6 130.2L639.7 126.1L642.4 126.3L642.5 124.3L647.3 124.3L647.3 119.9L642.2 119.3L636.4 121.1L635.0 120.7L635.3 119.2L633.5 117.4L631.4 117.5L629.1 115.6L632.1 109.8L634.9 111.5L635.3 109.4L641.0 106.4L645.4 106.3L654.8 109.4L657.7 108.2L662.1 108.2L665.7 109.6L670.4 108.9L671.1 107.6L666.6 105.7L671.4 102.8L669.4 100.9L670.7 100.0L681.1 99.0L691.9 96.2L696.8 96.8L697.7 99.6L704.2 99.9L704.0 101.4L713.6 98.6L712.6 99.5L716.1 101.7L722.3 108.7L723.8 107.3L727.6 108.9L731.6 108.1L737.6 112.0L741.2 111.6L742.7 113.3Z",
  LA:"M798.3 210.5L795.8 209.5L794.6 211.4L792.3 210.4L793.3 206.7L788.8 199.3L783.6 199.7L780.7 201.4L781.3 195.9L779.5 195.8L778.1 193.3L781.1 190.5L782.8 191.2L782.4 188.0L783.8 187.6L786.7 192.3L790.1 192.3L791.2 194.8L788.6 196.5L791.9 198.1L798.1 205.8L798.3 210.5Z",
  LB:"M599.5 157.6L597.6 158.1L600.0 153.8L601.2 153.9L601.7 155.0L599.5 157.6Z",
  LK:"M727.2 229.1L726.8 232.0L723.2 233.4L721.4 227.2L722.6 222.7L727.2 229.1Z",
  LR:"M476.6 228.6L476.1 232.0L479.0 234.1L478.6 237.9L475.0 236.6L468.2 231.2L471.6 226.6L472.9 226.3L474.4 229.7L476.6 228.6Z",
  LS:"M580.5 330.4L581.5 331.3L578.1 334.8L575.0 333.0L578.0 330.1L580.5 330.4Z",
  LT:"M573.6 95.5L573.9 96.8L570.9 99.2L565.2 100.2L563.1 99.1L563.2 97.6L559.1 96.7L558.5 94.4L569.1 93.4L573.6 95.5Z",
  LV:"M575.8 90.3L578.3 94.0L573.6 95.5L569.1 93.4L558.5 94.4L559.9 90.5L562.6 89.6L564.8 91.6L567.0 91.6L567.5 89.5L569.9 89.0L575.8 90.3Z",
  LY:"M569.4 188.9L569.4 194.4L566.2 194.4L566.2 195.6L544.1 185.0L539.3 187.5L529.9 181.8L528.6 182.3L525.9 177.5L527.0 176.4L527.4 169.6L526.3 165.8L527.7 165.2L527.6 162.8L531.8 160.1L531.9 158.0L542.3 160.4L543.6 162.8L553.0 165.9L555.7 163.9L555.1 161.8L557.9 159.1L563.6 159.3L564.5 160.6L569.2 161.4L569.4 188.9Z",
  MA:"M494.0 152.3L496.4 160.4L489.9 162.1L489.7 164.2L485.4 166.7L475.9 169.9L475.6 174.7L468.4 175.3L465.3 181.2L461.4 184.2L459.0 190.3L452.7 190.5L459.9 177.1L464.9 172.1L467.5 171.8L473.4 166.9L472.7 163.4L476.0 157.7L480.8 155.2L483.5 150.7L494.0 152.3Z",
  MD:"M573.9 116.1L576.5 115.4L579.6 116.3L583.4 121.0L580.2 121.0L578.4 123.6L578.1 120.0L573.9 116.1Z",
  ME:"M555.8 131.7L554.8 131.4L553.8 133.7L551.3 132.0L553.4 129.1L556.5 130.8L555.8 131.7Z",
  MG:"M637.6 284.6L639.9 293.6L639.4 294.4L638.5 292.8L638.0 293.6L638.3 296.9L630.8 319.3L626.1 321.1L622.3 319.4L620.4 313.3L620.6 309.3L621.9 308.8L623.5 304.0L622.1 298.4L623.5 295.0L628.6 293.8L632.5 290.5L633.0 288.0L634.1 288.3L636.7 283.4L637.6 284.6Z",
  MK:"M562.2 132.4L563.8 135.2L557.2 135.9L557.7 133.2L562.2 132.4Z",
  ML:"M468.0 215.4L466.2 209.4L467.6 207.3L484.6 206.9L485.2 205.0L482.1 180.7L486.3 180.6L508.7 195.3L508.8 197.1L511.9 196.8L511.9 203.2L510.1 206.8L497.0 208.4L491.4 212.4L488.9 212.6L485.5 217.5L485.0 221.2L477.7 221.6L474.6 215.8L471.8 217.1L468.2 216.5L468.0 215.4Z",
  MM:"M778.1 193.3L772.9 195.3L770.5 198.8L774.7 205.1L772.8 208.0L775.3 211.6L776.6 217.0L773.8 222.4L773.6 213.5L769.9 203.0L764.9 206.3L761.6 205.5L762.0 199.4L760.2 195.2L756.6 192.6L756.4 190.3L757.4 190.8L757.4 188.8L758.8 188.1L759.2 183.1L761.4 183.7L764.2 176.2L767.8 174.3L769.8 174.8L770.4 171.5L772.0 171.3L774.1 173.6L774.1 178.0L771.5 180.3L771.1 183.6L774.1 183.2L774.7 185.7L776.5 186.3L775.7 188.6L778.9 190.1L781.0 189.3L778.1 193.3Z",
  MN:"M743.8 113.1L756.2 108.9L770.2 111.9L772.9 109.9L771.7 108.3L774.6 105.4L783.5 107.6L784.0 109.7L788.0 110.9L796.9 110.3L801.3 113.1L807.4 113.5L817.7 110.4L824.1 111.4L820.8 116.3L821.5 117.4L828.0 116.5L832.7 119.3L832.4 120.3L826.2 120.4L815.2 125.5L810.8 124.7L809.3 126.5L810.6 128.5L806.7 130.9L791.6 134.5L780.1 131.5L767.6 131.3L764.7 127.1L759.7 125.1L752.6 124.2L751.6 123.0L752.7 119.8L750.8 117.5L744.5 115.0L743.8 113.1Z",
  MR:"M452.6 191.7L453.2 190.7L464.1 190.8L464.2 185.3L466.8 185.1L466.8 178.0L475.9 178.1L475.9 173.9L486.3 180.6L482.1 180.7L485.2 205.0L484.6 206.9L467.6 207.3L466.2 209.4L462.7 205.4L459.5 203.9L454.3 205.2L454.8 194.2L452.6 191.7Z",
  MW:"M591.0 275.6L593.7 276.2L595.2 278.2L596.0 287.7L599.1 290.6L599.4 294.2L597.3 296.7L595.5 295.0L595.7 290.6L590.8 288.1L592.5 284.5L593.0 279.2L591.0 275.6Z",
  MX:"M174.6 159.6L181.3 159.1L191.6 163.0L204.1 161.8L211.3 168.7L213.6 169.5L215.3 167.3L217.6 167.3L223.6 173.5L224.9 176.8L230.2 178.1L228.1 187.7L233.6 197.7L237.7 199.6L246.1 197.6L247.9 196.4L249.2 191.7L258.2 190.2L258.8 192.1L256.6 195.4L256.0 199.3L254.2 198.6L253.2 200.3L247.2 200.5L247.2 202.1L246.0 202.1L248.7 205.4L245.1 205.4L243.8 209.6L239.2 205.7L237.0 205.0L231.8 206.5L212.5 199.2L207.0 194.6L206.3 193.2L207.6 190.5L205.5 186.7L196.5 178.9L196.4 176.5L193.4 174.5L192.7 172.6L188.3 169.6L185.7 163.4L181.2 161.7L180.7 162.8L181.5 166.2L190.0 175.9L192.6 182.5L196.1 185.1L194.8 186.6L188.4 181.3L188.1 177.7L180.4 173.0L181.7 172.9L182.9 170.6L179.1 167.9L174.6 159.6Z",
  MY:"M778.0 232.0L780.8 232.8L781.0 234.2L783.7 232.7L786.0 234.7L789.5 246.4L787.6 246.6L781.6 242.3L778.0 232.0ZM827.5 238.5L821.8 238.0L818.4 246.0L813.5 245.8L807.0 247.9L805.1 246.3L804.6 244.4L808.8 244.9L809.4 242.5L813.9 241.4L817.2 237.4L818.5 238.9L820.4 238.0L820.7 234.9L824.2 230.8L826.9 233.4L831.1 235.0L827.5 238.5Z",
  MZ:"M596.0 282.0L604.1 282.1L612.0 278.7L613.3 290.8L609.6 296.4L603.9 298.9L596.6 305.0L596.4 306.9L598.8 311.4L598.5 317.0L591.7 320.4L590.5 321.5L591.2 324.3L589.1 324.3L588.7 317.7L586.6 311.8L590.7 306.4L591.2 296.4L584.3 294.1L583.8 291.1L592.3 288.8L595.7 290.6L595.5 295.0L597.3 296.7L599.4 294.2L599.1 290.6L596.0 287.7L596.0 282.0Z",
  NA:"M555.3 318.8L555.3 329.1L551.3 330.7L548.3 330.0L546.7 328.0L545.4 329.4L542.3 325.3L539.6 311.4L532.8 300.2L532.6 298.1L537.4 297.1L539.1 298.4L550.7 298.1L552.7 299.4L559.4 299.8L566.8 298.0L569.7 298.8L565.5 300.8L564.4 299.6L558.1 300.7L558.0 310.6L555.3 310.7L555.3 318.8Z",
  NC:"M960.5 308.6L964.2 311.6L963.2 312.2L959.7 310.2L955.6 305.8L960.5 308.6Z",
  NE:"M541.3 186.5L541.9 190.8L544.2 193.4L542.4 203.8L538.8 206.4L537.6 210.1L538.8 212.9L540.5 213.0L539.4 215.3L536.3 212.2L534.2 213.8L530.5 212.8L525.0 214.4L521.7 212.9L518.9 213.6L515.1 211.5L511.4 212.4L510.0 217.6L507.9 216.0L506.0 216.8L506.0 214.9L502.8 214.3L501.0 208.5L510.1 206.8L511.9 203.2L511.9 196.8L515.8 195.6L533.3 184.8L539.3 187.5L541.3 186.5Z",
  NG:"M507.5 232.6L507.6 226.4L510.3 222.0L510.2 215.1L512.1 211.8L515.1 211.5L518.9 213.6L521.7 212.9L525.0 214.4L530.5 212.8L534.2 213.8L536.3 212.2L540.5 216.4L532.6 230.6L530.7 231.5L528.1 230.4L525.6 232.1L523.6 236.7L516.4 238.2L512.0 232.6L507.5 232.6Z",
  NI:"M267.6 219.6L261.9 219.2L256.5 214.1L259.1 213.2L259.0 211.8L261.7 211.6L264.1 208.9L269.0 208.3L267.6 219.6Z",
  NL:"M519.2 101.4L519.0 104.9L516.6 106.0L517.1 108.9L513.8 107.0L509.2 107.4L513.1 102.5L519.2 101.4Z",
  NO:"M542.1 28.7L547.2 27.6L559.8 30.7L552.9 31.8L551.3 33.8L548.9 34.3L547.6 36.6L544.2 36.7L538.2 35.1L540.7 34.1L531.2 30.9L529.0 28.7L536.6 27.7L542.1 28.7ZM586.4 56.8L579.4 58.2L580.6 56.2L577.0 55.1L572.7 56.0L568.7 59.3L562.1 58.8L559.0 57.3L555.6 58.2L555.2 60.0L550.0 59.5L549.2 61.1L546.6 61.1L537.7 70.0L538.7 71.0L537.7 72.1L534.9 72.0L533.1 74.6L533.3 78.3L535.1 79.7L534.2 83.0L530.6 86.5L528.8 84.8L523.3 88.0L519.6 88.7L515.7 87.3L513.9 77.9L529.2 70.9L541.0 61.6L553.3 56.1L564.0 55.0L568.2 52.7L578.2 52.3L586.9 54.3L583.3 55.0L586.4 56.8ZM576.1 27.6L572.0 29.1L564.0 29.4L555.8 29.0L548.2 26.9L563.7 26.0L576.1 27.6ZM568.7 33.7L562.5 34.9L557.6 34.2L559.5 33.5L557.8 32.6L563.6 32.1L568.7 33.7Z",
  NP:"M744.8 172.6L744.6 176.6L742.3 176.7L731.4 174.0L722.5 170.0L723.5 167.4L726.5 165.5L738.4 171.7L744.8 172.6Z",
  NZ:"M991.3 361.3L988.9 364.7L986.8 365.8L985.1 364.7L986.7 362.4L982.8 359.7L984.9 357.8L985.3 353.8L979.5 345.9L984.2 348.0L987.0 353.4L987.1 351.5L988.4 352.2L988.8 354.3L992.9 355.4L995.9 354.7L994.4 358.8L992.2 358.7L991.3 361.3ZM971.3 371.0L980.0 362.5L981.2 364.8L983.2 363.7L984.0 364.9L979.8 370.5L980.8 371.8L976.3 372.9L973.9 377.5L970.4 379.6L963.0 378.4L964.0 375.3L971.3 371.0Z",
  OM:"M653.4 186.9L654.2 183.5L655.5 183.0L655.2 180.8L656.7 180.8L659.5 183.7L663.1 184.5L666.1 188.0L662.5 193.3L660.6 193.8L660.3 197.4L657.2 198.4L656.3 200.3L654.6 200.3L652.2 202.9L647.5 203.7L644.4 197.2L652.8 194.4L654.6 188.9L653.4 186.9Z",
  PA:"M285.1 225.9L285.4 228.0L283.7 229.9L282.1 227.6L282.8 226.9L280.2 225.0L276.7 226.9L277.8 229.0L275.3 229.9L273.0 227.5L269.9 227.6L269.6 223.7L273.8 225.6L280.5 223.5L285.1 225.9Z",
  PE:"M305.9 261.9L303.3 261.8L297.5 264.7L296.9 268.4L294.5 270.9L297.2 275.1L296.6 276.3L299.5 277.9L301.9 278.0L304.2 276.4L304.0 280.6L306.9 280.4L309.3 284.9L307.4 291.5L308.4 295.8L304.5 301.0L288.9 290.7L278.4 270.0L274.3 267.0L275.2 265.8L273.9 263.2L276.9 259.5L276.5 262.3L278.8 262.4L280.0 263.8L281.6 262.6L283.8 258.3L287.1 257.2L290.2 254.3L291.4 250.2L297.0 256.4L303.3 256.3L305.4 257.6L303.6 260.4L305.9 261.9Z",
  PG:"M891.7 257.2L901.6 260.7L905.5 265.2L910.1 266.9L910.8 268.4L908.3 268.7L908.9 270.5L913.2 275.3L914.7 275.2L914.6 276.4L918.9 278.6L918.6 279.4L910.9 278.1L905.7 272.4L902.1 271.2L898.0 272.9L898.4 275.0L896.2 275.9L891.8 275.3L891.7 257.2ZM924.0 260.2L925.4 262.5L924.5 263.2L923.4 260.5L918.5 257.6L919.3 256.9L924.0 260.2ZM920.3 266.2L915.9 267.5L912.0 266.0L912.2 265.1L916.2 265.3L917.1 263.9L917.3 265.4L918.9 265.2L921.2 263.2L920.9 261.6L922.6 261.5L923.1 263.5L920.3 266.2ZM929.9 264.8L933.0 268.9L931.0 268.2L929.2 264.3L929.9 264.8Z",
  PH:"M835.6 214.7L834.2 212.6L837.6 213.7L836.8 216.1L835.6 214.7ZM840.5 222.3L841.5 219.8L843.1 219.6L842.6 221.5L844.7 218.8L844.4 221.4L841.7 224.9L839.9 223.0L840.5 222.3ZM851.0 226.6L851.5 230.0L850.5 232.6L849.5 229.7L848.2 231.1L849.1 233.2L848.3 234.5L845.1 232.9L844.3 230.9L845.1 229.6L843.4 228.2L839.1 230.8L838.7 230.0L839.8 227.7L843.0 225.9L844.0 227.1L848.5 225.0L848.4 222.9L850.6 224.2L851.0 226.6ZM829.2 224.1L825.5 226.8L832.0 218.4L832.5 220.7L829.2 224.1ZM839.8 199.4L840.3 202.5L838.0 205.7L838.1 210.2L844.3 211.7L844.7 215.2L841.5 212.4L840.8 213.4L839.0 211.7L835.1 211.5L836.1 209.7L835.3 209.0L834.9 210.0L833.1 207.2L835.3 198.6L839.8 199.4ZM839.0 218.3L838.6 217.0L842.0 217.8L838.9 221.0L839.0 218.3ZM848.6 216.2L849.4 219.3L847.3 218.6L848.0 221.2L846.7 221.8L845.3 218.1L846.9 218.3L846.9 217.2L845.2 215.1L848.6 216.2Z",
  PK:"M716.2 151.4L713.5 153.7L706.2 153.5L704.9 154.7L706.8 159.0L709.1 160.4L706.7 162.0L706.7 163.9L699.4 172.5L696.2 172.3L693.1 175.2L694.9 176.4L697.3 182.3L691.2 182.3L689.4 184.2L687.3 183.5L684.4 179.4L670.8 180.3L671.9 177.1L675.9 175.7L674.3 173.9L674.2 171.5L669.1 167.1L673.7 168.6L684.3 167.0L684.4 164.6L685.9 163.0L692.5 161.4L692.4 159.7L695.3 157.3L694.3 155.5L696.9 155.6L698.9 152.4L698.0 149.8L699.6 148.6L708.8 146.9L711.6 150.3L716.2 151.4Z",
  PL:"M565.2 100.2L566.1 103.6L564.4 104.2L566.7 109.2L562.6 112.6L563.3 113.8L560.0 112.6L555.1 113.3L548.8 110.1L544.9 109.9L541.7 108.0L539.1 102.8L539.2 100.7L549.0 97.6L551.9 98.8L563.1 99.1L565.2 100.2Z",
  PR:"M315.9 198.6L317.8 199.4L313.4 200.1L313.6 198.6L315.9 198.6Z",
  PS:"M598.3 162.5L597.0 162.9L597.7 159.6L598.7 160.0L598.3 162.5Z",
  PT:"M474.9 133.7L477.0 132.6L477.7 133.9L481.5 133.7L482.3 135.1L481.0 135.8L480.4 139.7L479.2 139.9L480.5 144.2L478.2 147.7L475.3 147.6L475.4 143.7L473.5 142.4L475.6 136.8L474.9 133.7Z",
  PY:"M338.4 306.0L339.1 311.4L345.0 312.1L346.1 316.5L349.2 316.7L347.8 323.9L345.3 326.1L337.2 325.3L339.9 321.1L339.5 319.9L331.0 316.3L325.9 311.8L328.4 304.5L335.8 303.8L338.4 306.0Z",
  QA:"M641.1 181.2L641.0 179.2L642.5 177.5L643.4 180.0L642.7 181.6L641.1 181.2Z",
  RO:"M578.4 123.6L582.2 124.2L580.1 125.2L579.3 128.6L575.7 127.3L571.0 128.6L563.7 128.3L563.1 126.2L559.9 125.6L556.2 121.9L558.4 121.3L561.4 117.6L564.3 116.4L569.1 117.4L573.9 116.1L578.1 120.0L578.4 123.6Z",
  RS:"M552.3 122.5L556.2 121.9L559.9 125.6L563.1 126.2L562.3 127.8L563.9 130.0L562.6 132.1L559.9 132.7L560.5 131.4L557.8 129.8L556.3 131.1L553.4 129.1L554.4 127.7L553.1 126.6L553.9 124.3L552.3 122.5Z",
  RU:"M996.5 52.5L1000.0 51.3L1000.0 53.2L996.5 52.5ZM636.4 121.1L629.7 126.1L635.0 133.9L632.8 135.7L626.3 131.9L611.0 129.3L601.9 124.3L606.2 121.6L604.6 120.5L608.7 119.3L606.2 119.2L606.3 117.9L610.4 116.9L611.3 112.2L598.2 109.5L597.3 107.8L595.1 107.6L595.5 106.2L593.8 104.6L588.3 105.3L587.0 102.6L590.8 101.8L585.4 97.7L585.8 95.7L578.3 94.0L575.8 90.3L577.0 89.5L576.2 86.9L580.9 83.3L578.0 81.9L587.5 75.4L583.4 73.5L584.6 71.7L582.1 69.6L583.9 67.2L580.7 64.0L583.3 61.9L579.0 60.1L579.4 58.2L589.3 55.8L601.4 58.2L614.1 62.6L614.2 64.5L606.6 66.7L592.2 64.9L596.7 66.9L597.1 71.1L602.8 72.6L603.2 71.3L601.5 70.1L603.3 69.0L610.0 70.8L612.3 70.1L610.5 68.1L616.9 65.3L622.1 66.5L623.7 64.6L621.4 62.9L622.7 61.2L620.7 59.5L628.5 60.4L630.1 62.0L626.5 62.3L626.6 63.9L628.7 64.8L633.0 64.2L633.7 62.4L649.2 58.7L651.3 58.9L648.6 60.6L663.3 58.7L666.5 60.3L669.7 58.5L666.8 56.9L668.2 56.0L676.4 56.8L690.3 60.9L692.2 59.4L689.3 57.3L685.9 57.1L686.8 55.8L685.3 52.7L694.3 47.1L701.6 47.8L702.2 49.4L699.6 51.6L702.2 54.5L701.6 58.3L704.6 60.0L698.0 65.8L701.2 66.2L708.5 61.8L706.9 60.2L708.2 58.4L705.1 58.1L704.4 56.6L706.7 53.8L703.1 51.5L708.0 49.7L707.4 47.7L710.2 49.2L709.1 51.8L712.1 52.4L710.8 50.3L715.5 49.3L721.3 49.1L726.4 50.7L723.9 48.4L723.6 45.4L741.2 44.6L738.9 43.2L742.1 41.3L759.0 38.8L768.6 39.1L779.9 37.7L783.3 35.3L789.9 34.2L794.6 35.1L790.8 35.8L797.1 36.2L797.9 37.6L808.5 36.9L817.0 39.3L816.3 40.8L803.9 43.9L813.9 44.5L815.4 46.3L821.0 45.1L842.2 47.3L842.4 45.2L852.7 45.7L857.2 47.1L858.5 48.9L856.8 50.1L864.7 53.4L867.4 50.5L871.8 51.7L888.5 51.4L886.5 48.8L890.2 47.6L915.3 49.4L924.9 53.2L941.7 53.1L944.0 54.3L943.6 56.3L947.1 57.1L966.2 56.7L971.0 59.2L974.5 58.3L972.2 56.5L973.5 55.3L988.1 55.9L1000.0 58.4L1000.0 69.5L992.8 70.5L998.3 75.0L997.9 76.9L992.7 76.3L982.4 78.7L973.1 83.7L969.2 81.7L961.9 83.9L960.7 82.9L958.0 84.1L954.3 83.7L950.0 88.2L950.1 89.3L953.3 90.0L952.9 94.0L950.4 94.1L949.2 96.4L950.3 97.6L945.5 99.0L944.5 102.2L940.4 102.9L939.5 105.7L935.5 108.3L931.8 96.2L933.1 92.3L935.6 89.4L939.9 88.7L954.6 80.2L956.9 76.2L953.5 76.5L951.8 78.8L944.8 81.8L942.5 78.4L935.3 79.3L928.4 84.0L930.7 85.7L920.2 86.7L920.4 84.7L916.1 84.3L912.6 85.7L895.0 86.0L875.4 98.0L879.7 98.3L881.1 100.1L883.8 100.7L885.6 99.3L888.6 99.5L892.6 102.5L889.1 115.4L874.6 129.4L870.9 131.1L867.4 129.8L863.3 132.7L862.9 130.8L864.3 130.8L864.7 127.5L864.0 125.1L869.7 124.6L875.1 115.3L863.9 117.2L862.7 114.6L859.4 112.7L854.6 111.8L849.9 103.4L843.3 101.5L836.1 102.1L833.8 103.5L835.3 104.1L835.4 105.7L831.4 110.7L827.4 112.5L817.7 110.4L807.4 113.5L801.3 113.1L796.9 110.3L788.0 110.9L784.0 109.7L783.5 107.6L774.6 105.4L771.7 108.3L772.9 109.9L770.2 111.9L756.2 108.9L742.7 113.3L741.2 111.6L737.6 112.0L731.6 108.1L727.6 108.9L723.8 107.3L722.3 108.7L716.1 101.7L712.6 99.5L713.6 98.6L704.0 101.4L704.2 99.9L697.7 99.6L696.8 96.8L691.9 96.2L681.1 99.0L670.7 100.0L669.4 100.9L671.4 102.8L666.6 105.7L671.1 107.6L670.4 108.9L665.7 109.6L662.1 108.2L657.7 108.2L654.8 109.4L645.4 106.3L641.0 106.4L635.3 109.4L634.9 111.5L632.1 109.8L629.1 115.6L631.4 117.5L633.5 117.4L635.3 119.2L635.0 120.7L636.4 121.1ZM760.5 24.9L766.5 24.3L778.3 28.4L777.6 30.9L771.5 31.2L759.2 29.4L757.1 27.4L753.3 26.8L760.5 24.9ZM785.7 29.8L792.7 31.4L791.9 32.5L776.2 33.6L781.3 29.9L785.7 29.8ZM885.6 38.5L903.0 40.1L900.8 42.2L886.0 42.7L880.5 40.9L882.0 39.0L885.6 38.5ZM911.7 40.7L918.7 41.4L915.5 42.5L905.9 41.2L906.6 40.3L911.7 40.7ZM888.5 46.2L894.6 44.8L898.9 46.6L888.5 46.2ZM624.6 26.1L643.1 25.8L632.2 27.7L629.2 27.1L630.8 26.2L624.6 26.1ZM563.1 99.1L554.6 98.8L555.2 97.6L559.1 96.7L563.2 97.6L563.1 99.1ZM648.6 45.1L655.3 42.7L654.5 41.4L669.9 38.2L689.3 36.3L691.3 37.4L662.4 43.6L653.9 49.0L654.5 51.3L659.8 53.6L649.1 53.4L648.4 52.2L643.3 51.5L642.9 50.0L645.8 49.4L645.7 47.8L651.2 45.5L648.6 45.1ZM897.0 100.8L897.9 106.2L901.8 114.0L897.7 113.0L896.0 117.1L898.7 119.9L898.6 121.8L896.5 120.2L894.7 122.3L894.9 108.5L893.3 105.7L893.6 101.9L896.1 100.7L895.0 99.4L896.3 99.0L897.0 100.8ZM14.1 63.3L13.8 65.0L15.7 65.7L15.1 63.7L22.6 64.1L28.1 66.7L20.7 68.2L20.7 70.9L19.6 71.5L11.2 69.7L10.5 68.5L4.6 68.4L3.0 67.4L3.6 66.4L0.3 67.0L1.6 68.3L0.0 69.5L0.0 58.4L14.1 63.3ZM3.6 53.1L0.0 53.2L0.0 51.3L6.7 52.0L3.6 53.1ZM592.9 122.3L601.5 123.7L594.1 126.8L592.6 126.2L593.2 124.9L590.2 124.1L592.9 122.3Z",
  RW:"M584.5 253.2L585.4 256.4L580.6 257.9L581.4 254.5L584.5 253.2Z",
  SA:"M597.1 168.5L600.2 168.9L604.2 166.7L605.6 165.3L602.8 162.5L608.9 160.7L616.4 163.4L624.2 168.9L631.8 169.4L639.3 175.9L639.6 178.9L642.7 181.6L644.4 186.1L653.4 186.9L654.6 188.9L652.8 194.4L636.4 198.3L630.6 202.9L620.5 201.2L618.8 204.6L613.7 195.9L608.7 190.9L606.9 184.2L604.1 182.5L597.6 172.0L596.2 172.1L597.1 168.5Z",
  SB:"M950.3 279.1L951.1 280.1L949.2 280.1L948.1 278.3L950.3 279.1ZM946.8 277.4L944.0 277.2L943.6 275.7L946.8 277.4ZM943.4 272.3L944.2 273.7L939.5 270.6L943.4 272.3Z",
  SD:"M568.2 227.1L565.2 225.1L565.4 222.0L561.9 214.9L560.9 215.0L564.0 206.4L566.4 206.6L566.2 194.4L569.4 194.4L569.4 188.9L602.4 188.9L604.1 198.3L606.7 200.0L602.4 202.9L600.8 212.3L595.2 220.5L594.4 225.9L593.7 221.3L592.2 220.2L592.2 216.2L591.0 216.0L589.1 216.7L590.0 219.2L587.1 222.7L583.3 221.4L580.5 223.9L574.3 223.7L571.6 221.1L569.6 221.5L568.2 225.2L566.4 226.1L568.2 227.1Z",
  SE:"M530.6 86.5L534.2 83.0L535.1 79.7L533.3 78.3L533.1 74.6L534.9 72.0L537.7 72.1L538.7 71.0L537.7 70.0L546.6 61.1L549.2 61.1L550.0 59.5L555.2 60.0L555.6 58.2L557.3 58.0L565.4 61.3L566.4 66.6L561.6 67.4L558.9 69.4L559.4 71.1L549.6 75.7L547.6 79.6L552.2 83.1L549.6 86.2L546.7 86.9L544.1 94.2L540.7 93.9L539.2 96.1L536.0 96.2L530.6 86.5Z",
  SI:"M538.4 120.8L545.0 119.9L546.0 120.8L543.8 121.6L542.6 123.7L538.1 123.6L538.4 120.8Z",
  SK:"M562.7 113.7L560.8 115.8L557.8 114.9L549.6 117.3L546.9 115.4L551.5 112.5L562.7 113.7Z",
  SL:"M463.2 225.3L465.5 222.7L469.1 222.1L471.6 226.6L468.2 231.2L464.0 228.3L463.2 225.3Z",
  SN:"M453.6 212.2L451.0 209.1L455.2 204.3L459.5 203.9L462.7 205.4L466.2 209.4L468.0 215.4L453.7 215.6L453.2 213.5L461.5 212.5L458.1 211.5L453.6 212.2Z",
  SO:"M615.5 254.7L613.9 252.4L613.8 242.3L617.0 238.2L621.3 236.2L624.9 236.1L635.9 223.7L636.0 218.3L642.0 216.6L640.4 224.4L635.0 235.2L629.3 242.1L619.8 249.2L615.5 254.7Z",
  SR:"M348.5 243.6L344.5 243.0L344.5 245.0L342.9 244.7L340.0 240.7L338.8 238.7L341.3 233.4L350.1 234.0L348.7 236.4L350.0 239.9L348.5 243.6Z",
  SS:"M585.6 240.3L582.5 237.2L577.7 237.8L569.8 228.3L566.4 226.1L568.2 225.2L569.6 221.5L571.6 221.1L574.3 223.7L580.5 223.9L583.3 221.4L587.1 222.7L590.0 219.2L589.1 216.7L592.2 216.2L592.2 220.2L593.7 221.3L594.4 225.9L591.5 228.4L594.7 229.9L598.1 234.7L592.8 239.5L585.6 240.3Z",
  SV:"M251.8 209.9L256.3 211.7L255.8 213.5L249.7 211.8L251.8 209.9Z",
  SY:"M599.2 159.1L601.7 155.0L600.0 153.8L599.7 151.6L602.1 147.7L609.8 148.0L617.6 146.6L614.7 149.0L613.9 154.4L602.3 160.2L599.2 159.1Z",
  SZ:"M589.1 324.3L586.9 325.8L585.2 324.3L586.2 321.5L588.4 321.8L589.1 324.3Z",
  TD:"M566.2 195.6L566.4 206.6L564.0 206.4L560.9 215.0L561.9 214.9L563.5 219.0L560.3 220.6L558.3 223.7L552.3 225.0L552.5 226.0L549.9 228.1L542.4 229.4L541.6 225.6L538.8 223.5L539.4 222.2L543.0 222.3L541.5 219.7L540.5 213.0L538.8 212.9L537.6 210.1L538.8 206.4L542.4 203.8L544.2 193.4L541.9 190.8L541.3 186.5L544.1 185.0L566.2 195.6Z",
  TF:"M691.5 385.1L696.0 386.8L695.2 388.1L691.0 388.3L691.5 385.1Z",
  TG:"M502.5 219.5L502.1 220.9L504.6 224.6L505.2 232.9L502.9 233.5L501.6 230.8L501.0 221.7L499.9 220.3L502.5 219.5Z",
  TH:"M792.3 210.4L786.1 210.5L784.3 212.8L785.0 216.1L780.1 214.9L780.5 212.7L778.0 212.8L775.6 224.3L777.4 224.4L779.1 229.4L783.7 232.7L781.0 234.2L780.8 232.8L778.0 232.0L772.6 226.8L776.6 217.0L775.3 211.6L772.8 208.0L774.7 205.1L770.5 198.8L772.9 195.3L778.1 193.3L779.5 195.8L781.3 195.9L780.7 201.4L786.7 199.1L788.8 199.3L790.9 201.6L791.1 204.3L793.3 206.7L792.3 210.4Z",
  TJ:"M688.4 146.8L690.0 144.0L689.4 141.9L687.3 141.3L688.1 140.1L690.4 140.2L692.6 136.9L696.3 136.2L695.7 137.5L697.3 138.2L693.2 138.6L693.0 140.2L704.7 140.5L705.4 143.0L708.0 143.4L708.3 146.1L703.5 145.8L699.6 147.9L698.2 143.7L696.7 143.1L692.2 146.8L688.4 146.8Z",
  TL:"M847.1 274.7L853.7 273.3L847.5 276.1L847.1 274.7Z",
  TM:"M645.8 133.9L650.2 132.4L654.0 135.4L658.6 135.2L658.1 133.8L662.9 131.2L666.6 132.7L668.0 135.5L671.9 135.9L673.3 138.7L678.3 142.0L684.9 144.5L684.8 146.2L682.6 145.4L679.9 146.9L679.3 149.1L672.9 152.0L670.0 151.0L669.8 148.6L659.3 144.4L654.2 144.5L649.8 146.7L649.7 141.8L647.5 140.9L648.2 139.0L646.4 138.8L647.0 136.5L652.0 136.2L649.2 133.0L647.0 133.7L646.7 135.7L645.8 133.9Z",
  TN:"M526.3 165.8L525.2 160.8L521.1 157.4L520.9 155.3L522.6 153.7L523.4 147.4L526.4 146.3L528.4 146.6L528.3 148.0L530.6 147.0L529.4 148.9L530.0 153.2L528.2 154.6L531.9 158.0L531.8 160.1L527.6 162.8L527.7 165.2L526.3 165.8Z",
  TR:"M624.4 146.7L618.8 146.2L609.8 148.0L602.1 147.7L600.4 150.5L599.4 149.2L600.4 148.2L596.4 147.8L594.5 149.4L590.3 149.7L585.1 148.1L582.5 149.6L576.8 148.2L573.1 143.9L574.5 141.7L572.7 140.4L575.8 137.7L580.1 137.6L581.2 135.5L586.5 135.9L593.1 133.3L597.7 133.2L606.5 136.3L618.4 134.5L621.1 135.9L621.3 138.2L624.4 139.7L622.5 140.5L622.8 144.5L624.4 146.7ZM572.5 133.8L577.8 133.3L580.5 135.3L573.2 138.5L572.4 136.6L573.9 134.5L572.5 133.8Z",
  TT:"M328.7 220.1L330.8 219.8L330.7 221.9L327.9 222.0L328.7 220.1Z",
  TW:"M838.3 182.2L835.4 189.0L833.6 184.6L837.5 179.7L838.8 180.6L838.3 182.2Z",
  TZ:"M594.2 252.6L604.7 258.6L604.9 260.2L608.9 263.0L607.6 266.4L607.8 268.0L609.6 269.0L608.9 273.6L612.0 278.7L609.8 280.3L601.4 282.6L596.0 282.0L593.7 276.2L585.4 273.2L582.3 268.1L581.5 262.5L585.4 259.3L584.6 256.7L585.6 254.7L584.5 253.2L594.2 252.6Z",
  UA:"M588.3 105.3L593.8 104.6L595.5 106.2L595.1 107.6L597.3 107.8L598.2 109.5L611.3 112.2L610.4 116.9L597.1 121.5L597.3 123.0L588.2 121.3L588.0 120.3L585.4 120.6L582.2 124.2L579.7 124.2L578.4 123.6L580.2 121.0L583.4 121.0L579.6 116.3L576.5 115.4L569.1 117.4L563.1 117.0L561.3 115.5L563.3 113.8L562.6 112.6L566.5 109.9L565.4 106.7L570.4 105.8L584.9 107.4L585.9 105.4L588.3 105.3Z",
  UG:"M594.2 252.6L582.2 253.7L583.0 248.3L586.6 243.9L585.5 243.5L585.6 240.3L586.8 239.5L592.8 239.5L594.5 238.2L595.8 240.1L597.3 244.7L594.1 249.7L594.2 252.6Z",
  US:"M158.8 113.9L235.7 113.9L236.6 112.8L238.0 114.8L245.4 116.3L254.5 115.8L264.2 119.7L270.7 124.0L271.8 129.0L269.1 133.1L270.3 134.2L280.7 130.9L280.1 129.3L281.3 128.8L286.6 128.8L292.0 125.0L301.4 125.0L303.7 123.7L307.7 118.2L311.7 119.3L311.7 123.0L314.0 125.5L305.2 128.7L303.3 132.4L305.7 134.3L295.2 136.3L300.2 136.3L294.6 136.8L291.9 141.8L290.2 140.3L291.5 143.3L289.1 146.6L289.7 144.6L287.9 141.3L288.0 144.2L286.1 143.8L288.1 144.7L289.6 151.2L287.9 153.3L280.4 157.0L274.1 162.7L274.1 166.6L277.6 175.3L276.7 180.0L274.5 180.0L273.0 178.1L269.8 172.5L270.4 170.7L267.5 166.8L263.6 167.7L260.0 165.6L251.1 166.2L251.6 169.0L241.0 167.3L237.0 168.1L230.2 172.7L230.2 178.1L229.1 178.2L224.9 176.8L219.6 168.4L215.3 167.3L213.6 169.5L211.3 168.7L204.1 161.8L191.6 163.0L181.3 159.1L174.6 159.6L170.8 155.5L164.9 153.9L154.4 138.0L154.1 131.2L155.8 123.5L153.6 116.2L158.0 116.6L159.5 119.2L158.8 113.9ZM68.3 194.2L70.0 195.8L67.5 197.5L66.5 195.3L67.1 193.7L68.3 194.2ZM37.6 82.3L39.8 82.5L40.1 83.6L34.8 82.7L37.6 82.3ZM74.4 89.0L77.4 90.0L72.2 92.4L70.8 91.7L70.4 90.4L74.4 89.0ZM108.4 56.4L108.3 82.5L113.8 83.3L118.2 86.4L123.7 83.9L129.6 87.7L134.1 92.9L138.9 94.7L138.9 96.4L137.4 97.8L133.4 95.8L132.6 93.4L129.1 91.2L127.6 88.5L120.5 88.3L111.5 84.6L100.1 83.3L91.3 80.9L88.3 81.5L88.8 83.4L78.6 85.7L79.4 81.3L82.4 80.5L81.6 79.8L72.2 85.1L74.2 86.5L71.6 88.5L65.8 90.5L59.9 94.5L41.8 98.4L59.2 91.6L61.9 90.1L63.8 86.3L58.2 87.7L54.6 85.9L50.1 87.0L50.3 84.4L48.6 83.4L44.9 83.9L40.7 81.9L40.7 80.4L38.6 79.2L39.6 77.6L42.9 74.6L47.0 74.8L53.4 72.9L51.3 71.1L53.4 70.0L41.8 71.0L37.7 70.3L33.0 67.6L43.1 65.1L45.4 65.1L45.0 66.5L50.9 66.3L36.8 60.1L38.3 58.7L43.2 58.6L50.3 54.6L65.1 51.8L71.3 53.6L77.2 53.3L108.4 56.4ZM23.0 72.8L31.4 74.2L29.1 75.1L23.5 74.1L23.0 72.8Z",
  UY:"M339.9 333.9L341.7 333.6L350.6 339.0L352.2 340.9L350.5 345.5L347.4 347.1L343.8 346.8L337.7 344.2L339.9 333.9Z",
  UZ:"M655.5 135.3L655.4 125.0L662.5 123.4L672.3 129.2L680.3 128.5L683.6 130.6L683.4 133.3L684.8 133.4L685.3 135.6L688.8 135.7L689.6 137.0L697.1 132.6L697.9 132.9L695.6 134.7L702.9 136.5L699.4 138.5L696.1 138.3L696.3 136.2L692.6 136.9L690.4 140.2L688.1 140.1L687.3 141.3L689.4 141.9L690.0 144.0L688.4 146.8L684.8 146.2L684.9 144.5L678.3 142.0L673.3 138.7L671.9 135.9L668.0 135.5L666.6 132.7L662.9 131.2L658.1 133.8L658.6 135.2L655.5 135.3Z",
  VE:"M331.3 235.6L330.6 237.4L324.7 239.5L320.0 238.7L321.2 239.5L321.5 243.1L324.0 243.9L317.9 247.8L315.8 248.0L311.6 242.2L313.0 240.8L311.6 237.5L312.9 233.1L307.3 233.1L305.3 230.7L300.1 230.6L298.8 229.4L297.8 224.8L296.4 224.6L297.5 221.0L301.9 217.3L300.1 218.3L301.0 221.0L299.8 222.6L300.8 224.8L302.0 224.6L301.7 219.5L305.1 218.4L305.7 216.2L310.6 220.7L316.0 220.4L319.7 222.0L321.3 220.4L328.1 220.2L325.7 221.1L331.0 223.9L331.5 226.2L334.0 226.8L331.8 228.4L332.5 230.4L330.1 231.4L329.4 233.4L331.3 235.6Z",
  VN:"M789.8 220.9L795.1 219.6L793.9 217.9L798.6 215.7L798.8 207.8L791.9 198.1L788.6 196.5L791.2 194.8L790.1 192.3L786.7 192.3L783.8 187.6L792.6 185.1L796.5 186.7L796.0 188.3L797.3 189.4L800.1 190.1L796.4 192.5L793.5 197.1L802.4 207.6L803.7 212.7L803.3 217.6L792.1 226.1L791.1 224.3L791.9 222.4L789.8 220.9Z",
  XK:"M557.2 133.7L555.8 131.7L557.3 130.0L560.5 131.4L557.2 133.7Z",
  YE:"M644.4 197.2L647.5 203.7L645.5 204.5L644.9 206.7L635.2 211.1L626.7 213.1L625.0 214.7L620.8 214.9L618.3 207.7L620.5 201.2L630.6 202.9L636.4 198.3L644.4 197.2Z",
  ZA:"M545.4 329.4L546.7 328.0L548.3 330.0L551.3 330.7L555.3 329.1L555.3 318.8L557.7 321.9L558.0 324.5L560.0 324.2L564.8 320.2L567.3 321.3L571.3 320.8L575.3 315.5L581.8 311.4L586.6 311.8L588.7 317.7L588.4 321.8L586.2 321.5L585.2 324.3L586.9 325.8L591.2 324.3L589.5 329.9L578.4 341.0L571.6 344.3L562.7 344.1L555.8 346.7L551.0 344.8L549.8 340.6L550.6 337.9L545.4 329.4Z",
  ZM:"M585.4 273.2L592.3 276.9L592.5 284.5L590.8 288.1L592.3 288.8L583.8 291.1L584.1 293.1L580.4 294.6L575.1 299.8L568.6 298.2L564.5 298.7L560.8 294.7L560.9 285.8L566.7 285.9L566.4 280.4L571.5 282.7L575.5 282.2L580.4 286.8L582.5 286.8L582.3 283.8L578.8 282.8L579.0 275.5L580.6 273.4L585.4 273.2Z",
  ZW:"M586.6 311.8L577.8 309.7L577.0 306.9L572.7 303.6L570.2 299.3L575.1 299.8L580.4 294.6L584.1 293.1L584.3 294.1L591.2 296.4L590.7 306.4L586.6 311.8Z",
};

// Five nominal attack categories need five separable hues. Categorical set,
// deliberately distinct from the ordinal severity ramp and the single nominal
// accent used elsewhere. Every mark also carries a legend entry.
const ATTACK_COLORS = {
  web_attackers: '#e0653f', intruders: '#d6454f', scanners: '#3f9dd4',
  ddos_attackers: '#9b6dd6', anonymizers: '#3fae8c',
};
const ATTACK_ORDER = ['web_attackers', 'intruders', 'scanners', 'ddos_attackers', 'anonymizers'];

function attackMapData() {
  return (store.meta && store.meta.attack_map) || null;
}

function countForCountry(c) {
  return store.mapCat ? (c.by_category[store.mapCat] || 0) : c.total;
}

function dominantColor(c) {
  let best = null, bestN = -1;
  ATTACK_ORDER.forEach((cat) => {
    const n = c.by_category[cat] || 0;
    if (n > bestN) { bestN = n; best = cat; }
  });
  return ATTACK_COLORS[best] || SERIES_1;
}

// Perceptual-ish ramp from the surface colour up to the category hue. Using a
// sqrt scale because attacker counts are extremely long-tailed (China alone is
// ~40% of the total) and a linear ramp would leave every other country flat.
function shadeFor(value, max, baseColor) {
  if (!value) return null;
  const t = Math.sqrt(value / max);
  return { fill: baseColor, opacity: 0.15 + t * 0.75 };
}

// --- LIVE threat map -------------------------------------------------------
// Combines what the three reference maps each do well:
//   Radware    -> Top Origins / Top Targets rails beside the map
//   Check Point-> a live scrolling event ticker
//   Kaspersky  -> a running odometer and per-category toggles
//
// HONESTY: we own no sensors, so there is no packet telemetry to stream. Both
// ENDPOINTS of every arc are real - origins are the geolocated attacker hosts
// observed in the feeds, targets are the countries actually named as targeted
// in reporting (geopolitics.target_countries). Only the PAIRING is sampled from
// those real distributions, and the header says so. When no target data exists
// we animate origin pulses only, rather than invent a destination.

let mapRaf = null;          // animation frame handle, so views can cancel it
let mapArcs = [];           // in-flight arcs
let mapEventSeq = 0;
let mapCounter = 0;

function stopMapAnimation() {
  if (mapRaf !== null) { cancelAnimationFrame(mapRaf); mapRaf = null; }
  mapArcs = [];
}

function prefersReducedMotion() {
  return window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
}

// Weighted pick from [{w, ...}] using the real counts as weights.
function weightedPick(rows) {
  const total = rows.reduce((s, r) => s + r.w, 0);
  if (total <= 0) return null;
  let r = Math.random() * total;
  for (const row of rows) { r -= row.w; if (r <= 0) return row; }
  return rows[rows.length - 1];
}

function mapCentroid(cc) {
  if (!WORLD_PATHS[cc]) return null;
  return pathBBoxCenter(WORLD_PATHS[cc]);
}

function showMapView() {
  hideAllViews();
  stopMapAnimation();
  const host = $('map-view');
  if (!host) return;
  host.style.display = 'block';
  host.replaceChildren();

  const data = attackMapData();
  if (!data || !data.countries || !data.countries.length) {
    host.appendChild(el('h2', 'map-title', 'Threat map'));
    host.appendChild(el('p', 'chart-empty', 'No attacker-infrastructure data in the current run.'));
    return;
  }

  // ---- command bar ---------------------------------------------------------
  const bar = el('div', 'lm-bar');
  const live = el('div', 'lm-live');
  live.appendChild(el('span', 'lm-dot'));
  live.appendChild(el('span', 'lm-live-label', 'LIVE REPLAY'));
  bar.appendChild(live);

  const odo = el('div', 'lm-odo');
  odo.appendChild(el('span', 'lm-odo-label', 'HOSTS OBSERVED'));
  const odoVal = el('span', 'lm-odo-val', '0');
  odoVal.id = 'lm-odo-val';
  odo.appendChild(odoVal);
  bar.appendChild(odo);

  const controls = el('div', 'lm-controls');
  const pause = el('button', 'lm-btn', store.mapPaused ? '▶ Play' : '⏸ Pause');
  pause.type = 'button';
  pause.addEventListener('click', () => {
    store.mapPaused = !store.mapPaused;
    showMapView();
  });
  controls.appendChild(pause);
  bar.appendChild(controls);
  host.appendChild(bar);

  host.appendChild(el('p', 'lm-honesty',
    'Replay of observed attacker infrastructure and reported targeting. ' +
    'Origins and targets are real; the pairing is sampled from those distributions. ' +
    'This is not live packet telemetry.'));

  // ---- category toggles ----------------------------------------------------
  const toggles = el('div', 'map-toggles');
  const allBtn = el('button', 'map-toggle' + (store.mapCat === null ? ' active' : ''), 'All');
  allBtn.type = 'button';
  allBtn.addEventListener('click', () => { store.mapCat = null; showMapView(); });
  toggles.appendChild(allBtn);
  ATTACK_ORDER.forEach((cat) => {
    const n = data.totals[cat] || 0;
    if (!n) return;
    const b = el('button', 'map-toggle' + (store.mapCat === cat ? ' active' : ''));
    b.type = 'button';
    const dot = el('span', 'map-dot');
    dot.style.background = ATTACK_COLORS[cat];
    b.appendChild(dot);
    b.appendChild(el('span', 'map-toggle-label',
      (data.category_labels[cat] || cat) + ' ' + n.toLocaleString()));
    b.addEventListener('click', () => {
      store.mapCat = store.mapCat === cat ? null : cat;
      showMapView();
    });
    toggles.appendChild(b);
  });
  host.appendChild(toggles);

  // ---- three-column command layout ----------------------------------------
  const grid = el('div', 'lm-grid');
  grid.appendChild(buildOriginTargetRail(data));
  grid.appendChild(buildLiveMap(data));
  grid.appendChild(buildTicker());
  host.appendChild(grid);

  // ---- provenance ----------------------------------------------------------
  const prov = el('details', 'map-prov');
  prov.appendChild(el('summary', 'map-prov-summary',
    'Sources — ' + (data.sources || []).filter((s) => s.status === 'ok').length + ' feeds'));
  const list = el('div', 'map-prov-list');
  (data.sources || []).forEach((s) => {
    const row = el('div', 'map-prov-row');
    row.appendChild(el('span', 'map-prov-feed', s.feed));
    row.appendChild(el('span', 'map-prov-rows',
      s.status === 'ok' ? s.rows.toLocaleString() + ' rows' : 'unavailable'));
    list.appendChild(row);
  });
  prov.appendChild(list);
  if (data.attribution) prov.appendChild(el('p', 'map-attribution', data.attribution));
  host.appendChild(prov);

  startMapAnimation(data);
}

// ---- left rail: top origins + top targets ---------------------------------
function buildOriginTargetRail(data) {
  const rail = el('div', 'lm-rail');

  const origins = data.countries
    .map((c) => ({ c: c, v: countForCountry(c) }))
    .filter((d) => d.v > 0)
    .sort((a, b) => b.v - a.v)
    .slice(0, 10);

  rail.appendChild(railPanel('TOP ORIGINS', origins.map((d) => ({
    cc: d.c.cc, name: d.c.name, v: d.v,
    color: store.mapCat ? ATTACK_COLORS[store.mapCat] : dominantColor(d.c),
  })), 'hosts'));

  const targets = targetRows();
  if (targets.length) {
    rail.appendChild(railPanel('TOP REPORTED TARGETS', targets.map((t) => ({
      cc: t.cc, name: t.name, v: t.v, color: '#3f9dd4',
    })), 'mentions'));
  }
  return rail;
}

// Real reported targets, from country extraction over the feed.
function targetRows() {
  const g = (store.meta && store.meta.geopolitics) || {};
  const tc = g.target_countries || {};
  return Object.entries(tc)
    .map((e) => ({ cc: e[0], name: countryNameFor(e[0]), v: e[1] }))
    .sort((a, b) => b.v - a.v)
    .slice(0, 10);
}

function countryNameFor(cc) {
  const am = attackMapData();
  if (am) {
    const hit = am.countries.find((c) => c.cc === cc);
    if (hit) return hit.name;
  }
  return cc;
}

function railPanel(title, rows, unit) {
  const panel = el('div', 'lm-panel');
  panel.appendChild(el('div', 'lm-panel-title', title));
  if (!rows.length) {
    panel.appendChild(el('p', 'lm-panel-empty', 'No data'));
    return panel;
  }
  const max = Math.max(1, ...rows.map((r) => r.v));
  rows.forEach((r, i) => {
    const row = el('div', 'lm-row');
    row.appendChild(el('span', 'lm-row-rank', String(i + 1)));
    row.appendChild(el('span', 'lm-row-cc', r.cc));
    row.appendChild(el('span', 'lm-row-name', r.name));
    const track = el('span', 'lm-row-track');
    const fill = el('span', 'lm-row-fill');
    fill.style.width = ((r.v / max) * 100) + '%';
    fill.style.background = r.color;
    track.appendChild(fill);
    row.appendChild(track);
    const val = el('span', 'lm-row-val', r.v.toLocaleString());
    val.title = r.v.toLocaleString() + ' ' + unit;
    row.appendChild(val);
    panel.appendChild(row);
  });
  return panel;
}

// ---- centre: the animated map --------------------------------------------
function buildLiveMap(data) {
  const W = 1000, H = 500;
  const wrap = el('div', 'lm-canvas');

  const byCc = {};
  data.countries.forEach((c) => { byCc[c.cc] = c; });
  const values = data.countries.map((c) => countForCountry(c)).filter((v) => v > 0);
  const max = Math.max(1, ...values);

  const svg = svgEl('svg', {
    viewBox: '0 0 ' + W + ' ' + H, class: 'world-map lm-map',
    role: 'img', 'aria-label': 'Animated world map of attacker origins and reported targets',
  });
  svg.id = 'lm-svg';

  svg.appendChild(svgEl('rect', { x: 0, y: 0, width: W, height: H, class: 'map-ocean' }));
  for (let lon = -180; lon <= 180; lon += 30) {
    const x = ((lon + 180) / 360) * W;
    svg.appendChild(svgEl('line', { x1: x, y1: 0, x2: x, y2: H, class: 'map-grid-line' }));
  }
  for (let lat = -60; lat <= 60; lat += 30) {
    const y = ((90 - lat) / 180) * H;
    svg.appendChild(svgEl('line', { x1: 0, y1: y, x2: W, y2: y, class: 'map-grid-line' }));
  }

  const landGroup = svgEl('g', { class: 'map-land-group' });
  Object.keys(WORLD_PATHS).forEach((cc) => {
    const country = byCc[cc];
    const value = country ? countForCountry(country) : 0;
    const path = svgEl('path', { d: WORLD_PATHS[cc], class: 'map-country' });
    if (value) {
      const shade = shadeFor(value, max, store.mapCat
        ? ATTACK_COLORS[store.mapCat] : dominantColor(country));
      path.setAttribute('fill', shade.fill);
      path.setAttribute('fill-opacity', shade.opacity.toFixed(3));
      path.classList.add('has-data');
      path.dataset.cc = cc;
      const title = svgEl('title', {});
      title.textContent = country.name + ': ' + value.toLocaleString() + ' hosts';
      path.appendChild(title);
    }
    landGroup.appendChild(path);
  });
  svg.appendChild(landGroup);

  // Layers the animation writes into.
  svg.appendChild(svgEl('g', { id: 'lm-arc-layer', class: 'lm-arc-layer' }));
  svg.appendChild(svgEl('g', { id: 'lm-pulse-layer', class: 'lm-pulse-layer' }));

  wrap.appendChild(svg);

  const readout = el('div', 'map-readout');
  readout.appendChild(el('span', 'map-readout-hint', 'Hover a country for detail'));
  wrap.appendChild(readout);
  svg.addEventListener('mouseover', (ev) => {
    const cc = ev.target && ev.target.dataset && ev.target.dataset.cc;
    if (!cc || !byCc[cc]) return;
    const c = byCc[cc];
    readout.replaceChildren();
    readout.appendChild(el('span', 'map-readout-cc', c.cc));
    readout.appendChild(el('span', 'map-readout-name', c.name));
    const parts = ATTACK_ORDER.filter((cat) => c.by_category[cat])
      .map((cat) => (c.by_category[cat]).toLocaleString() + ' ' + (data.category_labels[cat] || cat));
    readout.appendChild(el('span', 'map-readout-detail',
      c.total.toLocaleString() + ' hosts · ' + parts.join(' · ')));
  });
  svg.addEventListener('mouseleave', () => {
    readout.replaceChildren(el('span', 'map-readout-hint', 'Hover a country for detail'));
  });
  return wrap;
}

// ---- right rail: live event ticker ----------------------------------------
function buildTicker() {
  const panel = el('div', 'lm-ticker');
  panel.appendChild(el('div', 'lm-panel-title', 'EVENT STREAM'));
  const list = el('div', 'lm-ticker-list');
  list.id = 'lm-ticker-list';
  panel.appendChild(list);
  return panel;
}

function pushTickerRow(ev) {
  const list = $('lm-ticker-list');
  if (!list) return;
  const row = el('div', 'lm-tick');
  const dot = el('span', 'lm-tick-dot');
  dot.style.background = ATTACK_COLORS[ev.cat] || '#3f9dd4';
  row.appendChild(dot);
  const body = el('span', 'lm-tick-body');
  body.appendChild(el('span', 'lm-tick-src', ev.from));
  body.appendChild(el('span', 'lm-tick-arrow', ev.to ? '→' : ''));
  if (ev.to) body.appendChild(el('span', 'lm-tick-dst', ev.to));
  row.appendChild(body);
  row.appendChild(el('span', 'lm-tick-cat', ev.label));
  list.insertBefore(row, list.firstChild);
  while (list.children.length > 14) list.removeChild(list.lastChild);
  requestAnimationFrame(() => row.classList.add('lm-tick-in'));
}

// ---- the animation loop ---------------------------------------------------
function startMapAnimation(data) {
  const reduced = prefersReducedMotion();
  mapCounter = 0;

  // Origin weights come straight from the observed host counts.
  const originRows = data.countries
    .map((c) => ({ w: countForCountry(c), cc: c.cc, name: c.name, country: c }))
    .filter((r) => r.w > 0 && WORLD_PATHS[r.cc]);

  const targets = targetRows().filter((t) => WORLD_PATHS[t.cc]);
  const targetRowsW = targets.map((t) => ({ w: t.v, cc: t.cc, name: t.name }));

  // Category weights, so the stream mirrors the real category mix.
  const catRows = ATTACK_ORDER
    .map((cat) => ({ w: (data.totals[cat] || 0), cat: cat }))
    .filter((r) => r.w > 0);

  const odo = $('lm-odo-val');
  const target = data.distinct_ips || 0;

  // Odometer counts up to the real observed total, then holds.
  let odoShown = 0;
  const odoStep = Math.max(1, Math.round(target / 90));

  if (reduced || store.mapPaused) {
    if (odo) odo.textContent = target.toLocaleString();
    // Still show a static sample in the ticker so the panel is not empty.
    for (let i = 0; i < 6; i++) spawnEvent(originRows, targetRowsW, catRows, data, true);
    return;
  }

  let last = 0;
  let acc = 0;
  const step = (ts) => {
    if (!last) last = ts;
    // Browsers pause rAF while the tab is hidden, so the first frame back can
    // carry a dt of many seconds. Clamp it, or every in-flight arc completes at
    // once and the odometer jumps.
    const dt = Math.min(120, ts - last);
    last = ts;

    if (odo && odoShown < target) {
      odoShown = Math.min(target, odoShown + odoStep);
      odo.textContent = odoShown.toLocaleString();
    }

    acc += dt;
    if (acc > 420) {                       // a new event roughly twice a second
      acc = 0;
      spawnEvent(originRows, targetRowsW, catRows, data, false);
    }
    advanceArcs(dt);
    mapRaf = requestAnimationFrame(step);
  };
  mapRaf = requestAnimationFrame(step);
}

function spawnEvent(originRows, targetRowsW, catRows, data, staticOnly) {
  const origin = weightedPick(originRows);
  if (!origin) return;
  const catRow = store.mapCat ? { cat: store.mapCat } : weightedPick(catRows);
  const cat = catRow ? catRow.cat : ATTACK_ORDER[0];
  const dest = targetRowsW.length ? weightedPick(targetRowsW) : null;

  pushTickerRow({
    from: origin.cc, to: dest && dest.cc !== origin.cc ? dest.cc : null,
    cat: cat, label: (data.category_labels[cat] || cat),
  });
  mapCounter += 1;

  if (staticOnly) return;

  const a = mapCentroid(origin.cc);
  if (!a) return;
  const b = dest && dest.cc !== origin.cc ? mapCentroid(dest.cc) : null;
  const color = ATTACK_COLORS[cat] || '#3f9dd4';

  if (b) {
    addArc(a, b, color);
  } else {
    addPulse(a, color);        // no real target: radiate at the origin only
  }
}

function addArc(a, b, color) {
  const layer = $('lm-arc-layer');
  if (!layer) return;
  // Quadratic bezier bowed perpendicular to the chord, so arcs read as flight
  // paths rather than straight lines.
  const mx = (a[0] + b[0]) / 2, my = (a[1] + b[1]) / 2;
  const dx = b[0] - a[0], dy = b[1] - a[1];
  const dist = Math.sqrt(dx * dx + dy * dy) || 1;
  const bow = Math.min(120, dist * 0.32);
  const cx = mx - (dy / dist) * bow;
  const cy = my + (dx / dist) * bow;
  const d = 'M' + a[0].toFixed(1) + ',' + a[1].toFixed(1) +
            ' Q' + cx.toFixed(1) + ',' + cy.toFixed(1) +
            ' ' + b[0].toFixed(1) + ',' + b[1].toFixed(1);

  const path = svgEl('path', { d: d, class: 'lm-arc', fill: 'none' });
  path.style.stroke = color;
  layer.appendChild(path);
  const len = path.getTotalLength ? path.getTotalLength() : dist * 1.4;
  const head = Math.max(28, len * 0.22);
  path.style.strokeDasharray = head + ' ' + (len + head);
  path.style.strokeDashoffset = String(head);

  mapArcs.push({ path: path, len: len, head: head, t: 0, dur: 1500, dest: b, color: color });
  if (mapArcs.length > 18) {
    const old = mapArcs.shift();
    if (old.path.parentNode) old.path.parentNode.removeChild(old.path);
  }
}

function advanceArcs(dt) {
  for (let i = mapArcs.length - 1; i >= 0; i--) {
    const arc = mapArcs[i];
    arc.t += dt;
    const p = Math.min(1, arc.t / arc.dur);
    arc.path.style.strokeDashoffset = String(arc.head - p * (arc.len + arc.head));
    arc.path.style.opacity = String(p < 0.85 ? 1 : (1 - p) / 0.15);
    if (p >= 1) {
      if (arc.path.parentNode) arc.path.parentNode.removeChild(arc.path);
      addPulse(arc.dest, arc.color);         // impact ring at the target
      mapArcs.splice(i, 1);
    }
  }
}

function addPulse(pt, color) {
  const layer = $('lm-pulse-layer');
  if (!layer || !pt) return;
  const ring = svgEl('circle', {
    cx: pt[0].toFixed(1), cy: pt[1].toFixed(1), r: 2, class: 'lm-impact',
  });
  ring.style.stroke = color;
  layer.appendChild(ring);
  // Self-removing: the CSS animation runs once, then we clean up.
  setTimeout(() => { if (ring.parentNode) ring.parentNode.removeChild(ring); }, 1400);
  while (layer.children.length > 40) layer.removeChild(layer.firstChild);
}

// Cheap centroid of a path's extent, for placing the pulse markers. Parsing the
// numbers out of the path beats hauling in a geometry library for five dots.
function pathBBoxCenter(d) {
  const nums = d.match(/-?\d+(?:\.\d+)?/g);
  if (!nums || nums.length < 4) return null;
  let minX = Infinity, maxX = -Infinity, minY = Infinity, maxY = -Infinity;
  for (let i = 0; i + 1 < nums.length; i += 2) {
    const x = parseFloat(nums[i]), y = parseFloat(nums[i + 1]);
    if (x < minX) minX = x;
    if (x > maxX) maxX = x;
    if (y < minY) minY = y;
    if (y > maxY) maxY = y;
  }
  return [(minX + maxX) / 2, (minY + maxY) / 2];
}

function buildCountryTable(data) {
  const wrap = el('div', 'map-table-wrap');
  const rows = data.countries
    .map((c) => ({ c: c, v: countForCountry(c) }))
    .filter((d) => d.v > 0)
    .sort((a, b) => b.v - a.v)
    .slice(0, 25);
  const max = Math.max(1, ...rows.map((d) => d.v));

  const table = el('table', 'map-table');
  table.appendChild(el('caption', 'map-table-caption',
    store.mapCat ? 'Top origins — ' + data.category_labels[store.mapCat]
                 : 'Top origins — all categories'));
  rows.forEach((d, i) => {
    const tr = el('tr', 'map-row');
    tr.appendChild(el('td', 'map-rank', String(i + 1)));
    tr.appendChild(el('td', 'map-cc', d.c.cc));
    tr.appendChild(el('td', 'map-name', d.c.name));
    const barTd = el('td', 'map-bar-cell');
    const bar = el('div', 'map-bar');
    bar.style.width = ((d.v / max) * 100) + '%';
    bar.style.background = store.mapCat ? ATTACK_COLORS[store.mapCat] : dominantColor(d.c);
    barTd.appendChild(bar);
    tr.appendChild(barTd);
    tr.appendChild(el('td', 'map-val', d.v.toLocaleString()));
    table.appendChild(tr);
  });
  wrap.appendChild(table);
  return wrap;
}

// --- Threat landscape (Phase 04) --------------------------------------------
// A "what's the situation right now" overview, composed from data we already
// hold: the current feed (severity/KEV/PoC, sectors, attacker map) plus the
// 30-day archive rollup (actor momentum, technique frequency). No new fetch
// beyond trends.json, which the Trends view already loads.

// --- Threat landscape -------------------------------------------------------
// Every panel states what it shows and what the number means. A chart with no
// axis, no units and no explanation is decoration, not information.

function statTile(label, value, sub) {
  const tile = el('div', 'ls-tile');
  tile.appendChild(el('div', 'ls-tile-val', String(value)));
  tile.appendChild(el('div', 'ls-tile-label', label));
  if (sub) tile.appendChild(el('div', 'ls-tile-sub', sub));
  return tile;
}

// A framed panel: title, one line of plain English, then the visual.
function lsPanel(title, explainer) {
  const fig = el('figure', 'ls-panel');
  const head = el('figcaption', 'ls-panel-head');
  head.appendChild(el('span', 'ls-panel-title', title));
  if (explainer) head.appendChild(el('span', 'ls-panel-explain', explainer));
  fig.appendChild(head);
  return fig;
}

async function showLandscapeView() {
  hideAllViews();
  const host = $('landscape-view');
  if (!host) return;
  host.style.display = 'block';
  host.replaceChildren(el('p', 'chart-empty', 'Composing landscape…'));

  if (!store.trends) {
    try {
      const resp = await fetch(TRENDS_URL, { cache: 'no-cache' });
      if (resp.ok) store.trends = await resp.json();
    } catch (_) { /* trends are optional here */ }
  }
  const t = store.trends || {};
  const items = store.items || [];
  host.replaceChildren();

  host.appendChild(el('h2', 'ls-title', 'Threat landscape'));
  host.appendChild(el('p', 'ls-sub',
    'This run, set against the last ' + (t.days_covered || 0) + ' days of history.'));

  const kev = items.filter((i) => i.cisa_kev).length;
  const urgent = items.filter((i) => i.priority_label === 'urgent').length;
  const withPoc = items.filter((i) => i.has_poc).length;
  const sectored = items.filter((i) => i.sector).length;
  const am = store.meta && store.meta.attack_map;

  const tiles = el('div', 'ls-tiles');
  tiles.appendChild(statTile('Items this run', items.length));
  tiles.appendChild(statTile('Urgent', urgent, 'patch within 24h'));
  tiles.appendChild(statTile('In CISA KEV', kev, 'confirmed exploited'));
  tiles.appendChild(statTile('Public PoC', withPoc, 'exploit code exists'));
  tiles.appendChild(statTile('Sector-tagged', sectored, 'target identified'));
  if (am) {
    tiles.appendChild(statTile('Attacker hosts', am.distinct_ips.toLocaleString(),
      'across ' + am.countries.length + ' countries'));
  }
  host.appendChild(tiles);

  const grid = el('div', 'ls-grid');
  grid.appendChild(buildKevVelocity(t.kev_daily || []));
  grid.appendChild(buildActorMomentum(t.top_actors || []));
  grid.appendChild(buildSectorHeat(items, t.sector_totals || {}));
  grid.appendChild(buildTechniqueRank(t.top_ttps || []));
  const dw = buildDarkWeb();
  if (dw) grid.appendChild(dw);
  host.appendChild(grid);
}

// ---- KEV velocity: a real chart, with axes, a mean, and a stated meaning ----
function buildKevVelocity(kevDaily) {
  const fig = lsPanel('Actively-exploited items per day',
    'Items in CISA’s Known Exploited Vulnerabilities catalogue. These are ' +
    'confirmed exploited in the wild, so the line is the volume of things that ' +
    'genuinely warrant same-day action.');
  if (!kevDaily.length) {
    fig.appendChild(el('p', 'chart-empty', 'No KEV history yet — this builds from the daily archive.'));
    return fig;
  }

  const vals = kevDaily.map((d) => d.kev);
  const max = Math.max(1, ...vals);
  const mean = vals.reduce((s, v) => s + v, 0) / vals.length;
  const latest = vals[vals.length - 1];
  // Compare the last week against the week before it, so the callout is a real
  // trend and not the noise between two adjacent days.
  const wk = Math.min(7, Math.floor(vals.length / 2));
  const recent = vals.slice(-wk).reduce((s, v) => s + v, 0) / Math.max(1, wk);
  const prior = vals.slice(-wk * 2, -wk).reduce((s, v) => s + v, 0) / Math.max(1, wk);
  const delta = prior ? ((recent - prior) / prior) * 100 : 0;

  const call = el('div', 'ls-callout');
  const cv = el('div', 'ls-callout-main');
  cv.appendChild(el('span', 'ls-callout-num', String(latest)));
  cv.appendChild(el('span', 'ls-callout-unit', 'latest day'));
  call.appendChild(cv);
  const trendCls = delta > 5 ? 'ls-up' : delta < -5 ? 'ls-down' : 'ls-flat';
  const arrow = delta > 5 ? '▲' : delta < -5 ? '▼' : '–';
  const tr = el('div', 'ls-callout-trend ' + trendCls);
  tr.appendChild(el('span', 'ls-trend-arrow', arrow));
  tr.appendChild(el('span', 'ls-trend-text',
    (delta === 0 ? 'level' : Math.abs(delta).toFixed(0) + '% ' + (delta > 0 ? 'higher' : 'lower')) +
    ' than the previous ' + wk + ' days'));
  call.appendChild(tr);
  call.appendChild(el('div', 'ls-callout-mean', 'Daily average ' + mean.toFixed(1)));
  fig.appendChild(call);

  const W = 560, H = 180;
  const PAD = { top: 14, right: 14, bottom: 28, left: 34 };
  const plotW = W - PAD.left - PAD.right;
  const plotH = H - PAD.top - PAD.bottom;
  const svg = svgEl('svg', {
    viewBox: '0 0 ' + W + ' ' + H, class: 'ls-chart',
    role: 'img', 'aria-label': 'KEV items per day over ' + kevDaily.length + ' days',
  });

  // y gridlines + labels, so bar heights are readable as numbers.
  const ticks = [0, Math.round(max / 2), max];
  ticks.forEach((v) => {
    const y = PAD.top + plotH - (v / max) * plotH;
    svg.appendChild(svgEl('line', {
      x1: PAD.left, y1: y.toFixed(1), x2: W - PAD.right, y2: y.toFixed(1), class: 'ls-grid',
    }));
    const lab = svgEl('text', {
      x: PAD.left - 6, y: (y + 3).toFixed(1), class: 'ls-axis', 'text-anchor': 'end',
    });
    lab.textContent = String(v);
    svg.appendChild(lab);
  });

  const bw = plotW / kevDaily.length;
  kevDaily.forEach((d, i) => {
    const h = (d.kev / max) * plotH;
    const rect = svgEl('rect', {
      x: (PAD.left + i * bw).toFixed(1), y: (PAD.top + plotH - h).toFixed(1),
      width: Math.max(1, bw - 1.5).toFixed(1), height: Math.max(0, h).toFixed(1),
      class: 'ls-kev-bar' + (i === kevDaily.length - 1 ? ' is-latest' : ''),
    });
    const ttl = svgEl('title', {});
    ttl.textContent = d.date + ': ' + d.kev + ' KEV item' + (d.kev === 1 ? '' : 's');
    rect.appendChild(ttl);
    svg.appendChild(rect);
  });

  // Mean line, labelled — turns "some bars" into "above or below normal".
  const my = PAD.top + plotH - (mean / max) * plotH;
  svg.appendChild(svgEl('line', {
    x1: PAD.left, y1: my.toFixed(1), x2: W - PAD.right, y2: my.toFixed(1), class: 'ls-mean',
  }));
  const ml = svgEl('text', {
    x: W - PAD.right, y: (my - 5).toFixed(1), class: 'ls-mean-label', 'text-anchor': 'end',
  });
  ml.textContent = 'avg ' + mean.toFixed(1);
  svg.appendChild(ml);

  // x axis: first and last date, so the window is explicit.
  const first = svgEl('text', { x: PAD.left, y: H - 8, class: 'ls-axis' });
  first.textContent = kevDaily[0].date;
  svg.appendChild(first);
  const lastT = svgEl('text', { x: W - PAD.right, y: H - 8, class: 'ls-axis', 'text-anchor': 'end' });
  lastT.textContent = kevDaily[kevDaily.length - 1].date;
  svg.appendChild(lastT);

  fig.appendChild(svg);
  return fig;
}

// ---- actor momentum --------------------------------------------------------
function buildActorMomentum(actors) {
  const fig = lsPanel('Threat-actor momentum',
    'Days each actor appeared over the window. The arrow compares the recent ' +
    'half against the earlier half, so it reads as rising or cooling rather ' +
    'than just a total.');
  if (!actors.length) {
    fig.appendChild(el('p', 'chart-empty', 'No actor history yet.'));
    return fig;
  }
  const max = Math.max(1, ...actors.map((a) => a.count || 0));
  const list = el('div', 'ls-bars');
  actors.slice(0, 8).forEach((a) => {
    const row = el('div', 'ls-bar-row');
    row.appendChild(el('span', 'ls-bar-name', a.name));
    const track = el('span', 'ls-bar-track');
    const fill = el('span', 'ls-bar-fill');
    fill.style.width = (((a.count || 0) / max) * 100) + '%';
    fill.style.background = a.momentum === 'rising' ? '#e0653f'
      : a.momentum === 'cooling' ? '#3fae8c' : SERIES_1;
    track.appendChild(fill);
    row.appendChild(track);
    const cls = a.momentum === 'rising' ? 'ls-up' : a.momentum === 'cooling' ? 'ls-down' : 'ls-flat';
    const arrow = a.momentum === 'rising' ? '▲' : a.momentum === 'cooling' ? '▼' : '–';
    const val = el('span', 'ls-bar-val ' + cls, arrow + ' ' + (a.count || 0) + 'd');
    val.title = a.momentum + ' — ' + (a.recent || 0) + ' days recently vs ' +
      (a.prior || 0) + ' days before';
    row.appendChild(val);
    list.appendChild(row);
  });
  fig.appendChild(list);
  return fig;
}

// ---- sector heat -----------------------------------------------------------
function buildSectorHeat(items, archiveTotals) {
  const fig = lsPanel('Targeted sectors',
    'Which industries this run’s items are aimed at. Tagged from the source ' +
    'where it names a victim sector, inferred from the text otherwise.');
  const labels = (store.meta && store.meta.sector_labels) || {};
  const counts = {};
  items.forEach((i) => { if (i.sector) counts[i.sector] = (counts[i.sector] || 0) + 1; });
  let source = counts, scope = 'this run';
  if (!Object.keys(counts).length && Object.keys(archiveTotals).length) {
    source = archiveTotals; scope = 'last 30 days';
  }
  const rows = Object.entries(source)
    .map((e) => ({ key: e[0], name: labels[e[0]] || e[0], count: e[1] }))
    .sort((a, b) => b.count - a.count);
  if (!rows.length) {
    fig.appendChild(el('p', 'chart-empty', 'No sectors identified yet.'));
    return fig;
  }
  const total = rows.reduce((s, r) => s + r.count, 0);
  const max = Math.max(1, ...rows.map((r) => r.count));
  const list = el('div', 'ls-bars');
  rows.slice(0, 9).forEach((r) => {
    const row = el('div', 'ls-bar-row is-click');
    row.dataset.sector = r.key;
    row.appendChild(el('span', 'ls-bar-name', r.name));
    const track = el('span', 'ls-bar-track');
    const fill = el('span', 'ls-bar-fill');
    fill.style.width = ((r.count / max) * 100) + '%';
    fill.style.background = SERIES_1;
    track.appendChild(fill);
    row.appendChild(track);
    const pct = ((r.count / total) * 100).toFixed(0);
    const val = el('span', 'ls-bar-val', r.count + ' · ' + pct + '%');
    val.title = r.count + ' of ' + total + ' tagged items (' + scope + ')';
    row.appendChild(val);
    list.appendChild(row);
  });
  fig.appendChild(list);
  fig.appendChild(el('p', 'ls-foot', total + ' tagged items · ' + scope));
  return fig;
}

// ---- dark web: ransomware leak-site activity -------------------------------
function buildDarkWeb() {
  const d = store.meta && store.meta.darkweb;
  if (!d) return null;
  const fig = lsPanel('Dark web — leak-site activity',
    'Ransomware crews post victims to their own Tor leak sites. A listing is ' +
    'the crew’s claim, not a confirmed breach.');

  const row = el('div', 'ls-callout');
  const main = el('div', 'ls-callout-main');
  main.appendChild(el('span', 'ls-callout-num', String(d.recent_posts)));
  main.appendChild(el('span', 'ls-callout-unit', 'recent listings'));
  row.appendChild(main);
  row.appendChild(el('div', 'ls-callout-mean',
    d.distinct_groups_active + ' groups active · ' +
    d.tracked_leak_sites.toLocaleString() + ' sites tracked'));
  fig.appendChild(row);

  const rows = d.most_active || [];
  if (rows.length) {
    const max = Math.max(1, ...rows.map((r) => r.posts));
    const list = el('div', 'ls-bars');
    rows.slice(0, 6).forEach((r) => {
      const line = el('div', 'ls-bar-row');
      line.appendChild(el('span', 'ls-bar-name', r.group));
      const track = el('span', 'ls-bar-track');
      const fill = el('span', 'ls-bar-fill');
      fill.style.width = ((r.posts / max) * 100) + '%';
      fill.style.background = '#d6454f';
      track.appendChild(fill);
      line.appendChild(track);
      line.appendChild(el('span', 'ls-bar-val', String(r.posts)));
      list.appendChild(line);
    });
    fig.appendChild(list);
  }
  if (d.collection_note) fig.appendChild(el('p', 'ls-foot', d.collection_note));
  return fig;
}

// ---- technique frequency ---------------------------------------------------
function buildTechniqueRank(ttps) {
  const fig = lsPanel('ATT&CK techniques',
    'How often each technique was mapped over the window. The matrix shows ' +
    'where in the kill chain these sit.');
  if (!ttps.length) {
    fig.appendChild(el('p', 'chart-empty', 'No technique history yet.'));
    return fig;
  }
  const max = Math.max(1, ...ttps.map((t) => t.count || 0));
  const list = el('div', 'ls-bars');
  ttps.slice(0, 8).forEach((t) => {
    const row = el('div', 'ls-bar-row');
    const name = el('span', 'ls-bar-name', t.id);
    name.title = t.name || t.id;
    row.appendChild(name);
    const track = el('span', 'ls-bar-track');
    const fill = el('span', 'ls-bar-fill');
    fill.style.width = (((t.count || 0) / max) * 100) + '%';
    fill.style.background = SERIES_1;
    track.appendChild(fill);
    row.appendChild(track);
    const val = el('span', 'ls-bar-val', String(t.count || 0));
    val.title = (t.name || '') + ' — mapped on ' + (t.count || 0) + ' days';
    row.appendChild(val);
    list.appendChild(row);
  });
  fig.appendChild(list);
  return fig;
}

// --- Geopolitical dashboard (Phase 05) --------------------------------------
// Suspected actor ORIGIN crossed with target country and target sector.
// Attribution is contested and frequently wrong, so this view is deliberately
// cautious: every origin is labelled suspected/attributed, every one shows its
// source, and no confidence percentage is ever invented.

function geoData() {
  return (store.meta && store.meta.geopolitics) || null;
}

function confidencePill(conf) {
  const pill = el('span', 'geo-pill geo-' + conf, conf);
  return pill;
}

function showGeopolView() {
  hideAllViews();
  const host = $('geopol-view');
  if (!host) return;
  host.style.display = 'block';
  host.replaceChildren();

  const g = geoData();
  if (!g || !g.suspected_origins || !g.suspected_origins.length) {
    host.appendChild(el('h2', 'ls-title', 'Geopolitical view'));
    host.appendChild(el('p', 'chart-empty',
      'No attributed activity in the current run. This view fills as items ' +
      'with a known actor arrive.'));
    return;
  }

  host.appendChild(el('h2', 'ls-title', 'Geopolitical view'));
  host.appendChild(el('p', 'ls-sub', g.disclaimer || ''));

  const labels = (store.meta && store.meta.sector_labels) || {};

  // Suspected-origin cards: each names its actors, its targets and its source.
  const wrap = el('div', 'geo-origins');
  g.suspected_origins.forEach((o) => {
    const card = el('div', 'geo-card');
    const head = el('div', 'geo-card-head');
    head.appendChild(el('span', 'geo-cc', o.cc));
    head.appendChild(el('span', 'geo-country', o.country));
    head.appendChild(confidencePill(o.confidence));
    head.appendChild(el('span', 'geo-count', o.count + ' item' + (o.count === 1 ? '' : 's')));
    card.appendChild(head);

    // Motive is shown before anything else: "Russia, 12 items" means something
    // very different for state-sponsored espionage than for a ransomware crew
    // that happens to be hosted there, and conflating them would be the most
    // misleading thing this view could do.
    const motives = Object.entries(o.by_motive || {}).sort((a, b) => b[1] - a[1]);
    if (motives.length) {
      const mrow = el('div', 'geo-motives');
      motives.forEach((m) => {
        const chip = el('span', 'geo-motive geo-motive-' + m[0]);
        chip.textContent = m[0] + ' ' + m[1];
        mrow.appendChild(chip);
      });
      card.appendChild(mrow);
    }

    card.appendChild(el('div', 'geo-actors', 'Actors: ' + o.actors.join(', ')));

    const sectors = Object.entries(o.by_sector || {}).sort((a, b) => b[1] - a[1]);
    if (sectors.length) {
      card.appendChild(el('div', 'geo-line',
        'Targets sectors: ' + sectors.map((s) => (labels[s[0]] || s[0]) + ' (' + s[1] + ')').join(', ')));
    }
    const targets = Object.entries(o.by_target || {}).sort((a, b) => b[1] - a[1]);
    if (targets.length) {
      card.appendChild(el('div', 'geo-line',
        'Targets countries: ' + targets.map((tt) => tt[0] + ' (' + tt[1] + ')').join(', ')));
    }
    if (o.sources && o.sources.length) {
      const src = el('details', 'geo-src');
      src.appendChild(el('summary', 'geo-src-sum', 'Attribution source'));
      o.sources.forEach((s) => src.appendChild(el('div', 'geo-src-row', s)));
      card.appendChild(src);
    }
    wrap.appendChild(card);
  });
  host.appendChild(wrap);

  // Per-actor attribution ledger, so the provenance of every claim is visible.
  if (g.attributions && g.attributions.length) {
    const led = el('details', 'geo-ledger');
    led.appendChild(el('summary', 'geo-ledger-sum',
      'Attribution ledger \u2014 ' + g.attributions.length + ' actors'));
    const table = el('table', 'geo-table');
    g.attributions.forEach((a) => {
      const tr = el('tr', 'geo-trow');
      tr.appendChild(el('td', 'geo-td-actor', a.actor));
      tr.appendChild(el('td', 'geo-td-cc', a.cc + ' ' + a.country));
      const cd = el('td', 'geo-td-conf');
      cd.appendChild(confidencePill(a.confidence));
      tr.appendChild(cd);
      const md = el('td', 'geo-td-motive');
      md.appendChild(el('span', 'geo-motive geo-motive-' + (a.motive || 'unknown'),
                        a.motive || 'unknown'));
      tr.appendChild(md);
      tr.appendChild(el('td', 'geo-td-src', a.source));
      table.appendChild(tr);
    });
    led.appendChild(table);
    host.appendChild(led);
  }
}


// --- OSINT provenance (Phase 06) --------------------------------------------
// The honest form of the "HUMINT" request. We have no human collection
// capability, so nothing here is HUMINT. What this does is separate
// human-authored intelligence from machine-generated feeds, and surface the
// adversary's own words as a distinct stream, because a Unit 42 write-up, a
// ransomware leak-site post and a URLhaus row are three different kinds of
// claim and the feed used to flatten them into one.

function renderProvenanceList() {
  const host = $('provenance-list');
  if (!host) return;
  const labels = (store.meta && store.meta.provenance_labels) || {};
  const notes = (store.meta && store.meta.provenance_notes) || {};
  const order = (store.meta && store.meta.provenance_order) || [];

  const counts = {};
  store.items.forEach((i) => {
    if (i.provenance) counts[i.provenance] = (counts[i.provenance] || 0) + 1;
  });
  host.replaceChildren();
  const present = order.filter((p) => counts[p]);
  if (!present.length) {
    host.appendChild(el('p', 'sector-empty', 'No provenance data in this run.'));
    return;
  }

  const humanCount = store.items.filter((i) => i.human_authored).length;
  const toggle = el('button',
    'prov-human-toggle' + (store.humanOnly ? ' active' : ''),
    (store.humanOnly ? '\u2713 ' : '') + 'Human-authored only (' + humanCount + ')');
  toggle.type = 'button';
  toggle.addEventListener('click', () => {
    store.humanOnly = !store.humanOnly;
    update();
  });
  host.appendChild(toggle);

  present.forEach((prov) => {
    const row = el('button', 'prov-row' + (store.provenance === prov ? ' active' : ''));
    row.type = 'button';
    row.dataset.provenance = prov;
    row.title = notes[prov] || '';
    const dot = el('span', 'prov-dot prov-dot-' + prov);
    row.appendChild(dot);
    row.appendChild(el('span', 'prov-name', labels[prov] || prov));
    row.appendChild(el('span', 'prov-count', String(counts[prov])));
    host.appendChild(row);
  });
}

// Analyst notes: the one place a human judgement can be recorded. Local-first,
// stored beside the existing dismiss/star state, and exportable.
function noteFor(key) {
  return (store.notes && store.notes[key]) || '';
}

function setNote(key, text) {
  if (!store.notes) store.notes = {};
  if (text && text.trim()) store.notes[key] = text.trim();
  else delete store.notes[key];
  writeLS(LS.notes, store.notes);
}

function buildNoteEditor(item) {
  const wrap = el('div', 'note-wrap');
  const label = el('div', 'note-label', 'ANALYST NOTE');
  wrap.appendChild(label);
  const ta = el('textarea', 'note-input');
  ta.value = noteFor(item._key);
  ta.rows = 2;
  ta.placeholder = 'Your assessment of this item\u2026';
  ta.setAttribute('aria-label', 'Analyst note for this item');
  // Save on blur rather than per-keystroke: this writes to localStorage.
  ta.addEventListener('blur', () => {
    setNote(item._key, ta.value);
    renderSidebar();
  });
  // Don't let typing in the note trigger the j/k/x triage shortcuts.
  ta.addEventListener('keydown', (ev) => ev.stopPropagation());
  wrap.appendChild(ta);
  return wrap;
}

function exportNotes() {
  const rows = Object.entries(store.notes || {});
  if (!rows.length) return null;
  const byKey = {};
  store.items.forEach((i) => { byKey[i._key] = i; });
  return rows.map((r) => {
    const item = byKey[r[0]] || {};
    return {
      key: r[0], note: r[1], title: item.title || null,
      url: item.url || null, cve_id: item.cve_id || null,
      provenance: item.provenance || null,
    };
  });
}

// ─── View switching ───────────────────────────────────────────────────────────
// --- About / portfolio ------------------------------------------------------
// Reached from the avatar in the header. Rendered as a view inside the SPA so
// it shares the shell, the theme and the router with everything else.
//
// The phone number on the source CV is deliberately NOT here: this deploys to a
// public GitHub Pages site, and a personal mobile number on a public page is an
// invitation to spam and SIM-swap fishing. Email and LinkedIn are already
// public, so those stay.

const PROFILE = {
  name: 'Priyanshu',
  title: 'Cybersecurity Professional',
  location: 'Hyderabad, India',
  email: 'priyanshu.kumar9650@gmail.com',
  linkedin: 'https://www.linkedin.com/in/priyanshu12/',
  github: 'https://github.com/priyanshu965',
  summary:
    'Cybersecurity professional with 3+ years across Incident Response, Threat ' +
    'Intelligence, External Attack Surface Management, Vulnerability Management ' +
    'and Access Management. I work OSINT-driven risk analysis, manage external ' +
    'exposure, and push organisational cyber risk ratings up through disciplined ' +
    'internet hygiene. Hands-on with vulnerability identification, validation, ' +
    'remediation tracking and penetration testing, using SIEM, EDR and WAF for ' +
    'detection and response, and translating technical findings into risk ' +
    'insight the business can act on.',
  stats: [
    { v: '3+', l: 'years in security' },
    { v: 'M.Tech', l: 'Cybersecurity, NFSU' },
    { v: '8', l: 'certifications' },
  ],
  experience: [
    {
      org: 'Bank of America', role: 'Info Security Analyst',
      period: 'Oct 2025 — Present', current: true,
      points: [
        'Own the external attack surface across SecurityScorecard, RiskRecon, BitSight and Xpanse, improving cyber risk ratings through proactive internet hygiene.',
        'OSINT-driven analysis with Shodan, VirusTotal and similar to find perimeter risk: shadow IT, phishing domains, leaked data, credential exposure.',
        'Validate and triage vendor-reported findings, kill false positives, and escalate P1/P2 for timely remediation.',
        'Map external assets to applications and owners, working with Infrastructure, Application, Cloud, SOC and Vendor Risk to cut exposure.',
      ],
    },
    {
      org: 'Bank of America', role: 'Senior Tech Associate',
      period: 'Aug 2024 — Oct 2025',
      points: [
        'Vulnerability identification and validation across servers, applications and cloud using Qualys VMDR, Qualys TotalCloud and Tanium.',
        'Manual validation with Nmap, PowerShell and version verification to eliminate false positives.',
        'Partnered with application, infrastructure and cloud teams to track and validate remediation against risk priority and SLA.',
        'Automated vulnerability reporting; built weekly dashboards for scan coverage, remediation status, SLA adherence and risk trend.',
      ],
    },
    {
      org: 'Bank of America', role: 'Apprentice',
      period: 'Aug 2023 — Aug 2024',
      points: [
        'Global Access Operations Mainframe team: enterprise-wide mainframe access control.',
        'User access provisioning and deprovisioning on mainframe systems.',
        'Led training sessions on cyber attacks for the whole information security team, from attack vectors through to mitigation.',
      ],
    },
    {
      org: 'RAXA Techno Security Solutions, GMR Group', role: 'Cybersecurity Trainee',
      period: 'Dec 2022 — Aug 2023',
      points: [
        'Configured and managed WAF to harden web applications.',
        'Ran VAPT across diverse applications and systems, exploiting findings with a mix of automated tooling and manual technique.',
        'Real-time monitoring via CASM, SIEM and EDR; led red-team simulations to test control effectiveness.',
        'Led quarterly VM scans across servers, network and security devices with remediation plans.',
      ],
    },
  ],
  skills: [
    { group: 'Threat Intelligence', items: ['OSINT', 'SecurityScorecard', 'BitSight', 'Xpanse', 'RiskRecon'] },
    { group: 'Vulnerability Management', items: ['Nessus Professional', 'Qualys VMDR', 'Tanium', 'CASM (CloudSek)'] },
    { group: 'Security Operations', items: ['SIEM (Seceon)', 'EDR (CrowdStrike)', 'Incident Response', 'Threat Hunting'] },
    { group: 'Access & Identity', items: ['SailPoint IIQ', 'IBM z/OS Mainframe'] },
    { group: 'Tooling', items: ['Burp Suite', 'Prophaze WAF', 'FTK', 'FourCore', 'Nmap'] },
    { group: 'Programming & Analysis', items: ['Python', 'Malware Analysis', 'Digital Forensics'] },
  ],
  projects: [
    {
      name: 'OpenThreat', tag: 'this dashboard',
      desc: 'Self-updating threat-intelligence pipeline: 45 sources, SSVC-based prioritisation, ' +
            'an attacker-infrastructure map over ~160k geolocated hosts, sector segregation and ' +
            'geopolitical attribution. Python + vanilla JS, zero infrastructure, runs hourly on ' +
            'GitHub Actions.',
      link: 'https://github.com/priyanshu965/OpenThreat',
    },
    {
      name: 'ICS Vulnerability Assessment Tool',
      desc: 'Passive ICS assessment tool that parses PLC configuration files (L5X, CXT) to extract ' +
            'asset and configuration data and identify weaknesses without touching live operations.',
    },
    {
      name: 'Static Malware Analysis',
      desc: 'Python tool analysing multiple samples concurrently, automating the repetitive triage ' +
            'steps so analysts reach an assessment faster and more consistently.',
    },
  ],
  certs: [
    'Certificate of Cloud Security Knowledge v5 — CSA',
    'Certificate of Competence in Zero Trust — CSA',
    'Certified AppSec Practitioner — The SecOps Group',
    'Certified Network Security Practitioner — The SecOps Group',
    'Practical Malware Analysis & Triage — TCM Security',
    'Proofpoint Certified Email Authentication Specialist',
    'IBM z/OS Mainframe Practitioner — Coursera',
    'Fortinet NSE 1, NSE 2, NSE 3',
  ],
  education: [
    { deg: 'M.Tech, Cybersecurity', school: 'National Forensic Sciences University', period: '2021 — 2023', place: 'Gandhinagar' },
    { deg: 'B.Tech, Information Technology', school: 'PDM College of Engineering', period: '2016 — 2020', place: 'Bahadurgarh' },
  ],
  interests: ['Motorbiking', 'Trekking', 'Cricket', 'Competitive gaming'],
};

// A flat-illustration avatar, drawn rather than fetched: the CSP blocks remote
// images and a photo would be a bigger privacy call than a monogram figure.
function avatarSvg(size) {
  const s = svgEl('svg', {
    viewBox: '0 0 64 64', width: size, height: size,
    class: 'pf-avatar-svg', 'aria-hidden': 'true', focusable: 'false',
  });
  const defs = svgEl('defs', {});
  const grad = svgEl('linearGradient', { id: 'pf-g', x1: '0', y1: '0', x2: '0', y2: '1' });
  const st1 = svgEl('stop', { offset: '0', 'stop-color': '#1e4d73' });
  const st2 = svgEl('stop', { offset: '1', 'stop-color': '#0d2038' });
  grad.appendChild(st1); grad.appendChild(st2);
  defs.appendChild(grad);
  s.appendChild(defs);
  s.appendChild(svgEl('circle', { cx: 32, cy: 32, r: 31, fill: 'url(#pf-g)', stroke: '#00ffe1', 'stroke-opacity': '0.45', 'stroke-width': '1.5' }));
  // shoulders
  s.appendChild(svgEl('path', { d: 'M12 60c0-11 9-17 20-17s20 6 20 17z', fill: '#c9d8e8', 'fill-opacity': '0.92' }));
  // collar
  s.appendChild(svgEl('path', { d: 'M26 44l6 7 6-7-6-3z', fill: '#00ffe1', 'fill-opacity': '0.8' }));
  // head
  s.appendChild(svgEl('circle', { cx: 32, cy: 28, r: 12.5, fill: '#e8d4bd' }));
  // hair
  s.appendChild(svgEl('path', { d: 'M19.5 27c0-8 6-13 12.5-13S44.5 19 44.5 27c0-3-3-5-6-5.5-2.5-.5-4 .8-6.5.8s-4-1.3-6.5-.8c-3 .5-6 2.5-6 5.5z', fill: '#22303c' }));
  // glasses
  s.appendChild(svgEl('circle', { cx: 27, cy: 28.5, r: 3.6, fill: 'none', stroke: '#22303c', 'stroke-width': '1.2' }));
  s.appendChild(svgEl('circle', { cx: 37, cy: 28.5, r: 3.6, fill: 'none', stroke: '#22303c', 'stroke-width': '1.2' }));
  s.appendChild(svgEl('line', { x1: 30.6, y1: 28.5, x2: 33.4, y2: 28.5, stroke: '#22303c', 'stroke-width': '1.2' }));
  // smile
  s.appendChild(svgEl('path', { d: 'M28 34.5c1.6 1.8 6.4 1.8 8 0', fill: 'none', stroke: '#22303c', 'stroke-width': '1.3', 'stroke-linecap': 'round' }));
  return s;
}

function pfSection(title) {
  const sec = el('section', 'pf-section');
  sec.appendChild(el('h3', 'pf-h3', title));
  return sec;
}

function showAboutView() {
  hideAllViews();
  const host = $('about-view');
  if (!host) return;
  host.style.display = 'block';
  host.replaceChildren();

  // ---- hero ---------------------------------------------------------------
  const hero = el('div', 'pf-hero');
  const av = el('div', 'pf-hero-avatar');
  av.appendChild(avatarSvg(96));
  hero.appendChild(av);

  const idBlock = el('div', 'pf-id');
  idBlock.appendChild(el('h2', 'pf-name', PROFILE.name));
  idBlock.appendChild(el('p', 'pf-role', PROFILE.title));
  const meta = el('p', 'pf-meta', PROFILE.location);
  idBlock.appendChild(meta);

  const links = el('div', 'pf-links');
  const mail = el('a', 'pf-link', 'Email');
  mail.href = 'mailto:' + PROFILE.email;
  links.appendChild(mail);
  const li = el('a', 'pf-link', 'LinkedIn');
  li.href = PROFILE.linkedin; li.target = '_blank'; li.rel = 'noopener noreferrer';
  links.appendChild(li);
  const gh = el('a', 'pf-link', 'GitHub');
  gh.href = PROFILE.github; gh.target = '_blank'; gh.rel = 'noopener noreferrer';
  links.appendChild(gh);
  idBlock.appendChild(links);
  hero.appendChild(idBlock);

  const stats = el('div', 'pf-stats');
  PROFILE.stats.forEach((s) => {
    const box = el('div', 'pf-stat');
    box.appendChild(el('span', 'pf-stat-v', s.v));
    box.appendChild(el('span', 'pf-stat-l', s.l));
    stats.appendChild(box);
  });
  hero.appendChild(stats);
  host.appendChild(hero);

  host.appendChild(el('p', 'pf-summary', PROFILE.summary));

  const cols = el('div', 'pf-cols');

  // ---- experience ---------------------------------------------------------
  const expSec = pfSection('Experience');
  const timeline = el('div', 'pf-timeline');
  PROFILE.experience.forEach((job) => {
    const entry = el('div', 'pf-job' + (job.current ? ' is-current' : ''));
    const head = el('div', 'pf-job-head');
    head.appendChild(el('span', 'pf-job-role', job.role));
    head.appendChild(el('span', 'pf-job-period', job.period));
    entry.appendChild(head);
    entry.appendChild(el('div', 'pf-job-org', job.org));
    const ul = el('ul', 'pf-job-points');
    job.points.forEach((p) => ul.appendChild(el('li', '', p)));
    entry.appendChild(ul);
    timeline.appendChild(entry);
  });
  expSec.appendChild(timeline);
  cols.appendChild(expSec);

  // ---- right column -------------------------------------------------------
  const right = el('div', 'pf-right');

  const skillSec = pfSection('Skills');
  PROFILE.skills.forEach((g) => {
    const grp = el('div', 'pf-skill-group');
    grp.appendChild(el('div', 'pf-skill-label', g.group));
    const chips = el('div', 'pf-chips');
    g.items.forEach((it) => chips.appendChild(el('span', 'pf-chip', it)));
    grp.appendChild(chips);
    skillSec.appendChild(grp);
  });
  right.appendChild(skillSec);

  const certSec = pfSection('Certifications');
  const certList = el('ul', 'pf-certs');
  PROFILE.certs.forEach((c) => certList.appendChild(el('li', '', c)));
  certSec.appendChild(certList);
  right.appendChild(certSec);

  const eduSec = pfSection('Education');
  PROFILE.education.forEach((e) => {
    const row = el('div', 'pf-edu');
    row.appendChild(el('div', 'pf-edu-deg', e.deg));
    row.appendChild(el('div', 'pf-edu-school', e.school + ' · ' + e.place));
    row.appendChild(el('div', 'pf-edu-period', e.period));
    eduSec.appendChild(row);
  });
  right.appendChild(eduSec);

  cols.appendChild(right);
  host.appendChild(cols);

  // ---- projects -----------------------------------------------------------
  const projSec = pfSection('Projects');
  const projGrid = el('div', 'pf-projects');
  PROFILE.projects.forEach((p) => {
    const card = el('div', 'pf-project');
    const h = el('div', 'pf-project-head');
    h.appendChild(el('span', 'pf-project-name', p.name));
    if (p.tag) h.appendChild(el('span', 'pf-project-tag', p.tag));
    card.appendChild(h);
    card.appendChild(el('p', 'pf-project-desc', p.desc));
    if (p.link) {
      const a = el('a', 'pf-link pf-project-link', 'View repository');
      a.href = p.link; a.target = '_blank'; a.rel = 'noopener noreferrer';
      card.appendChild(a);
    }
    projGrid.appendChild(card);
  });
  projSec.appendChild(projGrid);
  host.appendChild(projSec);

  const intSec = pfSection('Outside work');
  const intChips = el('div', 'pf-chips');
  PROFILE.interests.forEach((i) => intChips.appendChild(el('span', 'pf-chip', i)));
  intSec.appendChild(intChips);
  host.appendChild(intSec);

  const back = el('button', 'pf-back', '← Back to the feed');
  back.type = 'button';
  back.addEventListener('click', () => { store.filter = 'all'; setView('feed'); });
  host.appendChild(back);
}

// --- Dark web view ----------------------------------------------------------
// Leak-site exposure search, CASM-style. The index is built by the pipeline and
// lazily fetched here (it is ~550 KB and only this view needs it), so search is
// instant, local, and never touches a rate-limited API.

const DARKWEB_INDEX_URL = 'data/api/darkweb_index.json';

function dwNorm(s) {
  return String(s || '').toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim();
}

// Mirrors darkweb.search_index() on the Python side so both agree on a hit.
function dwSearch(index, term, limit) {
  const q = dwNorm(term);
  if (!q || !index || !index.victims) return [];
  const out = [];
  for (const row of index.victims) {
    if (dwNorm(row.v).includes(q)) {
      out.push(row);
      if (out.length >= (limit || 100)) break;
    }
  }
  return out;
}

async function loadDarkwebIndex() {
  if (store.darkwebIndex !== null) return store.darkwebIndex;
  try {
    const resp = await fetch(DARKWEB_INDEX_URL, { cache: 'no-cache' });
    store.darkwebIndex = resp.ok ? await resp.json() : false;
  } catch (_) {
    store.darkwebIndex = false;
  }
  return store.darkwebIndex;
}

async function showDarkwebView() {
  hideAllViews();
  const host = $('darkweb-view');
  if (!host) return;
  host.style.display = 'block';
  host.replaceChildren(el('p', 'chart-empty', 'Loading leak-site index…'));

  const index = await loadDarkwebIndex();
  const summary = (store.meta && store.meta.darkweb) || null;
  host.replaceChildren();

  host.appendChild(el('h2', 'ls-title', 'Dark web — leak-site exposure'));
  host.appendChild(el('p', 'ls-sub',
    'Ransomware and extortion crews publish victims to their own Tor leak ' +
    'sites. Search that corpus for a company name, or keep a standing watch.'));

  // ---- headline tiles ------------------------------------------------------
  const tiles = el('div', 'ls-tiles');
  if (index && index.count) {
    tiles.appendChild(statTile('Listings indexed', index.count.toLocaleString(),
      (index.from || '?') + ' → ' + (index.to || '?')));
  }
  if (summary) {
    tiles.appendChild(statTile('Leak sites tracked', summary.tracked_leak_sites.toLocaleString()));
    tiles.appendChild(statTile('Groups active', String(summary.distinct_groups_active), 'recent window'));
    tiles.appendChild(statTile('Recent listings', String(summary.recent_posts)));
  }
  host.appendChild(tiles);

  // ---- search --------------------------------------------------------------
  const panel = lsPanel('Exposure search',
    'Type an organisation name. Matching is on the victim name as the crew ' +
    'published it, so try short forms and trading names too.');

  const form = el('div', 'dw-search');
  const input = el('input', 'dw-input');
  input.type = 'search';
  input.placeholder = 'e.g. Acme, Contoso Ltd, a supplier name…';
  input.setAttribute('aria-label', 'Search leak-site listings for an organisation');
  input.value = store.darkwebQuery || '';
  form.appendChild(input);

  const watchBtn = el('button', 'dw-watch-btn', '☆ Watch this name');
  watchBtn.type = 'button';
  form.appendChild(watchBtn);
  panel.appendChild(form);

  const results = el('div', 'dw-results');
  panel.appendChild(results);

  const runSearch = () => {
    const q = input.value.trim();
    store.darkwebQuery = q;
    results.replaceChildren();
    if (!index) {
      results.appendChild(el('p', 'chart-empty',
        'The leak-site index is not published yet — it appears after the next pipeline run.'));
      return;
    }
    if (q.length < 3) {
      results.appendChild(el('p', 'dw-hint', 'Enter at least 3 characters.'));
      return;
    }
    const hits = dwSearch(index, q, 100);
    watchBtn.style.display = 'inline-block';
    if (!hits.length) {
      const none = el('div', 'dw-none');
      none.appendChild(el('div', 'dw-none-head', 'No listing found for “' + q + '”'));
      none.appendChild(el('div', 'dw-none-body',
        'That name does not appear in the leak sites we track. This is NOT ' +
        'evidence of safety: it covers ransomware leak sites only, not forums, ' +
        'markets, credential dumps or infostealer logs.'));
      results.appendChild(none);
      return;
    }
    results.appendChild(el('div', 'dw-count',
      hits.length + (hits.length === 100 ? '+ ' : ' ') +
      'listing' + (hits.length === 1 ? '' : 's') + ' matching “' + q + '”'));
    results.appendChild(dwTable(hits));
  };

  input.addEventListener('input', debounceDw(runSearch, 180));
  input.addEventListener('keydown', (e) => { if (e.key === 'Enter') runSearch(); });
  watchBtn.addEventListener('click', () => {
    const q = input.value.trim();
    if (q.length < 3) return;
    if (!store.darkwebWatch.includes(q)) {
      store.darkwebWatch.push(q);
      writeLS(LS.darkwebWatch, store.darkwebWatch);
    }
    showDarkwebView();
  });
  host.appendChild(panel);
  if (store.darkwebQuery) runSearch();

  // ---- standing watch ------------------------------------------------------
  const watchPanel = lsPanel('Standing watch',
    'Names you are watching are re-checked against the index every time the ' +
    'page loads. For alerting between visits, set DARKWEB_WATCH in the ' +
    'pipeline so a hit raises a webhook.');
  if (!store.darkwebWatch.length) {
    watchPanel.appendChild(el('p', 'dw-hint',
      'No names watched yet. Search for one and press “Watch this name”.'));
  } else {
    store.darkwebWatch.forEach((term) => {
      const hits = index ? dwSearch(index, term, 50) : [];
      const row = el('div', 'dw-watch-row' + (hits.length ? ' is-hit' : ''));
      const left = el('div', 'dw-watch-left');
      left.appendChild(el('span', 'dw-watch-term', term));
      left.appendChild(el('span', 'dw-watch-status',
        hits.length ? hits.length + ' listing' + (hits.length === 1 ? '' : 's') + ' found'
                    : 'no listing in the tracked corpus'));
      row.appendChild(left);
      const rm = el('button', 'dw-watch-rm', 'Remove');
      rm.type = 'button';
      rm.addEventListener('click', () => {
        store.darkwebWatch = store.darkwebWatch.filter((t) => t !== term);
        writeLS(LS.darkwebWatch, store.darkwebWatch);
        showDarkwebView();
      });
      row.appendChild(rm);
      watchPanel.appendChild(row);
      if (hits.length) watchPanel.appendChild(dwTable(hits.slice(0, 5)));
    });
  }
  host.appendChild(watchPanel);

  // ---- pipeline-side watch hits -------------------------------------------
  const serverHits = (store.meta && store.meta.darkweb_watch) || [];
  if (serverHits.length) {
    const sp = lsPanel('Pipeline watchlist hits',
      'From DARKWEB_WATCH, checked server-side on every run.');
    serverHits.forEach((h) => {
      sp.appendChild(el('div', 'dw-watch-row is-hit',
        h.term + ' — ' + h.count + ' listing' + (h.count === 1 ? '' : 's')));
      sp.appendChild(dwTable(h.matches || []));
    });
    host.appendChild(sp);
  }

  // ---- sector benchmark ----------------------------------------------------
  const bench = await loadJsonOnce('benchmark', EXPOSURE_URLS.benchmark);
  const bpanel = buildSectorBenchmark(bench);
  if (bpanel) host.appendChild(bpanel);

  // ---- most active crews ---------------------------------------------------
  if (summary && (summary.most_active || []).length) {
    const ap = lsPanel('Most active crews', 'By listings in the recent window.');
    const rows = summary.most_active;
    const max = Math.max(1, ...rows.map((r) => r.posts));
    const bars = el('div', 'ls-bars');
    rows.slice(0, 8).forEach((r) => {
      const line = el('div', 'ls-bar-row');
      line.appendChild(el('span', 'ls-bar-name', r.group));
      const track = el('span', 'ls-bar-track');
      const fill = el('span', 'ls-bar-fill');
      fill.style.width = ((r.posts / max) * 100) + '%';
      fill.style.background = '#d6454f';
      track.appendChild(fill);
      line.appendChild(track);
      line.appendChild(el('span', 'ls-bar-val', String(r.posts)));
      bars.appendChild(line);
    });
    ap.appendChild(bars);
    host.appendChild(ap);
  }

  // ---- coverage, stated plainly -------------------------------------------
  const cov = (index && index.coverage) || null;
  const covPanel = el('details', 'dw-coverage');
  covPanel.appendChild(el('summary', 'dw-coverage-sum', 'What this does and does not cover'));
  if (cov) {
    const yes = el('div', 'dw-cov-block');
    yes.appendChild(el('div', 'dw-cov-h', 'Covers'));
    const ul = el('ul', 'dw-cov-list');
    cov.covers.forEach((c) => ul.appendChild(el('li', '', c)));
    yes.appendChild(ul);
    covPanel.appendChild(yes);

    const no = el('div', 'dw-cov-block');
    no.appendChild(el('div', 'dw-cov-h dw-cov-no', 'Does NOT cover'));
    const ul2 = el('ul', 'dw-cov-list');
    cov.does_not_cover.forEach((c) => ul2.appendChild(el('li', '', c)));
    no.appendChild(ul2);
    covPanel.appendChild(no);

    covPanel.appendChild(el('p', 'dw-cov-caveat', cov.caveat));
  }
  if (summary && summary.collection_note) {
    covPanel.appendChild(el('p', 'dw-cov-caveat', summary.collection_note));
  }
  host.appendChild(covPanel);
}

function dwTable(rows) {
  const wrap = el('div', 'dw-table-wrap');
  const table = el('table', 'dw-table');
  const head = el('tr', 'dw-thead');
  ['Victim', 'Claimed by', 'Date', 'Country', 'Sector'].forEach((h) => {
    head.appendChild(el('th', '', h));
  });
  table.appendChild(head);
  rows.forEach((r) => {
    const tr = el('tr', 'dw-trow');
    tr.appendChild(el('td', 'dw-td-victim', r.v || '—'));
    tr.appendChild(el('td', 'dw-td-group', r.g || '—'));
    tr.appendChild(el('td', 'dw-td-date', r.d || '—'));
    tr.appendChild(el('td', 'dw-td-cc', r.c || '—'));
    tr.appendChild(el('td', 'dw-td-sector', r.s || '—'));
    table.appendChild(tr);
  });
  wrap.appendChild(table);
  return wrap;
}

let dwTimer = null;
function debounceDw(fn, ms) {
  return () => { clearTimeout(dwTimer); dwTimer = setTimeout(fn, ms); };
}

// --- Exposure view (your own estate) ----------------------------------------
// The other half of CASM: not "who got hit" but "what of ours is already out
// there". Infostealer credential exposure, external attack surface from
// Certificate Transparency, and the public breach catalogue.

const EXPOSURE_URLS = {
  exposure: 'data/api/exposure.json',
  surface: 'data/api/attack_surface.json',
  breaches: 'data/api/breaches.json',
  benchmark: 'data/api/sector_benchmark.json',
};

async function loadJsonOnce(key, url) {
  if (store.casm[key] !== undefined) return store.casm[key];
  try {
    const resp = await fetch(url, { cache: 'no-cache' });
    store.casm[key] = resp.ok ? await resp.json() : null;
  } catch (_) {
    store.casm[key] = null;
  }
  return store.casm[key];
}

async function showExposureView() {
  hideAllViews();
  const host = $('exposure-view');
  if (!host) return;
  host.style.display = 'block';
  host.replaceChildren(el('p', 'chart-empty', 'Loading exposure…'));

  const [exposure, surface, breaches] = await Promise.all([
    loadJsonOnce('exposure', EXPOSURE_URLS.exposure),
    loadJsonOnce('surface', EXPOSURE_URLS.surface),
    loadJsonOnce('breaches', EXPOSURE_URLS.breaches),
  ]);
  host.replaceChildren();

  host.appendChild(el('h2', 'ls-title', 'Exposure — your own estate'));
  host.appendChild(el('p', 'ls-sub',
    'What of yours is already circulating, and what of yours is reachable ' +
    'from the internet. Set MY_DOMAINS in the pipeline to populate this.'));

  if (!exposure && !surface) {
    const empty = lsPanel('No domains configured',
      'This view fills once MY_DOMAINS is set on the pipeline.');
    const code = el('pre', 'ex-code',
      'MY_DOMAINS="example.com,example.co.uk"\nDARKWEB_WATCH="Example Corp,example.com"');
    empty.appendChild(code);
    empty.appendChild(el('p', 'ls-foot',
      'Set them as repository variables under Settings → Secrets and variables → Actions.'));
    host.appendChild(empty);
  }

  // ---- infostealer credential exposure ------------------------------------
  if (exposure && exposure.domains && exposure.domains.length) {
    const t = exposure.totals || {};
    const tiles = el('div', 'ls-tiles');
    tiles.appendChild(statTile('Employee machines', (t.employees || 0).toLocaleString(),
      'in infostealer logs'));
    tiles.appendChild(statTile('User machines', (t.users || 0).toLocaleString(),
      'customers / visitors'));
    tiles.appendChild(statTile('Third parties', (t.third_parties || 0).toLocaleString(),
      'supply chain'));
    host.appendChild(tiles);

    const panel = lsPanel('Credential exposure',
      'Machines found in infostealer logs with credentials for these domains. ' +
      'Employee machines matter most: those are corporate logins already in ' +
      'criminal hands.');
    exposure.domains.forEach((d) => {
      const row = el('div', 'ex-row' + (d.employees ? ' is-bad' : ''));
      const left = el('div', 'ex-row-left');
      left.appendChild(el('span', 'ex-domain', d.domain));
      const detail = [];
      if (d.employees) detail.push(d.employees.toLocaleString() + ' employee');
      if (d.users) detail.push(d.users.toLocaleString() + ' user');
      if (d.third_parties) detail.push(d.third_parties.toLocaleString() + ' third-party');
      left.appendChild(el('span', 'ex-detail',
        detail.length ? detail.join(' · ') + ' machine(s)' : 'no exposure found'));
      if (d.last_employee_compromised) {
        left.appendChild(el('span', 'ex-date',
          'Most recent employee compromise: ' + d.last_employee_compromised));
      }
      row.appendChild(left);
      row.appendChild(el('span', 'ex-total', (d.total || 0).toLocaleString()));
      panel.appendChild(row);
    });
    if (exposure.domains[0] && exposure.domains[0].note) {
      panel.appendChild(el('p', 'ls-foot', exposure.domains[0].note));
    }
    host.appendChild(panel);
  }

  // ---- attack surface ------------------------------------------------------
  if (surface && surface.domains && surface.domains.length) {
    const panel = lsPanel('External attack surface',
      'Hostnames seen in public Certificate Transparency logs. Names like ' +
      'dev, staging, vpn or admin are surfaced first — those are usually the ' +
      'shadow IT nobody told you about.');
    surface.domains.forEach((d) => {
      const head = el('div', 'ex-surface-head');
      head.appendChild(el('span', 'ex-domain', d.domain));
      head.appendChild(el('span', 'ex-detail',
        d.hostnames.toLocaleString() + ' hostname' + (d.hostnames === 1 ? '' : 's')));
      panel.appendChild(head);

      if (d.noteworthy && d.noteworthy.length) {
        const chips = el('div', 'ex-chips');
        d.noteworthy.forEach((h) => chips.appendChild(el('span', 'ex-chip is-flag', h)));
        panel.appendChild(chips);
      }
      if (d.sample && d.sample.length) {
        const det = el('details', 'ex-hosts');
        det.appendChild(el('summary', 'ex-hosts-sum',
          'All discovered hostnames' + (d.truncated ? ' (first ' + d.sample.length + ')' : '')));
        const chips = el('div', 'ex-chips');
        d.sample.forEach((h) => chips.appendChild(el('span', 'ex-chip', h)));
        det.appendChild(chips);
        panel.appendChild(det);
      }
    });
    if (surface.note) panel.appendChild(el('p', 'ls-foot', surface.note));
    host.appendChild(panel);
  }

  // ---- public breach catalogue --------------------------------------------
  if (breaches && breaches.recent) {
    const panel = lsPanel('Public breach catalogue',
      breaches.total_breaches.toLocaleString() + ' known breaches covering ' +
      breaches.total_accounts.toLocaleString() + ' accounts. Most recently added first.');
    const wrap = el('div', 'dw-table-wrap');
    const table = el('table', 'dw-table');
    const head = el('tr', 'dw-thead');
    ['Breach', 'Occurred', 'Accounts', 'Data exposed'].forEach((h) =>
      head.appendChild(el('th', '', h)));
    table.appendChild(head);
    breaches.recent.slice(0, 15).forEach((b) => {
      const tr = el('tr', 'dw-trow');
      tr.appendChild(el('td', 'dw-td-victim', b.name || b.domain || '—'));
      tr.appendChild(el('td', 'dw-td-date', b.date || '—'));
      tr.appendChild(el('td', 'dw-td-cc', (b.accounts || 0).toLocaleString()));
      tr.appendChild(el('td', 'dw-td-sector', (b.classes || []).slice(0, 4).join(', ')));
      table.appendChild(tr);
    });
    wrap.appendChild(table);
    panel.appendChild(wrap);
    panel.appendChild(el('p', 'ls-foot', 'Source: ' + breaches.source));
    host.appendChild(panel);
  }
}

// --- Sector benchmarking (rendered on the Dark Web view) --------------------
function buildSectorBenchmark(bench) {
  if (!bench || !bench.sectors || !bench.sectors.length) return null;
  const fig = lsPanel('Sector benchmark',
    bench.note || 'Leak-site listings this window against the previous one.');
  const max = Math.max(1, ...bench.sectors.map((s) => s.current));
  const list = el('div', 'ls-bars');
  bench.sectors.slice(0, 12).forEach((s) => {
    const row = el('div', 'ls-bar-row');
    row.appendChild(el('span', 'ls-bar-name', s.sector));
    const track = el('span', 'ls-bar-track');
    const fill = el('span', 'ls-bar-fill');
    fill.style.width = ((s.current / max) * 100) + '%';
    fill.style.background = s.direction === 'up' ? '#e0653f'
      : s.direction === 'down' ? '#3fae8c' : SERIES_1;
    track.appendChild(fill);
    row.appendChild(track);
    const arrow = s.direction === 'up' ? '▲' : s.direction === 'down' ? '▼'
      : s.direction === 'new' ? '＋' : '–';
    const cls = s.direction === 'up' ? 'ls-up' : s.direction === 'down' ? 'ls-down' : 'ls-flat';
    const label = s.change_pct === null ? 'new'
      : (s.change_pct > 0 ? '+' : '') + s.change_pct + '%';
    const val = el('span', 'ls-bar-val ' + cls, arrow + ' ' + s.current + ' (' + label + ')');
    val.title = s.current + ' this window vs ' + s.previous + ' previous';
    row.appendChild(val);
    list.appendChild(row);
  });
  fig.appendChild(list);
  return fig;
}

const VIEW_NODES = ['loading-state', 'error-state', 'cards-container', 'matrix-view',
  'trends-view', 'map-view', 'landscape-view', 'geopol-view', 'about-view',
  'darkweb-view', 'exposure-view', 'no-results', 'graph-view', 'campaigns-view',
  'detections-view', 'malware-view', 'research-view', 'diff-view',
  'library-view', 'hunt-view', 'leaks-view', 'contact-view',
  'recon-view', 'creds-view', 'kev-view', 'lifecycle-view', 'cve-view',
  'ioc-view', 'phish-view',
  'triage-bar', 'triage-done'];

function hideAllViews() {
  // The map runs a rAF loop; leaving the view must stop it or it burns CPU
  // in the background forever.
  if (typeof stopMapAnimation === 'function') stopMapAnimation();
  VIEW_NODES.forEach((id) => { const n = $(id); if (n) n.style.display = 'none'; });
}

function showContent() {
  hideAllViews();
  const container = $('cards-container');
  if (container) container.style.display = 'grid';
}

/**
 * Show one of the v4 views, rendering it through a builder that may need to
 * fetch its data first. Keeps the loading/error handling in one place instead
 * of repeating it in seven view functions.
 */
async function showLazyView(nodeId, apiKey, builder, emptyMessage) {
  hideAllViews();
  const host = $(nodeId);
  if (!host) return;
  host.style.display = 'block';
  host.replaceChildren(el('div', 'view-loading', 'Loading…'));
  let data = store.research[apiKey];
  if (data === undefined) {
    try {
      const resp = await fetch(API[apiKey], { cache: 'no-cache' });
      data = resp.ok ? await resp.json() : null;
      // Same synthetic offline response as in loadIntelData(). Treated as no
      // data, so the view says so instead of rendering an empty chart that
      // looks like a real measurement of nothing.
      if (data && data.offline) data = null;
    } catch (_) { data = null; }
    store.research[apiKey] = data;
  }
  // The view may have changed while the fetch was in flight.
  if (host.style.display === 'none') return;
  host.replaceChildren();
  if (!data) {
    host.appendChild(emptyState(emptyMessage));
    return;
  }
  try {
    builder(host, data);
  } catch (err) {
    host.replaceChildren(emptyState(`Could not render this view: ${err.message}`));
  }
}

function emptyState(message) {
  const box = el('div', 'view-empty');
  box.appendChild(el('p', 'view-empty-icon', '◌'));
  box.appendChild(el('p', 'view-empty-text', message));
  return box;
}

// ─── Theme ────────────────────────────────────────────────────────────────────
// Three states, not two: `auto` follows the OS, and light and dark are explicit
// overrides. A tool read for long stretches in a bright room needs a light
// mode, and the CSS was already fully tokenised, so this is a token swap
// rather than a restyle.
const THEME_CYCLE = { auto: 'light', light: 'dark', dark: 'auto' };
const THEME_ICON = { auto: '◐', light: '☀', dark: '☾' };

function applyTheme() {
  const root = document.documentElement;
  if (store.theme === 'auto') root.removeAttribute('data-theme');
  else root.setAttribute('data-theme', store.theme);
  const btn = $('theme-toggle');
  if (btn) {
    btn.textContent = THEME_ICON[store.theme] || '◐';
    btn.title = `Theme: ${store.theme} (click for ${THEME_CYCLE[store.theme]})`;
  }
}

function cycleTheme() {
  store.theme = THEME_CYCLE[store.theme] || 'auto';
  writeLS(LS.theme, store.theme);
  applyTheme();
}

function showError(message) {
  hideAllViews();
  const node = $('error-state');
  if (node) {
    node.style.display = 'block';
    const detail = node.querySelector('.error-detail');
    if (detail) detail.textContent = message || '';
  }
}

/**
 * Route on VIEW, not on filter.
 *
 * The old build routed both through store.filter, which is exactly why the two
 * were indistinguishable in the UI: they were the same variable.
 */
function renderAll() {
  syncControls();
  // The header counts and the "updated N minutes ago" line describe the FEED,
  // not the current view, so they must not depend on the feed being rendered.
  // They used to be updated only inside renderSidebar(), which the feed branch
  // alone reaches — so opening the dashboard on a shared #view=graph link left
  // the header reading "Initializing feed…" and four em-dashes, for a feed
  // that had in fact loaded fine.
  updateHeaderStats();
  switch (store.view) {
    case 'matrix':     showMatrixView(); return;
    case 'trends':     showTrendsView(); return;
    case 'map':        showMapView(); return;
    case 'landscape':  showLandscapeView(); return;
    case 'geopol':     showGeopolView(); return;
    case 'about':      showAboutView(); return;
    case 'darkweb':    showDarkwebView(); return;
    case 'exposure':   showExposureView(); return;
    case 'graph':      showGraphView(); return;
    case 'campaigns':  showCampaignsView(); return;
    case 'detections': showDetectionsView(); return;
    case 'malware':    showMalwareView(); return;
    case 'research':   showResearchView(); return;
    case 'diff':       showDiffView(); return;
    case 'library':    showLibraryView(); return;
    case 'hunt':       showHuntView(); return;
    case 'leaks':      showLeaksView(); return;
    case 'contact':    showContactView(); return;
    case 'recon':      showReconView(); return;
    case 'creds':      showCredsView(); return;
    case 'kev':        showKevView(); return;
    case 'lifecycle':  showLifecycleView(); return;
    case 'cve':        showCveView(); return;
    case 'ioc':        showIocView(); return;
    case 'phish':      showPhishView(); return;
    default: break;
  }
  showContent();
  renderBrief();
  renderCards();
  renderSidebar();
}

/** Count the filters currently narrowing the feed, for the FILTERS badge. */
function activeFilterCount() {
  let n = 0;
  if (store.severity) n += 1;
  if (store.sector) n += 1;
  if (store.provenance) n += 1;
  if (store.humanOnly) n += 1;
  if (store.watchlistOnly) n += 1;
  if (store.query) n += 1;
  return n;
}

function syncControls() {
  const inFeed = store.view === 'feed';
  const controls = $('feed-controls');
  // Feed filters are meaningless while a map is on screen, so they leave with
  // the feed rather than sitting there doing nothing.
  if (controls) controls.style.display = inFeed ? '' : 'none';
  const brief = $('daily-brief');
  if (brief && !inFeed) brief.style.display = 'none';
  // Same for the row carrying "Showing 40 of 66" and the density/sort toggles:
  // it sat above the entity graph reading "Loading intelligence feed…".
  const feedHeader = document.querySelector('.feed-header');
  if (feedHeader) feedHeader.style.display = inFeed ? '' : 'none';

  renderModeNav();
  // The sub-nav appears and disappears with the mode, so the pinned height
  // changes with it.
  syncStickyOffsets();
  document.querySelectorAll('.stat-pill.is-clickable').forEach((p) => {
    const w = p.dataset.stat;
    const active = w === 'urgent' ? store.filter === 'urgent'
      : w === 'total' ? (store.filter === 'all' && !store.severity && !store.sector && !store.query)
      : store.severity === w;
    p.classList.toggle('is-active', !!active);
  });
  document.querySelectorAll('.filter-btn').forEach((b) => {
    b.classList.toggle('active', b.dataset.filter === store.filter);
  });
  document.querySelectorAll('.sev-row').forEach((b) => {
    b.classList.toggle('active', b.dataset.severity === store.severity);
  });
  const sortBtn = $('sort-toggle');
  if (sortBtn) {
    sortBtn.textContent = store.sort === 'priority' ? '⚑ TOP PRIORITY' : '↓ LATEST FIRST';
  }
  const densityBtn = $('density-toggle');
  if (densityBtn) {
    densityBtn.textContent = store.density === 'compact' ? '▤ COMPACT' : '▥ COMFORTABLE';
  }
  const filterBadge = $('active-filter-count');
  if (filterBadge) {
    const n = activeFilterCount();
    filterBadge.textContent = n ? String(n) : '';
    filterBadge.style.display = n ? '' : 'none';
  }
  const timeBtn = $('timemachine-open');
  if (timeBtn) {
    timeBtn.textContent = store.day ? `🕰 ${store.day}` : '🕰 TODAY';
    timeBtn.classList.toggle('is-active', !!store.day);
  }
  const search = $('search-input');
  if (search && search.value !== store.query) search.value = store.query;
}

function update() {
  applyFilters();
  renderAll();
}

/**
 * Set the search box contents AND re-parse it.
 *
 * Anything that writes store.query must go through here, otherwise a
 * previously-parsed structured query stays armed and silently filters against
 * a string the user can no longer see.
 */
function setQuery(text) {
  store.query = String(text || '');
  store.parsedQuery = (store.query && typeof parseQuery === 'function')
    ? parseQuery(store.query) : null;
  const input = $('search-input');
  if (input) input.value = store.query;
}

/** Return to the feed and re-filter. Used by anything that arms a feed filter. */
function backToFeed() {
  if (store.view !== 'feed') {
    store.view = 'feed';
    writeLS(LS.view, 'feed');
  }
  update();
}

// Views worth returning to. `diff` is a comparison of two specific dates and
// `about` is a profile page — reopening the dashboard onto either is landing
// on someone else's leftovers, not on your dashboard.
const TRANSIENT_VIEWS = new Set(['diff', 'about', 'contact']);

/**
 * Paint the mode row and rebuild the sub-nav for the active mode.
 *
 * The sub-nav is built rather than written into the HTML so MODE_VIEWS stays
 * the single source of truth: a view added to that table appears in the nav
 * automatically, and one removed cannot leave an orphaned button that routes
 * nowhere.
 */
function renderModeNav() {
  const mode = modeOf(store.view);
  document.querySelectorAll('.mode-btn').forEach((b) => {
    const active = b.dataset.mode === mode;
    b.classList.toggle('active', active);
    b.setAttribute('aria-current', active ? 'page' : 'false');
  });

  const strip = $('view-switcher');
  if (!strip) return;
  const views = MODE_VIEWS[mode] || [];
  // A one-view mode needs no switcher, and showing a single disabled-looking
  // button is worse than showing nothing.
  if (views.length < 2) {
    strip.replaceChildren();
    strip.style.display = 'none';
    return;
  }
  strip.style.display = '';
  strip.replaceChildren();
  views.forEach(([view, label]) => {
    const btn = el('button', `view-btn${view === store.view ? ' active' : ''}`, label);
    btn.type = 'button';
    btn.dataset.view = view;
    btn.setAttribute('aria-current', view === store.view ? 'page' : 'false');
    strip.appendChild(btn);
  });
}

/**
 * Publish the real height of the pinned chrome as CSS variables.
 *
 * The sticky bars cannot hard-code their offsets, because the header's height
 * is not a constant. A v4 fix gave it `flex-wrap: wrap; height: auto` so the
 * four stat pills stop overlapping on a narrow window — correct in itself, but
 * it means the header is 60px wide-open and 86px at ~880px, and every bar
 * below it was still pinned at `top: 60px`. The header then covered them, and
 * once v5 added a second nav row at that same offset the mode row and the view
 * row were painted on top of each other.
 *
 * Measuring is the only thing that survives wrapping, late font loading, zoom,
 * a long "updated N minutes ago" string, and the mobile breakpoints.
 */
function syncStickyOffsets() {
  const header = document.querySelector('.site-header');
  const modes = document.querySelector('.mode-switcher');
  if (!header) return;
  // Only bars that are ACTUALLY PINNED contribute. Below 640px the header is
  // `position: static` — it scrolls away — so counting its height would push
  // everything below it down by 85px of nothing.
  const pinnedHeight = (node) => {
    if (!node) return 0;
    const style = getComputedStyle(node);
    if (style.display === 'none' || style.position !== 'sticky') return 0;
    return Math.round(node.getBoundingClientRect().height);
  };
  const headerH = pinnedHeight(header);
  const modesH = pinnedHeight(modes);
  const root = document.documentElement.style;
  root.setProperty('--stack-header', `${headerH}px`);
  root.setProperty('--stack-nav', `${headerH + modesH}px`);
}

/** Keep the offsets correct as the chrome reflows. */
function watchStickyOffsets() {
  syncStickyOffsets();
  if (typeof ResizeObserver === 'function') {
    const ro = new ResizeObserver(() => syncStickyOffsets());
    ['.site-header', '.mode-switcher'].forEach((sel) => {
      const node = document.querySelector(sel);
      if (node) ro.observe(node);
    });
  } else {
    window.addEventListener('resize', syncStickyOffsets);
  }
  // Fonts land after first paint and change the header's height with them.
  if (document.fonts && document.fonts.ready) {
    document.fonts.ready.then(syncStickyOffsets).catch(() => {});
  }
}

/** Switch mode, landing on that mode's first view. */
function setMode(mode) {
  const views = MODE_VIEWS[mode];
  if (!views || !views.length) return;
  // Returning to the mode you are already in should not throw away where you
  // were inside it.
  if (modeOf(store.view) === mode) return;
  setView(views[0][0]);
}

/** Switch the primary view. Views replace the screen; filters do not. */
function setView(view) {
  if (!VIEWS.includes(view)) return;
  store.view = view;
  writeLS(LS.view, TRANSIENT_VIEWS.has(view) ? 'feed' : view);
  writeUrlState();
  renderAll();
}

// ─── Slide-over panels ────────────────────────────────────────────────────────
const PANEL_IDS = { filters: 'filter-panel', timemachine: 'timemachine-panel', saved: 'saved-panel' };

function openPanel(which) {
  const node = $(PANEL_IDS[which]);
  if (!node) return;
  Object.values(PANEL_IDS).forEach((id) => { const n = $(id); if (n) n.style.display = 'none'; });
  node.style.display = 'block';
  document.body.classList.add('panel-open');
  if (which === 'filters') renderSidebar();
  if (which === 'saved') { renderSaved(); $('saved-name')?.focus(); }
  if (which === 'timemachine' && typeof renderTimeMachine === 'function') renderTimeMachine();
}

function closePanel(which) {
  const node = which ? $(PANEL_IDS[which]) : null;
  if (node) node.style.display = 'none';
  else Object.values(PANEL_IDS).forEach((id) => { const n = $(id); if (n) n.style.display = 'none'; });
  if (!Object.values(PANEL_IDS).some((id) => $(id) && $(id).style.display === 'block')) {
    document.body.classList.remove('panel-open');
  }
}

function resetFilters() {
  store.severity = null;
  store.sector = null;
  store.provenance = null;
  store.humanOnly = false;
  store.watchlistOnly = false;
  store.query = '';
  store.parsedQuery = null;
  writeLS(LS.severity, null);
  writeLS(LS.watchlistOnly, false);
  update();
}

// ─── Entity drawer (actors, malware, techniques) ──────────────────────────────
function openEntityModal(kind, name) {
  const modal = $('entity-modal');
  const body = $('entity-body');
  const title = $('entity-title');
  if (!modal || !body) return;
  modal.style.display = 'flex';
  if (title) title.textContent = name;
  body.replaceChildren(el('div', 'modal-loading', 'Gathering what we know…'));

  const related = store.items.filter((i) => (
    kind === 'actor' ? (i.threat_actors || []).some((a) => a.toLowerCase() === name.toLowerCase())
      : kind === 'malware' ? (i.malware || []).some((m) => m.toLowerCase() === name.toLowerCase())
        : (i.ttps || []).some((t) => t.id === name)
  ));

  body.replaceChildren();
  const head = el('div', 'entity-head');
  head.appendChild(el('span', `entity-kind entity-${kind}`, kind.toUpperCase()));
  head.appendChild(el('span', 'entity-count',
    `${related.length} item${related.length === 1 ? '' : 's'} in the current feed`));
  body.appendChild(head);

  // Known facts from the published graph / malware endpoints, when loaded.
  const graph = store.research.graph;
  const node = graph && graph.nodes.find(
    (n) => n.type === kind && n.label.toLowerCase() === name.toLowerCase());
  if (node) {
    if (node.aliases && node.aliases.length) {
      body.appendChild(el('div', 'modal-section-title', 'Also known as'));
      const chips = el('div', 'entity-chips');
      node.aliases.forEach((a) => chips.appendChild(el('span', 'entity-chip', a)));
      body.appendChild(chips);
    }
    const linked = graph.edges.filter(
      (e) => e.source === node.id || e.target === node.id);
    const known = linked.filter((e) => e.origin === 'attack');
    const seen = linked.filter((e) => e.origin === 'observed');
    if (known.length) {
      body.appendChild(el('div', 'modal-section-title',
        `Known relationships (MITRE ATT&CK) — ${known.length}`));
      body.appendChild(edgeList(known, node.id, graph));
    }
    if (seen.length) {
      body.appendChild(el('div', 'modal-section-title',
        `Observed in this feed — ${seen.length}`));
      body.appendChild(edgeList(seen, node.id, graph));
    }
    if (node.url) {
      const link = el('a', 'modal-ref-link', 'MITRE ATT&CK profile');
      link.href = safeUrl(node.url); link.target = '_blank'; link.rel = 'noopener noreferrer';
      body.appendChild(link);
    }
  } else if (!store.research.graph) {
    body.appendChild(el('p', 'entity-hint',
      'Open the Graph view once to load ATT&CK relationships for this entity.'));
  }

  if (related.length) {
    body.appendChild(el('div', 'modal-section-title', 'In the feed'));
    const list = el('div', 'entity-items');
    related.slice(0, 12).forEach((item) => {
      const row = el('div', 'entity-item');
      const href = safeUrl(item.url);
      if (href) {
        const a = el('a', 'entity-item-title', item.title || '');
        a.href = href; a.target = '_blank'; a.rel = 'noopener noreferrer';
        row.appendChild(a);
      } else {
        row.appendChild(el('span', 'entity-item-title', item.title || ''));
      }
      row.appendChild(el('span', 'entity-item-meta',
        `${item.source || ''} · ${item.published ? timeAgo(new Date(item.published)) : ''}`));
      list.appendChild(row);
    });
    body.appendChild(list);
  }

  // The drawer is a summary. The Library entry is the whole record — aliases
  // from every corpus, the arsenal, the campaigns, the literature — so the
  // drawer should hand the reader over to it rather than being a dead end.
  const libBtn = el('button', 'entity-lib-btn', `Open the full library entry for ${name}`);
  libBtn.type = 'button';
  libBtn.addEventListener('click', () => {
    closeEntityModal();
    if (typeof libJump === 'function') {
      libJump(name, kind === 'actor' ? 'actor' : 'malware');
    }
  });
  body.appendChild(libBtn);

  const filterBtn = el('button', 'entity-filter-btn', `Filter the feed to ${name}`);
  filterBtn.type = 'button';
  filterBtn.dataset.entityFilter = name;
  body.appendChild(filterBtn);
}

function edgeList(edges, selfId, graph) {
  const labels = {};
  graph.nodes.forEach((n) => { labels[n.id] = n.name ? `${n.label} ${n.name}` : n.label; });
  const list = el('div', 'edge-list');
  edges.slice(0, 40).forEach((e) => {
    const otherId = e.source === selfId ? e.target : e.source;
    const row = el('div', 'edge-row');
    row.appendChild(el('span', 'edge-kind', e.kind));
    row.appendChild(el('span', 'edge-target', labels[otherId] || otherId));
    if (e.origin === 'observed' && e.weight > 1) {
      row.appendChild(el('span', 'edge-weight', `x${e.weight}`));
    }
    list.appendChild(row);
  });
  if (edges.length > 40) {
    list.appendChild(el('div', 'edge-more', `+${edges.length - 40} more`));
  }
  return list;
}

function closeEntityModal() {
  const modal = $('entity-modal');
  if (modal) modal.style.display = 'none';
}

// ─── Command palette ──────────────────────────────────────────────────────────
function paletteCommands() {
  const cmds = [
    { label: 'Sort by priority', hint: 'Blended CVSS + EPSS + KEV + SSVC', run: () => { store.sort = 'priority'; writeLS(LS.sort, store.sort); update(); } },
    { label: 'Sort by newest', hint: 'Publication time', run: () => { store.sort = 'latest'; writeLS(LS.sort, store.sort); update(); } },
    { label: 'Show all items', hint: 'including the ones with no verdict', run: () => { store.filter = 'all'; store.severity = null; update(); } },
    { label: 'Show actively exploited', hint: 'KEV, SSVC active, or public PoC', run: () => { store.filter = 'exploited'; update(); } },
    { label: 'Show items affecting my stack', run: () => { store.filter = 'stack'; update(); } },
    { label: 'Show starred', run: () => { store.filter = 'starred'; update(); } },
    { label: 'Toggle dismissed items', run: () => { store.showDismissed = !store.showDismissed; update(); } },
    { label: 'Clear all dismissals', run: () => { store.dismissed.clear(); writeLS(LS.dismissed, []); update(); } },
    { label: "Show today's verdicts", hint: 'the items the tool has an opinion about', run: () => { store.filter = 'verdicts'; update(); } },
    { label: 'Show what is new to you', hint: 'published since your last visit', run: () => { store.filter = 'fresh'; update(); } },
    { label: 'Toggle density', run: () => toggleDensity() },
    { label: 'Cycle theme (auto / light / dark)', run: () => cycleTheme() },
    { label: 'Open filters', run: () => openPanel('filters') },
    { label: 'Reset all filters', run: () => resetFilters() },
    { label: 'Open the time machine', hint: 'any of the last 90 days', run: () => openPanel('timemachine') },
    { label: 'Compare two days', hint: 'what changed', run: () => setView('diff') },
    { label: 'Save this investigation', run: () => openPanel('saved') },
    { label: 'Copy shareable link', run: () => copyText(location.href, 'Link copied') },
    { label: 'Export current view as CSV', run: () => exportCsv() },
    { label: 'Export analyst notes as markdown', run: () => exportNotes() },
    { label: 'Clear review marks', run: () => { store.reviewed.clear(); writeLS(LS.reviewed, []); update(); } },
  ];
  cmds.push({
    label: 'Search the library',
    hint: 'any actor, malware, technique or alias',
    run: () => setView('library'),
  });
  cmds.push({
    label: "Today's hunt queue",
    hint: 'generated from what is active now',
    run: () => { if (typeof huntState === 'object') huntState.tab = 'queue'; setView('hunt'); },
  });
  cmds.push({
    label: 'Detection coverage vs live activity',
    hint: 'paste your rule inventory',
    run: () => { if (typeof huntState === 'object') huntState.tab = 'coverage'; setView('hunt'); },
  });
  cmds.push({
    label: 'Ransomware leak sites',
    hint: 'who is claiming victims',
    run: () => setView('leaks'),
  });
  MODES.forEach((mode) => {
    cmds.push({ label: `Go to ${mode}`, hint: 'mode', run: () => setMode(mode) });
  });
  VIEWS.filter((v) => v !== 'about' && v !== 'diff').forEach((view) => {
    cmds.push({ label: `Go to ${view}`, hint: 'view', run: () => setView(view) });
  });
  SEVERITY_ORDER.forEach((sev) => {
    cmds.push({
      label: `Filter: ${sev}`,
      hint: 'severity',
      run: () => { store.severity = store.severity === sev ? null : sev; update(); },
    });
  });
  CATEGORIES.forEach((cat) => {
    cmds.push({ label: `Filter: ${cat}`, hint: 'category', run: () => { store.filter = cat; update(); } });
  });
  return cmds;
}

let paletteIndex = 0;
let paletteMatches = [];

function openPalette() {
  const overlay = $('palette');
  if (!overlay) return;
  overlay.style.display = 'flex';
  const input = $('palette-input');
  if (input) { input.value = ''; input.focus(); }
  renderPalette('');
}

function closePalette() {
  const overlay = $('palette');
  if (overlay) overlay.style.display = 'none';
}

function renderPalette(query) {
  const list = $('palette-list');
  if (!list) return;
  const q = query.trim().toLowerCase();
  const cmds = paletteCommands();

  paletteMatches = q
    ? cmds.filter((c) => c.label.toLowerCase().includes(q))
    : cmds.slice(0, 10);

  // The Library is the other reason to open this: typing any vendor's name for
  // an actor should land on the canonical page. Only searched once the index
  // has been loaded by visiting the Library — the palette must not trigger a
  // 370 KB download on a keystroke.
  if (q.length >= 2 && typeof libState === 'object' && libState.index) {
    libSearch(libState.index, q, 'all').slice(0, 6).forEach((row) => {
      const aka = (row.aliases || []).length
        ? `${row.kind} · aka ${row.aliases.slice(0, 3).join(', ')}`
        : row.kind;
      paletteMatches.push({
        label: row.id ? `${row.name} (${row.id})` : row.name,
        hint: aka,
        run: () => libOpen(row.slug),
      });
    });
  }

  // Jumping straight to a CVE is the most common reason to open this.
  if (q.length >= 3) {
    store.items
      .filter((i) => `${i.cve_id || ''} ${i.title}`.toLowerCase().includes(q))
      .slice(0, 6)
      .forEach((item) => {
        paletteMatches.push({
          label: item.cve_id ? `${item.cve_id} — ${item.title}` : item.title,
          hint: item.source,
          run: () => { setQuery(item.cve_id || item.title.slice(0, 40)); store.filter = 'all'; backToFeed(); },
        });
      });
  }

  paletteIndex = 0;
  list.replaceChildren();
  paletteMatches.forEach((cmd, i) => {
    const row = el('button', `palette-row${i === 0 ? ' active' : ''}`);
    row.type = 'button';
    row.dataset.idx = String(i);
    row.appendChild(el('span', 'palette-label', cmd.label));
    if (cmd.hint) row.appendChild(el('span', 'palette-hint', cmd.hint));
    list.appendChild(row);
  });
  if (!paletteMatches.length) list.appendChild(el('div', 'palette-empty', 'No matching command'));
}

function movePalette(delta) {
  const rows = document.querySelectorAll('.palette-row');
  if (!rows.length) return;
  rows[paletteIndex]?.classList.remove('active');
  paletteIndex = (paletteIndex + delta + rows.length) % rows.length;
  rows[paletteIndex].classList.add('active');
  rows[paletteIndex].scrollIntoView({ block: 'nearest' });
}

function runPalette(index) {
  const cmd = paletteMatches[index];
  closePalette();
  if (cmd) cmd.run();
}

// ─── Triage ───────────────────────────────────────────────────────────────────
function toggleSet(set, key, lsKey) {
  if (set.has(key)) set.delete(key); else set.add(key);
  writeLS(lsKey, [...set]);
}

function cardForKey(key) {
  return document.querySelector(`.intel-card[data-key="${CSS.escape(key)}"]`);
}

function moveCursor(delta) {
  const cards = [...document.querySelectorAll('.intel-card')];
  if (!cards.length) return;
  cards[store.cursor]?.classList.remove('cursor');
  const start = store.cursor < 0 ? (delta > 0 ? -1 : 0) : store.cursor;
  store.cursor = Math.max(0, Math.min(cards.length - 1, start + delta));
  const card = cards[store.cursor];
  card.classList.add('cursor');
  card.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
}

function currentItem() {
  const cards = [...document.querySelectorAll('.intel-card')];
  const card = cards[store.cursor];
  if (!card) return null;
  return store.filtered.find((i) => i._key === card.dataset.key) || null;
}

function copyText(text, message) {
  navigator.clipboard?.writeText(text)
    .then(() => showToast(message || 'Copied'))
    .catch(() => showToast('Copy failed'));
}

function itemAsMarkdown(item) {
  const bits = [`## ${item.title}`, ''];
  if (item.action) bits.push(`**${item.action}** — ${item.action_detail || ''}`, '');
  if (item.cve_id) bits.push(`- CVE: ${item.cve_id}`);
  if (item.priority_score != null) bits.push(`- Priority: P${Math.round(item.priority_score)} (${item.priority_rationale || ''})`);
  if (item.cvss_score != null) bits.push(`- CVSS: ${item.cvss_score}`);
  if (item.epss_score != null) bits.push(`- EPSS: ${(item.epss_score * 100).toFixed(2)}%`);
  if (item.cisa_kev) bits.push('- CISA KEV: yes');
  if (item.ssvc_exploitation) bits.push(`- SSVC exploitation: ${item.ssvc_exploitation}`);
  if (item.source) bits.push(`- Source: ${item.source}`);
  const url = safeUrl(item.url);
  if (url) bits.push(`- Link: ${url}`);
  bits.push('', displaySummary(item));
  return bits.join('\n');
}

function exportCsv() {
  const cols = ['title', 'cve_id', 'severity', 'priority_score', 'priority_label',
    'action', 'cvss_score', 'epss_score', 'cisa_kev', 'ssvc_exploitation', 'source', 'published', 'url'];
  const esc = (v) => `"${String(v ?? '').replace(/"/g, '""')}"`;
  const lines = [cols.join(',')];
  store.filtered.forEach((i) => lines.push(cols.map((c) => esc(i[c])).join(',')));
  const blob = new Blob([lines.join('\n')], { type: 'text/csv' });
  const a = el('a');
  a.href = URL.createObjectURL(blob);
  a.download = `openthreat-${new Date().toISOString().slice(0, 10)}.csv`;
  a.click();
  URL.revokeObjectURL(a.href);
  showToast(`Exported ${store.filtered.length} items`);
}

function toggleDensity() {
  store.density = store.density === 'compact' ? 'comfortable' : 'compact';
  writeLS(LS.density, store.density);
  renderCards();
  syncControls();
}

// ─── CVE modal ────────────────────────────────────────────────────────────────
async function openCveModal(cveId) {
  const modal = $('cve-modal');
  const body = $('modal-body');
  const titleNode = $('modal-cve-id');
  if (!modal || !body) return;
  if (!/^CVE-\d{4}-\d{4,7}$/i.test(cveId)) return;

  modal.style.display = 'flex';
  if (titleNode) titleNode.textContent = cveId.toUpperCase();
  body.replaceChildren(el('div', 'modal-loading', 'Fetching NVD details…'));

  const local = store.items.find((i) => (i.cve_id || '').toUpperCase() === cveId.toUpperCase());
  try {
    const resp = await fetch(
      `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${encodeURIComponent(cveId)}`);
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const data = await resp.json();
    const vuln = data?.vulnerabilities?.[0]?.cve;
    if (!vuln) throw new Error('Not found in NVD');

    body.replaceChildren();
    const desc = (vuln.descriptions || []).find((d) => d.lang === 'en')?.value || 'No description.';

    let score = null; let vector = null; let sev = 'UNKNOWN';
    for (const metric of ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']) {
      const m = vuln.metrics?.[metric];
      if (m?.length) {
        score = m[0].cvssData?.baseScore;
        vector = m[0].cvssData?.vectorString;
        sev = m[0].cvssData?.baseSeverity || sev;
        break;
      }
    }

    const stats = el('div', 'modal-grid');
    const stat = (label, value) => {
      const box = el('div', 'modal-stat');
      box.appendChild(el('div', 'modal-stat-label', label));
      box.appendChild(el('div', 'modal-stat-value', value));
      stats.appendChild(box);
    };
    stat('CVSS', score != null ? String(score) : 'N/A');
    stat('Severity', String(sev));
    stat('EPSS', local?.epss_score != null ? `${(local.epss_score * 100).toFixed(2)}%` : 'N/A');
    stat('Priority', local?.priority_score != null ? `P${Math.round(local.priority_score)}` : 'N/A');
    if (local?.ssvc_exploitation) stat('SSVC', local.ssvc_exploitation);
    if (local?.ssvc_automatable) stat('Automatable', local.ssvc_automatable);
    stat('Published', vuln.published ? vuln.published.slice(0, 10) : 'N/A');
    stat('Modified', vuln.lastModified ? vuln.lastModified.slice(0, 10) : 'N/A');
    body.appendChild(stats);

    if (local?.action) {
      const rec = el('div', `modal-action prio-${local.priority_label}`);
      rec.appendChild(el('strong', null, local.action));
      rec.appendChild(el('span', null, ` — ${local.action_detail || ''}`));
      body.appendChild(rec);
    }

    body.appendChild(el('div', 'modal-section-title', 'Description'));
    body.appendChild(el('p', 'modal-desc', desc));
    if (vector) {
      body.appendChild(el('div', 'modal-section-title', 'Vector'));
      body.appendChild(el('code', 'modal-vector', vector));
    }

    const links = el('div', 'modal-xrefs');
    const xref = (label, url) => {
      const a = el('a', 'modal-ref-link', label);
      a.href = url; a.target = '_blank'; a.rel = 'noopener noreferrer';
      links.appendChild(a);
    };
    // Encoded, not interpolated raw: cveId originates in feed data, and an
    // unencoded value can bend the path or query even though the origin is fixed.
    const cveParam = encodeURIComponent(cveId);
    xref('NVD', `https://nvd.nist.gov/vuln/detail/${cveParam}`);
    xref('MITRE', `https://www.cve.org/CVERecord?id=${cveParam}`);
    xref('Vulnrichment', `https://github.com/cisagov/vulnrichment/search?q=${cveParam}`);
    if (local?.poc_url && safeUrl(local.poc_url)) xref('Public PoC', safeUrl(local.poc_url));
    body.appendChild(el('div', 'modal-section-title', 'References'));
    body.appendChild(links);

    const refs = el('div', 'modal-xrefs');
    (vuln.references || []).slice(0, 8).forEach((r) => {
      const url = safeUrl(r.url);
      if (!url) return;
      const a = el('a', 'modal-ref-link', url.length > 70 ? `${url.slice(0, 70)}…` : url);
      a.href = url; a.target = '_blank'; a.rel = 'noopener noreferrer';
      refs.appendChild(a);
    });
    if (refs.childElementCount) body.appendChild(refs);
  } catch (err) {
    body.replaceChildren(el('div', 'modal-error', `Could not load NVD data: ${err.message}`));
  }
}

function closeCveModal() {
  const modal = $('cve-modal');
  if (modal) modal.style.display = 'none';
}

// ─── Event wiring (all delegated — the CSP forbids inline handlers) ───────────
function initEvents() {
  document.addEventListener('click', (ev) => {
    const t = ev.target;

    // Modes replace the screen and reset to the mode's first view…
    const modeBtn = t.closest('.mode-btn');
    if (modeBtn) { setMode(modeBtn.dataset.mode); return; }

    // …views switch within the active mode…
    const viewBtn = t.closest('.view-btn');
    if (viewBtn) { setView(viewBtn.dataset.view); return; }

    // …feed filters narrow the list in place. Two vocabularies, two handlers.
    const filterBtn = t.closest('.filter-btn');
    if (filterBtn) {
      const next = filterBtn.dataset.filter;
      if (!FEED_FILTERS.includes(next)) return;
      store.filter = next;
      writeLS(LS.filter, next);
      if (store.view !== 'feed') setView('feed');
      update();
      return;
    }

    const panelBtn = t.closest('[data-close]');
    if (panelBtn) { closePanel(panelBtn.dataset.close); return; }
    if (t.closest('#filters-open')) { openPanel('filters'); return; }
    if (t.closest('#timemachine-open')) { openPanel('timemachine'); return; }
    if (t.closest('#saved-open')) { openPanel('saved'); return; }
    if (t.closest('#filters-reset')) { resetFilters(); return; }
    if (t.closest('#theme-toggle')) { cycleTheme(); return; }
    if (t.closest('#query-help')) { showQueryHelp(); return; }

    const savedOpen = t.closest('[data-saved]');
    if (savedOpen) { loadInvestigation(savedOpen.dataset.saved); return; }
    const savedDel = t.closest('[data-saved-del]');
    if (savedDel) {
      store.saved = store.saved.filter((s) => s.name !== savedDel.dataset.savedDel);
      writeLS(LS.saved, store.saved);
      renderSaved();
      return;
    }

    if (t.closest('#triage-next')) {
      const idx = store.filtered.findIndex((i) => !store.reviewed.has(i._key)
        && !store.starred.has(i._key) && !store.dismissed.has(i._key));
      if (idx >= 0) {
        if (idx >= store.renderLimit) {
          store.renderLimit = idx + PAGE_SIZE;
          renderCards();
        }
        store.cursor = idx;
        const cards = [...document.querySelectorAll('.intel-card')];
        cards.forEach((c) => c.classList.remove('cursor'));
        cards[idx]?.classList.add('cursor');
        cards[idx]?.scrollIntoView({ block: 'center', behavior: 'smooth' });
      }
      return;
    }
    if (t.closest('#triage-reset')) {
      store.filtered.forEach((i) => store.reviewed.delete(i._key));
      writeLS(LS.reviewed, [...store.reviewed]);
      update();
      return;
    }

    const doneBtn = t.closest('.done-btn');
    if (doneBtn) {
      if (doneBtn.dataset.act === 'browse-rest') { store.filter = 'all'; update(); }
      if (doneBtn.dataset.act === 'open-research') setView('research');
      return;
    }

    const entityFilter = t.closest('[data-entity-filter]');
    if (entityFilter) {
      closeEntityModal();
      store.query = entityFilter.dataset.entityFilter;
      store.parsedQuery = null;
      store.filter = 'all';
      setView('feed');
      update();
      return;
    }

    const malwareChip = t.closest('.malware-badge');
    if (malwareChip) {
      ev.stopPropagation();
      openEntityModal('malware', malwareChip.dataset.malware);
      return;
    }

    const graphNode = t.closest('[data-node-kind]');
    if (graphNode) {
      openEntityModal(graphNode.dataset.nodeKind, graphNode.dataset.nodeLabel);
      return;
    }

    const sevRow = t.closest('.sev-row');
    if (sevRow) {
      const sev = sevRow.dataset.severity;
      store.severity = store.severity === sev ? null : sev;
      writeLS(LS.severity, store.severity);
      update();
      return;
    }

    const srcRow = t.closest('.src-row');
    if (srcRow) { setQuery(srcRow.dataset.source); backToFeed(); return; }

    const statPill = t.closest('.stat-pill.is-clickable');
    if (statPill) {
      const which = statPill.dataset.stat;
      if (which === 'total') {
        store.filter = 'all'; store.severity = null; store.sector = null;
        store.provenance = null; store.watchlistOnly = false;
        setQuery('');
      } else if (which === 'urgent') {
        // Urgent is a priority band, not a severity, so it filters differently.
        store.filter = store.filter === 'urgent' ? 'verdicts' : 'urgent';
        store.severity = null;
      } else {
        store.severity = store.severity === which ? null : which;
      }
      // A severity filter means nothing while a map is on screen, so selecting
      // one returns to the feed rather than silently arming a hidden filter.
      backToFeed();
      return;
    }

    const catRow = t.closest('.cat-row');
    if (catRow) { store.filter = catRow.dataset.filter; backToFeed(); return; }

    const provRow = t.closest('.prov-row');
    if (provRow) {
      const p = provRow.dataset.provenance;
      store.provenance = store.provenance === p ? null : p;
      backToFeed();
      return;
    }

    const lsSector = t.closest('.ls-bar-row.is-click');
    if (lsSector && lsSector.dataset.sector) {
      const s = lsSector.dataset.sector;
      store.sector = store.sector === s ? null : s;
      store.filter = 'all';
      backToFeed();
      return;
    }

    const sectorRow = t.closest('.sector-row');
    if (sectorRow) {
      const sec = sectorRow.dataset.sector;
      store.sector = store.sector === sec ? null : sec;
      backToFeed();
      return;
    }

    const actor = t.closest('.threat-actor-badge');
    if (actor) { ev.stopPropagation(); openEntityModal('actor', actor.dataset.actor); return; }

    const source = t.closest('.meta-source');
    if (source && source.dataset.source) {
      ev.stopPropagation();
      setQuery(`source:"${source.dataset.source}"`);
      backToFeed();
      return;
    }

    const cve = t.closest('.cve-id');
    if (cve) { ev.stopPropagation(); openCveModal(cve.dataset.cve); return; }

    const tech = t.closest('.tech-cell');
    if (tech) { store.filter = 'all'; setQuery(tech.dataset.technique); backToFeed(); return; }

    const chipX = t.closest('.chip-x');
    if (chipX) {
      const { act, value } = chipX.dataset;
      if (act === 'unwatch') {
        store.watchlist = store.watchlist.filter((w) => w !== value);
        writeLS(LS.watchlist, store.watchlist);
      } else {
        store.stack = store.stack.filter((s) => s !== value);
        writeLS(LS.stack, store.stack);
      }
      update();
      return;
    }

    // Clicking the score opens the arithmetic behind it, in place.
    const scoreBtn = t.closest('.card-score[data-act="score"]');
    if (scoreBtn) {
      ev.stopPropagation();
      const card = scoreBtn.closest('.intel-card');
      const panel = card && card.querySelector('.card-score-panel');
      if (panel) {
        const open = panel.style.display !== 'none';
        panel.style.display = open ? 'none' : 'block';
        card.classList.toggle('expanded', !open || card.classList.contains('expanded'));
        scoreBtn.classList.toggle('is-open', !open);
      }
      return;
    }

    const detectTag = t.closest('.meta-detect');
    if (detectTag) { ev.stopPropagation(); setView('detections'); return; }

    const cardBtn = t.closest('.card-btn');
    if (cardBtn) {
      ev.stopPropagation();
      const card = cardBtn.closest('.intel-card');
      const item = store.filtered.find((i) => i._key === card.dataset.key);
      if (!item) return;
      const act = cardBtn.dataset.act;
      if (act === 'star') { toggleSet(store.starred, item._key, LS.starred); update(); }
      if (act === 'dismiss') { toggleSet(store.dismissed, item._key, LS.dismissed); update(); }
      if (act === 'review') { toggleSet(store.reviewed, item._key, LS.reviewed); update(); }
      if (act === 'copy') copyText(itemAsMarkdown(item), 'Copied as markdown');
      return;
    }

    const paletteRow = t.closest('.palette-row');
    if (paletteRow) { runPalette(Number(paletteRow.dataset.idx)); return; }

    if (t.closest('#sort-toggle')) {
      store.sort = store.sort === 'priority' ? 'latest' : 'priority';
      writeLS(LS.sort, store.sort);
      update();
      return;
    }
    if (t.closest('#density-toggle')) { toggleDensity(); return; }
    if (t.closest('#palette-open')) { openPalette(); return; }
    if (t.closest('.modal-close') || t.classList.contains('modal-overlay')) {
      closeCveModal();
      closeEntityModal();
      return;
    }
    if (t.closest('#watchlist-only-btn')) {
      store.watchlistOnly = !store.watchlistOnly;
      writeLS(LS.watchlistOnly, store.watchlistOnly);
      update();
      return;
    }
    if (t.closest('#filters-open')) { openPanel('filters'); return; }
    if (t.closest('#palette')) {
      if (t.id === 'palette') closePalette();
      return;
    }

    // Card body click toggles expansion.
    const card = t.closest('.intel-card');
    if (card && !t.closest('a')) card.classList.toggle('expanded');
  });

  const search = $('search-input');
  if (search) {
    let debounce = null;
    search.addEventListener('input', (ev) => {
      clearTimeout(debounce);
      const value = ev.target.value;
      debounce = setTimeout(() => {
        store.query = value;
        // js/query.js turns "exploited VPN items this week" and
        // "epss > 0.5 and not kev" into a filter set. It returns null for
        // anything it cannot parse, and applyFilters falls back to substring
        // search — a query language that swallows a plain keyword search
        // would be a downgrade.
        store.parsedQuery = (value && typeof parseQuery === 'function')
          ? parseQuery(value) : null;
        const wrapper = search.closest('.search-wrapper');
        if (wrapper) wrapper.classList.toggle('is-structured', !!store.parsedQuery);
        if (store.view !== 'feed') { store.view = 'feed'; writeLS(LS.view, 'feed'); }
        update();
      }, 180);
    });
  }

  const savedName = document.body;
  savedName.addEventListener('keydown', (ev) => {
    if (ev.key !== 'Enter') return;
    if (ev.target && ev.target.id === 'saved-name') {
      saveInvestigation(ev.target.value);
      ev.target.value = '';
    }
  });

  const watchInput = $('watchlist-input');
  if (watchInput) {
    watchInput.addEventListener('keydown', (ev) => {
      if (ev.key !== 'Enter') return;
      const value = watchInput.value.trim();
      if (value && !store.watchlist.includes(value)) {
        store.watchlist.push(value);
        writeLS(LS.watchlist, store.watchlist);
      }
      watchInput.value = '';
      update();
    });
  }

  const stackInput = $('stack-input');
  if (stackInput) {
    stackInput.addEventListener('keydown', (ev) => {
      if (ev.key !== 'Enter') return;
      const value = stackInput.value.trim();
      if (value && !store.stack.includes(value)) {
        store.stack.push(value);
        writeLS(LS.stack, store.stack);
      }
      stackInput.value = '';
      update();
    });
  }

  const paletteInput = $('palette-input');
  if (paletteInput) {
    paletteInput.addEventListener('input', (ev) => renderPalette(ev.target.value));
    paletteInput.addEventListener('keydown', (ev) => {
      if (ev.key === 'ArrowDown') { ev.preventDefault(); movePalette(1); }
      if (ev.key === 'ArrowUp') { ev.preventDefault(); movePalette(-1); }
      if (ev.key === 'Enter') { ev.preventDefault(); runPalette(paletteIndex); }
      if (ev.key === 'Escape') closePalette();
    });
  }

  // Infinite scroll.
  const sentinel = $('scroll-sentinel');
  if (sentinel && 'IntersectionObserver' in window) {
    new IntersectionObserver((entries) => {
      if (entries[0].isIntersecting && store.renderLimit < store.filtered.length) {
        store.renderLimit += PAGE_SIZE;
        renderCards();
      }
    }, { rootMargin: '400px' }).observe(sentinel);
  }

  initKeyboard();
}

let goPending = false;
let goTimer = null;

/** Gmail-style triage. The point is to make 250 items tractable. */
function initKeyboard() {
  document.addEventListener('keydown', (ev) => {
    const typing = ['INPUT', 'TEXTAREA'].includes(ev.target.tagName);

    if ((ev.metaKey || ev.ctrlKey) && ev.key.toLowerCase() === 'k') {
      ev.preventDefault();
      openPalette();
      return;
    }
    if (ev.key === 'Escape') {
      closePalette();
      closeCveModal();
      closeEntityModal();
      closePanel();
      const help = $('shortcuts');
      if (help) help.style.display = 'none';
      if (typing) ev.target.blur();
      return;
    }
    if (typing || ev.metaKey || ev.ctrlKey || ev.altKey) return;

    // `g` then a digit jumps between MODES, the way every list-shaped tool
    // does it. It used to index into VIEWS, which meant the digits mapped to
    // an array order nothing on screen showed; now 1-5 are the five buttons in
    // the nav, in the order they appear.
    if (goPending) {
      goPending = false;
      clearTimeout(goTimer);
      const idx = Number(ev.key);
      if (idx >= 1 && idx <= MODES.length) {
        ev.preventDefault();
        setMode(MODES[idx - 1]);
        return;
      }
    }
    if (ev.key === 'g') {
      goPending = true;
      clearTimeout(goTimer);
      goTimer = setTimeout(() => { goPending = false; }, 1200);
      return;
    }

    switch (ev.key) {
      case '/':
        ev.preventDefault();
        $('search-input')?.focus();
        break;
      case 'f': ev.preventDefault(); openPanel('filters'); break;
      case 'l': ev.preventDefault(); setView('library'); break;
      case 'h': ev.preventDefault(); setView('hunt'); break;
      case 't': ev.preventDefault(); openPanel('timemachine'); break;
      case 'r': {
        const item = currentItem();
        if (item) { toggleSet(store.reviewed, item._key, LS.reviewed); update(); }
        break;
      }
      case 'n': {
        const item = currentItem();
        if (!item) break;
        const card = cardForKey(item._key);
        card?.classList.add('expanded');
        card?.querySelector('.note-input')?.focus();
        break;
      }
      case 'j': ev.preventDefault(); moveCursor(1); break;
      case 'k': ev.preventDefault(); moveCursor(-1); break;
      case 'e': case 'Enter': {
        ev.preventDefault();
        const cards = [...document.querySelectorAll('.intel-card')];
        cards[store.cursor]?.click();
        break;
      }
      case 'x': {
        const item = currentItem();
        if (item) { toggleSet(store.dismissed, item._key, LS.dismissed); update(); }
        break;
      }
      case 's': {
        const item = currentItem();
        if (item) { toggleSet(store.starred, item._key, LS.starred); update(); }
        break;
      }
      case 'w': {
        const item = currentItem();
        if (item) copyText(itemAsMarkdown(item), 'Copied as markdown');
        break;
      }
      case 'o': {
        const item = currentItem();
        const url = item && safeUrl(item.url);
        if (url) window.open(url, '_blank', 'noopener');
        break;
      }
      case '?': {
        const help = $('shortcuts');
        if (help) help.style.display = help.style.display === 'flex' ? 'none' : 'flex';
        break;
      }
      default: break;
    }
  });
}

// ─── Boot ─────────────────────────────────────────────────────────────────────
/**
 * Decide what "your last visit" means, and keep it stable for this session.
 *
 * The naive version — write lastVisit on every load — makes NEW empty as soon
 * as you refresh, which is worse than the hourly badge it replaces. So two
 * stamps are kept: `lastSeen` is bumped continuously while the tab is open,
 * and `lastVisit` only rolls forward to the previous `lastSeen` when the gap
 * since it exceeds VISIT_GAP_MS. Reloading three times in ten minutes is one
 * visit; coming back tomorrow is a new one.
 */
function rollVisit() {
  const now = Date.now();
  const lastSeen = Date.parse(readLS(LS.lastSeen, '') || '');
  const lastVisit = readLS(LS.lastVisit, null);

  if (!Number.isNaN(lastSeen) && lastSeen && (now - lastSeen) > VISIT_GAP_MS) {
    store.lastVisit = new Date(lastSeen).toISOString();
    writeLS(LS.lastVisit, store.lastVisit);
  } else {
    store.lastVisit = lastVisit || null;
  }
  const bump = () => writeLS(LS.lastSeen, new Date().toISOString());
  bump();
  setInterval(bump, 60000);
  window.addEventListener('pagehide', bump);
}

function restoreState() {
  store.theme = readLS(LS.theme, 'auto') || 'auto';
  const savedView = readLS(LS.view, 'feed');
  store.view = VIEWS.includes(savedView) ? savedView : 'feed';
  const savedFilter = readLS(LS.filter, 'verdicts');
  store.filter = FEED_FILTERS.includes(savedFilter) ? savedFilter : 'verdicts';
  store.severity = readLS(LS.severity, null) || null;
  store.sort = readLS(LS.sort, 'priority') || 'priority';
  // Compact by default. Comfortable put ~2 cards on a screen, which made a
  // 320-item feed roughly 160 screens long; triage wants 15-20 rows visible
  // and expands only what is interesting.
  store.density = readLS(LS.density, 'compact') || 'compact';
  store.watchlist = readLS(LS.watchlist, []) || [];
  store.watchlistOnly = readLS(LS.watchlistOnly, false) === true;
  store.stack = readLS(LS.stack, []) || [];
  store.dismissed = new Set(readLS(LS.dismissed, []) || []);
  store.starred = new Set(readLS(LS.starred, []) || []);
  store.reviewed = new Set(readLS(LS.reviewed, []) || []);
  store.darkwebWatch = readLS(LS.darkwebWatch, []) || [];
  store.notes = readLS(LS.notes, {}) || {};
  store.saved = readLS(LS.saved, []) || [];
  rollVisit();
  readUrlState();
  applyTheme();
}

// ─── Saved investigations ─────────────────────────────────────────────────────
// URL state already made a filter combination shareable; this makes one
// nameable and returnable-to, which is the half that was missing.
function currentInvestigation(name) {
  return {
    name,
    saved: new Date().toISOString(),
    view: store.view,
    filter: store.filter,
    severity: store.severity,
    sector: store.sector,
    provenance: store.provenance,
    query: store.query,
    sort: store.sort,
    watchlistOnly: store.watchlistOnly,
    humanOnly: store.humanOnly,
  };
}

function saveInvestigation(name) {
  const clean = String(name || '').trim().slice(0, 60);
  if (!clean) return;
  store.saved = store.saved.filter((s) => s.name !== clean);
  store.saved.unshift(currentInvestigation(clean));
  store.saved = store.saved.slice(0, 30);
  writeLS(LS.saved, store.saved);
  showToast(`Saved "${clean}"`);
  renderSaved();
}

function loadInvestigation(name) {
  const found = store.saved.find((s) => s.name === name);
  if (!found) return;
  store.view = VIEWS.includes(found.view) ? found.view : 'feed';
  store.filter = FEED_FILTERS.includes(found.filter) ? found.filter : 'verdicts';
  store.severity = found.severity || null;
  store.sector = found.sector || null;
  store.provenance = found.provenance || null;
  store.query = found.query || '';
  store.sort = found.sort || 'priority';
  store.watchlistOnly = !!found.watchlistOnly;
  store.humanOnly = !!found.humanOnly;
  store.parsedQuery = (store.query && typeof parseQuery === 'function')
    ? parseQuery(store.query) : null;
  closePanel('saved');
  update();
}

function renderSaved() {
  const host = $('saved-body');
  if (!host) return;
  host.replaceChildren();

  const form = el('div', 'saved-form');
  const input = el('input', 'watchlist-input');
  input.id = 'saved-name';
  input.type = 'text';
  input.placeholder = 'Name this view and press Enter';
  input.setAttribute('aria-label', 'Name for the saved investigation');
  form.appendChild(input);
  host.appendChild(form);

  const summary = el('p', 'saved-current',
    `Currently: ${store.view}${store.view === 'feed' ? ` / ${store.filter}` : ''}`
    + `${store.query ? ` · "${store.query}"` : ''}`
    + `${store.severity ? ` · ${store.severity}` : ''}`
    + `${store.sector ? ` · ${store.sector}` : ''}`);
  host.appendChild(summary);

  if (!store.saved.length) {
    host.appendChild(el('p', 'saved-empty',
      'Nothing saved yet. Investigations are stored in this browser only.'));
    return;
  }
  const list = el('div', 'saved-list');
  store.saved.forEach((entry) => {
    const row = el('div', 'saved-row');
    const open = el('button', 'saved-open', entry.name);
    open.type = 'button';
    open.dataset.saved = entry.name;
    const meta = el('span', 'saved-meta',
      `${entry.view}${entry.view === 'feed' ? ` · ${entry.filter}` : ''}`);
    const del = el('button', 'saved-del', '×');
    del.type = 'button';
    del.dataset.savedDel = entry.name;
    del.setAttribute('aria-label', `Delete ${entry.name}`);
    row.append(open, meta, del);
    list.appendChild(row);
  });
  host.appendChild(list);
}

function initAvatar() {
  const btn = $('about-open');
  if (!btn) return;
  btn.replaceChildren(avatarSvg(28));
  btn.addEventListener('click', () => setView('about'));
}

function initContactLink() {
  const btn = $('contact-open');
  if (btn) btn.addEventListener('click', () => setView('contact'));
}

/** Query syntax, shown from the `?` next to the search box. */
function showQueryHelp() {
  const modal = $('entity-modal');
  const body = $('entity-body');
  const title = $('entity-title');
  if (!modal || !body) return;
  modal.style.display = 'flex';
  if (title) title.textContent = 'Search & query';
  body.replaceChildren();

  body.appendChild(el('p', 'query-help-lead',
    'Type plain words to search, or a structured query. Everything runs in '
    + 'your browser over the loaded feed — nothing is sent anywhere.'));

  const examples = (typeof queryExamples === 'function') ? queryExamples() : [];
  if (examples.length) {
    body.appendChild(el('div', 'modal-section-title', 'Try one'));
    const list = el('div', 'query-examples');
    examples.forEach((ex) => {
      const btn = el('button', 'query-example', ex.q);
      btn.type = 'button';
      btn.dataset.queryExample = ex.q;
      const row = el('div', 'query-example-row');
      row.appendChild(btn);
      row.appendChild(el('span', 'query-example-note', ex.note));
      list.appendChild(row);
    });
    body.appendChild(list);
  }

  body.appendChild(el('div', 'modal-section-title', 'Fields'));
  const fields = (typeof queryFields === 'function') ? queryFields() : [];
  const table = el('div', 'query-fields');
  fields.forEach((f) => {
    const row = el('div', 'query-field-row');
    row.appendChild(el('code', 'query-field-name', f.name));
    row.appendChild(el('span', 'query-field-note', f.note));
    table.appendChild(row);
  });
  body.appendChild(table);

  body.appendChild(el('div', 'modal-section-title', 'Operators'));
  body.appendChild(el('p', 'query-help-note',
    'Comparisons: > >= < <= = != · combine with AND / OR / NOT (and parentheses) · '
    + 'quote phrases with "double quotes" · plain words fall back to substring search.'));
}

document.addEventListener('DOMContentLoaded', () => {
  // Before restoreState(), which is what reads the keys.
  migrateLegacyKeys();
  restoreState();
  initAvatar();
  initContactLink();
  initEvents();
  // Must run before the first render: the sticky bars read these variables,
  // and a wrong value for one frame is a visible jump.
  watchStickyOffsets();
  document.addEventListener('click', (ev) => {
    const ex = ev.target.closest('[data-query-example]');
    if (!ex) return;
    closeEntityModal();
    setQuery(ex.dataset.queryExample);
    store.filter = 'all';
    backToFeed();
  });
  loadIntelData().then((ok) => {
    if (!ok) return;
    initLivePolling();
    // A shared link can name a past day (#day=2026-07-12). Restoring it has to
    // wait for the live feed, because entering a day parks today's items.
    if (store.day && typeof enterDay === 'function') {
      const wanted = store.day;
      store.day = null;
      enterDay(wanted);
    }
  });
});

if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('service-worker.js').catch(() => {});
  });
}
