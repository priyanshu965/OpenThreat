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

// ─── Framing guard ────────────────────────────────────────────────────────────
// GitHub Pages cannot send X-Frame-Options or a frame-ancestors header, and a
// <meta> CSP ignores frame-ancestors by specification - so on the hosted site
// this is the only clickjacking defence available. Loaded inside another
// site's frame, the page hides itself and asks the top window to come here
// instead. Hiding comes FIRST because a sandboxed frame can refuse the
// navigation. (nginx.conf sends the real header for self-hosted installs.)
(function refuseFraming() {
  let framed = false;
  try { framed = window.top !== window.self; } catch (_) { framed = true; }
  if (!framed) return;
  document.documentElement.style.display = 'none';
  try { window.top.location = window.self.location.href; } catch (_) { /* sandboxed */ }
})();

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
  watchlist: [], watchlistOnly: false, stack: [], stackFocus: null,
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
 * from one of 71 third-party feeds and the scheme allowlist is what stops a
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

// matchesStack(), stackHit() and the rest of My Stack live in js/stack.js.

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
    // A hidden tab normally stops polling. It keeps going when stack alerts
    // are on, because a notification for a tab you are not looking at is the
    // entire point of one.
    if (document.hidden && !stackNotifyEnabled()) return;
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
      const mine = stackNotify(incoming);
      showToast(`${incoming.length} new item${incoming.length === 1 ? '' : 's'}`
        + (mine ? ` · ${mine} affect your stack` : ''), 'Load', () => {
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
  const stackTerm = stackHit(item);
  if (stackTerm) reasons.push(`matches your stack: ${stackTerm}`);
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
    list = list.filter(stackFilter);
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
  // Broken first, healthy next, and sources that are merely switched off
  // (no API key) last: they need a decision, not attention.
  const rank = (s) => (s === 'error' ? 0 : s === 'empty' ? 1 : s === 'stale' ? 2
    : s === 'disabled' ? 4 : 3);
  entries.sort((a, b) => rank(a[1].status) - rank(b[1].status));

  const okCount = entries.filter(([, h]) => h.status === 'ok').length;
  const summary = $('source-health-summary');
  if (summary) summary.textContent = `${okCount}/${entries.length} live`;

  host.replaceChildren();
  entries.forEach(([name, h]) => {
    const row = el('div', `health-item health-${h.status}`);
    const detail = h.status === 'error' ? (h.error || 'error')
      : h.status === 'disabled' ? `switched off — ${h.error || 'needs an API key'}`
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
    row.appendChild(el('span', 'health-count',
      h.status === 'error' ? '!' : h.status === 'disabled' ? 'off' : String(h.count)));
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
    markFeedStaleness(date);
  }
}

/**
 * Say so when the pipeline has stopped publishing.
 *
 * The age was already on screen and it was a small grey timestamp that read
 * the same at 20 minutes and at 11 hours. That is precisely how the scheduler
 * failure went unnoticed: GitHub's `schedule` event is best-effort and drops
 * runs under load, the cadence decayed from hourly to one run in 11 hours,
 * and the dashboard reported it in the same neutral voice it uses for fresh
 * data. A feed that has quietly stopped moving looks exactly like a quiet
 * day, which is the failure mode this project exists to refuse.
 *
 * The thresholds allow for the scheduler being unreliable: the cron attempts
 * twice an hour, so three hours is several missed attempts rather than one
 * unlucky one, and twelve hours means it is not coming back on its own.
 */
const FEED_STALE_HOURS = 3;
const FEED_VERY_STALE_HOURS = 12;

function markFeedStaleness(date) {
  const node = $('last-updated');
  const dot = document.querySelector('.status-dot');
  if (!node) return;
  const hours = (Date.now() - date.getTime()) / 3600000;
  const level = hours >= FEED_VERY_STALE_HOURS ? 'very-stale'
    : hours >= FEED_STALE_HOURS ? 'stale' : '';
  node.classList.toggle('is-stale', level === 'stale');
  node.classList.toggle('is-very-stale', level === 'very-stale');
  if (dot) {
    dot.classList.toggle('is-stale', level === 'stale');
    dot.classList.toggle('is-very-stale', level === 'very-stale');
  }
  if (level) {
    // Named plainly rather than implied by colour alone: colour is not
    // available to everyone, and "the pipeline has not run" is a different
    // statement from "nothing happened".
    node.textContent += level === 'very-stale'
      ? ' · PIPELINE STALLED' : ' · UPDATE OVERDUE';
    node.title = `${node.title} — the publishing pipeline has not run for `
      + `${Math.floor(hours)} hours. This is a delivery problem, not a quiet day.`;
  }
}

// ─── Charts (hand-rolled SVG; no charting dependency) ─────────────────────────
const SVG_NS = 'http://www.w3.org/2000/svg';
function svgEl(tag, attrs) {
  const node = document.createElementNS(SVG_NS, tag);
  for (const [k, v] of Object.entries(attrs || {})) node.setAttribute(k, String(v));
  return node;
}

// Trends view: see js/trends.js.

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

// Threat map: see js/map.js.

// Threat landscape and geopolitics views, plus the statTile()/lsPanel(): see js/landscape.js.

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
// About view: see js/about.js.

// Dark web and exposure views: see js/exposure.js.

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
  renderStackPanel();
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
  const stackPanel = $('stack-panel');
  if (stackPanel && !inFeed) stackPanel.style.display = 'none';
  // Same for the row carrying "Showing 40 of 66" and the density/sort toggles:
  // it sat above the entity graph reading "Loading intelligence feed…".
  const feedHeader = document.querySelector('.feed-header');
  if (feedHeader) feedHeader.style.display = inFeed ? '' : 'none';

  renderModeNav();
  renderRail();
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
  // A cell starting with = + - @ (or tab / CR) is evaluated as a formula by
  // Excel, LibreOffice and Sheets. Titles come from third-party feeds, so the
  // leading apostrophe is what stops a feed item running in a spreadsheet.
  const esc = (v) => {
    const text = String(v ?? '');
    const safe = /^[=+\-@\t\r]/.test(text) ? `'${text}` : text;
    return `"${safe.replace(/"/g, '""')}"`;
  };
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
        removeStackTerm(value);
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
      // Accepts a comma-separated list, so a stack can be pasted in one go.
      addStackTerms(stackInput.value);
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
