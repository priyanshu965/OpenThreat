/**
 * CYBERWATCH DASHBOARD — app.js
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
const POLL_INTERVAL = 120000;
const PAGE_SIZE     = 40;

const LS = {
  filter: 'cw_filter', severity: 'cw_severity', sort: 'cw_sort',
  watchlist: 'cw_watchlist', watchlistOnly: 'cw_watchlistOnly',
  stack: 'cw_stack', dismissed: 'cw_dismissed', starred: 'cw_starred',
  density: 'cw_density', lastVisit: 'cw_lastVisit',
};

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
  items: [], filtered: [], meta: {}, templates: {}, brief: null,
  health: {}, staleness: {}, trends: null,
  filter: 'all', severity: null, query: '', sort: 'priority',
  renderLimit: PAGE_SIZE, cursor: -1, density: 'comfortable',
  watchlist: [], watchlistOnly: false, stack: [],
  dismissed: new Set(), starred: new Set(), showDismissed: false,
  lastVisit: null, stamp: null,
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

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function $(id) { return document.getElementById(id); }

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

function graphFor(item) {
  return item.workflow_graph
    || store.templates[item.graph_template]
    || store.templates.default || '';
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
  if (params.get('filter')) store.filter = params.get('filter');
  if (params.get('severity')) store.severity = params.get('severity');
  if (params.get('q')) store.query = params.get('q');
  if (params.get('sort')) store.sort = params.get('sort');
}

function writeUrlState() {
  const params = new URLSearchParams();
  if (store.filter && store.filter !== 'all') params.set('filter', store.filter);
  if (store.severity) params.set('severity', store.severity);
  if (store.query) params.set('q', store.query);
  if (store.sort !== 'priority') params.set('sort', store.sort);
  const next = params.toString();
  history.replaceState(null, '', next ? `#${next}` : location.pathname + location.search);
}

// ─── Data loading ─────────────────────────────────────────────────────────────
function ingest(data) {
  store.items = data.items || [];
  store.meta = data;
  store.templates = data.graph_templates || {};
  store.brief = data.brief || null;
  store.health = data.source_health || {};
  store.items.forEach((item) => { item._key = itemKey(item); });
}

async function loadIntelData() {
  try {
    const resp = await fetch(`${DATA_URL}?v=${Date.now()}`);
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    store.stamp = resp.headers.get('etag') || resp.headers.get('last-modified');
    ingest(await resp.json());
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
    const resp = await fetch(`${HEALTH_URL}?v=${Date.now()}`);
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
    try {
      const head = await fetch(DATA_URL, { method: 'HEAD', cache: 'no-store' });
      const stamp = head.headers.get('etag') || head.headers.get('last-modified');
      if (!stamp || stamp === store.stamp) return;

      const known = new Set(store.items.map((i) => i._key));
      const fresh = await (await fetch(`${DATA_URL}?v=${Date.now()}`)).json();
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
  } else if (store.filter === 'exploited') {
    list = list.filter((i) => i.cisa_kev || i.ssvc_exploitation === 'active' || i.has_poc);
  } else if (CATEGORIES.includes(store.filter)) {
    list = list.filter((i) => (i.category || 'news') === store.filter);
  }

  if (store.severity) {
    list = list.filter((i) => (i.severity || '').toLowerCase() === store.severity);
  }
  if (q) {
    list = list.filter((i) => (
      `${i.title} ${i.description} ${i.cve_id || ''} ${i.source} ${(i.vendors || []).join(' ')}`
    ).toLowerCase().includes(q));
  }

  list = list.slice();
  if (store.sort === 'priority') {
    // Priority-first is the default now. `severity` is inferred from headline
    // keywords and is the weakest signal in the payload; priority_score blends
    // CVSS, EPSS, KEV, public PoC and SSVC, and is the defensible one.
    list.sort((a, b) => (b.priority_score || 0) - (a.priority_score || 0)
      || String(b.published || '').localeCompare(String(a.published || '')));
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

function buildCard(item, index) {
  const card = el('div', 'intel-card');
  card.dataset.key = item._key;
  card.dataset.index = String(index);
  card.dataset.category = item.category || 'news';

  const severity = (item.severity || 'medium').toLowerCase();
  const isNew = item.is_new === true;
  if (isNew) card.classList.add('new-item');
  if (item._justArrived) card.classList.add('just-arrived');
  if (matchesWatchlist(item)) card.classList.add('watchlist-hit');
  if (store.starred.has(item._key)) card.classList.add('starred');
  if (store.dismissed.has(item._key)) card.classList.add('is-dismissed');

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
  if (isNew) badges.appendChild(el('span', 'new-item-badge', 'NEW'));
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

  if (item.priority_label) {
    const badge = el('span', `badge prio-badge prio-${item.priority_label}`,
      item.priority_label.toUpperCase());
    badge.title = item.priority_rationale
      || 'Blended priority: CVSS + EPSS + KEV + public PoC + SSVC';
    top.appendChild(badge);
  } else {
    const badge = el('span', `badge ${severity}`, severity.toUpperCase());
    badge.title = 'Severity inferred from headline keywords — weaker than a priority score';
    top.appendChild(badge);
  }
  card.appendChild(top);

  // The action line is the point of the priority score: a decision, not a number.
  if (item.action) {
    const action = el('div', `card-action prio-${item.priority_label || 'low'}`);
    action.appendChild(el('span', 'action-verb', item.action));
    if (item.action_detail) action.appendChild(el('span', 'action-detail', item.action_detail));
    card.appendChild(action);
  }

  if (item.threat_actors && item.threat_actors.length) {
    const actors = el('div', 'card-actors');
    item.threat_actors.slice(0, 3).forEach((actor) => {
      const chip = el('span', 'threat-actor-badge', actor);
      chip.dataset.actor = actor;
      chip.title = `Filter by ${actor}`;
      actors.appendChild(chip);
    });
    card.appendChild(actors);
  }

  if (item.description) card.appendChild(el('p', 'card-description', item.description));

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
  if (item.published) meta.appendChild(el('span', 'meta-date', timeAgo(new Date(item.published))));
  card.appendChild(meta);

  if (item.iocs && Object.keys(item.iocs).length) card.appendChild(buildIocSection(item));

  const analysis = el('div', 'analysis-section');
  const header = el('div', 'analysis-header');
  const enriched = item.ai_provider && item.ai_provider !== 'rule';
  header.appendChild(el('span', 'analysis-label', enriched ? 'AI THREAT ANALYSIS' : 'SUMMARY'));
  if (item.ai_model) header.appendChild(el('span', 'analysis-model', item.ai_model));
  analysis.appendChild(header);
  analysis.appendChild(el('p', 'analysis-summary', displaySummary(item)));
  if (item.why_it_matters) analysis.appendChild(el('p', 'analysis-why', item.why_it_matters));

  const graph = graphFor(item);
  if (graph) {
    const wrap = el('div', 'analysis-graph-wrap');
    wrap.appendChild(el('div', 'analysis-graph-label', 'ATTACK FLOW'));
    const container = el('div', 'mermaid-container');
    container.dataset.rendered = 'false';
    container.appendChild(el('div', 'mermaid-spinner', 'Rendering diagram…'));
    wrap.appendChild(container);
    analysis.appendChild(wrap);
    card._graph = graph;
    card._graphContainer = container;
  }
  card.appendChild(analysis);

  const actions = el('div', 'card-actions');
  const star = el('button', 'card-btn', store.starred.has(item._key) ? '★ Starred' : '☆ Star');
  star.dataset.act = 'star';
  const dismiss = el('button', 'card-btn',
    store.dismissed.has(item._key) ? '↩ Restore' : '✕ Dismiss');
  dismiss.dataset.act = 'dismiss';
  const copy = el('button', 'card-btn', '⧉ Copy');
  copy.dataset.act = 'copy';
  copy.title = 'Copy as markdown for a ticket';
  actions.append(star, dismiss, copy);
  actions.appendChild(el('span', 'card-expand-hint', '▼ EXPAND'));
  card.appendChild(actions);

  return card;
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
    count.textContent = total === 0
      ? 'No items match'
      : `Showing ${Math.min(store.renderLimit, total)} of ${total}`
        + (hidden && !store.showDismissed ? ` · ${hidden} dismissed` : '');
  }
  const noResults = $('no-results');
  if (noResults) noResults.style.display = store.filtered.length ? 'none' : 'block';

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

// ─── Mermaid ──────────────────────────────────────────────────────────────────
let mermaidSeq = 0;
async function renderGraph(container, source) {
  if (typeof mermaid === 'undefined') {
    container.textContent = 'Diagram renderer unavailable';
    return;
  }
  try {
    const { svg } = await mermaid.render(`mmd-${++mermaidSeq}`, source.replace(/\\n/g, '\n'));
    container.innerHTML = svg;
    const svgEl = container.querySelector('svg');
    if (svgEl) {
      svgEl.style.maxWidth = '100%';
      svgEl.style.height = 'auto';
      svgEl.removeAttribute('width');
      svgEl.removeAttribute('height');
    }
  } catch (err) {
    console.warn('Mermaid render failed:', err);
    container.replaceChildren(el('pre', 'mermaid-raw-fallback', source));
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
  if (!tactics.size) {
    grid.appendChild(el('p', 'chart-empty', 'No techniques mapped in the current feed.'));
    return;
  }
  [...tactics.entries()].forEach(([tactic, ids]) => {
    const col = el('div', 'tactic-col');
    col.appendChild(el('div', 'tactic-header', tactic));
    [...ids].sort().forEach((id) => {
      const n = counts[id];
      const cell = el('button', `tech-cell ${n >= 3 ? 'active-high' : 'active-med'}`);
      cell.type = 'button';
      cell.dataset.technique = id;
      cell.title = `${id} — ${names[id]} (${n} item${n === 1 ? '' : 's'})`;
      cell.appendChild(el('span', 'tech-id', id));
      cell.appendChild(el('span', 'tech-count', String(n)));
      col.appendChild(cell);
    });
    grid.appendChild(col);
  });
}

// ─── View switching ───────────────────────────────────────────────────────────
function hideAllViews() {
  ['loading-state', 'error-state', 'cards-container', 'matrix-view', 'trends-view', 'no-results']
    .forEach((id) => { const n = $(id); if (n) n.style.display = 'none'; });
}

function showContent() {
  hideAllViews();
  const container = $('cards-container');
  if (container) container.style.display = 'grid';
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

function renderAll() {
  if (store.filter === 'matrix') { showMatrixView(); return; }
  if (store.filter === 'trends') { showTrendsView(); return; }
  showContent();
  renderBrief();
  renderCards();
  renderSidebar();
  syncControls();
}

function syncControls() {
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
  const search = $('search-input');
  if (search && search.value !== store.query) search.value = store.query;
}

function update() {
  applyFilters();
  renderAll();
}

// ─── Command palette ──────────────────────────────────────────────────────────
function paletteCommands() {
  const cmds = [
    { label: 'Sort by priority', hint: 'Blended CVSS + EPSS + KEV + SSVC', run: () => { store.sort = 'priority'; writeLS(LS.sort, store.sort); update(); } },
    { label: 'Sort by newest', hint: 'Publication time', run: () => { store.sort = 'latest'; writeLS(LS.sort, store.sort); update(); } },
    { label: 'Show all items', run: () => { store.filter = 'all'; store.severity = null; update(); } },
    { label: 'Show actively exploited', hint: 'KEV, SSVC active, or public PoC', run: () => { store.filter = 'exploited'; update(); } },
    { label: 'Show items affecting my stack', run: () => { store.filter = 'stack'; update(); } },
    { label: 'Show starred', run: () => { store.filter = 'starred'; update(); } },
    { label: 'Toggle dismissed items', run: () => { store.showDismissed = !store.showDismissed; update(); } },
    { label: 'Clear all dismissals', run: () => { store.dismissed.clear(); writeLS(LS.dismissed, []); update(); } },
    { label: 'Toggle density', run: () => toggleDensity() },
    { label: 'Open ATT&CK matrix', run: () => { store.filter = 'matrix'; renderAll(); } },
    { label: 'Open trends', run: () => { store.filter = 'trends'; renderAll(); } },
    { label: 'Copy shareable link', run: () => copyText(location.href, 'Link copied') },
    { label: 'Export current view as CSV', run: () => exportCsv() },
  ];
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

  // Jumping straight to a CVE is the most common reason to open this.
  if (q.length >= 3) {
    store.items
      .filter((i) => `${i.cve_id || ''} ${i.title}`.toLowerCase().includes(q))
      .slice(0, 6)
      .forEach((item) => {
        paletteMatches.push({
          label: item.cve_id ? `${item.cve_id} — ${item.title}` : item.title,
          hint: item.source,
          run: () => { store.query = item.cve_id || item.title.slice(0, 40); store.filter = 'all'; update(); },
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
  a.download = `cyberwatch-${new Date().toISOString().slice(0, 10)}.csv`;
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
    xref('NVD', `https://nvd.nist.gov/vuln/detail/${cveId}`);
    xref('MITRE', `https://www.cve.org/CVERecord?id=${cveId}`);
    xref('Vulnrichment', `https://github.com/cisagov/vulnrichment/search?q=${cveId}`);
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

    const filterBtn = t.closest('.filter-btn');
    if (filterBtn) {
      store.filter = filterBtn.dataset.filter;
      if (store.filter !== 'matrix' && store.filter !== 'trends') update();
      else { syncControls(); renderAll(); }
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
    if (srcRow) { store.query = srcRow.dataset.source; update(); return; }

    const catRow = t.closest('.cat-row');
    if (catRow) { store.filter = catRow.dataset.filter; update(); return; }

    const actor = t.closest('.threat-actor-badge');
    if (actor) { store.query = actor.dataset.actor; store.filter = 'all'; update(); return; }

    const source = t.closest('.meta-source');
    if (source && source.dataset.source) { store.query = source.dataset.source; update(); return; }

    const cve = t.closest('.cve-id');
    if (cve) { ev.stopPropagation(); openCveModal(cve.dataset.cve); return; }

    const tech = t.closest('.tech-cell');
    if (tech) { store.filter = 'all'; store.query = tech.dataset.technique; update(); return; }

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

    const cardBtn = t.closest('.card-btn');
    if (cardBtn) {
      ev.stopPropagation();
      const card = cardBtn.closest('.intel-card');
      const item = store.filtered.find((i) => i._key === card.dataset.key);
      if (!item) return;
      const act = cardBtn.dataset.act;
      if (act === 'star') { toggleSet(store.starred, item._key, LS.starred); update(); }
      if (act === 'dismiss') { toggleSet(store.dismissed, item._key, LS.dismissed); update(); }
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
    if (t.closest('.modal-close') || t.classList.contains('modal-overlay')) { closeCveModal(); return; }
    if (t.closest('#watchlist-only-btn')) {
      store.watchlistOnly = !store.watchlistOnly;
      writeLS(LS.watchlistOnly, store.watchlistOnly);
      update();
      return;
    }
    if (t.closest('#toggle-sidebar-btn')) {
      document.querySelector('.sidebar')?.classList.toggle('open');
      return;
    }
    if (t.closest('#palette')) {
      if (t.id === 'palette') closePalette();
      return;
    }

    // Card body click toggles expansion and lazily renders the diagram.
    const card = t.closest('.intel-card');
    if (card && !t.closest('a')) {
      const wasExpanded = card.classList.contains('expanded');
      card.classList.toggle('expanded');
      if (!wasExpanded && card._graph && card._graphContainer
          && card._graphContainer.dataset.rendered === 'false') {
        card._graphContainer.dataset.rendered = 'true';
        renderGraph(card._graphContainer, card._graph);
      }
    }
  });

  const search = $('search-input');
  if (search) {
    let debounce = null;
    search.addEventListener('input', (ev) => {
      clearTimeout(debounce);
      const value = ev.target.value;
      debounce = setTimeout(() => { store.query = value; update(); }, 180);
    });
  }

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
      if (typing) ev.target.blur();
      return;
    }
    if (typing || ev.metaKey || ev.ctrlKey || ev.altKey) return;

    switch (ev.key) {
      case '/':
        ev.preventDefault();
        $('search-input')?.focus();
        break;
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
function restoreState() {
  store.filter = readLS(LS.filter, 'all') || 'all';
  store.severity = readLS(LS.severity, null) || null;
  store.sort = readLS(LS.sort, 'priority') || 'priority';
  store.density = readLS(LS.density, 'comfortable') || 'comfortable';
  store.watchlist = readLS(LS.watchlist, []) || [];
  store.watchlistOnly = readLS(LS.watchlistOnly, false) === true;
  store.stack = readLS(LS.stack, []) || [];
  store.dismissed = new Set(readLS(LS.dismissed, []) || []);
  store.starred = new Set(readLS(LS.starred, []) || []);
  store.lastVisit = readLS(LS.lastVisit, null);
  writeLS(LS.lastVisit, new Date().toISOString());
  readUrlState();
}

function initMermaid() {
  if (typeof mermaid === 'undefined') return;
  mermaid.initialize({
    startOnLoad: false,
    theme: 'dark',
    // 'strict' HTML-encodes node labels and disables click-binding, closing the
    // XSS surface of rendering source-controlled graph text.
    securityLevel: 'strict',
    themeVariables: {
      background: '#080b0f', mainBkg: '#0d1117', primaryColor: '#0d2038',
      primaryTextColor: '#c9d8e8', primaryBorderColor: '#1e4d73',
      lineColor: '#4da6ff', secondaryColor: '#111820', tertiaryColor: '#080b0f',
      edgeLabelBackground: '#080b0f', nodeBorder: '#1e2d3d', clusterBkg: '#0d1117',
      fontFamily: "'JetBrains Mono', 'Courier New', monospace", fontSize: '12px',
    },
    flowchart: { htmlLabels: false, curve: 'linear', padding: 24 },
  });
}

document.addEventListener('DOMContentLoaded', () => {
  restoreState();
  initMermaid();
  initEvents();
  loadIntelData().then((ok) => { if (ok) initLivePolling(); });
});

if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('service-worker.js').catch(() => {});
  });
}
