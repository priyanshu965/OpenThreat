/*
 * OPENTHREAT — js/rail.js
 * =======================
 * The telemetry rail: evidence that the machine is running.
 *
 * WHAT PROBLEM THIS SOLVES
 * ------------------------
 * Not empty space. The feed was understating what the tool holds by about
 * four orders of magnitude: a visitor's first impression was nine cards,
 * while the payload those cards arrived in also carried 8,889 entities,
 * 16,528 aliases, 2,876 detection rules, 3,389 extortion claims and the live
 * status of 43 feeds. All of it was one click away, which for a first
 * impression is the same as not existing.
 *
 * WHY THIS IS NOT THE OLD SIDEBAR
 * -------------------------------
 * Eight always-on cards were removed from this exact space, correctly: they
 * competed with the content and several duplicated the nav. That judgement
 * still holds, so this rail obeys it —
 *
 *   * It is READ-ONLY. Every filter stays in the summoned panel.
 *   * It duplicates nothing. Not the nav, not the header stat pills.
 *   * Four blocks, not eight.
 *   * Feed view only. The other five modes fill the width themselves.
 *   * It disappears below 1280px, where the width genuinely is not there.
 *
 * WHY IT COSTS NOTHING
 * --------------------
 * Every number here is already in `store.meta` — the metadata that ships
 * inside intel.json, which the page has loaded before this runs. The ingest
 * histogram is computed from `store.items`. There is not one extra request,
 * which is what makes a permanent rail affordable at all.
 */

/* Freshness bands for the source matrix, in the order they are tested. */
const RAIL_SOURCE_STATES = [
  ['ok', 'live'],
  ['stale', 'stale'],
  ['empty', 'empty'],
  ['error', 'error'],
];

const RAIL_TICKER_MS = 4200;
let railTickerTimer = null;

function railBlock(host, title, meta) {
  const block = el('section', 'rail-block');
  const head = el('div', 'rail-head');
  head.appendChild(el('h3', 'rail-title', title));
  if (meta) head.appendChild(el('span', 'rail-meta', meta));
  block.appendChild(head);
  host.appendChild(block);
  return block;
}

/* A ledger row: label, leader dots, right-aligned figure. Deliberately not a
 * stat card — this is record-keeping, and it should read like a station log
 * rather than like a number someone is trying to sell you. */
function railLedgerRow(host, label, value, href) {
  const row = el(href ? 'a' : 'div', 'rail-row');
  if (href) {
    row.href = '#';
    row.dataset.railView = href;
    row.setAttribute('role', 'link');
  }
  row.appendChild(el('span', 'rail-row-label', label));
  row.appendChild(el('span', 'rail-leader', ''));
  row.appendChild(el('span', 'rail-row-value',
    typeof value === 'number' ? value.toLocaleString() : String(value)));
  host.appendChild(row);
  return row;
}

/* ── Ingest ───────────────────────────────────────────────────────────────
 * 24 hourly buckets built from the items already in memory. This is the one
 * block that is computed rather than read, and it is worth it: a shape is
 * the fastest way to say "things are still arriving".
 */
function railIngestBuckets(items) {
  const buckets = new Array(24).fill(0);
  const now = Date.now();
  (items || []).forEach((item) => {
    const stamp = Date.parse(item.published || '');
    if (!stamp) return;
    const hoursAgo = Math.floor((now - stamp) / 3600000);
    // Future-dated items exist: several feeds publish with a timezone the
    // parser reads as ahead of now. They belong in the current hour, not
    // discarded and not in a negative index.
    const index = 23 - Math.min(23, Math.max(0, hoursAgo));
    buckets[index] += 1;
  });
  return buckets;
}

function railRenderIngest(host, meta, items) {
  const block = railBlock(host, 'Ingest', '24h');
  const buckets = railIngestBuckets(items);
  const peak = Math.max(1, ...buckets);

  const chart = el('div', 'rail-spark');
  chart.setAttribute('role', 'img');
  chart.setAttribute('aria-label',
    `Items ingested per hour over the last 24 hours, peak ${peak}`);
  buckets.forEach((count, hour) => {
    const bar = el('span', 'rail-spark-bar' + (count ? '' : ' is-zero'));
    bar.style.height = `${Math.max(count ? 8 : 2, (count / peak) * 100)}%`;
    bar.title = `${23 - hour}h ago · ${count} item${count === 1 ? '' : 's'}`;
    chart.appendChild(bar);
  });
  block.appendChild(chart);

  const line = el('p', 'rail-note');
  line.textContent = `${(meta.total_items || 0).toLocaleString()} in the window`
    + (meta.new_since_last ? ` · ${meta.new_since_last.toLocaleString()} new` : '');
  block.appendChild(line);
}

/* ── Sources ──────────────────────────────────────────────────────────────
 * One cell per configured feed. This is the signature of the rail and the
 * only place it raises its voice: 43 cells is instantly legible as "43
 * things are being watched", which is a claim the page could not previously
 * make anywhere.
 *
 * The data is `source_health`, which the pipeline has always computed and
 * which was only ever visible inside a panel nobody opens.
 */
function railRenderSources(host, meta) {
  const health = meta.source_health || {};
  const names = Object.keys(health).sort();
  if (!names.length) return;

  const block = railBlock(host, 'Sources', String(meta.sources_configured || names.length));
  const grid = el('div', 'rail-matrix');
  grid.setAttribute('role', 'img');
  grid.setAttribute('aria-label',
    `${meta.sources_ok || 0} of ${names.length} sources live, `
    + `${meta.sources_stale || 0} stale, ${meta.sources_empty || 0} empty`);

  names.forEach((name) => {
    const entry = health[name] || {};
    const status = String(entry.status || 'error');
    const state = (RAIL_SOURCE_STATES.find(([key]) => key === status) || ['error', 'error'])[1];
    const cell = el('span', `rail-cell is-${state}`);
    // Title rather than a click target: the rail is read-only, and a grid of
    // 43 tiny buttons would be a keyboard trap for no benefit.
    const age = entry.median_age_days;
    cell.title = `${name} — ${state}`
      + (typeof age === 'number' ? ` · median age ${age}d` : '')
      + (entry.error ? ` · ${String(entry.error).slice(0, 60)}` : '');
    grid.appendChild(cell);
  });
  block.appendChild(grid);

  const legend = el('p', 'rail-legend');
  [['live', meta.sources_ok], ['stale', meta.sources_stale],
    ['empty', meta.sources_empty], ['error', meta.sources_error]]
    .forEach(([label, count]) => {
      if (!count) return;
      const item = el('span', 'rail-legend-item');
      item.appendChild(el('span', `rail-dot is-${label}`));
      item.appendChild(el('span', '', `${count} ${label}`));
      legend.appendChild(item);
    });
  block.appendChild(legend);
}

/* ── Corpus ───────────────────────────────────────────────────────────── */

function railRenderCorpus(host, meta) {
  const lib = meta.library_summary || {};
  const hunt = meta.hunt_summary || {};
  const leaks = meta.leak_summary || {};
  const det = meta.detection_summary || {};
  const breach = meta.breach_catalogue || {};

  const rows = [
    ['entities', lib.count, 'library'],
    ['aliases', lib.names, 'library'],
    ['detections', det.rules_indexed, 'detections'],
    ['hunt packs', hunt.packs, 'hunt'],
    ['leak claims', leaks.claims, 'leaks'],
    ['breaches', breach.total_breaches, null],
  ].filter(([, value]) => typeof value === 'number' && value > 0);
  if (!rows.length) return;

  const block = railBlock(host, 'Corpus', 'indexed');
  rows.forEach(([label, value, view]) => railLedgerRow(block, label, value, view));
}

/* ── KEV ──────────────────────────────────────────────────────────────────
 * The newest additions to CISA's catalogue of vulnerabilities known to be
 * exploited. This is the shortest list on the site of things that are
 * definitely being used against somebody right now, which makes it the one
 * block here that is not merely evidence of activity but a reason to act.
 *
 * Fed by `kev_recent`, a 14-row summary the pipeline puts in intel.json's
 * metadata. The browsable catalogue is a separate 880 KB endpoint and has no
 * business being downloaded by every visitor for a rail.
 */
function railRenderKev(host, meta) {
  const kev = meta.kev_recent || {};
  const entries = kev.entries || [];
  if (!entries.length) return;

  const block = railBlock(host, 'KEV', kev.added_7d ? `+${kev.added_7d} this week` : '');
  const note = el('p', 'rail-note');
  note.textContent = `${(kev.total || 0).toLocaleString()} confirmed exploited`
    + (kev.ransomware_linked
      ? ` · ${kev.ransomware_linked.toLocaleString()} ransomware-linked` : '');
  block.appendChild(note);

  const list = el('ul', 'rail-kev');
  entries.slice(0, 6).forEach((entry) => {
    const row = el('li', 'rail-kev-row');
    const link = el('a', 'rail-kev-cve', entry.cve);
    link.href = safeUrl('https://nvd.nist.gov/vuln/detail/'
      + encodeURIComponent(entry.cve || ''));
    link.target = '_blank';
    link.rel = 'noopener noreferrer';
    row.appendChild(link);
    if (entry.ransomware) row.appendChild(el('span', 'rail-kev-flag', 'ransomware'));
    // Vendor and product are CISA's strings, rendered as text.
    const what = [entry.vendor, entry.product].filter(Boolean).join(' ');
    row.appendChild(el('span', 'rail-kev-what', what || '—'));
    row.appendChild(el('span', 'rail-kev-date', entry.added || ''));
    list.appendChild(row);
  });
  block.appendChild(list);

  const more = el('a', 'rail-more', 'All KEV entries →');
  more.href = '#';
  more.dataset.railView = 'kev';
  block.appendChild(more);
}

/* ── Extortion ticker ─────────────────────────────────────────────────────
 * The one moving thing on the page, and it is deliberately slow.
 *
 * Motion beside a triage list competes for exactly the attention the feed is
 * asking for, so this rotates every four seconds rather than scrolling,
 * pauses on hover and on focus, and does not animate at all under
 * prefers-reduced-motion — where it renders as a static list instead.
 */
function railRenderTicker(host, meta) {
  const dark = meta.darkweb || {};
  const breach = meta.breach_catalogue || {};
  const entries = [];

  (dark.most_active || []).slice(0, 8).forEach((row) => {
    if (!row || !row.group) return;
    entries.push({
      lead: String(row.group),
      trail: `${row.posts} claim${row.posts === 1 ? '' : 's'}`,
      kind: 'extortion',
    });
  });
  (breach.recent || []).slice(0, 8).forEach((row) => {
    if (!row || !row.name) return;
    entries.push({
      lead: String(row.name),
      trail: row.accounts ? `${Number(row.accounts).toLocaleString()} accounts` : String(row.date || ''),
      kind: 'breach',
    });
  });
  if (!entries.length) return;

  const groups = dark.distinct_groups_active;
  const block = railBlock(host, 'Claimed', groups ? `${groups} groups` : '');
  const note = el('p', 'rail-note');
  note.textContent = 'Extortion listings and breach additions. A listing is '
    + 'the group’s claim, not a confirmed breach.';
  block.appendChild(note);

  const reduced = window.matchMedia
    && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  // Cleared unconditionally, before either branch. A visitor's motion
  // preference does not change mid-session, so the static branch never
  // inherits a running timer in practice — but leaving the clear inside the
  // rotating branch makes that a property of the environment rather than of
  // this function, and a timer that outlives its element is the kind of thing
  // that only shows up as a mystery later.
  clearInterval(railTickerTimer);
  railTickerTimer = null;

  if (reduced) {
    // No rotation: the whole list, static. Motion is the enhancement, not
    // the mechanism, so nothing is unreachable without it.
    const list = el('ul', 'rail-ticker is-static');
    entries.slice(0, 8).forEach((entry) => {
      list.appendChild(railTickerItem(entry));
    });
    block.appendChild(list);
    return;
  }

  const stage = el('div', 'rail-ticker');
  const item = railTickerItem(entries[0]);
  stage.appendChild(item);
  block.appendChild(stage);

  let index = 0;
  let paused = false;
  stage.addEventListener('mouseenter', () => { paused = true; });
  stage.addEventListener('mouseleave', () => { paused = false; });
  stage.addEventListener('focusin', () => { paused = true; });
  stage.addEventListener('focusout', () => { paused = false; });

  railTickerTimer = setInterval(() => {
    // Stop entirely once the rail leaves the DOM or the view changes, so a
    // background timer cannot outlive the thing it was drawing.
    if (!document.body.contains(stage)) {
      clearInterval(railTickerTimer);
      railTickerTimer = null;
      return;
    }
    if (paused) return;
    index = (index + 1) % entries.length;
    stage.replaceChildren(railTickerItem(entries[index]));
  }, RAIL_TICKER_MS);
}

function railTickerItem(entry) {
  const row = el('li', 'rail-ticker-row');
  row.appendChild(el('span', `rail-kind is-${entry.kind}`,
    entry.kind === 'breach' ? 'breach' : 'claim'));
  // textContent throughout: a group name is attacker-supplied and a breach
  // name comes from a third party.
  row.appendChild(el('span', 'rail-ticker-lead', entry.lead));
  row.appendChild(el('span', 'rail-ticker-trail', entry.trail));
  return row;
}

/* ── Entry point ──────────────────────────────────────────────────────── */

/*
 * Both gutters, above 1600px.
 *
 * A single left rail still left the right side bare on a wide screen, and an
 * unbalanced page reads as an unfinished one. Rather than pad it out, the
 * blocks are SPLIT by the question they answer, because that is a real
 * distinction and not a way to fill space:
 *
 *   left   is the machine healthy   ingest · sources · corpus
 *   right  what is happening        KEV · claimed
 *
 * Below 1600px there is only room for one column, so everything collapses
 * back into the left rail rather than anything being dropped. Below 1280px
 * neither rail appears and the feed gets the screen, exactly as before.
 */
/*
 * Both gutters, and the decision is CSS's alone.
 *
 * The blocks are SPLIT by the question they answer, which is a real
 * distinction rather than a way to fill space:
 *
 *   left   is the machine healthy   ingest · sources · corpus
 *   right  what is happening        KEV · claimed
 *
 * Below 1600px there is no room for a third column, so the right rail is
 * re-placed by CSS into the bottom of the left column — same DOM, same
 * content, different grid cell. Below 1280px neither appears.
 *
 * WHY NO JAVASCRIPT DECIDES THIS
 * ------------------------------
 * The first version branched in JS on a matchMedia query and re-rendered
 * from a `resize` listener. It left the rail in a split-brain state: the
 * query reported false at 1450px while the DOM still carried the wide
 * layout class and the world blocks sat in a column CSS had un-gridded.
 * Instrumenting it showed why — under viewport emulation NEITHER `resize`
 * nor matchMedia `change` fired at all, so the re-render never ran.
 *
 * Real browsers do fire both, so that code would probably have worked in
 * production. "Probably, and untestable here" is the problem: a layout that
 * depends on an event I cannot observe is one I cannot claim to have
 * verified. Grid placement needs no event, cannot desynchronise from the
 * media query that drives it, and is fully checkable at any width.
 */

function renderRail() {
  const left = $('pulse-rail');
  const right = $('pulse-rail-right');
  const dash = document.querySelector('.dashboard');
  if (!left || !dash) return;

  // Feed view only. In LIBRARY or HUNT the content fills the width on its
  // own, and a second column there would be the old sidebar's mistake.
  const show = store.view === 'feed' && store.items && store.items.length > 0;
  dash.classList.toggle('has-rail', show);
  left.style.display = show ? '' : 'none';
  if (right) right.style.display = show ? '' : 'none';

  if (!show) {
    clearInterval(railTickerTimer);
    railTickerTimer = null;
    left.replaceChildren();
    if (right) right.replaceChildren();
    return;
  }

  const meta = store.meta || {};
  left.replaceChildren();
  if (right) right.replaceChildren();
  const world = right || left;

  railRenderIngest(left, meta, store.items);
  railRenderSources(left, meta);
  railRenderCorpus(left, meta);
  railRenderKev(world, meta);
  railRenderTicker(world, meta);

  // Ledger rows that name a view navigate to it. Delegated, because the rows
  // are rebuilt on every render and the CSP forbids inline handlers. Adding
  // the same named listener repeatedly is a no-op, so this is safe to call on
  // every render.
  left.addEventListener('click', railOnClick);
  if (right) right.addEventListener('click', railOnClick);

}

function railOnClick(event) {
  const row = event.target.closest('[data-rail-view]');
  if (!row) return;
  event.preventDefault();
  setView(row.dataset.railView);
}
