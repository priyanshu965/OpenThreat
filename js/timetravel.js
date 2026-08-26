/**
 * CYBERWATCH — js/timetravel.js
 * =============================
 * Ninety days of daily snapshots that the dashboard could never open.
 *
 * The pipeline has archived a full snapshot every day since the project
 * started, and the UI has only ever rendered today. Two views use that history:
 *
 *   TIME MACHINE  load any past day into the feed. The board as it looked the
 *                 morning a CVE dropped, with the scores it carried THEN —
 *                 which is the only honest way to look at a past day, and the
 *                 reason the archive stores scores rather than recomputing.
 *
 *   DIFF          two days side by side: what arrived, what left, and what
 *                 changed underneath — a CVE that gained a KEV listing or
 *                 whose score moved. For a research tool, change is the
 *                 interesting signal, and it was only ever exposed as a
 *                 per-item `is_new` flag.
 *
 * Day files are the reduced snapshots published by scripts/timeline.py
 * (~60 KB each), fetched one at a time and cached in memory for the session.
 */

'use strict';

const DAY_MS = 86400000;

function ttDate(value) {
  return /^\d{4}-\d{2}-\d{2}$/.test(String(value || '')) ? String(value) : null;
}

/** Load the timeline index once. Returns null when it has not been published. */
async function loadTimeline() {
  if (store.timeline !== null && store.timeline !== undefined) return store.timeline;
  try {
    const resp = await fetch(API.timeline, { cache: 'no-cache' });
    store.timeline = resp.ok ? await resp.json() : null;
  } catch (_) {
    store.timeline = null;
  }
  return store.timeline;
}

/** Load one archived day, cached for the session. */
async function loadDay(date) {
  const stamp = ttDate(date);
  if (!stamp) return null;
  if (store.dayCache[stamp] !== undefined) return store.dayCache[stamp];
  try {
    const resp = await fetch(API.day(stamp), { cache: 'no-cache' });
    store.dayCache[stamp] = resp.ok ? await resp.json() : null;
  } catch (_) {
    store.dayCache[stamp] = null;
  }
  return store.dayCache[stamp];
}

/**
 * Swap the feed to an archived day.
 *
 * Today's items are parked in `store.liveItems` rather than refetched, so
 * coming back is instant and does not cost another 184 KB.
 */
async function enterDay(date) {
  const stamp = ttDate(date);
  if (!stamp) return;
  const day = await loadDay(stamp);
  if (!day) {
    showToast(`No snapshot published for ${stamp}`);
    return;
  }
  if (!store.liveItems) store.liveItems = store.items;
  store.day = stamp;
  store.items = (day.items || []).map((item) => ({ ...item, _key: itemKey(item) }));
  store.brief = day.brief || null;

  // Priority scoring only started part-way through the archive, so the oldest
  // snapshots legitimately carry no verdicts at all. Landing on one with the
  // default Verdicts filter shows an empty feed and looks broken. Fall back to
  // the full list and SAY why, rather than presenting absence as a result.
  const scored = store.items.some((i) => i.priority_label);
  if (!scored && store.filter === 'verdicts' && store.items.length) {
    store.filter = 'all';
    autoWidened = true;
    showToast(`${stamp} predates priority scoring — showing all ${store.items.length} items`);
  }

  closePanel('timemachine');
  renderTimeMachineBar();
  update();
}

// Set when enterDay() widened the filter on the reader's behalf, so leaving
// the archive puts their own filter back rather than silently keeping ours.
let autoWidened = false;

function exitDay() {
  if (!store.day) return;
  store.day = null;
  if (store.liveItems) {
    store.items = store.liveItems;
    store.liveItems = null;
  }
  store.brief = (store.meta && store.meta.brief) || null;
  if (autoWidened) {
    store.filter = 'verdicts';
    autoWidened = false;
  }
  renderTimeMachineBar();
  update();
}

/** The persistent "you are looking at the past" banner. */
function renderTimeMachineBar() {
  const bar = $('timemachine-bar');
  if (!bar) return;
  if (!store.day) { bar.style.display = 'none'; return; }
  bar.style.display = 'flex';
  bar.replaceChildren();

  bar.appendChild(el('span', 'tmb-badge', 'TIME MACHINE'));
  const days = Math.round((Date.now() - Date.parse(`${store.day}T00:00:00Z`)) / DAY_MS);
  bar.appendChild(el('span', 'tmb-text',
    `Showing ${store.day} — ${days} day${days === 1 ? '' : 's'} ago. Scores and `
    + 'verdicts are the ones this item carried on that day, not today.'));

  const prev = el('button', 'tmb-btn', '‹ PREV');
  prev.type = 'button';
  prev.dataset.tt = 'prev';
  const next = el('button', 'tmb-btn', 'NEXT ›');
  next.type = 'button';
  next.dataset.tt = 'next';
  const diff = el('button', 'tmb-btn', '⇄ COMPARE');
  diff.type = 'button';
  diff.dataset.tt = 'diff';
  const back = el('button', 'tmb-btn is-primary', 'BACK TO TODAY');
  back.type = 'button';
  back.dataset.tt = 'today';
  bar.append(prev, next, diff, back);
}

/** Move n days along the published timeline (not the calendar — days can be missing). */
function stepDay(delta) {
  const timeline = (store.timeline && store.timeline.timeline) || [];
  if (!timeline.length || !store.day) return;
  const idx = timeline.findIndex((row) => row.date === store.day);
  if (idx < 0) return;
  const next = timeline[idx + delta];
  if (!next) { showToast(delta > 0 ? 'Already at the newest snapshot' : 'Already at the oldest snapshot'); return; }
  if (next.live) exitDay(); else enterDay(next.date);
}

// ─── The panel ────────────────────────────────────────────────────────────────
async function renderTimeMachine() {                        // eslint-disable-line no-unused-vars
  const host = $('timemachine-body');
  if (!host) return;
  host.replaceChildren(el('div', 'view-loading', 'Loading the archive index…'));

  const timeline = await loadTimeline();
  host.replaceChildren();

  if (!timeline || !(timeline.timeline || []).length) {
    host.appendChild(emptyState(
      'No day snapshots have been published yet. They appear after a pipeline '
      + 'run with ENABLE_TIMELINE on.'));
    return;
  }

  const rows = timeline.timeline;
  const current = store.day || rows[rows.length - 1].date;

  host.appendChild(el('p', 'tm-lead',
    `${timeline.days} day${timeline.days === 1 ? '' : 's'} available, `
    + `${timeline.first} to ${timeline.last}. Each day is the board exactly as `
    + 'it stood, with the scores it carried then.'));

  // Slider. Indexed into the published list rather than bound to a date, so a
  // missing day cannot land you on a 404.
  const sliderWrap = el('div', 'tm-slider-wrap');
  const slider = el('input', 'tm-slider');
  slider.type = 'range';
  slider.min = '0';
  slider.max = String(rows.length - 1);
  slider.value = String(Math.max(0, rows.findIndex((r) => r.date === current)));
  slider.id = 'tm-slider';
  slider.setAttribute('aria-label', 'Choose a day');
  sliderWrap.appendChild(slider);
  const readout = el('div', 'tm-readout');
  readout.id = 'tm-readout';
  sliderWrap.appendChild(readout);
  host.appendChild(sliderWrap);

  // Sparkline of daily volume, so the slider has a shape to aim at.
  const spark = buildTimelineSpark(rows, current);
  if (spark) host.appendChild(spark);

  const go = el('button', 'tm-go', 'LOAD THIS DAY');
  go.type = 'button';
  go.id = 'tm-go';
  host.appendChild(go);

  if (store.day) {
    const back = el('button', 'tm-go ghost', 'BACK TO TODAY');
    back.type = 'button';
    back.dataset.tt = 'today';
    host.appendChild(back);
  }

  // Diff picker.
  const diffPanel = el('div', 'tm-diff');
  diffPanel.appendChild(el('h4', 'tm-diff-title', 'Compare two days'));
  diffPanel.appendChild(el('p', 'tm-diff-note',
    'What arrived, what left, and what changed underneath.'));
  const pickRow = el('div', 'tm-diff-row');
  [['from', 'From'], ['to', 'To']].forEach(([which, label]) => {
    const wrap = el('label', 'tm-diff-field');
    wrap.appendChild(el('span', 'tm-diff-label', label));
    const select = el('select', 'tm-diff-select');
    select.id = `tm-diff-${which}`;
    rows.forEach((row) => {
      const option = el('option', null, `${row.date}  (${row.items} items)`);
      option.value = row.date;
      select.appendChild(option);
    });
    const defaults = {
      from: store.diffFrom || rows[Math.max(0, rows.length - 8)].date,
      to: store.diffTo || rows[rows.length - 1].date,
    };
    select.value = defaults[which];
    wrap.appendChild(select);
    pickRow.appendChild(wrap);
  });
  diffPanel.appendChild(pickRow);
  const runDiff = el('button', 'tm-go', 'COMPARE');
  runDiff.type = 'button';
  runDiff.id = 'tm-diff-run';
  diffPanel.appendChild(runDiff);
  host.appendChild(diffPanel);

  // Archive health. Trends, the sector benchmark and the backtest all read the
  // archive, and it lives in a CI cache that can be evicted — so if history has
  // been silently truncated, this is where it shows.
  const health = timeline.archive || {};
  const healthBox = el('div', `tm-health${health.contiguous ? '' : ' is-gapped'}`);
  healthBox.appendChild(el('span', 'tm-health-label', 'ARCHIVE'));
  healthBox.appendChild(el('span', 'tm-health-text',
    `${health.days || 0} snapshot${health.days === 1 ? '' : 's'} spanning `
    + `${health.span_days || 0} days`
    + (health.contiguous ? ' · no gaps'
      : ` · ${health.missing_count} missing day${health.missing_count === 1 ? '' : 's'}`)));
  if (!health.contiguous && (health.missing || []).length) {
    healthBox.title = `Missing: ${health.missing.join(', ')}`;
  }
  host.appendChild(healthBox);

  updateTimeMachineReadout();
}

function buildTimelineSpark(rows, current) {
  if (rows.length < 3) return null;
  const width = 320;
  const height = 54;
  const max = Math.max(1, ...rows.map((r) => r.items));
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svg.setAttribute('viewBox', `0 0 ${width} ${height}`);
  svg.setAttribute('class', 'tm-spark');
  svg.setAttribute('role', 'img');
  svg.setAttribute('aria-label', 'Daily item volume across the archive');

  const step = width / rows.length;
  rows.forEach((row, i) => {
    const h = Math.max(1, (row.items / max) * (height - 14));
    const bar = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
    bar.setAttribute('x', String(i * step));
    bar.setAttribute('y', String(height - h));
    bar.setAttribute('width', String(Math.max(1, step - 1)));
    bar.setAttribute('height', String(h));
    bar.setAttribute('class', `tm-spark-bar${row.date === current ? ' is-current' : ''}`);
    const title = document.createElementNS('http://www.w3.org/2000/svg', 'title');
    title.textContent = `${row.date}: ${row.items} items, ${row.urgent} urgent, ${row.kev} KEV`;
    bar.appendChild(title);
    svg.appendChild(bar);
  });
  return svg;
}

function updateTimeMachineReadout() {
  const slider = $('tm-slider');
  const readout = $('tm-readout');
  if (!slider || !readout || !store.timeline) return;
  const row = (store.timeline.timeline || [])[Number(slider.value)];
  if (!row) return;
  readout.replaceChildren();
  readout.appendChild(el('span', 'tm-readout-date', row.date + (row.live ? ' (live)' : '')));
  readout.appendChild(el('span', 'tm-readout-stats',
    `${row.items} items · ${row.urgent} urgent · ${row.elevated} elevated · ${row.kev} KEV`));
}

// ─── Diff ─────────────────────────────────────────────────────────────────────
/** Fields whose change between two days is worth reporting. */
const DIFF_FIELDS = [
  { key: 'priority_score', label: 'priority', format: (v) => (v == null ? '—' : `P${Math.round(v)}`) },
  { key: 'priority_label', label: 'band', format: (v) => v || '—' },
  { key: 'cisa_kev', label: 'KEV', format: (v) => (v ? 'listed' : 'not listed') },
  { key: 'ssvc_exploitation', label: 'SSVC', format: (v) => v || '—' },
  { key: 'has_poc', label: 'public PoC', format: (v) => (v ? 'yes' : 'no') },
  { key: 'epss_score', label: 'EPSS', format: (v) => (v == null ? '—' : `${(v * 100).toFixed(1)}%`) },
  { key: 'cvss_score', label: 'CVSS', format: (v) => (v == null ? '—' : Number(v).toFixed(1)) },
];

function diffDays(fromDay, toDay) {
  const index = (day) => {
    const map = new Map();
    (day.items || []).forEach((item) => map.set(itemKey(item), item));
    return map;
  };
  const before = index(fromDay);
  const after = index(toDay);

  const added = [];
  const removed = [];
  const changed = [];

  after.forEach((item, key) => {
    if (!before.has(key)) { added.push(item); return; }
    const prev = before.get(key);
    const deltas = [];
    DIFF_FIELDS.forEach((field) => {
      const a = prev[field.key];
      const b = item[field.key];
      const same = (a === b) || (a == null && b == null)
        || (typeof a === 'number' && typeof b === 'number' && Math.abs(a - b) < 0.005);
      if (!same) {
        deltas.push({ label: field.label, from: field.format(a), to: field.format(b), key: field.key });
      }
    });
    if (deltas.length) changed.push({ item, prev, deltas });
  });
  before.forEach((item, key) => { if (!after.has(key)) removed.push(item); });

  // Escalation first: a CVE that gained a KEV listing or jumped a band is the
  // whole reason to look at a diff.
  const weight = (row) => {
    if (row.deltas.some((d) => d.key === 'cisa_kev' && d.to === 'listed')) return 0;
    if (row.deltas.some((d) => d.key === 'priority_label')) return 1;
    if (row.deltas.some((d) => d.key === 'has_poc' && d.to === 'yes')) return 2;
    return 3;
  };
  changed.sort((a, b) => weight(a) - weight(b)
    || (b.item.priority_score || 0) - (a.item.priority_score || 0));
  added.sort((a, b) => (b.priority_score || 0) - (a.priority_score || 0));

  return { added, removed, changed };
}

function diffItemRow(item, extra) {
  const row = el('div', 'diff-item');
  const head = el('div', 'diff-item-head');
  if (item.priority_label) {
    head.appendChild(el('span', `diff-band prio-${item.priority_label}`,
      item.priority_label.toUpperCase()));
  }
  const href = safeUrl(item.url);
  if (href) {
    const a = el('a', 'diff-item-title', item.title || '');
    a.href = href; a.target = '_blank'; a.rel = 'noopener noreferrer';
    head.appendChild(a);
  } else {
    head.appendChild(el('span', 'diff-item-title', item.title || ''));
  }
  row.appendChild(head);

  const meta = el('div', 'diff-item-meta');
  if (item.cve_id) meta.appendChild(el('span', 'diff-meta-tag', item.cve_id));
  if (item.source) meta.appendChild(el('span', 'diff-meta-tag', item.source));
  if (item.priority_score != null) {
    meta.appendChild(el('span', 'diff-meta-tag', `P${Math.round(item.priority_score)}`));
  }
  row.appendChild(meta);

  if (extra && extra.length) {
    const deltas = el('div', 'diff-deltas');
    extra.forEach((d) => {
      const chip = el('span', `diff-delta${d.key === 'cisa_kev' && d.to === 'listed' ? ' is-escalation' : ''}`);
      chip.appendChild(el('span', 'diff-delta-label', d.label));
      chip.appendChild(el('span', 'diff-delta-from', d.from));
      chip.appendChild(el('span', 'diff-delta-arrow', '→'));
      chip.appendChild(el('span', 'diff-delta-to', d.to));
      deltas.appendChild(chip);
    });
    row.appendChild(deltas);
  }
  return row;
}

async function showDiffView() {                             // eslint-disable-line no-unused-vars
  hideAllViews();
  const host = $('diff-view');
  if (!host) return;
  host.style.display = 'block';
  host.replaceChildren(el('div', 'view-loading', 'Loading both days…'));

  const timeline = await loadTimeline();
  const rows = (timeline && timeline.timeline) || [];
  if (!rows.length) {
    host.replaceChildren(emptyState('No archived days have been published yet.'));
    return;
  }
  const from = ttDate(store.diffFrom) || rows[Math.max(0, rows.length - 8)].date;
  const to = ttDate(store.diffTo) || rows[rows.length - 1].date;
  store.diffFrom = from;
  store.diffTo = to;

  const [fromDay, toDay] = await Promise.all([loadDay(from), loadDay(to)]);
  if (host.style.display === 'none') return;
  host.replaceChildren();

  rHead(host, 'What changed', `${from} → ${to}`);

  if (!fromDay || !toDay) {
    host.appendChild(emptyState(
      `Could not load ${!fromDay ? from : to}. That day may have fallen out of the `
      + 'retention window, or the archive has a gap there.'));
    return;
  }

  const result = diffDays(fromDay, toDay);
  const escalations = result.changed.filter(
    (c) => c.deltas.some((d) => (d.key === 'cisa_kev' && d.to === 'listed')
      || (d.key === 'priority_label' && ['urgent', 'elevated'].includes(d.to))));

  host.appendChild(rStatRow([
    { label: 'arrived', value: result.added.length, tone: 'ok' },
    { label: 'changed', value: result.changed.length },
    { label: 'escalated', value: escalations.length, tone: escalations.length ? 'urgent' : null,
      sub: 'gained a KEV listing or moved up a band' },
    { label: 'dropped out', value: result.removed.length },
  ]));

  const picker = el('div', 'diff-picker');
  picker.appendChild(el('span', 'diff-picker-label', 'Compare'));
  [['from', from], ['to', to]].forEach(([which, value]) => {
    const select = el('select', 'tm-diff-select');
    select.id = `diff-${which}`;
    rows.forEach((row) => {
      const option = el('option', null, row.date);
      option.value = row.date;
      select.appendChild(option);
    });
    select.value = value;
    picker.appendChild(select);
  });
  const rerun = el('button', 'tm-go', 'UPDATE');
  rerun.type = 'button';
  rerun.id = 'diff-rerun';
  picker.appendChild(rerun);
  host.appendChild(picker);

  const section = (title, note, items, renderer) => {
    if (!items.length) return;
    const panel = rPanel(`${title} — ${items.length}`, note);
    const list = el('div', 'diff-list');
    items.slice(0, 60).forEach((entry) => list.appendChild(renderer(entry)));
    if (items.length > 60) {
      list.appendChild(el('p', 'diff-more', `+${items.length - 60} more not shown`));
    }
    panel.appendChild(list);
    host.appendChild(panel);
  };

  if (escalations.length) {
    section('Escalations', 'Items that got worse between these two days. This is '
      + 'the part of a diff worth reading first.', escalations,
    (entry) => diffItemRow(entry.item, entry.deltas));
  }
  section('Arrived', 'Present on the later day, absent on the earlier one.',
    result.added, (item) => diffItemRow(item));
  section('Changed', 'Same item, different underlying signals.',
    result.changed.filter((c) => !escalations.includes(c)),
    (entry) => diffItemRow(entry.item, entry.deltas));
  section('Dropped out', 'Present on the earlier day and gone by the later one — '
    + 'usually because the source rotated it out of its feed, not because it '
    + 'stopped mattering.', result.removed, (item) => diffItemRow(item));

  if (!result.added.length && !result.changed.length && !result.removed.length) {
    host.appendChild(emptyState('These two days are identical.'));
  }
}

// ─── Wiring ───────────────────────────────────────────────────────────────────
document.addEventListener('click', (ev) => {
  const tt = ev.target.closest('[data-tt]');
  if (tt) {
    const act = tt.dataset.tt;
    if (act === 'today') exitDay();
    if (act === 'prev') stepDay(-1);
    if (act === 'next') stepDay(1);
    if (act === 'diff') { closePanel('timemachine'); setView('diff'); }
    return;
  }
  if (ev.target.closest('#tm-go')) {
    const slider = $('tm-slider');
    const row = store.timeline && (store.timeline.timeline || [])[Number(slider && slider.value)];
    if (!row) return;
    if (row.live) { closePanel('timemachine'); exitDay(); } else enterDay(row.date);
    return;
  }
  if (ev.target.closest('#tm-diff-run')) {
    store.diffFrom = ($('tm-diff-from') || {}).value || null;
    store.diffTo = ($('tm-diff-to') || {}).value || null;
    closePanel('timemachine');
    setView('diff');
    return;
  }
  if (ev.target.closest('#diff-rerun')) {
    store.diffFrom = ($('diff-from') || {}).value || null;
    store.diffTo = ($('diff-to') || {}).value || null;
    showDiffView();
  }
});

document.addEventListener('input', (ev) => {
  if (ev.target && ev.target.id === 'tm-slider') updateTimeMachineReadout();
});
