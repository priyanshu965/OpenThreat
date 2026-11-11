/**
 * OPENTHREAT — js/landscape.js
 *
 * Threat landscape and geopolitics views, plus the statTile()/lsPanel()
 * building blocks other views reuse.
 *
 * Moved out of app.js unchanged. Loaded as a classic script after it and
 * shares its top-level scope: store, el, $, svgEl and the other helpers are
 * defined there.
 */

'use strict';

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
