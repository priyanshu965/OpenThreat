/**
 * OPENTHREAT — js/trends.js
 *
 * Trends view: the volume chart, bar charts and the data table behind them.
 * Hand-rolled SVG; svgEl() itself stays in app.js because other views use it.
 *
 * Moved out of app.js unchanged. Loaded as a classic script after it and
 * shares its top-level scope: store, el, $, svgEl and the other helpers are
 * defined there.
 */

'use strict';

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
