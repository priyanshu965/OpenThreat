/**
 * CYBERWATCH — js/research.js
 * ===========================
 * The views that turn the feed into connected intelligence and into evidence:
 *
 *   Graph       actors → malware → techniques → sectors, with KNOWN edges
 *               (MITRE ATT&CK) drawn differently from OBSERVED ones (this
 *               feed, this week). Conflating those two would be the single
 *               most misleading thing this project could do.
 *   Campaigns   clusters of items that are one operation.
 *   Detections  ATT&CK technique activity crossed with SigmaHQ rules, and —
 *               more usefully — the techniques with no rule at all.
 *   Malware     families named this week, with attribution and observation
 *               reported separately.
 *   Research    the scoring backtest, source reliability and the
 *               exploitation-lag timeline.
 *
 * Every builder is pure DOM: no innerHTML anywhere, because everything on
 * screen here originates in a third-party feed.
 */

'use strict';

const NS = 'http://www.w3.org/2000/svg';

function rSvg(tag, attrs) {
  const node = document.createElementNS(NS, tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    node.setAttribute(k, String(v));
  }
  return node;
}

function rHead(host, title, subtitle) {
  const head = el('div', 'rv-head');
  head.appendChild(el('h2', 'rv-title', title));
  if (subtitle) head.appendChild(el('p', 'rv-sub', subtitle));
  host.appendChild(head);
  return head;
}

function rStat(label, value, sub, tone) {
  const box = el('div', `rv-stat${tone ? ` tone-${tone}` : ''}`);
  box.appendChild(el('div', 'rv-stat-value', String(value)));
  box.appendChild(el('div', 'rv-stat-label', label));
  if (sub) box.appendChild(el('div', 'rv-stat-sub', sub));
  return box;
}

function rStatRow(stats) {
  const row = el('div', 'rv-stats');
  stats.forEach((s) => row.appendChild(rStat(s.label, s.value, s.sub, s.tone)));
  return row;
}

function rPanel(title, note) {
  const panel = el('section', 'rv-panel');
  const head = el('div', 'rv-panel-head');
  head.appendChild(el('h3', 'rv-panel-title', title));
  if (note) head.appendChild(el('p', 'rv-panel-note', note));
  panel.appendChild(head);
  return panel;
}

function rNote(text) {
  return el('p', 'rv-note', text);
}

function rTable(columns, rows) {
  const wrap = el('div', 'rv-table-wrap');
  const table = el('table', 'rv-table');
  const thead = el('thead');
  const hr = el('tr');
  columns.forEach((c) => {
    const th = el('th', c.numeric ? 'is-num' : null, c.label);
    if (c.title) th.title = c.title;
    hr.appendChild(th);
  });
  thead.appendChild(hr);
  table.appendChild(thead);
  const tbody = el('tbody');
  rows.forEach((row) => {
    const tr = el('tr');
    if (row._class) tr.className = row._class;
    columns.forEach((c) => {
      const cell = row[c.key];
      const td = el('td', c.numeric ? 'is-num' : null);
      if (cell && cell.node) td.appendChild(cell.node);
      else td.textContent = cell === null || cell === undefined ? '—' : String(cell);
      if (cell && cell.title) td.title = cell.title;
      tr.appendChild(td);
    });
    tbody.appendChild(tr);
  });
  table.appendChild(tbody);
  wrap.appendChild(table);
  return wrap;
}

/** Horizontal bar rows. One hue: bar length already encodes the value. */
function rBars(rows, opts) {
  const options = opts || {};
  const max = Math.max(1, ...rows.map((r) => Math.abs(r.value)));
  const list = el('div', 'rv-bars');
  rows.forEach((row) => {
    const line = el('div', `rv-bar-row${row.click ? ' is-click' : ''}`);
    if (row.click) Object.assign(line.dataset, row.click);
    line.appendChild(el('span', 'rv-bar-label', row.label));
    const track = el('span', 'rv-bar-track');
    const fill = el('span', `rv-bar-fill${row.tone ? ` tone-${row.tone}` : ''}`);
    fill.style.width = `${(Math.abs(row.value) / max) * 100}%`;
    track.appendChild(fill);
    line.appendChild(track);
    line.appendChild(el('span', 'rv-bar-value',
      options.format ? options.format(row.value) : String(row.value)));
    if (row.note) line.title = row.note;
    list.appendChild(line);
  });
  return list;
}

// ═══════════════════════════════════════════════════════════════════════════
// GRAPH
// ═══════════════════════════════════════════════════════════════════════════

const GRAPH_COLUMNS = [
  { type: 'actor',     label: 'THREAT ACTORS' },
  { type: 'software',  label: 'MALWARE & TOOLS' },
  { type: 'technique', label: 'ATT&CK TECHNIQUES' },
  { type: 'sector',    label: 'TARGET SECTORS' },
];

/**
 * A layered layout rather than a force-directed hairball.
 *
 * The data has a natural direction — actor uses malware, malware implements
 * technique, technique is seen against a sector — and a spring simulation
 * throws that away in exchange for an unreadable ball of string. Columns keep
 * the reading order that the relationships actually have, and the layout is
 * deterministic, so the graph does not rearrange itself between visits.
 */
function buildGraphSvg(data, state) {
  const nodesByType = {};
  GRAPH_COLUMNS.forEach((col) => {
    nodesByType[col.type] = data.nodes
      .filter((n) => n.type === col.type)
      .sort((a, b) => (b.count || 0) - (a.count || 0))
      .slice(0, state.perColumn);
  });

  const visible = new Set();
  Object.values(nodesByType).forEach((list) => list.forEach((n) => visible.add(n.id)));

  let edges = data.edges.filter((e) => visible.has(e.source) && visible.has(e.target));
  if (state.origin !== 'all') edges = edges.filter((e) => e.origin === state.origin);
  if (state.focus) {
    edges = edges.filter((e) => e.source === state.focus || e.target === state.focus);
    const touched = new Set([state.focus]);
    edges.forEach((e) => { touched.add(e.source); touched.add(e.target); });
    GRAPH_COLUMNS.forEach((col) => {
      nodesByType[col.type] = nodesByType[col.type].filter((n) => touched.has(n.id));
    });
  }

  const colWidth = 250;
  const rowHeight = 26;
  const topPad = 46;
  const tallest = Math.max(1, ...GRAPH_COLUMNS.map((c) => nodesByType[c.type].length));
  const height = topPad + tallest * rowHeight + 24;
  const width = GRAPH_COLUMNS.length * colWidth;

  const svg = rSvg('svg', {
    viewBox: `0 0 ${width} ${height}`,
    class: 'graph-svg',
    role: 'img',
    'aria-label': 'Entity graph: threat actors, malware, techniques and sectors',
  });

  const pos = {};
  GRAPH_COLUMNS.forEach((col, ci) => {
    const x = ci * colWidth + 14;
    svg.appendChild(Object.assign(rSvg('text', {
      x, y: 22, class: 'graph-col-label',
    }), { textContent: col.label }));
    nodesByType[col.type].forEach((node, ri) => {
      pos[node.id] = { x, y: topPad + ri * rowHeight, col: ci };
    });
  });

  // Edges first so nodes sit on top of them.
  const edgeLayer = rSvg('g', { class: 'graph-edges' });
  edges.forEach((e) => {
    const a = pos[e.source];
    const b = pos[e.target];
    if (!a || !b || a.col === b.col) return;
    const x1 = a.x + 200;
    const y1 = a.y - 4;
    const x2 = b.x - 6;
    const y2 = b.y - 4;
    const mid = (x1 + x2) / 2;
    const path = rSvg('path', {
      d: `M ${x1} ${y1} C ${mid} ${y1}, ${mid} ${y2}, ${x2} ${y2}`,
      class: `graph-edge origin-${e.origin}`,
      'stroke-width': Math.min(3, 0.6 + (e.weight || 1) * 0.35),
    });
    const title = rSvg('title', {});
    title.textContent = `${e.kind} (${e.origin === 'attack' ? 'MITRE ATT&CK' : 'observed in this feed'})`;
    path.appendChild(title);
    edgeLayer.appendChild(path);
  });
  svg.appendChild(edgeLayer);

  GRAPH_COLUMNS.forEach((col) => {
    nodesByType[col.type].forEach((node) => {
      const p = pos[node.id];
      const g = rSvg('g', {
        class: `graph-node type-${node.type}${state.focus === node.id ? ' is-focus' : ''}`,
        tabindex: '0', role: 'button',
      });
      g.dataset.nodeId = node.id;
      g.dataset.nodeKind = node.type;
      g.dataset.nodeLabel = node.label;
      const box = rSvg('rect', {
        x: p.x - 6, y: p.y - 16, width: 206, height: 20, rx: 3,
        class: 'graph-node-box',
      });
      g.appendChild(box);
      const label = rSvg('text', { x: p.x, y: p.y - 2, class: 'graph-node-text' });
      const shown = node.type === 'technique' && node.name
        ? `${node.label} ${node.name}` : node.label;
      label.textContent = shown.length > 27 ? `${shown.slice(0, 26)}…` : shown;
      g.appendChild(label);
      if (node.count) {
        const count = rSvg('text', { x: p.x + 194, y: p.y - 2, class: 'graph-node-count' });
        count.textContent = String(node.count);
        g.appendChild(count);
      }
      const title = rSvg('title', {});
      title.textContent = `${shown}\n${node.count || 0} item(s) this week`
        + (node.aliases && node.aliases.length ? `\naka ${node.aliases.join(', ')}` : '');
      g.appendChild(title);
      svg.appendChild(g);
    });
  });

  return { svg, shown: edges.length };
}

const graphState = { origin: 'all', perColumn: 14, focus: null };

function renderGraph(host, data) {
  host.replaceChildren();
  rHead(host, 'Entity graph',
    'Threat actors, the malware they run, the techniques it implements and the '
    + 'sectors it lands on. Solid edges are MITRE ATT&CK relationships; dashed '
    + 'edges are co-occurrence in this feed, which is a much weaker claim.');

  const c = data.counts || {};
  host.appendChild(rStatRow([
    { label: 'actors', value: c.actors || 0 },
    { label: 'malware & tools', value: c.software || 0 },
    { label: 'techniques', value: c.techniques || 0 },
    { label: 'sectors', value: c.sectors || 0 },
    { label: 'ATT&CK edges', value: c.known_edges || 0, sub: 'curated' },
    { label: 'observed edges', value: c.observed_edges || 0, sub: 'this feed' },
  ]));

  const controls = el('div', 'graph-controls');
  [['all', 'ALL EDGES'], ['attack', 'ATT&CK ONLY'], ['observed', 'OBSERVED ONLY']]
    .forEach(([value, label]) => {
      const btn = el('button', `graph-toggle${graphState.origin === value ? ' active' : ''}`, label);
      btn.type = 'button';
      btn.dataset.graphOrigin = value;
      controls.appendChild(btn);
    });
  if (graphState.focus) {
    const clear = el('button', 'graph-toggle is-clear', '✕ CLEAR FOCUS');
    clear.type = 'button';
    clear.dataset.graphOrigin = 'clear-focus';
    controls.appendChild(clear);
  }
  const legend = el('div', 'graph-legend');
  legend.appendChild(el('span', 'graph-legend-item legend-attack', 'MITRE ATT&CK'));
  legend.appendChild(el('span', 'graph-legend-item legend-observed', 'observed together'));
  legend.appendChild(el('span', 'graph-hint', 'click a node to focus · double-click to open it'));
  controls.appendChild(legend);
  host.appendChild(controls);

  const board = el('div', 'graph-board');
  const built = buildGraphSvg(data, graphState);
  board.appendChild(built.svg);
  host.appendChild(board);

  if (!built.shown) {
    host.appendChild(rNote('No edges match this filter. Clear the focus or switch back to all edges.'));
  }
  host.appendChild(rNote(
    `ATT&CK knowledge base built ${(data.kb_built || '').slice(0, 10) || 'unknown'}. `
    + 'An observed edge means two things appeared in the same item, nothing more — '
    + 'MITRE has not asserted a relationship, and neither has this tool.'));
}

function showGraphView() {                                  // eslint-disable-line no-unused-vars
  showLazyView('graph-view', 'graph', renderGraph,
    'The entity graph has not been published yet. It appears after a pipeline '
    + 'run with ENABLE_ENTITY_GRAPH on.');
}

// ═══════════════════════════════════════════════════════════════════════════
// CAMPAIGNS
// ═══════════════════════════════════════════════════════════════════════════

function renderCampaigns(host, data) {
  host.replaceChildren();
  rHead(host, 'Campaigns',
    `Items grouped into operations over the last ${data.window_days} days. `
    + 'A cluster is a claim that several rows are one thing — so every one '
    + 'carries the evidence that joined it.');

  const campaigns = data.campaigns || [];
  host.appendChild(rStatRow([
    { label: 'clusters', value: data.count || 0 },
    { label: 'high confidence', value: campaigns.filter((x) => x.confidence === 'high').length, tone: 'urgent' },
    { label: 'items covered', value: campaigns.reduce((n, x) => n + x.items, 0) },
    { label: 'window', value: `${data.window_days}d` },
  ]));

  if (!campaigns.length) {
    host.appendChild(emptyState('Nothing clustered this window. That is a legitimate '
      + 'answer: a campaign needs a shared actor or malware family across at least '
      + `${data.min_items} items.`));
    return;
  }

  const list = el('div', 'campaign-list');
  campaigns.forEach((camp) => {
    const card = el('article', `campaign-card conf-${camp.confidence}`);

    const head = el('div', 'campaign-head');
    const name = el('button', 'campaign-name', camp.anchor);
    name.type = 'button';
    name.dataset.nodeKind = camp.anchor_type === 'actor' ? 'actor' : 'malware';
    name.dataset.nodeLabel = camp.anchor;
    head.appendChild(name);
    head.appendChild(el('span', `campaign-conf conf-${camp.confidence}`,
      `${camp.confidence} confidence`));
    card.appendChild(head);

    const facts = el('div', 'campaign-facts');
    const fact = (label, value, title) => {
      const box = el('span', 'campaign-fact');
      box.appendChild(el('span', 'campaign-fact-value', String(value)));
      box.appendChild(el('span', 'campaign-fact-label', label));
      if (title) box.title = title;
      facts.appendChild(box);
    };
    fact('items', camp.items);
    fact('sources', camp.distinct_sources,
      'Independent sources. Five rows from one feed is one observation repeated.');
    fact('days', camp.span_days || '<1');
    if (camp.cves.length) fact('CVEs', camp.cves.length);
    if (camp.kev_count) fact('KEV', camp.kev_count, 'Actively exploited vulnerabilities in this cluster');
    if (camp.top_priority) fact('top P', Math.round(camp.top_priority));
    card.appendChild(facts);

    const chips = el('div', 'campaign-chips');
    camp.sectors.forEach((s) => chips.appendChild(el('span', 'campaign-chip chip-sector', s)));
    camp.malware.forEach((m) => {
      const chip = el('span', 'campaign-chip chip-malware', m);
      chip.dataset.malware = m;
      chips.appendChild(chip);
    });
    camp.techniques.slice(0, 6).forEach((t) => {
      const chip = el('span', 'campaign-chip chip-tech', t);
      chip.dataset.nodeKind = 'technique';
      chip.dataset.nodeLabel = t;
      chips.appendChild(chip);
    });
    if (chips.childElementCount) card.appendChild(chips);

    const members = el('details', 'campaign-members');
    const summary = el('summary', 'campaign-members-summary',
      `Evidence — ${camp.members.length} item${camp.members.length === 1 ? '' : 's'}`
      + (camp.extended_items ? ` (${camp.extended_items} joined by technique + sector overlap)` : ''));
    members.appendChild(summary);
    camp.members.forEach((m) => {
      const row = el('div', 'campaign-member');
      const href = safeUrl(m.url);
      if (href) {
        const a = el('a', 'campaign-member-title', m.title);
        a.href = href; a.target = '_blank'; a.rel = 'noopener noreferrer';
        row.appendChild(a);
      } else {
        row.appendChild(el('span', 'campaign-member-title', m.title));
      }
      row.appendChild(el('span', 'campaign-member-meta',
        `${m.source} · ${(m.published || '').slice(0, 10)}`));
      row.appendChild(el('span',
        `campaign-join join-${m.joined_by === 'anchor' ? 'anchor' : 'weak'}`,
        m.joined_by === 'anchor' ? 'anchor' : 'technique + sector'));
      members.appendChild(row);
    });
    card.appendChild(members);
    list.appendChild(card);
  });
  host.appendChild(list);

  (data.notes || []).forEach((n) => host.appendChild(rNote(n)));
}

function showCampaignsView() {                              // eslint-disable-line no-unused-vars
  showLazyView('campaigns-view', 'campaigns', renderCampaigns,
    'No campaign clustering has been published yet.');
}

// ═══════════════════════════════════════════════════════════════════════════
// DETECTIONS (SigmaHQ)
// ═══════════════════════════════════════════════════════════════════════════

const LEVEL_TONE = { critical: 'urgent', high: 'elevated', medium: 'moderate', low: 'low' };

function renderDetections(host, data) {
  host.replaceChildren();
  rHead(host, 'Detection coverage',
    'Every technique the feed observed this week, crossed with the public '
    + 'SigmaHQ rules that would catch it. The gaps at the bottom are the part '
    + 'worth reading: activity with no public detection behind it.');

  host.appendChild(rStatRow([
    { label: 'coverage of activity', value: `${data.coverage_pct}%`,
      sub: 'observed technique hits with a rule',
      tone: data.coverage_pct >= 70 ? 'ok' : data.coverage_pct >= 40 ? 'moderate' : 'urgent' },
    { label: 'techniques active', value: data.techniques_active },
    { label: 'with rules', value: data.techniques_covered },
    { label: 'no rule at all', value: data.techniques_uncovered, tone: 'urgent' },
    { label: 'Sigma rules indexed', value: data.rules_indexed },
  ]));

  const covered = rPanel('Techniques with detection rules',
    'Ranked by how often the technique appeared in the feed, not by rule count.');
  (data.techniques || []).forEach((row) => {
    const block = el('details', 'detect-block');
    const summary = el('summary', 'detect-summary');
    summary.appendChild(el('span', 'detect-tech', row.technique));
    summary.appendChild(el('span', 'detect-name', row.name || ''));
    summary.appendChild(el('span', 'detect-seen', `${row.seen}x in feed`));
    summary.appendChild(el('span', 'detect-rules',
      `${row.rules.length}${row.rule_total > row.rules.length ? ` of ${row.rule_total}` : ''} rules`));
    block.appendChild(summary);
    row.rules.forEach((rule) => {
      const line = el('div', 'detect-rule');
      line.appendChild(el('span',
        `detect-level tone-${LEVEL_TONE[rule.level] || 'low'}`, rule.level || '?'));
      const href = safeUrl(rule.url);
      if (href) {
        const a = el('a', 'detect-rule-title', rule.title);
        a.href = href; a.target = '_blank'; a.rel = 'noopener noreferrer';
        line.appendChild(a);
      } else {
        line.appendChild(el('span', 'detect-rule-title', rule.title));
      }
      line.appendChild(el('span', 'detect-logsource', rule.logsource || ''));
      if (rule.status) line.appendChild(el('span', 'detect-status', rule.status));
      block.appendChild(line);
    });
    covered.appendChild(block);
  });
  host.appendChild(covered);

  if ((data.gaps || []).length) {
    const gaps = rPanel(`Detection gaps — ${data.gaps.length} techniques`,
      'Seen in the feed, no public Sigma rule tagged to them. Either the '
      + 'technique is hard to detect generically, or nobody has written the rule.');
    gaps.appendChild(rBars(data.gaps.slice(0, 20).map((g) => ({
      label: `${g.technique} ${g.name || ''}`.trim(),
      value: g.seen,
      tone: 'urgent',
      click: { nodeKind: 'technique', nodeLabel: g.technique },
    })), { format: (v) => `${v}x` }));
    host.appendChild(gaps);
  }

  host.appendChild(rNote(
    `Sigma index built ${(data.built || '').slice(0, 10)}. Rules are the public `
    + 'SigmaHQ corpus only — your own detections are not counted, so treat this '
    + 'as a floor on coverage rather than a measure of your SOC.'));
}

function showDetectionsView() {                             // eslint-disable-line no-unused-vars
  showLazyView('detections-view', 'detections', renderDetections,
    'No detection index has been published yet. It appears after a pipeline run '
    + 'with ENABLE_SIGMA on.');
}

// ═══════════════════════════════════════════════════════════════════════════
// MALWARE FAMILIES
// ═══════════════════════════════════════════════════════════════════════════

function renderMalware(host, data) {
  host.replaceChildren();
  rHead(host, 'Malware families',
    'Families named in the feed this week, resolved against Malpedia. '
    + 'Curated attribution and what this feed actually observed are shown '
    + 'separately — they are different kinds of claim.');

  host.appendChild(rStatRow([
    { label: 'families this week', value: data.count },
    { label: 'known corpus', value: data.corpus_size, sub: 'Malpedia' },
    { label: 'with attribution', value: (data.families || []).filter((f) => f.attributed_actors.length).length },
  ]));

  const list = el('div', 'malware-list');
  (data.families || []).forEach((fam) => {
    const card = el('article', 'malware-card');
    const head = el('div', 'malware-head');
    const name = el('button', 'malware-name', fam.name);
    name.type = 'button';
    name.dataset.nodeKind = 'malware';
    name.dataset.nodeLabel = fam.name;
    head.appendChild(name);
    if (fam.platform) head.appendChild(el('span', 'malware-platform', fam.platform));
    head.appendChild(el('span', 'malware-count', `${fam.count} item${fam.count === 1 ? '' : 's'}`));
    if (!fam.known) {
      const unknown = el('span', 'malware-unknown', 'not in Malpedia');
      unknown.title = 'Matched from the ATT&CK software list rather than the family corpus.';
      head.appendChild(unknown);
    }
    card.appendChild(head);

    if (fam.aliases.length) {
      card.appendChild(el('p', 'malware-aliases', `aka ${fam.aliases.join(', ')}`));
    }
    if (fam.description) {
      card.appendChild(el('p', 'malware-desc', fam.description));
    }

    const facets = el('div', 'malware-facets');
    const facet = (label, values, cls, title) => {
      if (!values || !values.length) return;
      const row = el('div', 'malware-facet');
      const key = el('span', 'malware-facet-label', label);
      if (title) key.title = title;
      row.appendChild(key);
      const chips = el('span', 'malware-facet-chips');
      values.slice(0, 8).forEach((v) => chips.appendChild(el('span', `malware-chip ${cls}`, v)));
      row.appendChild(chips);
      facets.appendChild(row);
    };
    facet('attributed to', fam.attributed_actors, 'chip-known',
      "Malpedia's curated attribution — a claim about the world.");
    facet('seen with', fam.observed_actors, 'chip-observed',
      'Actors named in the same items this week — co-occurrence, not attribution.');
    facet('sectors', fam.observed_sectors, 'chip-sector');
    facet('techniques', fam.observed_techniques, 'chip-tech');
    if (facets.childElementCount) card.appendChild(facets);

    if (fam.examples.length) {
      const ex = el('details', 'malware-examples');
      ex.appendChild(el('summary', 'malware-examples-summary',
        `${fam.examples.length} item${fam.examples.length === 1 ? '' : 's'} in the feed`));
      fam.examples.forEach((item) => {
        const row = el('div', 'malware-example');
        const href = safeUrl(item.url);
        if (href) {
          const a = el('a', 'malware-example-title', item.title);
          a.href = href; a.target = '_blank'; a.rel = 'noopener noreferrer';
          row.appendChild(a);
        } else {
          row.appendChild(el('span', 'malware-example-title', item.title));
        }
        row.appendChild(el('span', 'malware-example-meta',
          `${item.source} · ${(item.published || '').slice(0, 10)}`));
        ex.appendChild(row);
      });
      card.appendChild(ex);
    }
    if (fam.url) {
      const link = el('a', 'malware-link', 'Malpedia profile →');
      link.href = safeUrl(fam.url); link.target = '_blank'; link.rel = 'noopener noreferrer';
      card.appendChild(link);
    }
    list.appendChild(card);
  });
  host.appendChild(list);
}

function showMalwareView() {                                // eslint-disable-line no-unused-vars
  showLazyView('malware-view', 'malware', renderMalware,
    'No malware families were named in this run.');
}

// ═══════════════════════════════════════════════════════════════════════════
// RESEARCH — backtest, source reliability, exploitation lag
// ═══════════════════════════════════════════════════════════════════════════

const researchState = { tab: 'backtest' };
const RESEARCH_TABS = [
  { id: 'backtest', label: 'SCORING BACKTEST', api: 'backtest' },
  { id: 'reliability', label: 'SOURCE RELIABILITY', api: 'reliability' },
  { id: 'lag', label: 'EXPLOITATION LAG', api: 'lag' },
];

function renderBacktest(host, data) {
  rHead(host, 'Does the score predict exploitation?',
    'The pipeline blends CVSS, EPSS, SSVC, PoC availability and KEV using '
    + 'weights nobody ever checked. This checks them, against 90 days of '
    + 'archived scores and CISA KEV listing dates.');

  const cohort = data.cohort || {};
  host.appendChild(rStatRow([
    { label: 'CVEs evaluated', value: cohort.evaluated || 0,
      sub: 'scored, not already in KEV, past the horizon' },
    { label: 'later listed in KEV', value: cohort.became_kev || 0 },
    { label: 'base rate', value: `${((cohort.base_rate || 0) * 100).toFixed(2)}%`,
      sub: 'what random selection would achieve' },
    { label: 'horizon', value: `${data.horizon_days}d` },
    { label: 'archive depth', value: `${data.archive_days}d` },
  ]));

  const verdict = el('div', `rv-verdict${data.insufficient_data ? ' is-thin' : ''}`);
  verdict.appendChild(el('span', 'rv-verdict-label', 'RESULT'));
  verdict.appendChild(el('p', 'rv-verdict-text', data.verdict || ''));
  host.appendChild(verdict);

  if (data.insufficient_data) {
    host.appendChild(rNote(
      'The experiment is running but the archive is not deep enough to answer yet. '
      + 'It will fill in as the daily snapshots accumulate.'));
    (data.caveats || []).forEach((c) => host.appendChild(rNote(c)));
    return;
  }

  // Model comparison. Average precision, not ROC-AUC: the positive class is
  // ~2% of the cohort and ROC flatters a ranker on data that imbalanced.
  const models = data.models || [];
  const compare = rPanel('Blend vs its own inputs',
    'Average precision (area under the precision-recall curve), and lift over '
    + 'the base rate. Higher is better; 1.0x lift means no better than chance.');
  compare.appendChild(rTable([
    { key: 'name', label: 'Scoring method' },
    { key: 'ap', label: 'Avg precision', numeric: true, title: 'Area under the precision-recall curve' },
    { key: 'lift', label: 'Lift', numeric: true, title: 'How many times better than picking at random' },
    { key: 'p25', label: 'Precision@25', numeric: true, title: 'Of the top 25 it ranked, how many were later exploited' },
    { key: 'f1', label: 'Best F1', numeric: true },
  ], models.map((m) => {
    const p25 = (m.precision_at_k || []).find((k) => k.k === 25);
    const best = models.reduce((acc, x) => Math.max(acc, x.average_precision), 0);
    return {
      _class: m.average_precision >= best ? 'is-best' : '',
      name: m.name,
      ap: m.average_precision.toFixed(3),
      lift: `${m.lift_over_base.toFixed(2)}x`,
      p25: p25 ? `${(p25.precision * 100).toFixed(0)}%` : '—',
      f1: m.best_f1 ? m.best_f1.f1.toFixed(3) : '—',
    };
  })));
  host.appendChild(compare);

  // Threshold curve for the blend.
  const blend = models[0];
  if (blend && blend.curve) {
    const curve = rPanel('Precision and recall by score threshold',
      'Read it as: "if I only ever looked at items scoring above X, how much '
      + 'of what mattered would I have caught, and how much noise would I have read?"');
    curve.appendChild(rTable([
      { key: 'threshold', label: 'Score ≥', numeric: true },
      { key: 'flagged', label: 'Flagged', numeric: true },
      { key: 'tp', label: 'Hits', numeric: true },
      { key: 'precision', label: 'Precision', numeric: true },
      { key: 'recall', label: 'Recall', numeric: true },
      { key: 'f1', label: 'F1', numeric: true },
    ], blend.curve.filter((c) => c.flagged).map((c) => ({
      threshold: c.threshold,
      flagged: c.flagged,
      tp: c.tp,
      precision: `${(c.precision * 100).toFixed(1)}%`,
      recall: `${(c.recall * 100).toFixed(1)}%`,
      f1: c.f1.toFixed(3),
    }))));
    host.appendChild(curve);
  }

  // Weight search.
  const search = data.weight_search;
  if (search) {
    const panel = rPanel('What the weights should have been',
      search.note || '');
    const rows = [];
    if (search.current) {
      rows.push({
        _class: 'is-current',
        setup: `CVSS ${search.current.cvss} / EPSS ${search.current.epss} (in use)`,
        ap: search.current.average_precision.toFixed(4),
      });
    }
    (search.top || []).slice(0, 6).forEach((g) => rows.push({
      setup: `CVSS ${g.cvss} / EPSS ${g.epss}`,
      ap: g.average_precision.toFixed(4),
    }));
    panel.appendChild(rTable([
      { key: 'setup', label: 'Weights' },
      { key: 'ap', label: 'Avg precision', numeric: true },
    ], rows));
    panel.appendChild(rNote(
      'These are overridable without touching code: PRIORITY_CVSS_WEIGHT and '
      + 'PRIORITY_EPSS_WEIGHT are environment variables.'));
    host.appendChild(panel);
  }

  const caveats = rPanel('What this does not prove', '');
  (data.caveats || []).forEach((c) => caveats.appendChild(rNote(c)));
  host.appendChild(caveats);
}

function renderReliability(host, data) {
  rHead(host, 'Source reliability',
    'All 43 feeds are currently treated as equal. This asks which of them '
    + 'published things that later turned out to matter — and separates '
    + 'genuine early warning from reporting the announcement.');

  host.appendChild(rStatRow([
    { label: 'sources measured', value: (data.sources || []).length },
    { label: 'base rate', value: `${((data.base_rate || 0) * 100).toFixed(2)}%`,
      sub: 'corpus-wide' },
    { label: 'CVEs evaluated', value: data.corpus_evaluated_cves || 0 },
    { label: 'archive depth', value: `${data.archive_days}d` },
  ]));

  const ranked = rPanel('Ranked by early warning',
    'First-mover means this source was the earliest anywhere in the corpus to '
    + 'carry a CVE that was later listed — and carried it before the listing.');
  ranked.appendChild(rTable([
    { key: 'source', label: 'Source' },
    { key: 'first', label: 'First mover', numeric: true, title: 'Earliest in the corpus, ahead of the KEV listing' },
    { key: 'ahead', label: 'Ahead hits', numeric: true, title: 'Carried before CISA listed it' },
    { key: 'aheadP', label: 'Early precision', numeric: true },
    { key: 'lift', label: 'Lift', numeric: true },
    { key: 'lead', label: 'Median lead', numeric: true, title: 'Days ahead of the KEV listing; negative means behind' },
    { key: 'noise', label: 'Noise', numeric: true, title: 'Items with no CVE, score, actor, technique or indicator' },
    { key: 'volume', label: 'Items', numeric: true },
  ], (data.ranked || []).map((r) => ({
    source: r.source,
    first: r.first_mover_hits,
    ahead: `${r.ahead_hits}/${r.ahead_evaluated}`,
    aheadP: `${(r.ahead_precision * 100).toFixed(1)}%`,
    lift: `${r.lift.toFixed(1)}x`,
    lead: r.median_lead_days === null ? '—' : `${r.median_lead_days}d`,
    noise: `${(r.noise_ratio * 100).toFixed(0)}%`,
    volume: r.items,
  }))));
  host.appendChild(ranked);

  if ((data.dead_weight || []).length) {
    const dead = rPanel('Dead weight',
      'Publishing steadily, contributing nothing enrichable: no CVE, no score, '
      + 'no actor, no technique, no indicator. Not an argument for removal on '
      + 'its own — an indicator feed legitimately looks like this — but worth knowing.');
    dead.appendChild(rBars(data.dead_weight.map((r) => ({
      label: r.source,
      value: r.items,
      tone: 'moderate',
      note: `${(r.noise_ratio * 100).toFixed(0)}% of its items carry nothing enrichable`,
    }))));
    host.appendChild(dead);
  }

  const notes = rPanel('How to read this', '');
  (data.notes || []).forEach((n) => notes.appendChild(rNote(n)));
  host.appendChild(notes);
}

function renderLag(host, data) {
  rHead(host, 'Exploitation lag',
    'How long the patch window actually is: publication → public PoC → CISA '
    + 'KEV listing, tracked by quarter.');

  if (data.insufficient_data) {
    host.appendChild(rStatRow([
      { label: 'KEV entries', value: data.kev_entries },
      { label: 'dates resolved', value: data.dates_known },
      { label: 'coverage', value: `${data.coverage_pct}%` },
    ]));
    host.appendChild(rNote(data.note || 'Still backfilling publication dates.'));
    return;
  }

  const pk = data.published_to_kev || {};
  const pp = data.published_to_poc;
  const ptk = data.poc_to_kev;
  host.appendChild(rStatRow([
    { label: 'median publication → KEV', value: `${pk.median}d`,
      sub: `${pk.n} CVEs · p25 ${pk.p25}d · p75 ${pk.p75}d` },
    ...(pp ? [{ label: 'median publication → PoC', value: `${pp.median}d`, sub: `${pp.n} CVEs` }] : []),
    ...(ptk ? [{ label: 'median PoC → KEV', value: `${ptk.median}d`, sub: `${ptk.n} CVEs` }] : []),
    { label: 'KEV coverage', value: `${data.coverage_pct}%`, sub: 'entries with a publication date' },
  ]));

  if (data.trend) {
    const tone = data.trend.direction === 'shortening' ? 'urgent'
      : data.trend.direction === 'lengthening' ? 'ok' : 'moderate';
    const box = el('div', `rv-verdict tone-${tone}`);
    box.appendChild(el('span', 'rv-verdict-label', 'TREND'));
    box.appendChild(el('p', 'rv-verdict-text',
      `The window is ${data.trend.direction}: median ${data.trend.recent_median} days `
      + `across the two most recent quarters against ${data.trend.earlier_median} days `
      + `in the two before them (${data.trend.delta_days > 0 ? '+' : ''}${data.trend.delta_days} days). `
      + (data.trend.direction === 'shortening'
        ? 'A 30-day patch SLA written against the older figure no longer describes reality.'
        : '')));
    host.appendChild(box);
  }

  if ((data.by_quarter || []).length) {
    const panel = rPanel('Median days from publication to KEV listing, by quarter',
      'Quarters with fewer than three listed CVEs are omitted.');
    panel.appendChild(rBars(data.by_quarter.map((q) => ({
      label: q.quarter,
      value: q.median,
      note: `${q.n} CVEs · p25 ${q.p25}d · p75 ${q.p75}d`,
    })), { format: (v) => `${v}d` }));
    host.appendChild(panel);
  }

  if ((data.fastest || []).length) {
    const panel = rPanel('Fastest to exploitation',
      'The CVEs that went from published to actively-exploited-and-listed quickest. '
      + 'These are what a patch SLA has to survive.');
    panel.appendChild(rTable([
      { key: 'cve', label: 'CVE' },
      { key: 'product', label: 'Product' },
      { key: 'published', label: 'Published' },
      { key: 'added', label: 'KEV listed' },
      { key: 'days', label: 'Days', numeric: true },
      { key: 'ransom', label: 'Ransomware' },
    ], data.fastest.map((r) => ({
      cve: r.cve,
      product: `${r.vendor} ${r.product}`.trim(),
      published: r.published,
      added: r.kev_added,
      days: r.days_to_kev,
      ransom: r.ransomware ? 'known' : '—',
    }))));
    host.appendChild(panel);
  }

  const notes = rPanel('Caveats', '');
  (data.notes || []).forEach((n) => notes.appendChild(rNote(n)));
  host.appendChild(notes);
}

const RESEARCH_RENDERERS = {
  backtest: renderBacktest,
  reliability: renderReliability,
  lag: renderLag,
};

async function showResearchView() {                         // eslint-disable-line no-unused-vars
  hideAllViews();
  const host = $('research-view');
  if (!host) return;
  host.style.display = 'block';
  host.replaceChildren();

  const tabs = el('div', 'research-tabs');
  RESEARCH_TABS.forEach((tab) => {
    const btn = el('button',
      `research-tab${researchState.tab === tab.id ? ' active' : ''}`, tab.label);
    btn.type = 'button';
    btn.dataset.researchTab = tab.id;
    tabs.appendChild(btn);
  });
  host.appendChild(tabs);

  const body = el('div', 'research-body');
  body.appendChild(el('div', 'view-loading', 'Loading…'));
  host.appendChild(body);

  const tab = RESEARCH_TABS.find((t) => t.id === researchState.tab) || RESEARCH_TABS[0];
  let data = store.research[tab.api];
  if (data === undefined) {
    try {
      const resp = await fetch(API[tab.api], { cache: 'no-cache' });
      data = resp.ok ? await resp.json() : null;
    } catch (_) { data = null; }
    store.research[tab.api] = data;
  }
  if (host.style.display === 'none') return;

  body.replaceChildren();
  if (!data) {
    body.appendChild(emptyState(
      'This report has not been published yet. It appears after a pipeline run '
      + 'once the archive is deep enough to say something.'));
    return;
  }
  try {
    RESEARCH_RENDERERS[tab.id](body, data);
  } catch (err) {
    body.replaceChildren(emptyState(`Could not render this report: ${err.message}`));
  }
}

// ─── Delegated interactions for these views ───────────────────────────────────
document.addEventListener('click', (ev) => {
  const tab = ev.target.closest('[data-research-tab]');
  if (tab) {
    researchState.tab = tab.dataset.researchTab;
    showResearchView();
    return;
  }
  const origin = ev.target.closest('[data-graph-origin]');
  if (origin) {
    const value = origin.dataset.graphOrigin;
    if (value === 'clear-focus') graphState.focus = null;
    else graphState.origin = value;
    if (store.research.graph) renderGraph($('graph-view'), store.research.graph);
    return;
  }
  const node = ev.target.closest('.graph-node');
  if (node) {
    // Single click focuses the neighbourhood; the entity drawer is on the
    // label, so exploring the graph does not keep throwing a modal at you.
    graphState.focus = graphState.focus === node.dataset.nodeId ? null : node.dataset.nodeId;
    if (store.research.graph) renderGraph($('graph-view'), store.research.graph);
  }
});

document.addEventListener('dblclick', (ev) => {
  const node = ev.target.closest('.graph-node');
  if (node) openEntityModal(node.dataset.nodeKind, node.dataset.nodeLabel);
});

document.addEventListener('keydown', (ev) => {
  if (ev.key !== 'Enter') return;
  const node = ev.target.closest && ev.target.closest('.graph-node');
  if (node) openEntityModal(node.dataset.nodeKind, node.dataset.nodeLabel);
});
