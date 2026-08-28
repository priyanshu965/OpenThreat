/**
 * OPENTHREAT — js/hunt.js
 * =======================
 * THE HUNT BENCH: what I should do.
 *
 * Everything else in this project tells you something. This is the only part
 * that hands you an instrument:
 *
 *   QUEUE      hypotheses generated from what is active RIGHT NOW, each with
 *              its own justification and a finish line.
 *   PACKS      one technique, fully equipped: MITRE's detection guidance, the
 *              Sigma rules, those rules COMPILED for Splunk / ES|QL / Lucene /
 *              EQL / Sentinel KQL / Defender KQL, the Atomic Red Team tests
 *              that make it happen, and the countermeasures.
 *   COVERAGE   your own detection inventory crossed with what is active, as an
 *              ATT&CK heatmap, exportable as a Navigator layer.
 *   CONTROLS   which controls carry the most weight this week.
 *   NEW RULES  what SigmaHQ shipped since the last run, ranked by whether it
 *              covers anything you are actually seeing.
 *
 * COVERAGE IS PRIVATE
 * -------------------
 * The inventory you paste in is YOUR detection estate — arguably the most
 * sensitive thing a defender could hand a website. It is held in localStorage
 * and never leaves the browser. There is no backend here to send it to, and
 * the CSP has no endpoint that would accept it; that is a property of the
 * architecture, not a promise.
 */

'use strict';

const HUNT_TABS = [
  { key: 'queue', label: 'QUEUE', hint: 'what to hunt today' },
  { key: 'packs', label: 'PACKS', hint: 'technique + rules + queries + tests' },
  { key: 'coverage', label: 'COVERAGE', hint: 'your rules vs live activity' },
  { key: 'controls', label: 'CONTROLS', hint: 'what to fix' },
  { key: 'newrules', label: 'NEW RULES', hint: 'SigmaHQ since last run' },
];

const huntState = {
  tab: 'queue',
  packQuery: '',
  openPack: null,
  backend: readLS('ot.hunt.backend', 'splunk'),
  inventory: readLS('ot.hunt.inventory', ''),
  done: readLS('ot.hunt.done', []),
};

// ─── Hunt queue ───────────────────────────────────────────────────────────────

function huntDone(tid) { return huntState.done.includes(tid); }

function huntToggleDone(tid) {
  const idx = huntState.done.indexOf(tid);
  if (idx >= 0) huntState.done.splice(idx, 1);
  else huntState.done.push(tid);
  writeLS('ot.hunt.done', huntState.done);
}

function renderHuntQueue(host, data) {
  host.replaceChildren();
  if (!data || !data.hunts || !data.hunts.length) {
    host.appendChild(emptyState(
      'No hunt hypotheses yet. They appear once the feed has actors or '
      + 'techniques the pipeline can attribute.'));
    return;
  }

  const outstanding = data.hunts.filter((h) => !huntDone(h.technique)).length;
  const done = data.hunts.length - outstanding;

  const stats = el('div', 'rv-stats');
  stats.appendChild(rStat('OUTSTANDING', outstanding, 'hunts to run',
    outstanding ? 'elevated' : 'low'));
  stats.appendChild(rStat('DONE', done, 'this session'));
  stats.appendChild(rStat('NO COVERAGE', data.uncovered,
    'no public rule exists', data.uncovered ? 'urgent' : 'low'));
  host.appendChild(stats);

  // A finishable list needs a finish line — the v4 triage lesson, applied to
  // hunting. Progress is per-browser and resets with the queue.
  const bar = el('div', 'hunt-progress');
  const fill = el('div', 'hunt-progress-fill');
  fill.style.width = `${Math.round(100 * done / data.hunts.length)}%`;
  bar.appendChild(fill);
  host.appendChild(bar);

  if (!outstanding) {
    const finished = el('div', 'hunt-finished');
    finished.appendChild(el('p', 'hunt-finished-icon', '✓'));
    finished.appendChild(el('p', 'hunt-finished-text',
      `All ${data.hunts.length} hunts reviewed. New ones appear as the feed changes.`));
    const reset = el('button', 'hunt-reset', 'START OVER');
    reset.type = 'button';
    reset.addEventListener('click', () => {
      huntState.done = [];
      writeLS('ot.hunt.done', []);
      renderHuntQueue(host, data);
    });
    finished.appendChild(reset);
    host.appendChild(finished);
  }

  const list = el('div', 'hunt-list');
  data.hunts.forEach((hunt) => list.appendChild(huntCard(hunt, host, data)));
  host.appendChild(list);
}

function huntCard(hunt, host, data) {
  const card = el('article', `hunt-card${huntDone(hunt.technique) ? ' is-done' : ''}`);

  const top = el('div', 'hunt-card-top');
  top.appendChild(el('span', 'hunt-tid', hunt.technique));
  top.appendChild(el('span', 'hunt-name', hunt.name));
  if (!hunt.has_coverage) top.appendChild(el('span', 'hunt-gap', 'NO PUBLIC RULE'));
  else top.appendChild(el('span', 'hunt-rules', `${hunt.rule_count} rules`));
  card.appendChild(top);

  card.appendChild(el('p', 'hunt-hypothesis', hunt.hypothesis));

  const why = el('div', 'hunt-why');
  if (hunt.observed) {
    why.appendChild(el('span', 'hunt-why-item', `seen ${hunt.observed}× this window`));
  }
  (hunt.actors || []).forEach((a) => {
    const chip = el('button', 'hunt-why-actor', a);
    chip.type = 'button';
    chip.addEventListener('click', () => {
      if (typeof libJump === 'function') libJump(a, 'actor');
    });
    why.appendChild(chip);
  });
  card.appendChild(why);

  if (hunt.data_sources && hunt.data_sources.length) {
    const ds = el('div', 'hunt-telemetry');
    ds.appendChild(el('span', 'hunt-telemetry-label', 'telemetry'));
    hunt.data_sources.forEach((d) => ds.appendChild(el('span', 'ent-chip', d)));
    card.appendChild(ds);
  }

  if (hunt.evidence && hunt.evidence.length) {
    const ev = el('ul', 'hunt-evidence');
    hunt.evidence.forEach((e) => {
      const li = el('li', '');
      li.appendChild(libLink(e.title, e.url, 'hunt-evidence-link'));
      ev.appendChild(li);
    });
    card.appendChild(ev);
  }

  const actions = el('div', 'hunt-actions');
  const open = el('button', 'hunt-action', 'OPEN PACK');
  open.type = 'button';
  open.addEventListener('click', () => huntOpenPack(hunt.technique));
  actions.appendChild(open);

  const mark = el('button', 'hunt-action is-ghost',
    huntDone(hunt.technique) ? 'REOPEN' : 'MARK DONE');
  mark.type = 'button';
  mark.addEventListener('click', () => {
    huntToggleDone(hunt.technique);
    renderHuntQueue(host, data);
  });
  actions.appendChild(mark);
  card.appendChild(actions);
  return card;
}

// ─── Hunt packs ───────────────────────────────────────────────────────────────

function huntOpenPack(technique) {                   // eslint-disable-line no-unused-vars
  huntState.tab = 'packs';
  huntState.openPack = technique;
  if (store.view !== 'hunt') {
    store.view = 'hunt';
    writeLS(LS.view, 'hunt');
  }
  writeUrlState();
  showHuntView();
}

function renderHuntPacks(host, data) {
  host.replaceChildren();
  if (!data || !data.packs || !data.packs.length) {
    host.appendChild(emptyState(
      'No hunt packs published yet. They appear after a pipeline run with '
      + 'ENABLE_HUNT_PACKS on.'));
    return;
  }

  if (huntState.openPack) {
    const summary = data.packs.find((p) => p.technique === huntState.openPack);
    if (summary) {
      const back = el('button', 'ent-back', '← ALL PACKS');
      back.type = 'button';
      back.addEventListener('click', () => {
        huntState.openPack = null;
        renderHuntPacks(host, data);
      });
      host.appendChild(back);
      const slot = el('div', 'hunt-pack-detail');
      slot.appendChild(el('div', 'view-loading', 'Loading pack…'));
      host.appendChild(slot);
      // The index row is only a summary; the full pack is its own shard.
      huntLoadPack(huntState.openPack).then((pack) => {
        if (!host.isConnected) return;
        slot.replaceChildren();
        if (!pack) {
          slot.appendChild(emptyState(
            `The hunt pack for ${summary.technique} has not been published yet.`));
          return;
        }
        try {
          slot.appendChild(huntPackDetail(pack, data));
        } catch (err) {
          slot.replaceChildren(emptyState(`Could not render this pack: ${err.message}`));
        }
      });
      return;
    }
    // Asked for a pack that has none: say so rather than silently listing all.
    huntState.openPack = null;
    host.appendChild(rNote(
      'No hunt pack exists for that technique — it has no public Sigma rules '
      + 'and was not seen in this window.'));
  }

  const stats = el('div', 'rv-stats');
  stats.appendChild(rStat('PACKS', data.count, 'techniques equipped'));
  stats.appendChild(rStat('WITH QUERIES', data.with_queries, 'paste-ready SIEM queries',
    data.with_queries ? 'low' : 'elevated'));
  stats.appendChild(rStat('WITH TESTS', data.with_atomics, 'Atomic Red Team'));
  host.appendChild(stats);

  if (!data.queries_available) {
    host.appendChild(rNote(
      'Query compilation is unavailable in this build — the optional pySigma '
      + 'backends are not installed, so packs carry the raw Sigma rules only.'));
  } else {
    host.appendChild(rNote(
      `Queries compiled for: ${data.backends.map((b) => b.label).join(' · ')}`));
  }

  const search = el('input', 'lib-search');
  search.type = 'text';
  search.placeholder = 'Filter by technique id, name or tactic…';
  search.value = huntState.packQuery;
  search.setAttribute('aria-label', 'Filter hunt packs');
  search.addEventListener('input', () => {
    huntState.packQuery = search.value;
    huntRenderPackList($('hunt-pack-list'), data);
  });
  host.appendChild(search);

  const list = el('div', 'hunt-pack-list');
  list.id = 'hunt-pack-list';
  host.appendChild(list);
  huntRenderPackList(list, data);
}

function huntRenderPackList(host, data) {
  if (!host) return;
  host.replaceChildren();
  const needle = huntState.packQuery.trim().toLowerCase();
  const rows = data.packs.filter((p) => !needle
    || p.technique.toLowerCase().includes(needle)
    || (p.name || '').toLowerCase().includes(needle)
    || (p.tactics || []).some((t) => t.toLowerCase().includes(needle)));

  if (!rows.length) {
    host.appendChild(emptyState(`No pack matches "${huntState.packQuery}".`));
    return;
  }
  rows.slice(0, 200).forEach((pack) => {
    const row = el('button', 'hunt-pack-row');
    row.type = 'button';
    row.appendChild(el('span', 'hunt-tid', pack.technique));
    row.appendChild(el('span', 'hunt-pack-name', pack.name));
    const meta = el('span', 'hunt-pack-meta');
    if (pack.observed) meta.appendChild(el('span', 'hunt-pack-seen', `${pack.observed}×`));
    meta.appendChild(el('span', 'hunt-pack-count',
      `${pack.rules} rule${pack.rules === 1 ? '' : 's'}`));
    if (pack.atomics) {
      meta.appendChild(el('span', 'hunt-pack-count', `${pack.atomics} tests`));
    }
    if (pack.has_queries) meta.appendChild(el('span', 'hunt-pack-count', 'queries'));
    row.appendChild(meta);
    row.addEventListener('click', () => {
      huntState.openPack = pack.technique;
      renderHuntPacks(host.parentElement, data);
    });
    host.appendChild(row);
  });
}

function huntPackDetail(pack, data) {
  const page = el('article', 'ent-page');

  const header = el('header', 'ent-head');
  const badges = el('div', 'ent-head-badges');
  badges.appendChild(el('span', 'ent-id', pack.technique));
  (pack.tactics || []).forEach((t) => badges.appendChild(el('span', 'ent-chip', t)));
  if (pack.observed) {
    badges.appendChild(el('span', 'ent-observed', `${pack.observed} in this feed`));
  }
  header.appendChild(badges);
  header.appendChild(el('h1', 'ent-name', pack.name));
  page.appendChild(header);

  if (pack.description) {
    const sec = libSection('What it is', 'MITRE ATT&CK');
    sec.appendChild(el('p', 'ent-prose', pack.description));
    const btn = el('button', 'ent-action is-ghost', 'FULL LIBRARY ENTRY →');
    btn.type = 'button';
    btn.addEventListener('click', () => {
      if (typeof libJump === 'function') libJump(pack.technique, 'technique');
    });
    sec.appendChild(btn);
    page.appendChild(sec);
  }

  if (pack.mitre_detection || (pack.detection_strategies || []).length) {
    const sec = libSection('How to see it', 'MITRE ATT&CK detection strategies');
    // Same renderer as the entity page: one place for "how do I see this",
    // so the two surfaces cannot drift.
    libRenderDetection(sec, {
      detection: pack.mitre_detection,
      detection_strategies: pack.detection_strategies,
      telemetry: pack.telemetry,
      data_sources: pack.data_sources,
    });
    page.appendChild(sec);
  }

  // ── Queries ───────────────────────────────────────────────────────────
  if (pack.rules && pack.rules.length) {
    const sec = libSection('Detections and queries',
      `${pack.rules.length}${pack.rules_total > pack.rules.length
        ? ` of ${pack.rules_total}` : ''} Sigma rules`);

    const backends = (data.backends || []);
    if (backends.length) {
      const picker = el('div', 'hunt-backends');
      picker.appendChild(el('span', 'hunt-backend-label', 'SIEM'));
      backends.forEach((b) => {
        const btn = el('button',
          `hunt-backend${huntState.backend === b.key ? ' active' : ''}`, b.label);
        btn.type = 'button';
        btn.addEventListener('click', () => {
          huntState.backend = b.key;
          writeLS('ot.hunt.backend', b.key);
          // Re-render into the pack HOST, not into #hunt-view: the latter also
          // carries the tab strip, which would be wiped.
          const host = sec.closest('.rv-body') || sec.parentElement;
          if (host) renderHuntPacks(host, data);
        });
        picker.appendChild(btn);
      });
      sec.appendChild(picker);
    }

    pack.rules.forEach((rule) => {
      const block = el('div', 'hunt-rule');
      const head = el('div', 'hunt-rule-head');
      head.appendChild(el('span', `ent-rule-level level-${rule.level || 'medium'}`,
        rule.level || 'medium'));
      head.appendChild(libLink(rule.title, rule.url, 'ent-rule-title'));
      if (rule.logsource) head.appendChild(el('span', 'ent-rule-src', rule.logsource));
      block.appendChild(head);

      const query = (rule.queries || {})[huntState.backend];
      if (query) {
        const label = (backends.find((b) => b.key === huntState.backend) || {}).label
          || huntState.backend;
        block.appendChild(libCode(label, query));
      } else if (backends.length) {
        const available = Object.keys(rule.queries || {});
        block.appendChild(el('p', 'hunt-noquery', available.length
          ? `Not compiled for this SIEM. Available: ${available.join(', ')}.`
          : 'This rule could not be compiled — open the Sigma source above.'));
      }
      sec.appendChild(block);
    });
    page.appendChild(sec);
  }

  if (pack.atomics && pack.atomics.length) {
    const sec = libSection('Validate it', 'Atomic Red Team');
    sec.appendChild(el('p', 'ent-warn',
      'These are live attack commands. Run them in a lab you own, never on '
      + 'production, and run the cleanup step afterwards.'));
    pack.atomics.forEach((t) => sec.appendChild(libAtomic(t)));
    page.appendChild(sec);
  }

  if ((pack.countermeasures && pack.countermeasures.length)
      || (pack.controls && Object.keys(pack.controls).length)) {
    libRenderDefence(page, {
      countermeasures: pack.countermeasures,
      controls: pack.controls,
      attack_mitigations: [],
      rules: [],
      atomics: [],
    });
  }
  return page;
}

// ─── Coverage ─────────────────────────────────────────────────────────────────

/**
 * Parse whatever the analyst pasted into a set of rule ids and technique ids.
 *
 * Deliberately forgiving: people export inventories from a dozen tools and
 * none of them agree on a format. Anything that looks like a Sigma UUID or an
 * ATT&CK technique id counts, wherever it appears in the text.
 */
function huntParseInventory(text) {
  const rules = new Set();
  const techniques = new Set();
  const uuid = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi;
  const tid = /\bT\d{4}(?:\.\d{3})?\b/gi;
  let m;
  while ((m = uuid.exec(text)) !== null) rules.add(m[0].toLowerCase());
  while ((m = tid.exec(text)) !== null) techniques.add(m[0].toUpperCase());
  return { rules, techniques };
}

function renderHuntCoverage(host, packs) {
  host.replaceChildren();
  rHead(host, 'Detection coverage',
    'Paste your rule inventory. It stays in this browser — there is no backend '
    + 'to send it to.');

  const box = el('div', 'hunt-inventory');
  const area = el('textarea', 'hunt-inventory-input');
  area.rows = 6;
  area.placeholder = 'Paste Sigma rule ids (UUIDs) and/or ATT&CK technique ids '
    + '(T1059.001). Any format — a CSV export, a rule list, a Navigator layer.';
  area.value = huntState.inventory;
  area.setAttribute('aria-label', 'Your detection inventory');
  box.appendChild(area);

  const actions = el('div', 'hunt-inventory-actions');
  const save = el('button', 'hunt-action', 'ANALYSE');
  save.type = 'button';
  save.addEventListener('click', () => {
    huntState.inventory = area.value;
    writeLS('ot.hunt.inventory', huntState.inventory);
    renderHuntCoverage(host, packs);
  });
  actions.appendChild(save);

  const clear = el('button', 'hunt-action is-ghost', 'CLEAR');
  clear.type = 'button';
  clear.addEventListener('click', () => {
    huntState.inventory = '';
    writeLS('ot.hunt.inventory', '');
    renderHuntCoverage(host, packs);
  });
  actions.appendChild(clear);
  box.appendChild(actions);
  host.appendChild(box);

  if (!packs || !packs.packs) {
    host.appendChild(emptyState('Hunt packs are needed to compute coverage.'));
    return;
  }

  const mine = huntParseInventory(huntState.inventory);
  const active = packs.packs.filter((p) => p.observed > 0);
  const scope = active.length ? active : packs.packs.slice(0, 60);

  // The pack INDEX carries rule COUNTS, not rule ids. Matching a pasted Sigma
  // rule id therefore needs the shard, which is fetched lazily below; until
  // then a technique matches on its ATT&CK id alone. Stated in the legend
  // rather than silently under-reporting coverage.
  const rows = scope.map((pack) => {
    const shard = huntPackCache.get(pack.technique);
    const packRuleIds = shard
      ? (shard.rules || []).map((r) => (r.id || '').toLowerCase())
      : [];
    const covered = mine.techniques.has(pack.technique)
      || packRuleIds.some((id) => id && mine.rules.has(id));
    return { pack, covered, available: pack.rules || 0 };
  });

  // Warm the shards for the techniques on screen so a second visit to this
  // tab can match on rule ids too. Bounded: this is a background nicety, not
  // a reason to pull 220 files.
  if (mine.rules.size) {
    scope.slice(0, 40).forEach((pack) => {
      if (!huntPackCache.has(pack.technique)) huntLoadPack(pack.technique);
    });
  }

  const have = rows.filter((r) => r.covered).length;
  const gapsNoRule = rows.filter((r) => !r.covered && !r.available).length;

  const stats = el('div', 'rv-stats');
  stats.appendChild(rStat('IN SCOPE', rows.length,
    active.length ? 'techniques active this window' : 'top techniques'));
  stats.appendChild(rStat('YOU COVER', have,
    huntState.inventory ? 'matched your inventory' : 'paste an inventory above',
    have ? 'low' : 'elevated'));
  stats.appendChild(rStat('NO PUBLIC RULE', gapsNoRule,
    'nothing to deploy even if you wanted to',
    gapsNoRule ? 'urgent' : 'low'));
  host.appendChild(stats);

  if (!huntState.inventory.trim()) {
    host.appendChild(rNote(
      'Without an inventory this is a map of what is active and what public '
      + 'detection exists for it — still useful, but the coverage column is '
      + 'empty until you paste something.'));
  }

  const grid = el('div', 'cov-grid');
  rows.sort((a, b) => (b.pack.observed - a.pack.observed)
    || a.pack.technique.localeCompare(b.pack.technique));
  rows.forEach(({ pack, covered, available }) => {
    const cell = el('button',
      `cov-cell ${covered ? 'is-covered' : available ? 'is-uncovered' : 'is-norule'}`);
    cell.type = 'button';
    cell.title = `${pack.technique} ${pack.name} — `
      + `${covered ? 'covered by your inventory'
        : available ? `${available} public rules available, none in your inventory`
          : 'no public rule exists'}`;
    cell.appendChild(el('span', 'cov-tid', pack.technique));
    cell.appendChild(el('span', 'cov-name', pack.name));
    if (pack.observed) cell.appendChild(el('span', 'cov-seen', `${pack.observed}×`));
    cell.addEventListener('click', () => huntOpenPack(pack.technique));
    grid.appendChild(cell);
  });
  host.appendChild(grid);

  const legend = el('div', 'cov-legend');
  [['is-covered', 'You have a rule'], ['is-uncovered', 'Public rule exists, you do not have it'],
    ['is-norule', 'No public rule exists']].forEach(([cls, label]) => {
    const item = el('span', 'cov-legend-item');
    item.appendChild(el('span', `cov-swatch ${cls}`));
    item.appendChild(el('span', '', label));
    legend.appendChild(item);
  });
  host.appendChild(legend);

  const exportBtn = el('button', 'hunt-action', 'EXPORT ATT&CK NAVIGATOR LAYER');
  exportBtn.type = 'button';
  exportBtn.addEventListener('click', () => huntExportLayer(rows));
  host.appendChild(exportBtn);
  host.appendChild(rNote(
    'The layer opens in mitre-attack.github.io/attack-navigator — the tool your '
    + 'team already uses for this.'));
}

/**
 * Write an ATT&CK Navigator layer.
 *
 * Copied to the clipboard rather than downloaded: the artifact viewer and some
 * embedded browsers block script-initiated downloads outright, and a button
 * that silently does nothing is worse than one that says what it did.
 */
function huntExportLayer(rows) {
  const layer = {
    name: 'OpenThreat coverage',
    versions: { attack: '16', navigator: '5.1.0', layer: '4.5' },
    domain: 'enterprise-attack',
    description: 'Detection coverage vs techniques active in the OpenThreat feed.',
    techniques: rows.map(({ pack, covered, available }) => ({
      techniqueID: pack.technique,
      score: covered ? 100 : available ? 50 : 0,
      color: covered ? '#2f7d4f' : available ? '#b8892b' : '#a13b4d',
      comment: `${pack.observed || 0} observed · ${available} public rules`
        + `${covered ? ' · in your inventory' : ''}`,
      enabled: true,
    })),
    gradient: { colors: ['#a13b4d', '#b8892b', '#2f7d4f'], minValue: 0, maxValue: 100 },
    legendItems: [
      { label: 'You have a rule', color: '#2f7d4f' },
      { label: 'Public rule exists', color: '#b8892b' },
      { label: 'No public rule', color: '#a13b4d' },
    ],
  };
  const text = JSON.stringify(layer, null, 2);
  navigator.clipboard.writeText(text).then(
    () => showToast(`Navigator layer copied (${rows.length} techniques) — paste it into a .json file`),
    () => showToast('Could not copy the layer to the clipboard'),
  );
}

// ─── Controls ─────────────────────────────────────────────────────────────────

function renderHuntControls(host, data) {
  host.replaceChildren();
  if (!data || !data.frameworks) {
    host.appendChild(emptyState(
      'No control focus published yet. It needs the ATT&CK control mappings '
      + 'and at least one technique observed in the feed.'));
    return;
  }
  rHead(host, 'Controls under load',
    `Which controls address the ${data.techniques_considered} techniques active `
    + 'in this window. Ranked by observed activity, not by audit order.');

  Object.entries(data.frameworks).forEach(([, fw]) => {
    const panel = rPanel(fw.label, '');
    const table = rTable(
      ['Control', 'What it covers', 'Active techniques', 'Weight'],
      (fw.controls || []).map((c) => [
        c.id,
        c.name || c.group_name || '',
        (c.techniques || []).join(' '),
        String(c.activity),
      ]),
    );
    panel.appendChild(table);
    host.appendChild(panel);
  });
}

// ─── New rules ────────────────────────────────────────────────────────────────

function renderHuntNewRules(host, data) {
  host.replaceChildren();
  if (!data) {
    host.appendChild(emptyState('No detection diff published yet.'));
    return;
  }
  if (data.baseline) {
    rHead(host, 'New detections', 'Baseline recorded.');
    host.appendChild(rNote(
      `${data.tracked} Sigma rules are being tracked. Changes are reported from `
      + 'the next SigmaHQ refresh onward — declaring all of them "new" on the '
      + 'first run would be true and useless.'));
    return;
  }

  rHead(host, 'New detections',
    `${data.added_count} added and ${data.removed_count} removed since the last `
    + `Sigma refresh, out of ${data.tracked} tracked.`);

  const stats = el('div', 'rv-stats');
  stats.appendChild(rStat('ADDED', data.added_count, 'new Sigma rules'));
  stats.appendChild(rStat('RELEVANT', data.relevant,
    'cover something in this feed', data.relevant ? 'elevated' : 'low'));
  stats.appendChild(rStat('REMOVED', data.removed_count, 'withdrawn upstream'));
  host.appendChild(stats);

  if (!data.added.length) {
    host.appendChild(rNote('No new rules since the last refresh.'));
    return;
  }

  const list = el('div', 'hunt-newrules');
  data.added.forEach((rule) => {
    const row = el('div', `hunt-newrule${rule.relevance ? ' is-relevant' : ''}`);
    const head = el('div', 'hunt-rule-head');
    head.appendChild(el('span', `ent-rule-level level-${rule.level || 'medium'}`,
      rule.level || 'medium'));
    head.appendChild(libLink(rule.title, rule.url, 'ent-rule-title'));
    if (rule.logsource) head.appendChild(el('span', 'ent-rule-src', rule.logsource));
    if (rule.relevance) {
      head.appendChild(el('span', 'hunt-relevant',
        `${rule.relevance} matching item${rule.relevance === 1 ? '' : 's'}`));
    }
    row.appendChild(head);
    const tech = el('div', 'ent-chips');
    (rule.techniques || []).forEach((t) => {
      const chip = el('button', 'ent-chip', `${t.id} ${t.name}`.trim());
      chip.type = 'button';
      chip.addEventListener('click', () => huntOpenPack(t.id));
      tech.appendChild(chip);
    });
    row.appendChild(tech);
    list.appendChild(row);
  });
  host.appendChild(list);
}

// ─── View entry point ─────────────────────────────────────────────────────────

const huntPackCache = new Map();

/** One technique's full pack. Cached per session; ~20 KB each. */
async function huntLoadPack(technique) {
  if (huntPackCache.has(technique)) return huntPackCache.get(technique);
  // The id is interpolated into a fetch path, so it is validated here as well
  // as in the pipeline that wrote the file.
  if (!/^T\d{4}(\.\d{3})?$/.test(String(technique))) return null;
  let pack = null;
  try {
    const resp = await fetch(API.huntPack(technique), { cache: 'no-cache' });
    pack = resp.ok ? await resp.json() : null;
  } catch (_) { pack = null; }
  huntPackCache.set(technique, pack);
  return pack;
}

async function huntFetch(key) {
  if (store.research[key] !== undefined) return store.research[key];
  let data = null;
  try {
    const resp = await fetch(API[key], { cache: 'no-cache' });
    data = resp.ok ? await resp.json() : null;
  } catch (_) { data = null; }
  store.research[key] = data;
  return data;
}

async function showHuntView() {                      // eslint-disable-line no-unused-vars
  hideAllViews();
  const host = $('hunt-view');
  if (!host) return;
  host.style.display = 'block';
  host.replaceChildren();

  const tabs = el('div', 'rv-tabs');
  HUNT_TABS.forEach((tab) => {
    const btn = el('button', `rv-tab${huntState.tab === tab.key ? ' active' : ''}`,
      tab.label);
    btn.type = 'button';
    btn.title = tab.hint;
    btn.addEventListener('click', () => {
      huntState.tab = tab.key;
      huntState.openPack = null;
      writeUrlState();
      showHuntView();
    });
    tabs.appendChild(btn);
  });
  host.appendChild(tabs);

  const body = el('div', 'rv-body');
  body.appendChild(el('div', 'view-loading', 'Loading…'));
  host.appendChild(body);

  let data;
  if (huntState.tab === 'queue') data = await huntFetch('huntQueue');
  else if (huntState.tab === 'controls') data = await huntFetch('controlFocus');
  else if (huntState.tab === 'newrules') data = await huntFetch('detectionDiff');
  else data = await huntFetch('huntPacks');

  if (host.style.display === 'none') return;
  body.replaceChildren();
  try {
    if (huntState.tab === 'queue') renderHuntQueue(body, data);
    else if (huntState.tab === 'packs') renderHuntPacks(body, data);
    else if (huntState.tab === 'coverage') renderHuntCoverage(body, data);
    else if (huntState.tab === 'controls') renderHuntControls(body, data);
    else renderHuntNewRules(body, data);
  } catch (err) {
    body.replaceChildren(emptyState(`Could not render this view: ${err.message}`));
  }
}
