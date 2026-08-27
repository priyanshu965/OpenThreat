/**
 * CYBERWATCH — js/library.js
 * ==========================
 * THE LIBRARY: what is known.
 *
 * One page per actor, malware family, tool, technique, campaign and
 * mitigation, merged in the pipeline from ATT&CK, MISP galaxy, Malpedia, ORKL,
 * D3FEND, the control mappings, SigmaHQ, Atomic Red Team and the feed itself.
 *
 * TWO IDEAS DO ALL THE WORK HERE
 * ------------------------------
 * 1. NAME DECONFLICTION. Every alias from every corpus resolves to one entry,
 *    so "Midnight Blizzard", "Cozy Bear", "Nobelium", "UNC2452" and "APT29"
 *    are one page. That is a genuine daily friction removed: vendors do not
 *    coordinate actor naming and never will.
 *
 * 2. ONE SKELETON, ALWAYS THE SAME ORDER.
 *
 *        identity -> summary -> timeline -> relationships -> defence -> sources
 *
 *    After reading two entity pages you know where to look on the third
 *    without hunting. That consistency IS the professional feel; it is worth
 *    more than any amount of styling.
 *
 * LOADING
 * -------
 * entity_index.json (~1.7 MB raw, ~370 KB over the wire once gzipped) is
 * fetched once and holds identity plus a teaser for every entity. The full
 * record for one entity is a separate ~2.5 KB shard, fetched on open. Opening
 * a page therefore costs a couple of kilobytes, not the whole corpus.
 *
 * As everywhere else in this project: no innerHTML. Every string on screen
 * comes from a third-party corpus and is set as text.
 */

'use strict';

const LIB_KINDS = [
  { key: 'all', label: 'ALL' },
  { key: 'actor', label: 'ACTORS' },
  { key: 'malware', label: 'MALWARE' },
  { key: 'tool', label: 'TOOLS' },
  { key: 'technique', label: 'TECHNIQUES' },
  { key: 'attack-campaign', label: 'CAMPAIGNS' },
  { key: 'mitigation', label: 'MITIGATIONS' },
];

const KIND_LABEL = {
  actor: 'Threat actor',
  malware: 'Malware family',
  tool: 'Tool',
  technique: 'ATT&CK technique',
  'attack-campaign': 'ATT&CK campaign',
  mitigation: 'ATT&CK mitigation',
};

const libState = {
  index: undefined,      // undefined = not fetched, null = failed
  kind: 'all',
  query: '',
  open: null,            // slug of the entity currently on screen
  entity: null,
  cache: new Map(),      // slug -> record
  page: 0,
};

const LIB_PAGE_SIZE = 60;

// ─── Data ─────────────────────────────────────────────────────────────────────

async function libLoadIndex() {
  if (libState.index !== undefined) return libState.index;
  try {
    const resp = await fetch(API.entityIndex, { cache: 'no-cache' });
    libState.index = resp.ok ? await resp.json() : null;
  } catch (_) { libState.index = null; }
  return libState.index;
}

async function libLoadEntity(slug) {
  if (libState.cache.has(slug)) return libState.cache.get(slug);
  let record = null;
  try {
    const resp = await fetch(API.entity(slug), { cache: 'no-cache' });
    record = resp.ok ? await resp.json() : null;
  } catch (_) { record = null; }
  libState.cache.set(slug, record);
  return record;
}

/**
 * Resolve any name a reader might type to a slug.
 *
 * Exact alias hit first, then a prefix scan. The exact pass matters: typing
 * "APT29" must land on APT29 and not on the first of the forty entities whose
 * text happens to contain it.
 */
function libResolve(text) {                          // eslint-disable-line no-unused-vars
  const index = libState.index;
  if (!index || !text) return null;
  const needle = String(text).trim().toLowerCase();
  if (!needle) return null;
  const exact = (index.aliases || {})[needle];
  if (exact) return exact;
  for (const [alias, slug] of Object.entries(index.aliases || {})) {
    if (alias.startsWith(needle)) return slug;
  }
  return null;
}

function libSearch(index, query, kind) {
  const rows = (index && index.entities) || [];
  const needle = String(query || '').trim().toLowerCase();
  let out = kind && kind !== 'all' ? rows.filter((r) => r.kind === kind) : rows.slice();

  if (needle) {
    const scored = [];
    for (const row of out) {
      const name = (row.name || '').toLowerCase();
      const aliases = (row.aliases || []).map((a) => a.toLowerCase());
      const id = (row.id || '').toLowerCase();
      let score = -1;
      if (name === needle || id === needle || aliases.includes(needle)) score = 0;
      else if (name.startsWith(needle) || id.startsWith(needle)) score = 1;
      else if (aliases.some((a) => a.startsWith(needle))) score = 2;
      else if (name.includes(needle)) score = 3;
      else if (aliases.some((a) => a.includes(needle))) score = 4;
      else if ((row.teaser || '').toLowerCase().includes(needle)) score = 5;
      if (score >= 0) scored.push([score, row]);
    }
    // Stable within a score band: the index already arrives ordered by
    // observed activity, so the most relevant of several equal matches wins.
    scored.sort((a, b) => a[0] - b[0]);
    out = scored.map((s) => s[1]);
  }
  return out;
}

// ─── Browser ──────────────────────────────────────────────────────────────────

function libRenderBrowser(host) {
  const index = libState.index;
  host.replaceChildren();

  const head = el('div', 'rv-head');
  head.appendChild(el('h2', 'rv-title', 'Library'));
  const kinds = (index && index.by_kind) || {};
  const total = (index && index.count) || 0;
  head.appendChild(el('p', 'rv-sub',
    `${total.toLocaleString()} entities · ${Object.entries(kinds)
      .map(([k, v]) => `${v} ${k.replace('attack-', '')}`).join(' · ')}`));
  host.appendChild(head);

  // Search
  const bar = el('div', 'lib-searchbar');
  const input = el('input', 'lib-search');
  input.type = 'text';
  input.placeholder = 'Search any name or alias — Midnight Blizzard, T1566, Emotet…';
  input.value = libState.query;
  input.setAttribute('aria-label', 'Search the library');
  input.addEventListener('input', () => {
    libState.query = input.value;
    libState.page = 0;
    libRenderResults($('lib-results'));
  });
  bar.appendChild(input);
  host.appendChild(bar);

  // Kind filter
  const tabs = el('div', 'lib-kinds');
  LIB_KINDS.forEach((k) => {
    const btn = el('button', `lib-kind${libState.kind === k.key ? ' active' : ''}`, k.label);
    btn.type = 'button';
    const n = k.key === 'all' ? total : (kinds[k.key] || 0);
    if (n) btn.appendChild(el('span', 'lib-kind-count', String(n)));
    btn.addEventListener('click', () => {
      libState.kind = k.key;
      libState.page = 0;
      libRenderBrowser(host);
    });
    tabs.appendChild(btn);
  });
  host.appendChild(tabs);

  const results = el('div', 'lib-results');
  results.id = 'lib-results';
  host.appendChild(results);
  libRenderResults(results);
}

function libRenderResults(host) {
  if (!host) return;
  host.replaceChildren();
  const rows = libSearch(libState.index, libState.query, libState.kind);

  if (!rows.length) {
    host.appendChild(emptyState(
      libState.query
        ? `Nothing in the library matches "${libState.query}".`
        : 'The library is empty.'));
    return;
  }

  const shown = rows.slice(0, (libState.page + 1) * LIB_PAGE_SIZE);
  const list = el('div', 'lib-list');
  shown.forEach((row) => list.appendChild(libCard(row)));
  host.appendChild(list);

  const count = el('p', 'lib-count',
    `Showing ${shown.length.toLocaleString()} of ${rows.length.toLocaleString()}`);
  host.appendChild(count);

  if (shown.length < rows.length) {
    const more = el('button', 'lib-more', 'LOAD MORE');
    more.type = 'button';
    more.addEventListener('click', () => {
      libState.page += 1;
      libRenderResults(host);
    });
    host.appendChild(more);
  }
}

function libCard(row) {
  const card = el('button', 'lib-card');
  card.type = 'button';
  card.setAttribute('aria-label', `Open ${row.name}`);

  const top = el('div', 'lib-card-top');
  top.appendChild(el('span', `lib-badge kind-${row.kind}`, KIND_LABEL[row.kind] || row.kind));
  if (row.id) top.appendChild(el('span', 'lib-card-id', row.id));
  if (row.observed) {
    top.appendChild(el('span', 'lib-card-seen', `${row.observed} this window`));
  }
  card.appendChild(top);

  card.appendChild(el('div', 'lib-card-name', row.name));
  if (row.country) card.appendChild(el('span', 'lib-card-flag', row.country));

  if (row.aliases && row.aliases.length) {
    card.appendChild(el('div', 'lib-card-aka', `aka ${row.aliases.slice(0, 4).join(' · ')}`));
  }
  if (row.teaser) card.appendChild(el('div', 'lib-card-teaser', row.teaser));

  card.addEventListener('click', () => libOpen(row.slug));
  return card;
}

// ─── Entity page ──────────────────────────────────────────────────────────────

function libOpen(slug) {                             // eslint-disable-line no-unused-vars
  libState.open = slug;
  if (store.view !== 'library') {
    store.view = 'library';
    writeLS(LS.view, 'library');
  }
  writeUrlState();
  showLibraryView();
}

function libBack() {
  libState.open = null;
  libState.entity = null;
  writeUrlState();
  showLibraryView();
}

/** Section wrapper. Every entity page uses these, in the same order. */
function libSection(title, note) {
  const sec = el('section', 'ent-section');
  const head = el('div', 'ent-section-head');
  head.appendChild(el('h3', 'ent-section-title', title));
  if (note) head.appendChild(el('span', 'ent-section-note', note));
  sec.appendChild(head);
  return sec;
}

function libChipRow(values, onClick, className) {
  const row = el('div', className || 'ent-chips');
  (values || []).forEach((value) => {
    const label = typeof value === 'string' ? value : value.label;
    const chip = el(onClick ? 'button' : 'span', 'ent-chip', label);
    if (onClick) {
      chip.type = 'button';
      chip.addEventListener('click', () => onClick(value));
    }
    row.appendChild(chip);
  });
  return row;
}

function libLink(text, url, className) {
  const href = safeUrl(url);
  if (!href) return el('span', className || 'ent-link', text);
  const a = el('a', className || 'ent-link', text);
  a.href = href;
  a.target = '_blank';
  a.rel = 'noopener noreferrer';
  return a;
}

function libRenderEntity(host, entity) {
  host.replaceChildren();

  const back = el('button', 'ent-back', '← LIBRARY');
  back.type = 'button';
  back.addEventListener('click', libBack);
  host.appendChild(back);

  const page = el('article', 'ent-page');

  // ── 1. Identity ───────────────────────────────────────────────────────
  const header = el('header', 'ent-head');
  const badges = el('div', 'ent-head-badges');
  badges.appendChild(el('span', `lib-badge kind-${entity.kind}`,
    KIND_LABEL[entity.kind] || entity.kind));
  if (entity.id) badges.appendChild(el('span', 'ent-id', entity.id));
  if (entity.country) badges.appendChild(el('span', 'ent-country', entity.country));
  if (entity.observed_count) {
    badges.appendChild(el('span', 'ent-observed',
      `${entity.observed_count} in this feed`));
  }
  header.appendChild(badges);
  header.appendChild(el('h1', 'ent-name', entity.name));

  if (entity.aliases && entity.aliases.length) {
    const aka = el('div', 'ent-aka');
    aka.appendChild(el('span', 'ent-aka-label', 'also known as'));
    aka.appendChild(el('span', 'ent-aka-list', entity.aliases.join(' · ')));
    header.appendChild(aka);
  }

  // The same name legitimately belongs to more than one thing: "Emotet" is a
  // malware family AND the crew that runs it. Saying so is the honest version
  // of name deconfliction — collapsing them would be a different error from
  // the one this feature exists to fix.
  if (entity.also_known_here && entity.also_known_here.length) {
    const also = el('div', 'ent-disambig');
    also.appendChild(el('span', 'ent-disambig-label', 'also the name of'));
    entity.also_known_here.forEach((other) => {
      const btn = el('button', 'ent-disambig-link',
        `${other.name} (${KIND_LABEL[other.kind] || other.kind})`);
      btn.type = 'button';
      btn.addEventListener('click', () => libOpen(other.slug));
      also.appendChild(btn);
    });
    header.appendChild(also);
  }

  const facts = [];
  if (entity.sponsor) facts.push(['Suspected sponsor', entity.sponsor]);
  if (entity.motive) facts.push(['Motive', entity.motive]);
  if (entity.attribution_confidence) {
    facts.push(['Attribution confidence', entity.attribution_confidence]);
  }
  if (entity.platform) facts.push(['Platform', entity.platform]);
  if (entity.platforms && entity.platforms.length) {
    facts.push(['Platforms', entity.platforms.join(', ')]);
  }
  if (entity.tactics && entity.tactics.length) {
    facts.push(['Tactics', entity.tactics.join(', ')]);
  }
  if (entity.first_seen) facts.push(['First seen', entity.first_seen]);
  if (entity.last_seen) facts.push(['Last seen', entity.last_seen]);
  if (facts.length) {
    const dl = el('dl', 'ent-facts');
    facts.forEach(([k, v]) => {
      dl.appendChild(el('dt', 'ent-fact-key', k));
      dl.appendChild(el('dd', 'ent-fact-val', v));
    });
    header.appendChild(dl);
  }
  page.appendChild(header);

  // ── 2. Summary ────────────────────────────────────────────────────────
  if (entity.description) {
    const sec = libSection('Summary',
      entity.description_source ? `via ${entity.description_source}` : '');
    sec.appendChild(el('p', 'ent-prose', entity.description));
    page.appendChild(sec);
  }

  // Detection guidance is a technique's most useful paragraph, so it sits
  // immediately after the summary rather than buried with the rules.
  if (entity.detection || (entity.detection_strategies || []).length) {
    const sec = libSection('How to see it', 'MITRE ATT&CK detection strategies');
    libRenderDetection(sec, entity);
    page.appendChild(sec);
  }

  // ── 3. Timeline: what THIS feed saw ───────────────────────────────────
  if (entity.observed && entity.observed.length) {
    const sec = libSection('Seen in this feed',
      `${entity.observed_count} item${entity.observed_count === 1 ? '' : 's'}`);
    const list = el('ul', 'ent-obs');
    entity.observed.forEach((row) => {
      const li = el('li', 'ent-obs-row');
      li.appendChild(el('span', 'ent-obs-date', row.published || ''));
      li.appendChild(libLink(row.title, row.url, 'ent-obs-title'));
      const meta = el('span', 'ent-obs-meta');
      if (row.source) meta.appendChild(el('span', 'ent-obs-source', row.source));
      if (row.priority) {
        meta.appendChild(el('span', `ent-obs-band band-${row.priority}`, row.priority));
      }
      li.appendChild(meta);
      list.appendChild(li);
    });
    sec.appendChild(list);
    page.appendChild(sec);
  }

  // ── 4. Leak-site activity (ransomware crews) ──────────────────────────
  if (entity.leak_activity) {
    const leak = entity.leak_activity;
    const sec = libSection('Leak-site activity', 'via public leak-site aggregators');
    const stats = el('div', 'ent-metrics');
    stats.appendChild(libMetric(leak.victims, 'claimed victims'));
    if (leak.first_in_window) {
      stats.appendChild(libMetric(leak.first_in_window, 'first in window'));
    }
    if (leak.last_in_window) {
      stats.appendChild(libMetric(leak.last_in_window, 'most recent'));
    }
    if (leak.sites) stats.appendChild(libMetric(leak.sites, 'known sites'));
    sec.appendChild(stats);
    if (leak.top_sectors && leak.top_sectors.length) {
      sec.appendChild(el('p', 'ent-subhead', 'Sectors hit'));
      sec.appendChild(libChipRow(leak.top_sectors));
    }
    if (leak.tools && leak.tools.length) {
      sec.appendChild(el('p', 'ent-subhead', 'Reported tooling'));
      sec.appendChild(libChipRow(leak.tools));
    }
    page.appendChild(sec);
  }

  // ── 5. Relationships ──────────────────────────────────────────────────
  libRenderRelations(page, entity);

  // ── 6. Defence ────────────────────────────────────────────────────────
  libRenderDefence(page, entity);

  // ── 7. Sources ────────────────────────────────────────────────────────
  libRenderSources(page, entity);

  host.appendChild(page);
}

/**
 * "How to see it", from ATT&CK v18's detection-strategy graph.
 *
 * The old ATT&CK carried one free-text paragraph per technique. v18 replaced
 * it with strategies made of analytics, each naming the log source and channel
 * it needs — "WinEventLog:Sysmon (EventCode=1)", "auditd:SYSCALL (execve)".
 * That is the difference between "monitor for suspicious encryption" and
 * knowing whether you are even collecting the telemetry to try.
 *
 * Shared by the entity page and the hunt pack so the two cannot drift.
 */
function libRenderDetection(sec, entity) {          // eslint-disable-line no-unused-vars
  const strategies = entity.detection_strategies || [];

  strategies.forEach((strategy) => {
    const block = el('div', 'ent-detstrat');
    const head = el('div', 'ent-detstrat-head');
    if (strategy.id) head.appendChild(el('span', 'ent-detstrat-id', strategy.id));
    head.appendChild(strategy.url
      ? libLink(strategy.name, strategy.url, 'ent-detstrat-name')
      : el('span', 'ent-detstrat-name', strategy.name));
    block.appendChild(head);
    if (strategy.description) {
      block.appendChild(el('p', 'ent-prose', strategy.description));
    }
    (strategy.analytics || []).forEach((an) => {
      const row = el('div', 'ent-analytic');
      const top = el('div', 'ent-analytic-head');
      if (an.id) top.appendChild(el('span', 'ent-analytic-id', an.id));
      (an.platforms || []).forEach((pl) => top.appendChild(el('span', 'ent-chip', pl)));
      row.appendChild(top);
      if (an.description) row.appendChild(el('p', 'ent-analytic-desc', an.description));
      block.appendChild(row);
    });
    sec.appendChild(block);
  });

  // Fallback for anything that has prose but no structured strategy.
  if (!strategies.length && entity.detection) {
    sec.appendChild(el('p', 'ent-prose', entity.detection));
  }

  if (entity.telemetry && entity.telemetry.length) {
    sec.appendChild(el('p', 'ent-subhead', 'Log sources you need'));
    sec.appendChild(libChipRow(entity.telemetry, null, 'ent-chips ent-telemetry'));
  }
  if (entity.data_sources && entity.data_sources.length) {
    sec.appendChild(el('p', 'ent-subhead', 'ATT&CK data components'));
    sec.appendChild(libChipRow(entity.data_sources));
  }
}

function libMetric(value, label) {
  const box = el('div', 'ent-metric');
  box.appendChild(el('span', 'ent-metric-value', String(value)));
  box.appendChild(el('span', 'ent-metric-label', label));
  return box;
}

function libJump(name, kind) {
  // Resolve through the alias table so a related-entity chip lands on the
  // canonical page even when the relationship names it by an alias.
  const index = libState.index || {};
  const slug = (index.aliases || {})[String(name).toLowerCase()]
    || `${kind}-${String(name).toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '')}`;
  libOpen(slug);
}

function libRenderRelations(page, entity) {
  const rows = [];

  if (entity.software && entity.software.length) {
    rows.push(['Arsenal', entity.software, (n) => libJump(n, 'malware')]);
  }
  if (entity.actors && entity.actors.length) {
    rows.push(['Used by', entity.actors, (n) => libJump(n, 'actor')]);
  }
  if (entity.campaigns && entity.campaigns.length) {
    rows.push(['Campaigns', entity.campaigns, (n) => libJump(n, 'attack-campaign')]);
  }
  if (entity.subtechniques && entity.subtechniques.length) {
    rows.push(['Sub-techniques', entity.subtechniques, (n) => libJump(n, 'technique')]);
  }
  if (entity.parent) {
    rows.push(['Parent technique', [entity.parent], (n) => libJump(n, 'technique')]);
  }
  if (entity.target_categories && entity.target_categories.length) {
    rows.push(['Targets', entity.target_categories, null]);
  }
  if (entity.known_victims && entity.known_victims.length) {
    rows.push(['Reported victims', entity.known_victims, null]);
  }

  if (!rows.length && !(entity.techniques && entity.techniques.length)) return;

  const sec = libSection('Relationships', 'from MITRE ATT&CK unless noted');
  rows.forEach(([label, values, onClick]) => {
    sec.appendChild(el('p', 'ent-subhead', label));
    sec.appendChild(libChipRow(values, onClick));
  });

  // Techniques get a table rather than chips: the detection-coverage column is
  // the point, and it does not fit on a chip.
  if (entity.techniques && entity.techniques.length) {
    sec.appendChild(el('p', 'ent-subhead',
      `Techniques (${entity.techniques.length})`));
    const table = el('div', 'ent-tech-table');
    entity.techniques.forEach((t) => {
      const row = el('button', 'ent-tech-row');
      row.type = 'button';
      row.appendChild(el('span', 'ent-tech-id', t.id));
      row.appendChild(el('span', 'ent-tech-name', t.name || ''));
      const rules = Number(t.rules || 0);
      row.appendChild(el('span', `ent-tech-rules${rules ? '' : ' is-gap'}`,
        rules ? `${rules} rule${rules === 1 ? '' : 's'}` : 'no public rule'));
      row.addEventListener('click', () => libJump(t.id, 'technique'));
      table.appendChild(row);
    });
    sec.appendChild(table);
  }
  page.appendChild(sec);
}

const D3FEND_TACTIC_ORDER = ['Model', 'Harden', 'Detect', 'Isolate', 'Deceive',
  'Evict', 'Restore'];

function libRenderDefence(page, entity) {
  const hasAny = (entity.rules && entity.rules.length)
    || (entity.countermeasures && entity.countermeasures.length)
    || (entity.attack_mitigations && entity.attack_mitigations.length)
    || (entity.controls && Object.keys(entity.controls).length)
    || (entity.atomics && entity.atomics.length);
  if (!hasAny) return;

  const sec = libSection('Defence', 'detect it, stop it, prove it');

  if (entity.rules && entity.rules.length) {
    sec.appendChild(el('p', 'ent-subhead',
      `Detection rules (${entity.rules.length}${entity.rules_total > entity.rules.length
        ? ` of ${entity.rules_total}` : ''})`));
    const list = el('ul', 'ent-rules');
    entity.rules.forEach((rule) => {
      const li = el('li', 'ent-rule');
      li.appendChild(el('span', `ent-rule-level level-${rule.level || 'medium'}`,
        rule.level || 'medium'));
      li.appendChild(libLink(rule.title, rule.url, 'ent-rule-title'));
      if (rule.logsource) li.appendChild(el('span', 'ent-rule-src', rule.logsource));
      list.appendChild(li);
    });
    sec.appendChild(list);
    const toHunt = el('button', 'ent-action', 'OPEN THE HUNT PACK →');
    toHunt.type = 'button';
    toHunt.addEventListener('click', () => {
      if (typeof huntOpenPack === 'function') huntOpenPack(entity.id || entity.name);
    });
    sec.appendChild(toHunt);
  }

  if (entity.countermeasures && entity.countermeasures.length) {
    sec.appendChild(el('p', 'ent-subhead', 'Countermeasures (MITRE D3FEND)'));
    const grouped = new Map();
    entity.countermeasures.forEach((cm) => {
      const key = cm.tactic || 'Other';
      if (!grouped.has(key)) grouped.set(key, []);
      grouped.get(key).push(cm);
    });
    const order = [...grouped.keys()].sort(
      (a, b) => D3FEND_TACTIC_ORDER.indexOf(a) - D3FEND_TACTIC_ORDER.indexOf(b));
    order.forEach((tactic) => {
      const block = el('div', 'ent-d3f-group');
      block.appendChild(el('span', `ent-d3f-tactic tactic-${tactic.toLowerCase()}`, tactic));
      const items = el('div', 'ent-d3f-items');
      grouped.get(tactic).forEach((cm) => {
        const item = el('div', 'ent-d3f-item');
        item.appendChild(libLink(cm.name, cm.url, 'ent-d3f-name'));
        if (cm.artifacts && cm.artifacts.length) {
          item.appendChild(el('span', 'ent-d3f-artifact',
            `${cm.relation || 'acts on'} ${cm.artifacts.join(', ')}`));
        }
        if (cm.inherited) {
          item.appendChild(el('span', 'ent-inherited', `inherited from ${cm.inherited}`));
        }
        items.appendChild(item);
      });
      block.appendChild(items);
      sec.appendChild(block);
    });
  }

  if (entity.attack_mitigations && entity.attack_mitigations.length) {
    sec.appendChild(el('p', 'ent-subhead', 'Mitigations (MITRE ATT&CK)'));
    const list = el('div', 'ent-mitigations');
    entity.attack_mitigations.forEach((m) => {
      const row = el('button', 'ent-mitigation');
      row.type = 'button';
      row.appendChild(el('span', 'ent-mit-id', m.id));
      row.appendChild(el('span', 'ent-mit-name', m.name || ''));
      row.addEventListener('click', () => libOpen(
        `mitigation-${String(m.id).toLowerCase()}`));
      list.appendChild(row);
    });
    sec.appendChild(list);
  }

  if (entity.controls && Object.keys(entity.controls).length) {
    sec.appendChild(el('p', 'ent-subhead', 'Controls that address this'));
    Object.entries(entity.controls).forEach(([, fw]) => {
      const block = el('div', 'ent-ctrl-group');
      const head = el('div', 'ent-ctrl-head');
      head.appendChild(el('span', 'ent-ctrl-fw', fw.label));
      if (fw.inherited) {
        head.appendChild(el('span', 'ent-inherited', `via ${fw.inherited}`));
      }
      block.appendChild(head);
      const chips = el('div', 'ent-chips');
      (fw.controls || []).forEach((c) => {
        const chip = el('span', 'ent-chip ent-ctrl', c.id);
        chip.title = c.name || '';
        chips.appendChild(chip);
      });
      block.appendChild(chips);
      sec.appendChild(block);
    });
  }

  if (entity.atomics && entity.atomics.length) {
    sec.appendChild(el('p', 'ent-subhead',
      `Validation — Atomic Red Team (${entity.atomics.length})`));
    sec.appendChild(el('p', 'ent-warn',
      'These are live attack commands. Run them in a lab you own, never on '
      + 'production, and run the cleanup step afterwards.'));
    entity.atomics.forEach((t) => sec.appendChild(libAtomic(t)));
  }

  page.appendChild(sec);
}

function libAtomic(test) {
  const box = el('details', 'ent-atomic');
  const summary = el('summary', 'ent-atomic-head');
  summary.appendChild(el('span', 'ent-atomic-name', test.name));
  if (test.executor) summary.appendChild(el('span', 'ent-atomic-exec', test.executor));
  if (test.elevation_required) {
    summary.appendChild(el('span', 'ent-atomic-flag', 'needs admin'));
  }
  if (test.destructive) {
    summary.appendChild(el('span', 'ent-atomic-flag is-danger', 'destructive'));
  }
  if (test.inherited) {
    summary.appendChild(el('span', 'ent-inherited', `exercises ${test.inherited}`));
  }
  box.appendChild(summary);

  if (test.description) box.appendChild(el('p', 'ent-atomic-desc', test.description));
  if (test.platforms && test.platforms.length) {
    box.appendChild(el('p', 'ent-atomic-plat', test.platforms.join(' · ')));
  }
  if (test.prereqs && test.prereqs.length) {
    box.appendChild(el('p', 'ent-subhead', 'Prerequisites'));
    const ul = el('ul', 'ent-atomic-prereqs');
    test.prereqs.forEach((p) => ul.appendChild(el('li', '', p)));
    box.appendChild(ul);
  }
  if (test.command) box.appendChild(libCode('Command', test.command));
  if (test.cleanup) box.appendChild(libCode('Cleanup', test.cleanup));
  return box;
}

/** A copyable code block. Used for atomics and for compiled SIEM queries. */
function libCode(label, text) {                      // eslint-disable-line no-unused-vars
  const box = el('div', 'code-block');
  const head = el('div', 'code-head');
  head.appendChild(el('span', 'code-label', label));
  const copy = el('button', 'code-copy', 'COPY');
  copy.type = 'button';
  copy.addEventListener('click', () => {
    navigator.clipboard.writeText(text).then(
      () => { copy.textContent = 'COPIED'; setTimeout(() => { copy.textContent = 'COPY'; }, 1400); },
      () => { copy.textContent = 'FAILED'; },
    );
  });
  head.appendChild(copy);
  box.appendChild(head);
  box.appendChild(el('pre', 'code-body', text));
  return box;
}

function libRenderSources(page, entity) {
  const refs = entity.references || [];
  const external = entity.external || [];
  const reports = entity.reports || [];
  if (!refs.length && !external.length && !reports.length && !entity.url) return;

  const sec = libSection('Sources', 'primary material');

  if (reports.length) {
    sec.appendChild(el('p', 'ent-subhead',
      `Threat reports (${reports.length}) — via ORKL`));
    const list = el('ul', 'ent-reports');
    reports.forEach((r) => {
      const li = el('li', 'ent-report');
      li.appendChild(el('span', 'ent-report-date', r.date || r.added || ''));
      li.appendChild(libLink(r.title, r.url, 'ent-report-title'));
      if (r.authors) li.appendChild(el('span', 'ent-report-author', r.authors));
      list.appendChild(li);
    });
    sec.appendChild(list);
  }

  if (refs.length) {
    sec.appendChild(el('p', 'ent-subhead', 'References'));
    const list = el('ul', 'ent-refs');
    refs.forEach((r) => {
      const li = el('li', 'ent-ref');
      li.appendChild(libLink(r.name || r.url, r.url, 'ent-ref-link'));
      if (r.description) li.appendChild(el('span', 'ent-ref-desc', r.description));
      list.appendChild(li);
    });
    sec.appendChild(list);
  }

  if (external.length) {
    sec.appendChild(el('p', 'ent-subhead', 'Further reading'));
    const list = el('ul', 'ent-refs');
    external.forEach((u) => {
      const li = el('li', 'ent-ref');
      li.appendChild(libLink(u, u, 'ent-ref-link'));
      list.appendChild(li);
    });
    sec.appendChild(list);
  }

  if (entity.url) {
    const foot = el('p', 'ent-canonical');
    foot.appendChild(libLink('View the canonical entry →', entity.url));
    sec.appendChild(foot);
  }
  page.appendChild(sec);
}

// ─── View entry point ─────────────────────────────────────────────────────────

async function showLibraryView() {                   // eslint-disable-line no-unused-vars
  hideAllViews();
  const host = $('library-view');
  if (!host) return;
  host.style.display = 'block';
  host.replaceChildren(el('div', 'view-loading', 'Loading the library…'));

  const index = await libLoadIndex();
  if (host.style.display === 'none') return;

  if (!index) {
    host.replaceChildren(emptyState(
      'The library has not been published yet. It appears after a pipeline run '
      + 'with ENABLE_KNOWLEDGE_BASE on.'));
    return;
  }

  if (!libState.open) {
    libRenderBrowser(host);
    return;
  }

  host.replaceChildren(el('div', 'view-loading', 'Loading entity…'));
  const entity = await libLoadEntity(libState.open);
  if (host.style.display === 'none') return;
  if (!entity) {
    host.replaceChildren();
    const back = el('button', 'ent-back', '← LIBRARY');
    back.type = 'button';
    back.addEventListener('click', libBack);
    host.appendChild(back);
    host.appendChild(emptyState(`No library entry for "${libState.open}".`));
    return;
  }
  libState.entity = entity;
  try {
    libRenderEntity(host, entity);
  } catch (err) {
    host.replaceChildren(emptyState(`Could not render this entity: ${err.message}`));
  }
}
