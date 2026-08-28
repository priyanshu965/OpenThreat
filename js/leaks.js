/**
 * OPENTHREAT — js/leaks.js
 * ========================
 * Ransomware leak-site activity, and the Telegram watch.
 *
 * This is the dark-web section made real. The previous Dark Web view showed
 * whatever the darkweb module had scraped; this shows the actual shape of
 * extortion activity — who is claiming victims, in which sectors, in which
 * countries, and whether the volume is rising.
 *
 * TWO HONESTY RULES, ENFORCED IN THE RENDERING
 * --------------------------------------------
 * 1. SOURCE FRESHNESS IS ON THE PAGE. Each feed reports the age of its newest
 *    record. A leak aggregator that quietly stops updating otherwise reads as
 *    "ransomware went quiet", which is the most misleading thing this view
 *    could possibly say.
 * 2. CLAIMS ARE CLAIMS. Every victim row is an assertion by a criminal group
 *    on its own leak site. Some are fabricated, some are recycled, some name
 *    organisations that were never breached. The view says so, once, plainly,
 *    at the top — not in a footnote.
 *
 * The extortion prose itself is dropped in the pipeline and never reaches
 * here; see scripts/ransomware_leaks.py for why.
 */

'use strict';

const leakState = { tab: 'groups' };

const LEAK_TABS = [
  { key: 'groups', label: 'GROUPS' },
  { key: 'sectors', label: 'SECTORS & GEOGRAPHY' },
  { key: 'recent', label: 'RECENT CLAIMS' },
  { key: 'telegram', label: 'CHANNEL WATCH' },
];

function leakFreshness(host, data) {
  const fresh = data.freshness || {};
  const rows = Object.entries(fresh);
  if (!rows.length) return;
  const box = el('div', 'leak-freshness');
  box.appendChild(el('span', 'leak-fresh-label', 'source freshness'));
  rows.forEach(([name, info]) => {
    const age = info.age_days;
    const stale = age !== null && age !== undefined && age > 45;
    const chip = el('span', `leak-fresh${stale ? ' is-stale' : ''}`);
    chip.appendChild(el('span', 'leak-fresh-name', name));
    chip.appendChild(el('span', 'leak-fresh-age',
      age === null || age === undefined
        ? 'unknown'
        : age === 0 ? 'today' : `${age}d old`));
    chip.appendChild(el('span', 'leak-fresh-count',
      `${(info.records || 0).toLocaleString()} records`));
    if (stale) {
      chip.title = `This feed has not published anything new for ${age} days. `
        + 'Its history is still valid; its silence is not evidence of a quiet period.';
    }
    box.appendChild(chip);
  });
  host.appendChild(box);
}

function renderLeakGroups(host, data) {
  const stats = el('div', 'rv-stats');
  stats.appendChild(rStat('CLAIMS', data.window_claims.toLocaleString(),
    `in the last ${data.window_days} days`));
  stats.appendChild(rStat('ACTIVE GROUPS', data.active_groups, 'claimed at least one'));
  stats.appendChild(rStat('TRACKED', data.total_claims.toLocaleString(),
    'claims in the corpus'));
  host.appendChild(stats);

  const panel = rPanel('Most active groups',
    `Victim counts over the last ${data.window_days} days.`);
  const rows = (data.groups || []).slice(0, 30);
  panel.appendChild(rBars(rows.map((g) => ({ label: g.group, value: g.victims })),
    { max: rows.length ? rows[0].victims : 1 }));
  host.appendChild(panel);

  const list = el('div', 'leak-groups');
  rows.forEach((g) => {
    const card = el('details', 'leak-group');
    const summary = el('summary', 'leak-group-head');
    summary.appendChild(el('span', 'leak-group-name', g.group));
    summary.appendChild(el('span', 'leak-group-count', `${g.victims} victims`));
    if (g.last_in_window) {
      summary.appendChild(el('span', 'leak-group-last', `latest ${g.last_in_window}`));
    }
    card.appendChild(summary);

    if (g.description) card.appendChild(el('p', 'ent-prose', g.description));
    if (g.first_seen) {
      card.appendChild(el('p', 'leak-meta', `First tracked ${g.first_seen}`));
    }
    if (g.top_sectors && g.top_sectors.length) {
      card.appendChild(el('p', 'ent-subhead', 'Sectors hit'));
      card.appendChild(libChipRow(g.top_sectors));
    }
    if (g.tools && g.tools.length) {
      card.appendChild(el('p', 'ent-subhead', 'Reported tooling'));
      card.appendChild(libChipRow(g.tools));
    }
    if (g.ttps && g.ttps.length) {
      card.appendChild(el('p', 'ent-subhead', 'Reported TTPs'));
      const ul = el('ul', 'leak-ttps');
      g.ttps.forEach((t) => ul.appendChild(el('li', '', t)));
      card.appendChild(ul);
    }
    const open = el('button', 'ent-action is-ghost', 'LIBRARY ENTRY →');
    open.type = 'button';
    open.addEventListener('click', () => {
      if (typeof libJump === 'function') libJump(g.group, 'actor');
    });
    card.appendChild(open);
    list.appendChild(card);
  });
  host.appendChild(list);
}

function renderLeakSectors(host, data) {
  const bySector = data.by_sector || [];
  const byCountry = data.by_country || [];
  const byMonth = data.by_month || [];

  if (bySector.length) {
    const panel = rPanel('Sectors targeted',
      `Claims in the last ${data.window_days} days, by the sector the group named.`);
    panel.appendChild(rBars(bySector.map((s) => ({ label: s.name, value: s.count })),
      { max: bySector[0].count }));
    host.appendChild(panel);
  }
  if (byCountry.length) {
    const panel = rPanel('Victim geography',
      'Where the claimed victims are headquartered.');
    panel.appendChild(rBars(byCountry.map((c) => ({ label: c.name, value: c.count })),
      { max: byCountry[0].count }));
    host.appendChild(panel);
  }
  if (byMonth.length > 2) {
    const panel = rPanel('Claim volume over time',
      'Monthly totals across the whole tracked corpus. Read the trend, not the '
      + 'last bar: the current month is still filling, and a source that stops '
      + 'updating also makes this line fall.');
    const max = Math.max(...byMonth.map((m) => m.count));
    panel.appendChild(rBars(byMonth.map((m) => ({ label: m.month, value: m.count })),
      { max }));
    host.appendChild(panel);
  }
}

function renderLeakRecent(host, data) {
  const rows = data.recent || [];
  if (!rows.length) {
    host.appendChild(emptyState('No recent claims in the window.'));
    return;
  }
  host.appendChild(rNote(
    `${rows.length} claims in the last ${data.window_days} days. Each row is an `
    + 'assertion published by the group on its own leak site.'));
  host.appendChild(rTable(
    ['Date', 'Group', 'Claimed victim', 'Sector', 'Country'],
    rows.slice(0, 300).map((r) => [r.date, r.group, r.victim, r.sector || '—',
      r.country || '—']),
  ));
}

async function renderLeakTelegram(host) {
  host.replaceChildren(el('div', 'view-loading', 'Loading…'));
  let data = store.research.telegram;
  if (data === undefined) {
    try {
      const resp = await fetch(API.telegram, { cache: 'no-cache' });
      data = resp.ok ? await resp.json() : null;
    } catch (_) { data = null; }
    store.research.telegram = data;
  }
  host.replaceChildren();
  if (!data || !data.posts || !data.posts.length) {
    host.appendChild(emptyState(
      'Channel watch is off. It monitors public Telegram channel previews and '
      + 'is disabled by default — set ENABLE_TELEGRAM and TELEGRAM_CHANNELS to '
      + 'choose which channels to follow.'));
    return;
  }
  rHead(host, 'Channel watch',
    `${data.count} posts from ${data.channels_ok} of ${data.channels.length} `
    + 'monitored public channels.');
  host.appendChild(rNote(data.disclaimer));

  const list = el('div', 'leak-posts');
  data.posts.forEach((post) => {
    const row = el('article', 'leak-post');
    const head = el('div', 'leak-post-head');
    head.appendChild(el('span', 'leak-post-channel', `@${post.channel}`));
    if (post.posted) head.appendChild(el('span', 'leak-post-time', post.posted));
    head.appendChild(libLink('open', post.url, 'leak-post-link'));
    row.appendChild(head);
    row.appendChild(el('p', 'leak-post-text', post.text));
    list.appendChild(row);
  });
  host.appendChild(list);
}

async function showLeaksView() {                     // eslint-disable-line no-unused-vars
  hideAllViews();
  const host = $('leaks-view');
  if (!host) return;
  host.style.display = 'block';
  host.replaceChildren();

  const tabs = el('div', 'rv-tabs');
  LEAK_TABS.forEach((tab) => {
    const btn = el('button', `rv-tab${leakState.tab === tab.key ? ' active' : ''}`,
      tab.label);
    btn.type = 'button';
    btn.addEventListener('click', () => { leakState.tab = tab.key; showLeaksView(); });
    tabs.appendChild(btn);
  });
  host.appendChild(tabs);

  const body = el('div', 'rv-body');
  host.appendChild(body);

  if (leakState.tab === 'telegram') {
    await renderLeakTelegram(body);
    return;
  }

  body.appendChild(el('div', 'view-loading', 'Loading…'));
  let data = store.research.leaks;
  if (data === undefined) {
    try {
      const resp = await fetch(API.leaks, { cache: 'no-cache' });
      data = resp.ok ? await resp.json() : null;
    } catch (_) { data = null; }
    store.research.leaks = data;
  }
  if (host.style.display === 'none') return;
  body.replaceChildren();

  if (!data) {
    body.appendChild(emptyState(
      'Leak-site tracking has not been published yet. It appears after a '
      + 'pipeline run with ENABLE_LEAK_SITES on.'));
    return;
  }

  rHead(body, 'Ransomware leak sites',
    'Extortion claims aggregated from public leak-site trackers. Every entry is '
    + 'a claim made by the group itself — treat it as an allegation, not a '
    + 'confirmed breach.');
  leakFreshness(body, data);

  try {
    if (leakState.tab === 'groups') renderLeakGroups(body, data);
    else if (leakState.tab === 'sectors') renderLeakSectors(body, data);
    else renderLeakRecent(body, data);
  } catch (err) {
    body.appendChild(emptyState(`Could not render this view: ${err.message}`));
  }
}
