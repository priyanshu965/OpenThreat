/**
 * OPENTHREAT — js/exposure.js
 *
 * Dark web and exposure views: leak-site search, the browser-side
 * watchlist, credential exposure and attack surface.
 *
 * Moved out of app.js unchanged. Loaded as a classic script after it and
 * shares its top-level scope: store, el, $, svgEl and the other helpers are
 * defined there.
 */

'use strict';

// --- Dark web view ----------------------------------------------------------
// Leak-site exposure search, CASM-style. The index is built by the pipeline and
// lazily fetched here (it is ~550 KB and only this view needs it), so search is
// instant, local, and never touches a rate-limited API.

const DARKWEB_INDEX_URL = 'data/api/darkweb_index.json';

function dwNorm(s) {
  return String(s || '').toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim();
}

// Mirrors darkweb.search_index() on the Python side so both agree on a hit.
function dwSearch(index, term, limit) {
  const q = dwNorm(term);
  if (!q || !index || !index.victims) return [];
  const out = [];
  for (const row of index.victims) {
    if (dwNorm(row.v).includes(q)) {
      out.push(row);
      if (out.length >= (limit || 100)) break;
    }
  }
  return out;
}

async function loadDarkwebIndex() {
  if (store.darkwebIndex !== null) return store.darkwebIndex;
  try {
    const resp = await fetch(DARKWEB_INDEX_URL, { cache: 'no-cache' });
    store.darkwebIndex = resp.ok ? await resp.json() : false;
  } catch (_) {
    store.darkwebIndex = false;
  }
  return store.darkwebIndex;
}

async function showDarkwebView() {
  hideAllViews();
  const host = $('darkweb-view');
  if (!host) return;
  host.style.display = 'block';
  host.replaceChildren(el('p', 'chart-empty', 'Loading leak-site index…'));

  const index = await loadDarkwebIndex();
  const summary = (store.meta && store.meta.darkweb) || null;
  host.replaceChildren();

  host.appendChild(el('h2', 'ls-title', 'Dark web — leak-site exposure'));
  host.appendChild(el('p', 'ls-sub',
    'Ransomware and extortion crews publish victims to their own Tor leak ' +
    'sites. Search that corpus for a company name, or keep a standing watch.'));

  // ---- headline tiles ------------------------------------------------------
  const tiles = el('div', 'ls-tiles');
  if (index && index.count) {
    tiles.appendChild(statTile('Listings indexed', index.count.toLocaleString(),
      (index.from || '?') + ' → ' + (index.to || '?')));
  }
  if (summary) {
    tiles.appendChild(statTile('Leak sites tracked', summary.tracked_leak_sites.toLocaleString()));
    tiles.appendChild(statTile('Groups active', String(summary.distinct_groups_active), 'recent window'));
    tiles.appendChild(statTile('Recent listings', String(summary.recent_posts)));
  }
  host.appendChild(tiles);

  // ---- search --------------------------------------------------------------
  const panel = lsPanel('Exposure search',
    'Type an organisation name. Matching is on the victim name as the crew ' +
    'published it, so try short forms and trading names too.');

  const form = el('div', 'dw-search');
  const input = el('input', 'dw-input');
  input.type = 'search';
  input.placeholder = 'e.g. Acme, Contoso Ltd, a supplier name…';
  input.setAttribute('aria-label', 'Search leak-site listings for an organisation');
  input.value = store.darkwebQuery || '';
  form.appendChild(input);

  const watchBtn = el('button', 'dw-watch-btn', '☆ Watch this name');
  watchBtn.type = 'button';
  form.appendChild(watchBtn);
  panel.appendChild(form);

  const results = el('div', 'dw-results');
  panel.appendChild(results);

  const runSearch = () => {
    const q = input.value.trim();
    store.darkwebQuery = q;
    results.replaceChildren();
    if (!index) {
      results.appendChild(el('p', 'chart-empty',
        'The leak-site index is not published yet — it appears after the next pipeline run.'));
      return;
    }
    if (q.length < 3) {
      results.appendChild(el('p', 'dw-hint', 'Enter at least 3 characters.'));
      return;
    }
    const hits = dwSearch(index, q, 100);
    watchBtn.style.display = 'inline-block';
    if (!hits.length) {
      const none = el('div', 'dw-none');
      none.appendChild(el('div', 'dw-none-head', 'No listing found for “' + q + '”'));
      none.appendChild(el('div', 'dw-none-body',
        'That name does not appear in the leak sites we track. This is NOT ' +
        'evidence of safety: it covers ransomware leak sites only, not forums, ' +
        'markets, credential dumps or infostealer logs.'));
      results.appendChild(none);
      return;
    }
    results.appendChild(el('div', 'dw-count',
      hits.length + (hits.length === 100 ? '+ ' : ' ') +
      'listing' + (hits.length === 1 ? '' : 's') + ' matching “' + q + '”'));
    results.appendChild(dwTable(hits));
  };

  input.addEventListener('input', debounceDw(runSearch, 180));
  input.addEventListener('keydown', (e) => { if (e.key === 'Enter') runSearch(); });
  watchBtn.addEventListener('click', () => {
    const q = input.value.trim();
    if (q.length < 3) return;
    if (!store.darkwebWatch.includes(q)) {
      store.darkwebWatch.push(q);
      writeLS(LS.darkwebWatch, store.darkwebWatch);
    }
    showDarkwebView();
  });
  host.appendChild(panel);
  if (store.darkwebQuery) runSearch();

  // ---- standing watch ------------------------------------------------------
  const watchPanel = lsPanel('Standing watch',
    'Names you are watching are re-checked against the index every time the ' +
    'page loads. For alerting between visits, set DARKWEB_WATCH in the ' +
    'pipeline so a hit raises a webhook.');
  if (!store.darkwebWatch.length) {
    watchPanel.appendChild(el('p', 'dw-hint',
      'No names watched yet. Search for one and press “Watch this name”.'));
  } else {
    store.darkwebWatch.forEach((term) => {
      const hits = index ? dwSearch(index, term, 50) : [];
      const row = el('div', 'dw-watch-row' + (hits.length ? ' is-hit' : ''));
      const left = el('div', 'dw-watch-left');
      left.appendChild(el('span', 'dw-watch-term', term));
      left.appendChild(el('span', 'dw-watch-status',
        hits.length ? hits.length + ' listing' + (hits.length === 1 ? '' : 's') + ' found'
                    : 'no listing in the tracked corpus'));
      row.appendChild(left);
      const rm = el('button', 'dw-watch-rm', 'Remove');
      rm.type = 'button';
      rm.addEventListener('click', () => {
        store.darkwebWatch = store.darkwebWatch.filter((t) => t !== term);
        writeLS(LS.darkwebWatch, store.darkwebWatch);
        showDarkwebView();
      });
      row.appendChild(rm);
      watchPanel.appendChild(row);
      if (hits.length) watchPanel.appendChild(dwTable(hits.slice(0, 5)));
    });
  }
  host.appendChild(watchPanel);

  // ---- pipeline-side watch hits -------------------------------------------
  const serverHits = (store.meta && store.meta.darkweb_watch) || [];
  if (serverHits.length) {
    const sp = lsPanel('Pipeline watchlist hits',
      'From DARKWEB_WATCH, checked server-side on every run.');
    serverHits.forEach((h) => {
      sp.appendChild(el('div', 'dw-watch-row is-hit',
        h.term + ' — ' + h.count + ' listing' + (h.count === 1 ? '' : 's')));
      sp.appendChild(dwTable(h.matches || []));
    });
    host.appendChild(sp);
  }

  // ---- sector benchmark ----------------------------------------------------
  const bench = await loadJsonOnce('benchmark', EXPOSURE_URLS.benchmark);
  const bpanel = buildSectorBenchmark(bench);
  if (bpanel) host.appendChild(bpanel);

  // ---- most active crews ---------------------------------------------------
  if (summary && (summary.most_active || []).length) {
    const ap = lsPanel('Most active crews', 'By listings in the recent window.');
    const rows = summary.most_active;
    const max = Math.max(1, ...rows.map((r) => r.posts));
    const bars = el('div', 'ls-bars');
    rows.slice(0, 8).forEach((r) => {
      const line = el('div', 'ls-bar-row');
      line.appendChild(el('span', 'ls-bar-name', r.group));
      const track = el('span', 'ls-bar-track');
      const fill = el('span', 'ls-bar-fill');
      fill.style.width = ((r.posts / max) * 100) + '%';
      fill.style.background = '#d6454f';
      track.appendChild(fill);
      line.appendChild(track);
      line.appendChild(el('span', 'ls-bar-val', String(r.posts)));
      bars.appendChild(line);
    });
    ap.appendChild(bars);
    host.appendChild(ap);
  }

  // ---- coverage, stated plainly -------------------------------------------
  const cov = (index && index.coverage) || null;
  const covPanel = el('details', 'dw-coverage');
  covPanel.appendChild(el('summary', 'dw-coverage-sum', 'What this does and does not cover'));
  if (cov) {
    const yes = el('div', 'dw-cov-block');
    yes.appendChild(el('div', 'dw-cov-h', 'Covers'));
    const ul = el('ul', 'dw-cov-list');
    cov.covers.forEach((c) => ul.appendChild(el('li', '', c)));
    yes.appendChild(ul);
    covPanel.appendChild(yes);

    const no = el('div', 'dw-cov-block');
    no.appendChild(el('div', 'dw-cov-h dw-cov-no', 'Does NOT cover'));
    const ul2 = el('ul', 'dw-cov-list');
    cov.does_not_cover.forEach((c) => ul2.appendChild(el('li', '', c)));
    no.appendChild(ul2);
    covPanel.appendChild(no);

    covPanel.appendChild(el('p', 'dw-cov-caveat', cov.caveat));
  }
  if (summary && summary.collection_note) {
    covPanel.appendChild(el('p', 'dw-cov-caveat', summary.collection_note));
  }
  host.appendChild(covPanel);
}

function dwTable(rows) {
  const wrap = el('div', 'dw-table-wrap');
  const table = el('table', 'dw-table');
  const head = el('tr', 'dw-thead');
  ['Victim', 'Claimed by', 'Date', 'Country', 'Sector'].forEach((h) => {
    head.appendChild(el('th', '', h));
  });
  table.appendChild(head);
  rows.forEach((r) => {
    const tr = el('tr', 'dw-trow');
    tr.appendChild(el('td', 'dw-td-victim', r.v || '—'));
    tr.appendChild(el('td', 'dw-td-group', r.g || '—'));
    tr.appendChild(el('td', 'dw-td-date', r.d || '—'));
    tr.appendChild(el('td', 'dw-td-cc', r.c || '—'));
    tr.appendChild(el('td', 'dw-td-sector', r.s || '—'));
    table.appendChild(tr);
  });
  wrap.appendChild(table);
  return wrap;
}

let dwTimer = null;
function debounceDw(fn, ms) {
  return () => { clearTimeout(dwTimer); dwTimer = setTimeout(fn, ms); };
}

// --- Exposure view (your own estate) ----------------------------------------
// The other half of CASM: not "who got hit" but "what of ours is already out
// there". Infostealer credential exposure, external attack surface from
// Certificate Transparency, and the public breach catalogue.

const EXPOSURE_URLS = {
  exposure: 'data/api/exposure.json',
  surface: 'data/api/attack_surface.json',
  breaches: 'data/api/breaches.json',
  benchmark: 'data/api/sector_benchmark.json',
};

async function loadJsonOnce(key, url) {
  if (store.casm[key] !== undefined) return store.casm[key];
  try {
    const resp = await fetch(url, { cache: 'no-cache' });
    store.casm[key] = resp.ok ? await resp.json() : null;
  } catch (_) {
    store.casm[key] = null;
  }
  return store.casm[key];
}

async function showExposureView() {
  hideAllViews();
  const host = $('exposure-view');
  if (!host) return;
  host.style.display = 'block';
  host.replaceChildren(el('p', 'chart-empty', 'Loading exposure…'));

  const [exposure, surface, breaches] = await Promise.all([
    loadJsonOnce('exposure', EXPOSURE_URLS.exposure),
    loadJsonOnce('surface', EXPOSURE_URLS.surface),
    loadJsonOnce('breaches', EXPOSURE_URLS.breaches),
  ]);
  host.replaceChildren();

  host.appendChild(el('h2', 'ls-title', 'Exposure — your own estate'));
  host.appendChild(el('p', 'ls-sub',
    'What of yours is already circulating, and what of yours is reachable ' +
    'from the internet. Set MY_DOMAINS in the pipeline to populate this.'));

  if (!exposure && !surface) {
    const empty = lsPanel('No domains configured',
      'This view fills once MY_DOMAINS is set on the pipeline.');
    const code = el('pre', 'ex-code',
      'MY_DOMAINS="example.com,example.co.uk"\nDARKWEB_WATCH="Example Corp,example.com"');
    empty.appendChild(code);
    empty.appendChild(el('p', 'ls-foot',
      'Set them as repository variables under Settings → Secrets and variables → Actions.'));
    host.appendChild(empty);
  }

  // ---- infostealer credential exposure ------------------------------------
  if (exposure && exposure.domains && exposure.domains.length) {
    const t = exposure.totals || {};
    const tiles = el('div', 'ls-tiles');
    tiles.appendChild(statTile('Employee machines', (t.employees || 0).toLocaleString(),
      'in infostealer logs'));
    tiles.appendChild(statTile('User machines', (t.users || 0).toLocaleString(),
      'customers / visitors'));
    tiles.appendChild(statTile('Third parties', (t.third_parties || 0).toLocaleString(),
      'supply chain'));
    host.appendChild(tiles);

    const panel = lsPanel('Credential exposure',
      'Machines found in infostealer logs with credentials for these domains. ' +
      'Employee machines matter most: those are corporate logins already in ' +
      'criminal hands.');
    exposure.domains.forEach((d) => {
      const row = el('div', 'ex-row' + (d.employees ? ' is-bad' : ''));
      const left = el('div', 'ex-row-left');
      left.appendChild(el('span', 'ex-domain', d.domain));
      const detail = [];
      if (d.employees) detail.push(d.employees.toLocaleString() + ' employee');
      if (d.users) detail.push(d.users.toLocaleString() + ' user');
      if (d.third_parties) detail.push(d.third_parties.toLocaleString() + ' third-party');
      left.appendChild(el('span', 'ex-detail',
        detail.length ? detail.join(' · ') + ' machine(s)' : 'no exposure found'));
      if (d.last_employee_compromised) {
        left.appendChild(el('span', 'ex-date',
          'Most recent employee compromise: ' + d.last_employee_compromised));
      }
      row.appendChild(left);
      row.appendChild(el('span', 'ex-total', (d.total || 0).toLocaleString()));
      panel.appendChild(row);
    });
    if (exposure.domains[0] && exposure.domains[0].note) {
      panel.appendChild(el('p', 'ls-foot', exposure.domains[0].note));
    }
    host.appendChild(panel);
  }

  // ---- attack surface ------------------------------------------------------
  if (surface && surface.domains && surface.domains.length) {
    const panel = lsPanel('External attack surface',
      'Hostnames seen in public Certificate Transparency logs. Names like ' +
      'dev, staging, vpn or admin are surfaced first — those are usually the ' +
      'shadow IT nobody told you about.');
    surface.domains.forEach((d) => {
      const head = el('div', 'ex-surface-head');
      head.appendChild(el('span', 'ex-domain', d.domain));
      head.appendChild(el('span', 'ex-detail',
        d.hostnames.toLocaleString() + ' hostname' + (d.hostnames === 1 ? '' : 's')));
      panel.appendChild(head);

      if (d.noteworthy && d.noteworthy.length) {
        const chips = el('div', 'ex-chips');
        d.noteworthy.forEach((h) => chips.appendChild(el('span', 'ex-chip is-flag', h)));
        panel.appendChild(chips);
      }
      if (d.sample && d.sample.length) {
        const det = el('details', 'ex-hosts');
        det.appendChild(el('summary', 'ex-hosts-sum',
          'All discovered hostnames' + (d.truncated ? ' (first ' + d.sample.length + ')' : '')));
        const chips = el('div', 'ex-chips');
        d.sample.forEach((h) => chips.appendChild(el('span', 'ex-chip', h)));
        det.appendChild(chips);
        panel.appendChild(det);
      }
    });
    if (surface.note) panel.appendChild(el('p', 'ls-foot', surface.note));
    host.appendChild(panel);
  }

  // ---- public breach catalogue --------------------------------------------
  if (breaches && breaches.recent) {
    const panel = lsPanel('Public breach catalogue',
      breaches.total_breaches.toLocaleString() + ' known breaches covering ' +
      breaches.total_accounts.toLocaleString() + ' accounts. Most recently added first.');
    const wrap = el('div', 'dw-table-wrap');
    const table = el('table', 'dw-table');
    const head = el('tr', 'dw-thead');
    ['Breach', 'Occurred', 'Accounts', 'Data exposed'].forEach((h) =>
      head.appendChild(el('th', '', h)));
    table.appendChild(head);
    breaches.recent.slice(0, 15).forEach((b) => {
      const tr = el('tr', 'dw-trow');
      tr.appendChild(el('td', 'dw-td-victim', b.name || b.domain || '—'));
      tr.appendChild(el('td', 'dw-td-date', b.date || '—'));
      tr.appendChild(el('td', 'dw-td-cc', (b.accounts || 0).toLocaleString()));
      tr.appendChild(el('td', 'dw-td-sector', (b.classes || []).slice(0, 4).join(', ')));
      table.appendChild(tr);
    });
    wrap.appendChild(table);
    panel.appendChild(wrap);
    panel.appendChild(el('p', 'ls-foot', 'Source: ' + breaches.source));
    host.appendChild(panel);
  }
}

// --- Sector benchmarking (rendered on the Dark Web view) --------------------
function buildSectorBenchmark(bench) {
  if (!bench || !bench.sectors || !bench.sectors.length) return null;
  const fig = lsPanel('Sector benchmark',
    bench.note || 'Leak-site listings this window against the previous one.');
  const max = Math.max(1, ...bench.sectors.map((s) => s.current));
  const list = el('div', 'ls-bars');
  bench.sectors.slice(0, 12).forEach((s) => {
    const row = el('div', 'ls-bar-row');
    row.appendChild(el('span', 'ls-bar-name', s.sector));
    const track = el('span', 'ls-bar-track');
    const fill = el('span', 'ls-bar-fill');
    fill.style.width = ((s.current / max) * 100) + '%';
    fill.style.background = s.direction === 'up' ? '#e0653f'
      : s.direction === 'down' ? '#3fae8c' : SERIES_1;
    track.appendChild(fill);
    row.appendChild(track);
    const arrow = s.direction === 'up' ? '▲' : s.direction === 'down' ? '▼'
      : s.direction === 'new' ? '＋' : '–';
    const cls = s.direction === 'up' ? 'ls-up' : s.direction === 'down' ? 'ls-down' : 'ls-flat';
    const label = s.change_pct === null ? 'new'
      : (s.change_pct > 0 ? '+' : '') + s.change_pct + '%';
    const val = el('span', 'ls-bar-val ' + cls, arrow + ' ' + s.current + ' (' + label + ')');
    val.title = s.current + ' this window vs ' + s.previous + ' previous';
    row.appendChild(val);
    list.appendChild(row);
  });
  fig.appendChild(list);
  return fig;
}
