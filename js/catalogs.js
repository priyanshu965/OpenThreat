/*
 * OPENTHREAT — js/catalogs.js
 * ===========================
 * Three browsable tables over data the pipeline already had:
 *
 *   KEV        CISA's catalogue of vulnerabilities known to be exploited.
 *   LIFECYCLE  What is out of vendor support, and what shipped recently.
 *   CVE        Every CVE in the current corpus, searchable.
 *
 * WHY THESE ARE TABLES AND NOT MORE FEED
 * --------------------------------------
 * The feed answers "what needs action today" and is deliberately short. These
 * answer "let me look something up", which is a reference question, and
 * reference material wants a table with a filter box — not a triage list.
 *
 * The KEV catalogue in particular was ALREADY being downloaded every run for
 * the backtest and the exploitation-lag report, and then thrown away except
 * for a boolean on each feed item. 1,600 records the pipeline was holding
 * anyway now have a page.
 *
 * All three read pre-rendered JSON. Nothing here calls a third-party API: that
 * is what TOOLS is for, and the distinction is deliberate — a page that
 * sometimes reaches out and sometimes does not is a page whose privacy
 * properties nobody can state.
 */

const KEV_URL = 'data/api/kev.json';
const LIFECYCLE_URL = 'data/api/lifecycle.json';

/* Rendering more than this at once locks the main thread on a mid-range
 * laptop. The filter box is the navigation, not the scrollbar. */
const CATALOG_PAGE = 120;

function catCell(row, text, cls) {
  const cell = el('td', cls || '');
  cell.textContent = text === undefined || text === null || text === '' ? '—' : String(text);
  row.appendChild(cell);
  return cell;
}

function catTable(headers) {
  const wrap = el('div', 'cat-table-wrap');
  const table = el('table', 'cat-table');
  const thead = el('thead');
  const hrow = el('tr');
  headers.forEach((h) => hrow.appendChild(el('th', '', h)));
  thead.appendChild(hrow);
  table.appendChild(thead);
  const tbody = el('tbody');
  table.appendChild(tbody);
  wrap.appendChild(table);
  return { wrap, tbody };
}

function catSearchBox(placeholder, onInput) {
  const form = el('form', 'tool-form');
  const input = el('input', 'tool-input');
  input.type = 'search';
  input.placeholder = placeholder;
  input.setAttribute('aria-label', placeholder);
  input.autocomplete = 'off';
  form.appendChild(input);
  form.addEventListener('submit', (e) => e.preventDefault());
  let timer = null;
  input.addEventListener('input', () => {
    // Debounced: these tables are up to 1,600 rows and re-filtering on every
    // keystroke of a fast typist is visibly janky.
    clearTimeout(timer);
    timer = setTimeout(() => onInput(input.value.trim().toLowerCase()), 120);
  });
  return form;
}

function catCount(shown, total, noun) {
  return `${shown.toLocaleString()} of ${total.toLocaleString()} ${noun}`;
}

/* ── KEV ──────────────────────────────────────────────────────────────────── */

function catKevOverdue(entry, today) {
  /* A due date in the past is a missed FEDERAL deadline, not yours. Labelled
   * as such: BOD 22-01 binds US federal civilian agencies, and presenting
   * their deadline as everyone's is the kind of borrowed urgency that makes
   * a dashboard less trusted, not more. */
  if (!entry.due) return null;
  const days = Math.floor((today - Date.parse(entry.due)) / 86400000);
  return days > 0 ? days : null;
}

function showKevView() {
  showLazyView('kev-view', 'kev', (host, data) => {
    host.appendChild(el('h2', 'view-title', 'Known Exploited Vulnerabilities'));
    const sub = el('p', 'view-sub');
    sub.textContent = `${(data.count || 0).toLocaleString()} entries from CISA, `
      + `${(data.ransomware_linked || 0).toLocaleString()} linked to ransomware `
      + 'campaigns. Every one of these is confirmed exploited in the wild — '
      + 'this is the shortest list of things that are definitely being used.';
    host.appendChild(sub);

    const note = el('p', 'tool-note');
    note.textContent = 'Due dates are the BOD 22-01 remediation deadlines for '
      + 'US federal civilian agencies. If you are not one, they are a useful '
      + 'reference point and not your deadline.';
    host.appendChild(note);

    const entries = Array.isArray(data.entries) ? data.entries : [];
    const today = Date.now();
    const status = el('p', 'cat-status');
    const { wrap, tbody } = catTable(
      ['CVE', 'Vendor', 'Product', 'Added', 'Due', 'Vulnerability']);

    function render(query) {
      const hits = query
        ? entries.filter((e) => `${e.cve} ${e.vendor} ${e.product} ${e.name} ${e.desc}`
            .toLowerCase().includes(query))
        : entries;
      tbody.replaceChildren();
      hits.slice(0, CATALOG_PAGE).forEach((entry) => {
        const row = el('tr');
        const idCell = el('td', 'cat-id');
        const link = el('a', '', entry.cve);
        link.href = safeUrl('https://nvd.nist.gov/vuln/detail/' + entry.cve);
        link.target = '_blank'; link.rel = 'noopener noreferrer';
        idCell.appendChild(link);
        if (entry.ransomware) {
          idCell.appendChild(el('span', 'cat-flag', 'ransomware'));
        }
        row.appendChild(idCell);
        catCell(row, entry.vendor);
        catCell(row, entry.product);
        catCell(row, entry.added);
        const overdue = catKevOverdue(entry, today);
        const dueCell = catCell(row, entry.due);
        if (overdue) {
          dueCell.classList.add('is-overdue');
          dueCell.title = `${overdue} days past the federal deadline`;
        }
        catCell(row, entry.name || entry.desc, 'cat-desc');
        tbody.appendChild(row);
      });
      status.textContent = catCount(Math.min(hits.length, CATALOG_PAGE),
        hits.length, 'entries shown')
        + (hits.length > CATALOG_PAGE ? ' — narrow the search to see more' : '');
    }

    host.appendChild(catSearchBox('Search CVE, vendor, product or description…', render));
    host.appendChild(status);
    host.appendChild(wrap);
    render('');
  }, 'The KEV catalogue has not been published yet. It appears after the next pipeline run.');
}

/* ── Lifecycle ────────────────────────────────────────────────────────────── */

const LIFECYCLE_STATE_LABEL = {
  eol: 'end of life',
  extended: 'extended support',
  'security-only': 'security fixes only',
  supported: 'supported',
  unknown: 'not announced',
};
const LIFECYCLE_STATE_LEVEL = {
  eol: 'bad',
  extended: 'warn',
  'security-only': 'warn',
  supported: 'good',
  unknown: 'info',
};

function showLifecycleView() {
  showLazyView('lifecycle-view', 'lifecycle', (host, data) => {
    host.appendChild(el('h2', 'view-title', 'Software lifecycle'));
    const sub = el('p', 'view-sub');
    sub.textContent = 'When each release stops getting fixes, and what shipped '
      + 'recently. Out of support is a statement about the vendor, not about '
      + 'you — running an unsupported release is a risk decision, not '
      + 'automatically a vulnerability.';
    host.appendChild(sub);

    if (data.complete === false) {
      const warn = el('p', 'tool-note');
      warn.textContent = 'Some upstreams did not answer on the last run, so '
        + 'this board is partial. It is shown as partial rather than as a '
        + 'shorter list.';
      host.appendChild(warn);
    }

    // ── End of life ──
    const products = Array.isArray(data.products) ? data.products : [];
    const status = el('p', 'cat-status');
    const { wrap, tbody } = catTable(
      ['Product', 'Release', 'Latest', 'Status', 'Until', 'Days']);

    function render(query) {
      const rows = [];
      products.forEach((product) => {
        if (query && !product.product.toLowerCase().includes(query)) return;
        (product.cycles || []).forEach((cycle) => rows.push({ product, cycle }));
      });
      // Out of support first — that is the reason to open this page.
      const order = { eol: 0, 'security-only': 1, extended: 2, supported: 3, unknown: 4 };
      rows.sort((a, b) => (order[a.cycle.state] ?? 9) - (order[b.cycle.state] ?? 9));

      tbody.replaceChildren();
      rows.slice(0, CATALOG_PAGE).forEach(({ product, cycle }) => {
        const row = el('tr');
        const nameCell = el('td', 'cat-id');
        const link = el('a', '', product.product);
        link.href = safeUrl(product.url);
        link.target = '_blank'; link.rel = 'noopener noreferrer';
        nameCell.appendChild(link);
        row.appendChild(nameCell);
        catCell(row, cycle.cycle + (cycle.lts ? ' (LTS)' : ''));
        catCell(row, cycle.latest);
        const stateCell = el('td');
        stateCell.appendChild(toolVerdict(
          LIFECYCLE_STATE_LEVEL[cycle.state] || 'info',
          LIFECYCLE_STATE_LABEL[cycle.state] || cycle.state));
        row.appendChild(stateCell);
        catCell(row, cycle.eol);
        catCell(row, cycle.days === null || cycle.days === undefined
          ? '' : Math.abs(cycle.days).toLocaleString());
        tbody.appendChild(row);
      });
      status.textContent = catCount(Math.min(rows.length, CATALOG_PAGE),
        rows.length, 'release cycles shown');
    }

    host.appendChild(catSearchBox('Filter by product…', render));
    host.appendChild(status);
    host.appendChild(wrap);
    render('');

    // ── Releases ──
    const releases = Array.isArray(data.releases) ? data.releases : [];
    if (releases.length) {
      host.appendChild(el('h3', 'comm-section-title', 'Latest security-tooling releases'));
      const note = el('p', 'tool-note');
      note.textContent = 'If your detection content is a version behind, you '
        + 'are missing coverage that already exists.';
      host.appendChild(note);
      const rel = catTable(['Project', 'Release', 'Published', 'Age']);
      releases.forEach((r) => {
        const row = el('tr');
        const cell = el('td', 'cat-id');
        const link = el('a', '', r.repo);
        link.href = safeUrl(r.url);
        link.target = '_blank'; link.rel = 'noopener noreferrer';
        cell.appendChild(link);
        if (r.prerelease) cell.appendChild(el('span', 'cat-flag', 'pre-release'));
        row.appendChild(cell);
        catCell(row, r.tag);
        catCell(row, r.published);
        catCell(row, r.age_days === null ? '' : `${r.age_days}d`);
        rel.tbody.appendChild(row);
      });
      host.appendChild(rel.wrap);
    }
  }, 'The lifecycle board has not been published yet. It appears after the next pipeline run.');
}

/* ── CVE browser ──────────────────────────────────────────────────────────── */

/**
 * Every CVE in the current corpus.
 *
 * Built from `store.items`, which is already loaded — not from a second
 * download and not from the NVD API. The feed is the corpus; this is a
 * different lens on it, and re-fetching what is already in memory to show the
 * same records in a table would be a second source of truth for no benefit.
 */
function showCveView() {
  hideAllViews();
  const host = $('cve-view');
  if (!host) return;
  host.style.display = 'block';
  host.replaceChildren();

  host.appendChild(el('h2', 'view-title', 'CVE browser'));

  const withCve = (store.items || []).filter((i) => i.cve_id);
  const sub = el('p', 'view-sub');
  sub.textContent = `${withCve.length.toLocaleString()} CVEs in the current `
    + 'corpus, with everything the pipeline knows about each. This is the same '
    + 'data as the feed, as a reference table rather than a triage list.';
  host.appendChild(sub);

  const status = el('p', 'cat-status');
  const { wrap, tbody } = catTable(
    ['CVE', 'Severity', 'CVSS', 'EPSS', 'Score', 'Action', 'Flags', 'Title']);

  function render(query) {
    const hits = query
      ? withCve.filter((i) => `${i.cve_id} ${i.title} ${i.source}`
          .toLowerCase().includes(query))
      : withCve;
    const sorted = hits.slice().sort(
      (a, b) => (b.priority_score || 0) - (a.priority_score || 0));
    tbody.replaceChildren();
    sorted.slice(0, CATALOG_PAGE).forEach((item) => {
      const row = el('tr');
      const idCell = el('td', 'cat-id');
      const link = el('a', '', item.cve_id);
      link.href = safeUrl(item.url || ('https://nvd.nist.gov/vuln/detail/' + item.cve_id));
      link.target = '_blank'; link.rel = 'noopener noreferrer';
      idCell.appendChild(link);
      row.appendChild(idCell);
      catCell(row, item.severity);
      catCell(row, item.cvss_score);
      catCell(row, item.epss_score === undefined || item.epss_score === null
        ? '' : `${(item.epss_score * 100).toFixed(1)}%`);
      catCell(row, item.priority_score);
      catCell(row, item.priority_label);
      const flags = el('td');
      if (item.cisa_kev) flags.appendChild(el('span', 'cat-flag', 'KEV'));
      if (item.has_poc) flags.appendChild(el('span', 'cat-flag', 'PoC'));
      if (item.ssvc_exploitation === 'active') {
        flags.appendChild(el('span', 'cat-flag', 'active'));
      }
      row.appendChild(flags);
      catCell(row, item.title, 'cat-desc');
      tbody.appendChild(row);
    });
    status.textContent = catCount(Math.min(sorted.length, CATALOG_PAGE),
      sorted.length, 'CVEs shown')
      + (sorted.length > CATALOG_PAGE ? ' — narrow the search to see more' : '');
  }

  host.appendChild(catSearchBox('Search CVE id, title or source…', render));
  host.appendChild(status);
  host.appendChild(wrap);
  render('');
}
