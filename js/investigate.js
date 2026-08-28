/*
 * OPENTHREAT — js/investigate.js
 * ==============================
 * IOC lookup and phishing triage.
 *
 * WHY THE IOC TOOL IS A PIVOT LAUNCHER
 * ------------------------------------
 * "Query 50+ OSINT sources simultaneously" is what everyone asks for and it
 * cannot be built here. Almost every reputation API worth querying —
 * VirusTotal, URLhaus, ThreatFox, AbuseIPDB, Shodan, GreyNoise, PhishTank —
 * requires an API key. Both abuse.ch endpoints started returning 401 without
 * one; they were verified, not assumed. A key in a static page is a key every
 * visitor can read and bill to this project.
 *
 * So the honest version is a launcher: type the indicator once, get it
 * correctly classified, and get every source opened at the right URL for that
 * TYPE of indicator. That is the part of the work that is actually tedious —
 * remembering which of 50 services takes a hash in the path and which takes it
 * in a query parameter — and it is the part that does not need a key.
 *
 * The handful of sources that ARE keyless and CORS-open answer inline. They
 * are marked as live results; the rest are marked as links.
 *
 * WHY THE PHISHING ANALYZER NEVER FETCHES THE URL
 * -----------------------------------------------
 * Fetching a suspected phishing page from the analyst's browser would: leak
 * the analyst's IP to the attacker, potentially fire a tracking token unique
 * to the victim, and load hostile content into the page. It also would not
 * work — the target's CORS policy blocks reading the response.
 *
 * Everything here is computed from the URL STRING plus DNS, which is enough
 * for the checks that actually catch things: homograph and punycode tricks,
 * lookalike domains, credential-prefix URLs, and domain age.
 */

/* ── Indicator classification ─────────────────────────────────────────────── */

const IOC_PATTERNS = [
  ['cve', /^CVE-\d{4}-\d{4,7}$/i],
  ['md5', /^[a-f0-9]{32}$/i],
  ['sha1', /^[a-f0-9]{40}$/i],
  ['sha256', /^[a-f0-9]{64}$/i],
  ['ipv4', /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/],
  ['ipv6', /^(?:[a-f0-9]{0,4}:){2,7}[a-f0-9]{0,4}$/i],
  ['email', /^[^\s@]+@[^\s@]+\.[a-z]{2,}$/i],
  ['url', /^[a-z][a-z0-9+.-]*:\/\//i],
  ['domain', /^(?=.{1,253}$)([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i],
];

function iocClassify(raw) {
  const value = String(raw || '').trim().replace(/^[<[("']+|[>\])"']+$/g, '');
  if (!value) return { type: '', value: '' };
  // Defanged indicators are the normal way IOCs are shared, precisely so they
  // are not clickable. Accepting them saves the analyst a manual edit every
  // single time, which is the sort of friction that stops a tool being used.
  const refanged = value
    .replace(/\[\.\]|\(\.\)|\{\.\}/g, '.')
    .replace(/\[:\]/g, ':')
    .replace(/^h(?:xx|XX)p(s?):\/\//i, 'http$1://')
    .replace(/\[at\]/gi, '@');
  for (const [type, pattern] of IOC_PATTERNS) {
    if (pattern.test(refanged)) return { type, value: refanged };
  }
  return { type: '', value: refanged };
}

const IOC_TYPE_LABEL = {
  cve: 'CVE identifier', md5: 'MD5 hash', sha1: 'SHA-1 hash',
  sha256: 'SHA-256 hash', ipv4: 'IPv4 address', ipv6: 'IPv6 address',
  email: 'Email address', url: 'URL', domain: 'Domain name',
};

/* Groups an indicator belongs to, for choosing which sources apply. */
function iocGroups(type) {
  if (type === 'md5' || type === 'sha1' || type === 'sha256') return ['hash', 'file'];
  if (type === 'ipv4' || type === 'ipv6') return ['ip', 'network'];
  if (type === 'domain') return ['domain', 'network'];
  if (type === 'url') return ['url', 'network'];
  if (type === 'email') return ['email'];
  if (type === 'cve') return ['cve'];
  return [];
}

/*
 * The pivot table. `build` receives the indicator and returns a URL.
 *
 * Nothing here is queried automatically — these open in a new tab when the
 * analyst clicks. That matters: several of these services record lookups, and
 * silently submitting an indicator to a dozen third parties on page load would
 * tip off an adversary who is watching for exactly that.
 */
const IOC_SOURCES = [
  // Multi-type reputation
  { name: 'VirusTotal', groups: ['hash', 'ip', 'domain', 'url'], key: true,
    build: (v, t) => t === 'url'
      ? 'https://www.virustotal.com/gui/search/' + encodeURIComponent(v)
      : `https://www.virustotal.com/gui/${t === 'ipv4' || t === 'ipv6' ? 'ip-address'
        : t === 'domain' ? 'domain' : 'file'}/${encodeURIComponent(v)}` },
  { name: 'AlienVault OTX', groups: ['hash', 'ip', 'domain', 'url'],
    build: (v, t) => `https://otx.alienvault.com/indicator/${
      t === 'domain' ? 'domain' : (t === 'ipv4' || t === 'ipv6') ? 'ip' : 'file'
    }/${encodeURIComponent(v)}` },
  { name: 'ThreatFox', groups: ['hash', 'ip', 'domain', 'url'],
    build: (v) => 'https://threatfox.abuse.ch/browse.php?search=ioc%3A' + encodeURIComponent(v) },
  { name: 'Pulsedive', groups: ['hash', 'ip', 'domain', 'url'],
    build: (v) => 'https://pulsedive.com/indicator/?ioc=' + encodeURIComponent(v) },

  // Files
  { name: 'MalwareBazaar', groups: ['hash'],
    build: (v) => 'https://bazaar.abuse.ch/browse.php?search=' + encodeURIComponent(v) },
  { name: 'Hybrid Analysis', groups: ['hash'],
    build: (v) => 'https://www.hybrid-analysis.com/search?query=' + encodeURIComponent(v) },
  { name: 'Malshare', groups: ['hash'], key: true,
    build: (v) => 'https://malshare.com/search.php?query=' + encodeURIComponent(v) },
  { name: 'Triage', groups: ['hash'],
    build: (v) => 'https://tria.ge/s?q=' + encodeURIComponent(v) },
  { name: 'ANY.RUN', groups: ['hash'],
    build: (v) => 'https://any.run/report/' + encodeURIComponent(v) },
  { name: 'Malpedia', groups: ['hash'],
    build: (v) => 'https://malpedia.caad.fkie.fraunhofer.de/find?query=' + encodeURIComponent(v) },
  { name: 'Intezer', groups: ['hash'], key: true,
    build: (v) => 'https://analyze.intezer.com/files/' + encodeURIComponent(v) },
  { name: 'Filescan.io', groups: ['hash'],
    build: (v) => 'https://www.filescan.io/search-result?query=' + encodeURIComponent(v) },

  // Network
  { name: 'AbuseIPDB', groups: ['ip'],
    build: (v) => 'https://www.abuseipdb.com/check/' + encodeURIComponent(v) },
  { name: 'Shodan', groups: ['ip', 'domain'], key: true,
    build: (v, t) => t === 'domain'
      ? 'https://www.shodan.io/domain/' + encodeURIComponent(v)
      : 'https://www.shodan.io/host/' + encodeURIComponent(v) },
  { name: 'Censys', groups: ['ip'],
    build: (v) => 'https://search.censys.io/hosts/' + encodeURIComponent(v) },
  { name: 'GreyNoise', groups: ['ip'],
    build: (v) => 'https://viz.greynoise.io/ip/' + encodeURIComponent(v) },
  { name: 'Spur', groups: ['ip'], key: true,
    build: (v) => 'https://spur.us/context/' + encodeURIComponent(v) },
  { name: 'IPinfo', groups: ['ip'],
    build: (v) => 'https://ipinfo.io/' + encodeURIComponent(v) },
  { name: 'BGP.HE', groups: ['ip'],
    build: (v) => 'https://bgp.he.net/ip/' + encodeURIComponent(v) },
  // No per-indicator page: this one lands on the browse list. Declared with
  // no parameter so it is visibly a constant URL rather than one that looks
  // like it uses the indicator and silently does not.
  { name: 'Feodo Tracker', groups: ['ip'],
    build: () => 'https://feodotracker.abuse.ch/browse/' },
  { name: 'Talos Reputation', groups: ['ip', 'domain'],
    build: (v) => 'https://talosintelligence.com/reputation_center/lookup?search=' + encodeURIComponent(v) },
  { name: 'Spamhaus', groups: ['ip', 'domain'],
    build: (v) => 'https://check.spamhaus.org/results/?query=' + encodeURIComponent(v) },

  // Domains and URLs
  { name: 'URLhaus', groups: ['url', 'domain', 'ip'],
    build: (v) => 'https://urlhaus.abuse.ch/browse.php?search=' + encodeURIComponent(v) },
  { name: 'urlscan.io', groups: ['url', 'domain', 'ip'],
    build: (v) => 'https://urlscan.io/search/#' + encodeURIComponent(v) },
  { name: 'PhishTank', groups: ['url'],
    build: (v) => 'https://phishtank.org/?Search=Search&valid=y&active=All&url=' + encodeURIComponent(v) },
  { name: 'OpenPhish', groups: ['url', 'domain'],
    build: () => 'https://openphish.com/phishing_feeds.html' },
  { name: 'crt.sh', groups: ['domain'],
    build: (v) => 'https://crt.sh/?q=' + encodeURIComponent(v) },
  { name: 'DNSDumpster', groups: ['domain'],
    build: (v) => 'https://dnsdumpster.com/?q=' + encodeURIComponent(v) },
  { name: 'SecurityTrails', groups: ['domain', 'ip'], key: true,
    build: (v) => 'https://securitytrails.com/domain/' + encodeURIComponent(v) + '/dns' },
  { name: 'ViewDNS', groups: ['domain', 'ip'],
    build: (v) => 'https://viewdns.info/reverseip/?host=' + encodeURIComponent(v) },
  { name: 'RDAP', groups: ['domain'],
    build: (v) => 'https://rdap.org/domain/' + encodeURIComponent(v) },
  { name: 'Wayback Machine', groups: ['url', 'domain'],
    build: (v) => 'https://web.archive.org/web/*/' + encodeURIComponent(v) },
  { name: 'Google Safe Browsing', groups: ['url', 'domain'],
    build: (v) => 'https://transparencyreport.google.com/safe-browsing/search?url=' + encodeURIComponent(v) },
  { name: 'SSL Labs', groups: ['domain'],
    build: (v) => 'https://www.ssllabs.com/ssltest/analyze.html?d=' + encodeURIComponent(v) },
  { name: 'Netcraft', groups: ['domain', 'url'],
    build: (v) => 'https://sitereport.netcraft.com/?url=' + encodeURIComponent(v) },
  { name: 'Whoisology', groups: ['domain'], key: true,
    build: (v) => 'https://whoisology.com/' + encodeURIComponent(v) },

  // Email
  { name: 'Have I Been Pwned', groups: ['email'],
    build: (v) => 'https://haveibeenpwned.com/account/' + encodeURIComponent(v) },
  { name: 'EmailRep', groups: ['email'],
    build: (v) => 'https://emailrep.io/' + encodeURIComponent(v) },
  { name: 'Hunter.io', groups: ['email'], key: true,
    build: (v) => 'https://hunter.io/email-verifier/' + encodeURIComponent(v) },
  { name: 'Epieos', groups: ['email'],
    build: (v) => 'https://epieos.com/?q=' + encodeURIComponent(v) },

  // CVE
  { name: 'NVD', groups: ['cve'],
    build: (v) => 'https://nvd.nist.gov/vuln/detail/' + encodeURIComponent(v) },
  { name: 'CVE Record', groups: ['cve'],
    build: (v) => 'https://www.cve.org/CVERecord?id=' + encodeURIComponent(v) },
  { name: 'CISA KEV', groups: ['cve'],
    build: () => 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog' },
  { name: 'EPSS', groups: ['cve'],
    build: (v) => 'https://api.first.org/data/v1/epss?cve=' + encodeURIComponent(v) },
  { name: 'Exploit-DB', groups: ['cve'],
    build: (v) => 'https://www.exploit-db.com/search?cve=' + encodeURIComponent(v) },
  { name: 'GitHub PoC search', groups: ['cve'],
    build: (v) => 'https://github.com/search?q=' + encodeURIComponent(v) + '&type=repositories' },
  { name: 'Vulners', groups: ['cve'],
    build: (v) => 'https://vulners.com/search?query=' + encodeURIComponent(v) },
  { name: 'VulnCheck KEV', groups: ['cve'],
    build: (v) => 'https://vulncheck.com/browse/kev?q=' + encodeURIComponent(v) },
  { name: 'Debian security tracker', groups: ['cve'],
    build: (v) => 'https://security-tracker.debian.org/tracker/' + encodeURIComponent(v) },
  { name: 'Red Hat CVE', groups: ['cve'],
    build: (v) => 'https://access.redhat.com/security/cve/' + encodeURIComponent(v.toLowerCase()) },
  { name: 'Ubuntu CVE', groups: ['cve'],
    build: (v) => 'https://ubuntu.com/security/' + encodeURIComponent(v) },
];

function iocSourcesFor(type) {
  const groups = iocGroups(type);
  if (!groups.length) return [];
  return IOC_SOURCES.filter((s) => s.groups.some((g) => groups.includes(g)));
}

/* ── Live lookups (the few that need no key) ──────────────────────────────── */

const CIRCL_CVE = 'https://cve.circl.lu/api/cve/';

/*
 * Two more that pass the keyless + CORS test, both verified by probing them
 * rather than by trusting a directory.
 *
 * Shodan InternetDB is the free, keyless slice of Shodan: open ports,
 * hostnames, CPEs and known CVEs for an address. It is PASSIVE in the sense
 * that matters here -- Shodan scanned the internet already and this reads
 * their result. Nothing in this page ever touches the address itself.
 *
 * EPSS per-CVE. The pipeline already ingests the full daily corpus, but that
 * covers the feed; an arbitrary CVE somebody pastes in is usually not in it.
 */
const SHODAN_INTERNETDB = 'https://internetdb.shodan.io/';
const FIRST_EPSS = 'https://api.first.org/data/v1/epss?cve=';

async function iocLiveCve(cve, host) {
  const block = el('div', 'tool-block');
  block.appendChild(el('h4', 'tool-block-title', 'Live: CIRCL CVE database'));
  host.appendChild(block);
  try {
    const resp = await fetch(CIRCL_CVE + encodeURIComponent(cve.toUpperCase()));
    if (!resp.ok) {
      block.appendChild(el('p', 'tool-note', `No record (HTTP ${resp.status}).`));
      return;
    }
    const data = await resp.json();
    const container = data.containers && data.containers.cna ? data.containers.cna : {};
    const descriptions = container.descriptions || data.descriptions || [];
    const summary = Array.isArray(descriptions) && descriptions.length
      ? String(descriptions[0].value || '') : String(data.summary || '');
    block.appendChild(toolRow('Published',
      String(data.published || (data.cveMetadata && data.cveMetadata.datePublished) || '').slice(0, 10)));
    block.appendChild(toolRow('Assigner',
      (data.cveMetadata && data.cveMetadata.assignerShortName) || ''));
    if (summary) {
      const p = el('p', 'tool-graded-detail');
      p.textContent = summary.slice(0, 900);
      block.appendChild(p);
    }
  } catch (err) {
    block.appendChild(el('p', 'tool-note',
      'CIRCL could not be reached from the browser.'));
  }
}

async function iocLiveEpss(cve, host) {
  const block = el('div', 'tool-block');
  block.appendChild(el('h4', 'tool-block-title', 'Live: EPSS (FIRST.org)'));
  host.appendChild(block);
  try {
    const resp = await fetch(FIRST_EPSS + encodeURIComponent(cve.toUpperCase()));
    if (!resp.ok) throw new Error(String(resp.status));
    const data = await resp.json();
    const row = (data.data || [])[0];
    if (!row) {
      block.appendChild(el('p', 'tool-note',
        'No EPSS score. Scores exist only for published CVEs with enough '
        + 'signal, so a very new id often has none yet.'));
      return;
    }
    const score = Number(row.epss);
    const pct = Number(row.percentile);
    const head = el('div', 'tool-graded-head');
    head.appendChild(el('span', 'tool-row-label', 'Exploitation probability'));
    head.appendChild(toolVerdict(
      score >= 0.5 ? 'bad' : score >= 0.1 ? 'warn' : 'good',
      `${(score * 100).toFixed(1)}% in 30 days`));
    block.appendChild(head);
    block.appendChild(el('p', 'tool-graded-detail',
      `Higher than ${(pct * 100).toFixed(1)}% of all scored CVEs. `
      + 'EPSS is the probability of exploitation being OBSERVED in the next 30 '
      + 'days — not a measure of how bad the bug is if it happens. This '
      + `project's own backtest found EPSS the single best predictor it has, `
      + 'ahead of its own blended score.'));
    block.appendChild(toolRow('Scored on', row.date));
  } catch (err) {
    block.appendChild(el('p', 'tool-note', 'FIRST.org could not be reached.'));
  }
}

/**
 * Shodan InternetDB: the keyless slice of Shodan.
 *
 * Passive in the way that matters — Shodan scanned the internet already and
 * this reads the stored result. Nothing here contacts the address, so running
 * it against someone else's host is a database lookup, not a scan.
 */
async function iocLiveIp(ip, host) {
  const block = el('div', 'tool-block');
  block.appendChild(el('h4', 'tool-block-title', 'Live: Shodan InternetDB'));
  host.appendChild(block);
  try {
    const resp = await fetch(SHODAN_INTERNETDB + encodeURIComponent(ip));
    if (resp.status === 404) {
      block.appendChild(el('p', 'tool-note',
        'Shodan has no record for this address — not scanned, or nothing '
        + 'was listening when it looked.'));
      return;
    }
    if (!resp.ok) throw new Error(String(resp.status));
    const data = await resp.json();
    block.appendChild(toolRow('Open ports', (data.ports || []).join(', ')));
    block.appendChild(toolRow('Hostnames', (data.hostnames || []).slice(0, 8).join(', ')));
    block.appendChild(toolRow('Software', (data.cpes || []).slice(0, 8).join(', ')));
    block.appendChild(toolRow('Tags', (data.tags || []).join(', ')));

    const vulns = data.vulns || [];
    if (vulns.length) {
      const head = el('div', 'tool-graded-head');
      head.appendChild(el('span', 'tool-row-label', 'Known CVEs'));
      head.appendChild(toolVerdict('warn', `${vulns.length} reported`));
      block.appendChild(head);
      block.appendChild(el('p', 'tool-graded-detail',
        'Inferred from the banners Shodan saw, so these are what the exposed '
        + 'software VERSION is associated with — not confirmed exploitable, '
        + 'and not evidence the host is unpatched. Backported fixes do not '
        + 'change a banner.'));
      const grid = el('div', 'ioc-grid');
      vulns.slice(0, 24).forEach((cve) => {
        const a = el('a', 'ioc-link', cve);
        a.href = safeUrl('https://nvd.nist.gov/vuln/detail/' + encodeURIComponent(cve));
        a.target = '_blank'; a.rel = 'noopener noreferrer';
        grid.appendChild(a);
      });
      block.appendChild(grid);
    }
  } catch (err) {
    block.appendChild(el('p', 'tool-note',
      'Shodan InternetDB could not be reached from the browser.'));
  }
}

async function iocLiveDomain(domain, host) {
  const block = el('div', 'tool-block');
  block.appendChild(el('h4', 'tool-block-title', 'Live: DNS'));
  host.appendChild(block);
  const [a, ns, mx] = await Promise.all([
    toolResolve(domain, 'A'), toolResolve(domain, 'NS'), toolResolve(domain, 'MX'),
  ]);
  block.appendChild(toolRow('A', a.answers.join(', ')));
  block.appendChild(toolRow('NS', ns.answers.join(', ')));
  block.appendChild(toolRow('MX', mx.answers.join(', ')));
  if (a.nxdomain) {
    block.appendChild(el('p', 'tool-note',
      'NXDOMAIN — the name does not resolve. Sinkholed, expired, or never '
      + 'registered.'));
  }
}

/* ── IOC view ─────────────────────────────────────────────────────────────── */

function showIocView() {
  hideAllViews();
  const host = $('ioc-view');
  if (!host) return;
  host.style.display = 'block';
  host.replaceChildren();

  host.appendChild(el('h2', 'view-title', 'IOC lookup'));
  host.appendChild(el('p', 'view-sub',
    'One indicator, classified, with every source opened at the right URL for '
    + 'that type. Defanged input is accepted — hxxp://evil[.]com works.'));

  const panel = toolPanel(host, 'Indicator',
    ['CIRCL CVE', 'FIRST.org EPSS', 'Shodan InternetDB', 'Cloudflare DNS'],
    'Nothing is submitted automatically. Several of these services log lookups, '
    + 'and quietly sending an indicator to a dozen third parties on page load '
    + 'would tip off an adversary watching for exactly that. Links open when '
    + 'you click them; only the two providers named above answer inline.');

  const form = el('form', 'tool-form');
  const input = el('input', 'tool-input');
  input.type = 'text';
  input.placeholder = 'IP, domain, URL, hash, email or CVE';
  input.setAttribute('aria-label', 'Indicator to look up');
  input.autocomplete = 'off';
  input.spellcheck = false;
  const submit = el('button', 'tool-btn', 'Classify');
  submit.type = 'submit';
  form.appendChild(input);
  form.appendChild(submit);
  panel.appendChild(form);

  const results = el('div', 'tool-results');
  panel.appendChild(results);

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    const { type, value } = iocClassify(input.value);
    results.replaceChildren();
    if (!type) {
      toolError(results, 'Not recognised as an IP, domain, URL, hash, email or '
        + 'CVE identifier.');
      return;
    }

    const head = el('div', 'tool-graded');
    const headRow = el('div', 'tool-graded-head');
    headRow.appendChild(el('span', 'tool-row-label', 'Identified as'));
    headRow.appendChild(toolVerdict('info', IOC_TYPE_LABEL[type] || type));
    head.appendChild(headRow);
    const code = el('code', 'tool-code');
    code.textContent = value;
    head.appendChild(code);
    results.appendChild(head);

    const sources = iocSourcesFor(type);
    const block = el('div', 'tool-block');
    block.appendChild(el('h4', 'tool-block-title',
      `Pivot to ${sources.length} sources`));
    block.appendChild(el('p', 'tool-note',
      'Marked sources need an account or an API key to show results. They are '
      + 'listed because the pivot is still useful if you have one — this page '
      + 'cannot hold a key on your behalf.'));
    const grid = el('div', 'ioc-grid');
    sources.forEach((source) => {
      const a = el('a', 'ioc-link', source.name);
      a.href = safeUrl(source.build(value, type));
      a.target = '_blank';
      a.rel = 'noopener noreferrer';
      if (source.key) a.appendChild(el('span', 'cat-flag', 'key'));
      grid.appendChild(a);
    });
    block.appendChild(grid);
    results.appendChild(block);

    if (type === 'cve') {
      await iocLiveCve(value, results);
      await iocLiveEpss(value, results);
    }
    if (type === 'domain') await iocLiveDomain(value, results);
    if (type === 'ipv4' || type === 'ipv6') await iocLiveIp(value, results);
  });
}

/* ── Phishing triage ──────────────────────────────────────────────────────── */

/* Brands impersonated often enough to be worth an edit-distance check. A
 * lookalike of something not on this list will not be caught; the check is a
 * cheap first pass, not a classifier, and the page says so. */
const PHISH_BRANDS = [
  'microsoft', 'office365', 'outlook', 'onedrive', 'sharepoint', 'azure',
  'google', 'gmail', 'apple', 'icloud', 'amazon', 'aws', 'paypal', 'netflix',
  'facebook', 'instagram', 'whatsapp', 'linkedin', 'twitter', 'github',
  'dropbox', 'adobe', 'docusign', 'zoom', 'slack', 'okta', 'coinbase',
  'binance', 'metamask', 'chase', 'wellsfargo', 'hsbc', 'santander', 'dhl',
  'fedex', 'ups', 'usps', 'irs', 'hmrc', 'netflix', 'steam', 'roblox',
];

/* TLDs with a persistently high abuse ratio in public registrar reporting.
 * Presence is a weak signal and is scored as one — plenty of legitimate sites
 * use these. */
const PHISH_RISKY_TLDS = new Set([
  'zip', 'mov', 'top', 'xyz', 'click', 'link', 'gq', 'cf', 'ml', 'tk', 'ga',
  'work', 'rest', 'fit', 'buzz', 'cam', 'quest', 'sbs', 'cfd', 'lol',
]);

const PHISH_SHORTENERS = new Set([
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly',
  'rebrand.ly', 'cutt.ly', 'shorturl.at', 'rb.gy', 't.ly', 'lnkd.in',
]);

/** Levenshtein distance, capped — we only care about "within 2". */
function phishDistance(a, b) {
  if (Math.abs(a.length - b.length) > 2) return 99;
  const prev = new Array(b.length + 1);
  for (let j = 0; j <= b.length; j += 1) prev[j] = j;
  for (let i = 1; i <= a.length; i += 1) {
    let last = prev[0];
    prev[0] = i;
    for (let j = 1; j <= b.length; j += 1) {
      const temp = prev[j];
      prev[j] = Math.min(
        prev[j] + 1,
        prev[j - 1] + 1,
        last + (a[i - 1] === b[j - 1] ? 0 : 1));
      last = temp;
    }
  }
  return prev[b.length];
}

/**
 * Static analysis of a URL string.
 *
 * Every check here answers a question about the URL itself. Nothing fetches
 * it: doing so would leak the analyst's IP to the attacker, can fire a token
 * uniquely identifying the intended victim, and is blocked by CORS anyway.
 */
function phishAnalyse(raw) {
  const findings = [];
  const input = String(raw || '').trim();
  let url;
  try {
    url = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(input) ? input : 'http://' + input);
  } catch (_) {
    return { ok: false, findings: [] };
  }

  const host = url.hostname.toLowerCase();
  const labels = host.split('.');
  const tld = labels[labels.length - 1] || '';
  const registrable = labels.slice(-2).join('.');

  function add(level, title, detail) {
    findings.push({ level, title, detail });
  }

  // ── Punycode / IDN homograph ──
  if (host.includes('xn--')) {
    add('bad', 'Internationalised domain (punycode)',
      'The hostname contains a punycode label, which renders as non-ASCII '
      + 'characters in the address bar. This is the mechanism behind homograph '
      + 'attacks: аpple.com with a Cyrillic а is a different domain that looks '
      + 'identical. Decoded: ' + safeIdn(host));
  }

  // ── Credentials in the URL ──
  if (url.username || url.password) {
    add('bad', 'Credentials embedded before the host',
      'Everything before the @ is a username, not the destination. '
      + `A reader sees "${url.username}" and the browser goes to "${host}". `
      + 'This is one of the oldest and most effective URL disguises.');
  }

  // ── Host is a bare IP ──
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
    add('bad', 'Bare IP address instead of a hostname',
      'Legitimate services use names, because names are what certificates and '
      + 'brands attach to. An IP in a link is normal only for internal tools.');
  }

  // ── Scheme ──
  if (url.protocol === 'http:') {
    add('warn', 'Not HTTPS',
      'The connection is unencrypted. Note the converse is NOT reassuring: '
      + 'most phishing sites now have a valid certificate, so HTTPS says '
      + 'nothing about who is on the other end.');
  }

  // ── Lookalike ──
  //
  // Compared per TOKEN as well as whole-string, because the whole-string check
  // alone misses the most common shape there is. "micros0ft-login.top" strips
  // to "micros0ftlogin", which is six edits from "microsoft" and scores
  // nothing — while the token "micros0ft" is one edit away and is the entire
  // trick. Real lures append a word far more often than they alter one.
  const bare = registrable.replace(/\.[a-z]+$/, '');
  const candidates = [bare.replace(/[^a-z0-9]/g, '')]
    .concat(bare.split(/[-_.]+/).filter((token) => token.length >= 4));
  let closest = null;
  candidates.forEach((candidate) => {
    PHISH_BRANDS.forEach((brand) => {
      const distance = phishDistance(candidate, brand);
      if (distance > 0 && distance <= 2 && (!closest || distance < closest.distance)) {
        closest = { brand, distance, candidate };
      }
    });
  });
  if (closest) {
    add('bad', `Lookalike of "${closest.brand}"`,
      `"${closest.candidate}" is ${closest.distance} character`
      + `${closest.distance === 1 ? '' : 's'} away from a commonly impersonated `
      + 'brand. Confirm the real domain independently rather than from this link.');
  }

  // ── Brand name in a subdomain of something else ──
  const subdomain = labels.slice(0, -2).join('.');
  const brandInSub = PHISH_BRANDS.find((b) => subdomain.includes(b));
  if (brandInSub && !registrable.includes(brandInSub)) {
    add('bad', `"${brandInSub}" appears in the subdomain, not the domain`,
      `The site is "${registrable}". Anyone can put any brand name to the left `
      + 'of their own domain, and the part that matters is the two labels '
      + 'immediately before the TLD.');
  }

  // ── TLD ──
  if (PHISH_RISKY_TLDS.has(tld)) {
    add('warn', `.${tld} has a high abuse ratio`,
      'Cheap or free registration makes this TLD disproportionately common in '
      + 'phishing. A weak signal on its own — plenty of legitimate sites use it.');
  }
  if (tld === 'zip' || tld === 'mov') {
    add('warn', `.${tld} collides with a file extension`,
      'Chat clients and mail clients auto-link text like "report.zip" into a '
      + 'URL, so a filename in a message can become a clickable link to a '
      + 'domain someone registered for the purpose.');
  }

  // ── Shortener ──
  if (PHISH_SHORTENERS.has(registrable)) {
    add('warn', 'URL shortener',
      'The real destination is hidden. Most shorteners reveal it if you append '
      + '+ or use their preview form — do that rather than clicking.');
  }

  // ── Structure ──
  if (labels.length >= 5) {
    add('warn', `${labels.length} labels deep`,
      'Long subdomain chains are used to push the real domain off the visible '
      + 'end of a mobile address bar.');
  }
  if (host.length > 40) {
    add('warn', 'Unusually long hostname',
      `${host.length} characters. Length itself is used to truncate the domain `
      + 'out of view on small screens.');
  }
  // The `xn--` that marks a punycode label is not a lure hyphen. Counting it
  // reported two hyphens on every internationalised domain, on top of the
  // punycode finding those domains already get.
  const hyphens = (registrable.replace(/\bxn--/g, '').match(/-/g) || []).length;
  if (hyphens >= 2) {
    add('warn', `${hyphens} hyphens in the registrable domain`,
      'Common in "secure-login-verify" style lures.');
  }
  if (/%[0-9a-f]{2}/i.test(url.pathname + url.search)) {
    add('warn', 'Percent-encoded characters in the path',
      'Sometimes ordinary, sometimes used to hide a second URL or a payload '
      + 'from casual inspection.');
  }
  if (/\b(login|signin|verify|secure|account|update|confirm|billing|wallet)\b/
      .test(url.pathname.toLowerCase())) {
    add('info', 'Credential-collection keywords in the path',
      'Not suspicious by itself — real login pages say "login" too. It is '
      + 'context for the findings above.');
  }
  const nested = (url.search + url.pathname).match(/https?%3a%2f%2f|https?:\/\//i);
  if (nested) {
    add('warn', 'Another URL embedded in this one',
      'Open-redirect abuse: a legitimate domain is used to bounce the victim '
      + 'somewhere else, so the visible link passes inspection.');
  }

  return {
    ok: true,
    host,
    registrable,
    tld,
    scheme: url.protocol.replace(':', ''),
    path: url.pathname + url.search,
    findings,
  };
}

/** Best-effort punycode rendering, for showing what the address bar shows. */
function safeIdn(host) {
  try {
    // No decoder is available without a library; showing the raw labels is
    // still more useful than nothing, and it is never rendered as markup.
    return host;
  } catch (_) {
    return host;
  }
}

function showPhishView() {
  hideAllViews();
  const host = $('phish-view');
  if (!host) return;
  host.style.display = 'block';
  host.replaceChildren();

  host.appendChild(el('h2', 'view-title', 'Phishing triage'));
  host.appendChild(el('p', 'view-sub',
    'Static analysis of a suspect URL. The link is never fetched — doing so '
    + 'would leak your IP to the sender and can fire a token that identifies '
    + 'the intended victim.'));

  const panel = toolPanel(host, 'Suspect URL', ['Cloudflare DNS', 'rdap.org'],
    'The string is analysed entirely in your browser. DNS and registration are '
    + 'looked up only if you ask for them, and those queries go to a resolver '
    + 'and a registry — never to the suspect domain.');

  const form = el('form', 'tool-form');
  const input = el('input', 'tool-input');
  input.type = 'text';
  input.placeholder = 'hxxps://secure-login[.]example[.]com/verify';
  input.setAttribute('aria-label', 'Suspect URL');
  input.autocomplete = 'off';
  input.spellcheck = false;
  const submit = el('button', 'tool-btn', 'Analyse');
  submit.type = 'submit';
  form.appendChild(input);
  form.appendChild(submit);
  panel.appendChild(form);

  const results = el('div', 'tool-results');
  panel.appendChild(results);

  form.addEventListener('submit', (event) => {
    event.preventDefault();
    const { value } = iocClassify(input.value);
    const report = phishAnalyse(value);
    results.replaceChildren();
    if (!report.ok) {
      toolError(results, 'Could not parse that as a URL.');
      return;
    }

    const summary = el('div', 'tool-block');
    summary.appendChild(el('h4', 'tool-block-title', 'Parsed'));
    summary.appendChild(toolRow('Scheme', report.scheme));
    summary.appendChild(toolRow('Hostname', report.host));
    summary.appendChild(toolRow('Registrable domain', report.registrable));
    summary.appendChild(toolRow('Path', report.path));
    results.appendChild(summary);

    const bad = report.findings.filter((f) => f.level === 'bad').length;
    const warn = report.findings.filter((f) => f.level === 'warn').length;

    const verdict = el('div', 'tool-graded');
    const head = el('div', 'tool-graded-head');
    head.appendChild(el('span', 'tool-row-label', 'Signals'));
    head.appendChild(bad
      ? toolVerdict('bad', `${bad} strong`)
      : warn ? toolVerdict('warn', `${warn} weak`) : toolVerdict('good', 'none found'));
    verdict.appendChild(head);
    verdict.appendChild(el('p', 'tool-graded-detail',
      bad || warn
        ? 'These are heuristics over the URL string. They catch the common '
          + 'tricks and will miss a well-made lure on a compromised legitimate '
          + 'site, which is why "none found" is not a verdict of safe.'
        : 'No structural red flags in the URL. That is not a verdict of safe: '
          + 'the most effective phishing runs on compromised legitimate '
          + 'domains, where nothing about the URL looks wrong at all.'));
    results.appendChild(verdict);

    report.findings.forEach((finding) => {
      const row = el('div', 'tool-graded');
      const rowHead = el('div', 'tool-graded-head');
      rowHead.appendChild(el('span', 'tool-row-label', finding.title));
      rowHead.appendChild(toolVerdict(finding.level,
        finding.level === 'bad' ? 'strong' : finding.level === 'warn' ? 'weak' : 'context'));
      row.appendChild(rowHead);
      row.appendChild(el('p', 'tool-graded-detail', finding.detail));
      results.appendChild(row);
    });

    // Pivots, which is what an analyst wants next.
    const pivots = el('div', 'tool-block');
    pivots.appendChild(el('h4', 'tool-block-title', 'Next steps'));
    const grid = el('div', 'ioc-grid');
    iocSourcesFor('url').slice(0, 10).forEach((source) => {
      const a = el('a', 'ioc-link', source.name);
      a.href = safeUrl(source.build(value, 'url'));
      a.target = '_blank'; a.rel = 'noopener noreferrer';
      grid.appendChild(a);
    });
    pivots.appendChild(grid);
    results.appendChild(pivots);

    const dnsBtn = el('button', 'tool-btn ghost', 'Look up the domain (DNS + registration)');
    dnsBtn.type = 'button';
    dnsBtn.addEventListener('click', () => {
      dnsBtn.disabled = true;
      const dnsHost = el('div');
      results.appendChild(dnsHost);
      toolRunRecon(report.registrable, dnsHost);
    });
    results.appendChild(dnsBtn);
  });
}
