/*
 * OPENTHREAT — js/tools.js
 * ========================
 * TOOLS: check one thing, right now.
 *
 * WHY THIS IS A SIXTH MODE
 * ------------------------
 * The other five answer questions about the world from data this project
 * published. These answer a question about an artifact YOU have, using APIs
 * called live from your own browser. That is a different kind of thing, and
 * filing it under HUNT would repeat exactly the conflation the mode split was
 * built to remove.
 *
 * WHY THE BROWSER AND NOT THE PIPELINE
 * ------------------------------------
 * The input is yours and arrives after the pipeline has finished. There is no
 * server here to forward it to, and there never will be. So every provider
 * used on this page had to satisfy two conditions, both verified before a line
 * of this was written:
 *
 *   1. Keyless. A key in a static page is a key every visitor can read.
 *   2. CORS `*`. Without it the browser refuses the response.
 *
 * That is what decided the feature set. DNS, RDAP and the k-anonymity password
 * range API pass. Live TLS cipher inspection does not — JavaScript cannot see
 * a handshake — and neither does technology fingerprinting, which needs to
 * fetch the target's HTML and is blocked by that target's own CORS policy.
 * Those are absent rather than faked.
 *
 * THE PRIVACY POSITION
 * --------------------
 * These requests leave YOUR browser and carry YOUR IP to Cloudflare, Google,
 * a domain registry, or Have I Been Pwned. Nothing reaches OpenThreat — there
 * is no endpoint here that could receive it. That is better than a proxy for
 * your privacy from this site and worse for your privacy from them, so every
 * panel names its providers before you run it. It is passive throughout: the
 * target is never contacted.
 */

/* ── Providers, and the one place they are named ──────────────────────────── */

const DOH_CLOUDFLARE = 'https://cloudflare-dns.com/dns-query';
const DOH_GOOGLE = 'https://dns.google/resolve';
const PWNED_RANGE = 'https://api.pwnedpasswords.com/range/';
const HIBP_BREACHES = 'https://haveibeenpwned.com/api/v3/breaches';

/*
 * RDAP is per-TLD: rdap.org answers with a 302 to the authoritative registry
 * server, and a CSP connect-src applies to EVERY hop of a redirect, not just
 * the first. So each registry that visitors will actually hit has to be named
 * in the CSP, and a TLD outside that list cannot be queried from the page at
 * all. Rather than fail opaquely, an unlisted TLD gets a link to the URL that
 * would have answered.
 *
 * All of these were verified to return Access-Control-Allow-Origin: *.
 */
const RDAP_BOOTSTRAP = 'https://rdap.org/domain/';
const RDAP_KNOWN_TLDS = new Set([
  'com', 'net', 'org', 'in', 'uk', 'co.uk', 'io', 'dev', 'app', 'google',
]);

/* ── Small helpers ────────────────────────────────────────────────────────── */

function toolPanel(host, title, providers, note) {
  const sec = el('section', 'tool-panel');
  sec.appendChild(el('h3', 'tool-panel-title', title));
  if (note) sec.appendChild(el('p', 'tool-note', note));
  if (providers && providers.length) {
    const line = el('p', 'tool-providers');
    line.appendChild(el('span', 'tool-providers-label', 'Queried directly by your browser:'));
    line.appendChild(el('span', '', ' ' + providers.join(' · ')));
    sec.appendChild(line);
  }
  host.appendChild(sec);
  return sec;
}

function toolRow(label, value, cls) {
  const row = el('div', 'tool-row' + (cls ? ' ' + cls : ''));
  row.appendChild(el('span', 'tool-row-label', label));
  const v = el('span', 'tool-row-value');
  // textContent throughout: every value here came from a third party.
  v.textContent = value === '' || value === undefined || value === null ? '—' : String(value);
  row.appendChild(v);
  return row;
}

function toolVerdict(level, text) {
  // level: good | warn | bad | info
  const pill = el('span', 'tool-verdict is-' + level, text);
  return pill;
}

function toolBusy(host, message) {
  host.replaceChildren(el('div', 'tool-busy', message || 'Working…'));
}

function toolError(host, message) {
  host.replaceChildren(el('div', 'tool-error', message));
}

/** A hostname, or '' if it is not one. Accepts a pasted URL or email. */
function toolHostname(raw) {
  let value = String(raw || '').trim().toLowerCase();
  if (!value) return '';
  if (value.includes('@')) value = value.split('@').pop();
  value = value.replace(/^[a-z][a-z0-9+.-]*:\/\//, '').split('/')[0].split('?')[0];
  value = value.replace(/^\.+|\.+$/g, '').replace(/:\d+$/, '');
  // Deliberately strict. This string is about to be placed in a query
  // parameter on four different third-party APIs.
  if (!/^(?=.{1,253}$)([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(value)) {
    return '';
  }
  return value;
}

function toolRegistrableTld(hostname) {
  const parts = String(hostname).split('.');
  const last2 = parts.slice(-2).join('.');
  if (RDAP_KNOWN_TLDS.has(last2)) return last2;
  return parts[parts.length - 1] || '';
}

/* ── DNS over HTTPS ───────────────────────────────────────────────────────── */

/**
 * One DoH lookup. Cloudflare first, Google as failover.
 *
 * Both speak the same JSON shape (RFC 8484's companion `application/dns-json`)
 * so the failover is a URL swap rather than a second parser. Answers are
 * returned as plain strings; nothing here is rendered as markup.
 */
async function toolResolve(name, type) {
  const attempts = [
    { url: `${DOH_CLOUDFLARE}?name=${encodeURIComponent(name)}&type=${type}`,
      headers: { Accept: 'application/dns-json' } },
    { url: `${DOH_GOOGLE}?name=${encodeURIComponent(name)}&type=${type}`, headers: {} },
  ];
  for (const attempt of attempts) {
    try {
      const resp = await fetch(attempt.url, { headers: attempt.headers });
      if (!resp.ok) continue;
      const data = await resp.json();
      const answers = (data.Answer || [])
        .filter((a) => a && typeof a.data === 'string')
        .map((a) => a.data.replace(/^"|"$/g, ''));
      // NXDOMAIN is 3 and is a real answer, not a failure.
      return { ok: true, answers, nxdomain: data.Status === 3 };
    } catch (_) { /* try the next resolver */ }
  }
  return { ok: false, answers: [], nxdomain: false };
}

/* ── Email authentication posture ─────────────────────────────────────────── */

/**
 * SPF, DMARC and MTA-STS read together.
 *
 * These are graded rather than merely listed, because a record that exists and
 * a record that does anything are different things, and the difference is the
 * whole finding: `v=spf1 ... ?all` and `p=none` are the two most common ways
 * to have "email security configured" and be exactly as spoofable as having
 * none at all.
 */
function toolGradeSpf(records) {
  const spf = records.find((r) => /^v=spf1\b/i.test(r));
  if (!spf) {
    return { level: 'bad', label: 'missing',
             detail: 'No SPF record. Anyone can send as this domain.' };
  }
  if (/[~-]all\s*$/i.test(spf.trim()) === false && /\?all/i.test(spf)) {
    return { level: 'warn', label: 'neutral (?all)',
             detail: 'Ends in ?all, which tells receivers to accept anything. '
                   + 'Equivalent to no SPF in practice.', value: spf };
  }
  if (/-all\s*$/i.test(spf.trim())) {
    return { level: 'good', label: 'strict (-all)',
             detail: 'Hard fail for unlisted senders.', value: spf };
  }
  if (/~all\s*$/i.test(spf.trim())) {
    return { level: 'warn', label: 'soft fail (~all)',
             detail: 'Unlisted senders are marked, not rejected. Common as a '
                   + 'deployment step; weak as a destination.', value: spf };
  }
  return { level: 'warn', label: 'no all mechanism',
           detail: 'No terminating mechanism, so the policy is undefined.', value: spf };
}

function toolGradeDmarc(records) {
  const dmarc = records.find((r) => /^v=DMARC1\b/i.test(r));
  if (!dmarc) {
    return { level: 'bad', label: 'missing',
             detail: 'No DMARC record, so SPF and DKIM failures carry no '
                   + 'instruction and reporting is off.' };
  }
  const policy = (dmarc.match(/\bp\s*=\s*(none|quarantine|reject)/i) || [])[1];
  const rua = /\brua\s*=/.test(dmarc);
  const pct = (dmarc.match(/\bpct\s*=\s*(\d+)/i) || [])[1];
  const partial = pct && Number(pct) < 100 ? ` Applied to only ${pct}% of mail.` : '';
  if (/^reject$/i.test(policy || '')) {
    return { level: 'good', label: 'p=reject',
             detail: 'Failing mail is rejected.' + partial
                   + (rua ? '' : ' No rua= address, so you receive no reports.'),
             value: dmarc };
  }
  if (/^quarantine$/i.test(policy || '')) {
    return { level: 'warn', label: 'p=quarantine',
             detail: 'Failing mail goes to spam rather than being rejected.' + partial,
             value: dmarc };
  }
  return { level: 'bad', label: 'p=none',
           detail: 'Monitoring only. A DMARC record with p=none blocks nothing '
                 + '— it is the reporting stage, not the enforcing one.' + partial,
           value: dmarc };
}

/* ── RDAP ─────────────────────────────────────────────────────────────────── */

function toolRdapEvent(rdap, action) {
  const events = Array.isArray(rdap.events) ? rdap.events : [];
  const found = events.find((e) => e && e.eventAction === action);
  return found && found.eventDate ? String(found.eventDate).slice(0, 10) : '';
}

function toolRdapRegistrar(rdap) {
  const entities = Array.isArray(rdap.entities) ? rdap.entities : [];
  for (const entity of entities) {
    const roles = entity && Array.isArray(entity.roles) ? entity.roles : [];
    if (!roles.includes('registrar')) continue;
    // vCard: ['vcard', [['fn', {}, 'text', 'Name'], ...]]
    const card = entity.vcardArray && entity.vcardArray[1];
    if (Array.isArray(card)) {
      const fn = card.find((f) => Array.isArray(f) && f[0] === 'fn');
      if (fn && typeof fn[3] === 'string') return fn[3];
    }
    if (typeof entity.handle === 'string') return entity.handle;
  }
  return '';
}

/* ── Recon view ───────────────────────────────────────────────────────────── */

async function toolRunRecon(domain, host) {
  toolBusy(host, `Resolving ${domain}…`);

  const [a, aaaa, mx, ns, txt, dmarcTxt, caa] = await Promise.all([
    toolResolve(domain, 'A'),
    toolResolve(domain, 'AAAA'),
    toolResolve(domain, 'MX'),
    toolResolve(domain, 'NS'),
    toolResolve(domain, 'TXT'),
    toolResolve('_dmarc.' + domain, 'TXT'),
    toolResolve(domain, 'CAA'),
  ]);

  host.replaceChildren();

  if (!a.ok && !ns.ok) {
    toolError(host, 'Both resolvers refused or failed. Check the domain, or '
      + 'your network may be blocking DNS over HTTPS.');
    return;
  }
  if (a.nxdomain && !ns.answers.length) {
    host.appendChild(el('div', 'tool-error',
      `${domain} does not resolve (NXDOMAIN). The name may be unregistered, `
      + 'or delegation has not completed.'));
  }

  // ── Addresses and delegation ──
  const dns = el('div', 'tool-block');
  dns.appendChild(el('h4', 'tool-block-title', 'DNS'));
  dns.appendChild(toolRow('A', a.answers.join(', ')));
  dns.appendChild(toolRow('AAAA', aaaa.answers.join(', ')));
  dns.appendChild(toolRow('NS', ns.answers.join(', ')));
  dns.appendChild(toolRow('MX', mx.answers.join(', ')));
  dns.appendChild(toolRow('CAA', caa.answers.join(', ')
    || 'none — any CA may issue for this domain'));
  host.appendChild(dns);

  // ── Email authentication, graded ──
  const spf = toolGradeSpf(txt.answers);
  const dmarc = toolGradeDmarc(dmarcTxt.answers);
  const mail = el('div', 'tool-block');
  mail.appendChild(el('h4', 'tool-block-title', 'Email authentication'));

  [['SPF', spf], ['DMARC', dmarc]].forEach(([name, grade]) => {
    const row = el('div', 'tool-graded');
    const head = el('div', 'tool-graded-head');
    head.appendChild(el('span', 'tool-row-label', name));
    head.appendChild(toolVerdict(grade.level, grade.label));
    row.appendChild(head);
    row.appendChild(el('p', 'tool-graded-detail', grade.detail));
    if (grade.value) {
      const code = el('code', 'tool-code');
      code.textContent = grade.value;
      row.appendChild(code);
    }
    mail.appendChild(row);
  });

  if (!mx.answers.length) {
    mail.appendChild(el('p', 'tool-graded-detail',
      'No MX records: this domain does not receive mail. SPF and DMARC still '
      + 'matter, because a domain that receives no mail can still be forged as '
      + 'a sender.'));
  }
  host.appendChild(mail);

  // ── Other TXT, which is where the SaaS inventory hides ──
  const others = txt.answers.filter((r) => !/^v=spf1\b/i.test(r));
  if (others.length) {
    const block = el('div', 'tool-block');
    block.appendChild(el('h4', 'tool-block-title', 'Other TXT records'));
    block.appendChild(el('p', 'tool-note',
      'Verification tokens name the SaaS platforms a domain has enrolled in. '
      + 'That is an attack-surface inventory, published in DNS, for free.'));
    others.slice(0, 25).forEach((record) => {
      const code = el('code', 'tool-code');
      code.textContent = record.length > 220 ? record.slice(0, 220) + '…' : record;
      block.appendChild(code);
    });
    host.appendChild(block);
  }

  // ── Registration ──
  await toolRenderRdap(domain, host);

  // ── What this deliberately does not do ──
  const limits = el('div', 'tool-block');
  limits.appendChild(el('h4', 'tool-block-title', 'Not shown, and why'));
  const ul = el('ul', 'tool-list');
  [
    'TLS cipher suites and certificate chain — JavaScript cannot inspect a TLS '
      + 'handshake. No amount of API access changes that.',
    'Technology stack — fingerprinting needs the target’s HTML, and the '
      + 'target’s own CORS policy blocks the browser from reading it. Doing it '
      + 'server-side would make this an active scanner.',
    'Anything requiring a packet to the target. Everything above is answered by '
      + 'a resolver or a registry; the domain is never contacted.',
  ].forEach((line) => ul.appendChild(el('li', '', line)));
  limits.appendChild(ul);
  const out = el('div', 'tool-linkrow');
  const ssl = el('a', 'tool-btn ghost', 'Certificate history (crt.sh)');
  ssl.href = safeUrl('https://crt.sh/?q=' + encodeURIComponent(domain));
  ssl.target = '_blank'; ssl.rel = 'noopener noreferrer';
  out.appendChild(ssl);
  const labs = el('a', 'tool-btn ghost', 'TLS analysis (SSL Labs)');
  labs.href = safeUrl('https://www.ssllabs.com/ssltest/analyze.html?d='
    + encodeURIComponent(domain));
  labs.target = '_blank'; labs.rel = 'noopener noreferrer';
  out.appendChild(labs);
  limits.appendChild(out);
  host.appendChild(limits);
}

async function toolRenderRdap(domain, host) {
  const block = el('div', 'tool-block');
  block.appendChild(el('h4', 'tool-block-title', 'Registration (RDAP)'));
  host.appendChild(block);

  const tld = toolRegistrableTld(domain);
  const url = RDAP_BOOTSTRAP + encodeURIComponent(domain);

  if (!RDAP_KNOWN_TLDS.has(tld)) {
    // Honest about the reason rather than showing an empty panel: the CSP
    // applies to every redirect hop, and this TLD's registry is not on it.
    block.appendChild(el('p', 'tool-note',
      `RDAP for .${tld} resolves to a registry this page’s content-security `
      + 'policy does not allow it to reach. The lookup itself is public — open '
      + 'it directly:'));
    const a = el('a', 'tool-btn ghost', `rdap.org/domain/${domain}`);
    a.href = safeUrl(url);
    a.target = '_blank'; a.rel = 'noopener noreferrer';
    block.appendChild(a);
    return;
  }

  try {
    const resp = await fetch(url, { headers: { Accept: 'application/rdap+json' } });
    if (!resp.ok) {
      block.appendChild(el('p', 'tool-note',
        resp.status === 404
          ? 'The registry has no record for this domain — it is unregistered.'
          : `The registry answered HTTP ${resp.status}.`));
      return;
    }
    const rdap = await resp.json();
    block.appendChild(toolRow('Registrar', toolRdapRegistrar(rdap)));
    block.appendChild(toolRow('Registered', toolRdapEvent(rdap, 'registration')));
    block.appendChild(toolRow('Last changed', toolRdapEvent(rdap, 'last changed')));
    block.appendChild(toolRow('Expires', toolRdapEvent(rdap, 'expiration')));
    block.appendChild(toolRow('Status', (rdap.status || []).join(', ')));
    const servers = (rdap.nameservers || [])
      .map((n) => n && n.ldhName).filter(Boolean);
    block.appendChild(toolRow('Nameservers', servers.join(', ')));

    const created = toolRdapEvent(rdap, 'registration');
    if (created) {
      const ageDays = Math.floor((Date.now() - Date.parse(created)) / 86400000);
      if (ageDays >= 0 && ageDays < 30) {
        const warn = el('div', 'tool-graded');
        const head = el('div', 'tool-graded-head');
        head.appendChild(el('span', 'tool-row-label', 'Domain age'));
        head.appendChild(toolVerdict('warn', `${ageDays} days old`));
        warn.appendChild(head);
        warn.appendChild(el('p', 'tool-graded-detail',
          'Newly registered domains are disproportionately used for phishing '
          + 'and command-and-control. Age alone proves nothing, but it is the '
          + 'cheapest signal available.'));
        block.appendChild(warn);
      }
    }
  } catch (err) {
    block.appendChild(el('p', 'tool-note',
      'The registry could not be reached from the browser. This is usually the '
      + 'registry being down or refusing cross-origin requests, not a problem '
      + 'with the domain.'));
  }
}

function showReconView() {
  hideAllViews();
  const host = $('recon-view');
  if (!host) return;
  host.style.display = 'block';
  host.replaceChildren();

  host.appendChild(el('h2', 'view-title', 'Passive recon'));
  host.appendChild(el('p', 'view-sub',
    'Public records only. The domain you enter is never contacted — every '
    + 'answer here comes from a resolver or a registry.'));

  const panel = toolPanel(host, 'Domain',
    ['Cloudflare DNS', 'Google DNS', 'rdap.org'],
    'These requests go from your browser to those providers, carrying your IP. '
    + 'Nothing reaches OpenThreat: there is no endpoint here that could receive '
    + 'it.');

  const form = el('form', 'tool-form');
  const input = el('input', 'tool-input');
  input.type = 'text';
  input.placeholder = 'example.com';
  input.setAttribute('aria-label', 'Domain to look up');
  input.autocomplete = 'off';
  input.spellcheck = false;
  const submit = el('button', 'tool-btn', 'Look up');
  submit.type = 'submit';
  form.appendChild(input);
  form.appendChild(submit);
  panel.appendChild(form);

  const results = el('div', 'tool-results');
  panel.appendChild(results);

  form.addEventListener('submit', (event) => {
    event.preventDefault();
    const domain = toolHostname(input.value);
    if (!domain) {
      toolError(results, 'That does not look like a domain name.');
      return;
    }
    toolRunRecon(domain, results);
  });
}

/* ── Credentials ──────────────────────────────────────────────────────────── */

const PW_ALPHABETS = {
  upper: 'ABCDEFGHJKLMNPQRSTUVWXYZ',   // no I or O
  lower: 'abcdefghijkmnopqrstuvwxyz',  // no l
  digits: '23456789',                  // no 0 or 1
  symbols: '!@#$%^&*()-_=+[]{};:,.?/',
};

/**
 * Uniform random selection from `alphabet`.
 *
 * `getRandomValues() % alphabet.length` is the obvious version and it is
 * biased: 256 does not divide most alphabet lengths, so the first
 * (256 % length) characters come up more often. Rejection sampling removes
 * that. It matters less than it sounds for one password and it costs nothing,
 * and a password generator that quietly narrows its own keyspace is precisely
 * the kind of thing this project exists to point at.
 */
function pwPick(alphabet) {
  const limit = 256 - (256 % alphabet.length);
  const buf = new Uint8Array(1);
  for (;;) {
    crypto.getRandomValues(buf);
    if (buf[0] < limit) return alphabet[buf[0] % alphabet.length];
  }
}

function pwGenerate(length, sets) {
  const pools = sets.filter((s) => PW_ALPHABETS[s]).map((s) => PW_ALPHABETS[s]);
  if (!pools.length) return '';
  const all = pools.join('');
  // One character from each selected set first, so "include symbols" is a
  // guarantee rather than a probability.
  const chars = pools.map((pool) => pwPick(pool));
  while (chars.length < length) chars.push(pwPick(all));
  // Fisher-Yates with unbiased indices, so the guaranteed characters do not
  // always sit at the front.
  for (let i = chars.length - 1; i > 0; i -= 1) {
    const j = pwRandomBelow(i + 1);
    [chars[i], chars[j]] = [chars[j], chars[i]];
  }
  return chars.slice(0, length).join('');
}

function pwRandomBelow(n) {
  const limit = 4294967296 - (4294967296 % n);
  const buf = new Uint32Array(1);
  for (;;) {
    crypto.getRandomValues(buf);
    if (buf[0] < limit) return buf[0] % n;
  }
}

function pwEntropyBits(length, sets) {
  const size = sets.reduce((n, s) => n + (PW_ALPHABETS[s] ? PW_ALPHABETS[s].length : 0), 0);
  return size > 1 ? Math.floor(length * Math.log2(size)) : 0;
}

async function pwSha1Hex(text) {
  const bytes = new TextEncoder().encode(text);
  const digest = await crypto.subtle.digest('SHA-1', bytes);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, '0')).join('').toUpperCase();
}

/**
 * k-anonymity breach check.
 *
 * The password never leaves this machine, and that is a property of the
 * protocol rather than a promise on a page: only the first FIVE characters of
 * the SHA-1 are sent. The service returns every suffix sharing that prefix —
 * hundreds of them — and the comparison happens here. The service cannot tell
 * which one was being asked about, and it never sees the password.
 */
async function pwCheckBreached(password) {
  const hash = await pwSha1Hex(password);
  const prefix = hash.slice(0, 5);
  const suffix = hash.slice(5);
  const resp = await fetch(PWNED_RANGE + prefix, { headers: { 'Add-Padding': 'true' } });
  if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
  const body = await resp.text();
  for (const line of body.split('\n')) {
    const [candidate, count] = line.trim().split(':');
    if (candidate === suffix) return Number(count) || 0;
  }
  return 0;
}

function showCredsView() {
  hideAllViews();
  const host = $('creds-view');
  if (!host) return;
  host.style.display = 'block';
  host.replaceChildren();

  host.appendChild(el('h2', 'view-title', 'Credentials'));
  host.appendChild(el('p', 'view-sub',
    'Generate one, or find out whether one you already have is in a public '
    + 'breach corpus — without sending it anywhere.'));

  buildPasswordGenerator(host);
  buildBreachChecker(host);
  buildBreachCatalogue(host);
}

function buildPasswordGenerator(host) {
  const panel = toolPanel(host, 'Generate a password', [],
    'Entirely local. This panel makes no network request of any kind, and the '
    + 'randomness comes from the Web Crypto API rather than a general-purpose '
    + 'PRNG, with rejection sampling so the character distribution is uniform.');

  const controls = el('div', 'tool-controls');

  const lenWrap = el('label', 'tool-field');
  lenWrap.appendChild(el('span', 'tool-field-label', 'Length'));
  const len = el('input', 'tool-range');
  len.type = 'range'; len.min = '8'; len.max = '64'; len.value = '20';
  const lenOut = el('span', 'tool-field-value', '20');
  lenWrap.appendChild(len);
  lenWrap.appendChild(lenOut);
  controls.appendChild(lenWrap);

  const boxes = {};
  [['upper', 'A–Z'], ['lower', 'a–z'], ['digits', '0–9'], ['symbols', '!@#$']]
    .forEach(([key, label]) => {
      const wrap = el('label', 'tool-check');
      const box = el('input');
      box.type = 'checkbox';
      box.checked = true;
      boxes[key] = box;
      wrap.appendChild(box);
      wrap.appendChild(el('span', '', label));
      controls.appendChild(wrap);
    });
  panel.appendChild(controls);

  const out = el('div', 'tool-password');
  const value = el('code', 'tool-password-value', 'Press Generate');
  out.appendChild(value);
  panel.appendChild(out);

  const meta = el('p', 'tool-note', '');
  panel.appendChild(meta);

  const row = el('div', 'tool-linkrow');
  const gen = el('button', 'tool-btn', 'Generate');
  gen.type = 'button';
  const copy = el('button', 'tool-btn ghost', 'Copy');
  copy.type = 'button';
  row.appendChild(gen);
  row.appendChild(copy);
  panel.appendChild(row);

  function regenerate() {
    const sets = Object.keys(boxes).filter((k) => boxes[k].checked);
    if (!sets.length) {
      value.textContent = 'Select at least one character set';
      meta.textContent = '';
      return;
    }
    const length = Number(len.value);
    value.textContent = pwGenerate(length, sets);
    const bits = pwEntropyBits(length, sets);
    meta.textContent = `${length} characters · about ${bits} bits of entropy. `
      + 'Entropy assumes the generator, not the pattern: it is only this high '
      + 'because the characters were chosen at random rather than by a person.';
  }

  len.addEventListener('input', () => { lenOut.textContent = len.value; regenerate(); });
  Object.values(boxes).forEach((b) => b.addEventListener('change', regenerate));
  gen.addEventListener('click', regenerate);
  copy.addEventListener('click', () => {
    const text = value.textContent || '';
    if (!text || text.startsWith('Press') || text.startsWith('Select')) return;
    navigator.clipboard.writeText(text)
      .then(() => showToast('Password copied'))
      .catch(() => showToast('Clipboard unavailable'));
  });
}

function buildBreachChecker(host) {
  const panel = toolPanel(host, 'Is this password in a breach?',
    ['Have I Been Pwned (range API)'],
    'k-anonymity: only the first five characters of the password’s SHA-1 are '
    + 'sent. The service returns every hash sharing that prefix and the match '
    + 'is made here, so it cannot tell which one you asked about and never '
    + 'sees the password. That is how the protocol works, not a promise.');

  const form = el('form', 'tool-form');
  const input = el('input', 'tool-input');
  input.type = 'password';
  input.placeholder = 'Password to check';
  input.setAttribute('aria-label', 'Password to check against breach corpora');
  input.autocomplete = 'off';
  const submit = el('button', 'tool-btn', 'Check');
  submit.type = 'submit';
  form.appendChild(input);
  form.appendChild(submit);
  panel.appendChild(form);

  const result = el('div', 'tool-results');
  panel.appendChild(result);

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    const password = input.value;
    if (!password) return;
    toolBusy(result, 'Checking prefix…');
    try {
      const count = await pwCheckBreached(password);
      result.replaceChildren();
      const row = el('div', 'tool-graded');
      const head = el('div', 'tool-graded-head');
      head.appendChild(el('span', 'tool-row-label', 'Result'));
      head.appendChild(count
        ? toolVerdict('bad', `seen ${count.toLocaleString()} times`)
        : toolVerdict('good', 'not found'));
      row.appendChild(head);
      row.appendChild(el('p', 'tool-graded-detail', count
        ? 'This password appears in public breach corpora, so it is in the '
          + 'wordlists attackers use. Change it anywhere it is in use.'
        : 'Not in this corpus. That is not proof it is strong — an unbroken '
          + 'password can still be guessable — only that it has not appeared '
          + 'in a known breach.'));
      result.appendChild(row);
    } catch (err) {
      toolError(result, 'Could not reach the range API. Nothing was sent that '
        + 'could identify the password.');
    }
  });
}

function buildBreachCatalogue(host) {
  const panel = toolPanel(host, 'Breach catalogue',
    ['Have I Been Pwned (breaches)'],
    'Which breaches exist, how large, and what was taken. Searching whether a '
    + 'specific ADDRESS appears in one is deliberately absent: that endpoint '
    + 'needs a paid API key, and a key in a static page is a key every visitor '
    + 'can read and bill to this project. It is not built rather than built '
    + 'insecurely.');

  const form = el('form', 'tool-form');
  const input = el('input', 'tool-input');
  input.type = 'text';
  input.placeholder = 'Search by name or domain, e.g. linkedin';
  input.setAttribute('aria-label', 'Search the breach catalogue');
  input.autocomplete = 'off';
  const submit = el('button', 'tool-btn', 'Search');
  submit.type = 'submit';
  form.appendChild(input);
  form.appendChild(submit);
  panel.appendChild(form);

  const result = el('div', 'tool-results');
  panel.appendChild(result);

  let cache = null;

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    const query = String(input.value || '').trim().toLowerCase();
    if (!query) return;
    toolBusy(result, 'Loading catalogue…');
    try {
      if (!cache) {
        const resp = await fetch(HIBP_BREACHES);
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        cache = await resp.json();
      }
      const hits = cache.filter((b) => b
        && ((b.Name || '').toLowerCase().includes(query)
          || (b.Domain || '').toLowerCase().includes(query)
          || (b.Title || '').toLowerCase().includes(query)))
        .sort((x, y) => (y.PwnCount || 0) - (x.PwnCount || 0))
        .slice(0, 25);
      result.replaceChildren();
      if (!hits.length) {
        result.appendChild(el('p', 'tool-note', 'No breach in the catalogue matches that.'));
        return;
      }
      hits.forEach((breach) => {
        const card = el('div', 'tool-block');
        const head = el('div', 'tool-graded-head');
        head.appendChild(el('span', 'tool-row-label', breach.Title || breach.Name || '—'));
        if (breach.IsVerified === false) head.appendChild(toolVerdict('warn', 'unverified'));
        if (breach.IsSensitive) head.appendChild(toolVerdict('info', 'sensitive'));
        card.appendChild(head);
        card.appendChild(toolRow('Domain', breach.Domain));
        card.appendChild(toolRow('Breached', String(breach.BreachDate || '').slice(0, 10)));
        card.appendChild(toolRow('Accounts', (breach.PwnCount || 0).toLocaleString()));
        card.appendChild(toolRow('Data taken', (breach.DataClasses || []).join(', ')));
        result.appendChild(card);
      });
    } catch (err) {
      toolError(result, 'Could not load the breach catalogue.');
    }
  });
}
