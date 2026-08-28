/*
 * OPENTHREAT — js/community.js
 * ============================
 * The Contact page, and the honest answer to "can we have a forum?".
 *
 * WHY THERE IS NO FORUM HERE
 * --------------------------
 * A forum needs authentication, storage, moderation and a spam position. This
 * site has no server and no database, and adding one would discard the single
 * property that makes the rest of the project defensible: there is nowhere for
 * a visitor's data to be stored, because there is no back end at all.
 *
 * GitHub Discussions gives real accounts, real moderation, real spam handling
 * and a real abuse process, for free, run by someone else. It is linked rather
 * than embedded on purpose: the CSP is a single page-level meta tag covering
 * the whole single-page app, so embedding a third-party comment widget would
 * widen script-src and frame-src for EVERY view, not just this one. A link
 * costs nothing and weakens nothing.
 *
 * WHY THE CONTACT FORM IS A mailto:
 * ---------------------------------
 * Same reason. A form needs somewhere to POST. The alternatives are a
 * third-party form service — which means visitor messages land in someone
 * else's database under someone else's privacy policy — or a server. A
 * mailto: link is honest about where the message goes.
 */

const CONTACT_EMAIL = 'priyanshu@openthreat.in';
const REPO_URL = 'https://github.com/priyanshu965/OpenThreat';
const DISCUSSIONS_URL = REPO_URL + '/discussions';

/* Subject presets. The point is not decoration: a report that arrives with
 * "Vulnerability report" in the subject gets read differently from one titled
 * "hi". */
const CONTACT_REASONS = [
  {
    id: 'vuln',
    label: 'Report a vulnerability',
    subject: 'Vulnerability report',
    blurb: 'Something wrong with this site, its API or its pipeline. Read the '
         + 'disclosure policy first — it says what is in scope and what safe '
         + 'harbour you have.',
    body: 'What I did:\n\nWhat I expected:\n\nWhat happened instead:\n\n'
        + 'Affected URL or endpoint:\n\nDisclosure deadline (if any):\n',
  },
  {
    id: 'data',
    label: 'Something published that should not be',
    subject: 'Takedown / data concern',
    blurb: 'This site republishes third-party claims, including ransomware '
         + 'leak-site postings that name organisations. If something here is '
         + 'about you and should not be, say so and it gets looked at.',
    body: 'The page or endpoint:\n\nWhat is published:\n\nWhy it should not '
        + 'be:\n\nYour relationship to it:\n',
  },
  {
    id: 'data-quality',
    label: 'Correct something',
    subject: 'Data correction',
    blurb: 'An attribution, an alias, a mapping or a score that is wrong. '
         + 'Upstream errors get passed through here too — those are worth '
         + 'reporting even though the fix belongs upstream.',
    body: 'Where:\n\nWhat it says:\n\nWhat it should say:\n\nSource:\n',
  },
  {
    id: 'general',
    label: 'Anything else',
    subject: 'OpenThreat',
    blurb: 'Questions, corrections, feature ideas, or a note that something is '
         + 'broken.',
    body: '',
  },
];

function commMailto(reason) {
  // safeMailto() lives in app.js next to safeUrl(), validates the address and
  // does the percent-encoding. safeUrl() itself allows http(s) only, on
  // purpose — see the comment there.
  return safeMailto(CONTACT_EMAIL, reason.subject, reason.body);
}

function commExtLink(href, text, cls) {
  const a = el('a', cls || 'comm-link', text);
  a.href = safeUrl(href);
  a.target = '_blank';
  a.rel = 'noopener noreferrer';
  return a;
}

function showContactView() {
  hideAllViews();
  const host = $('contact-view');
  if (!host) return;
  host.style.display = 'block';
  host.replaceChildren();

  host.appendChild(el('h2', 'view-title', 'Contact'));
  host.appendChild(el('p', 'view-sub',
    'One address, read by one person. There is no form, because a form needs a '
    + 'server and this site does not have one — so a message would have to go '
    + 'through a third party instead. A mailto is honest about where it lands.'));

  // ── Reasons ───────────────────────────────────────────────────────────────
  const grid = el('div', 'comm-grid');
  CONTACT_REASONS.forEach((reason) => {
    const card = el('div', 'comm-card');
    card.appendChild(el('h4', 'comm-card-title', reason.label));
    card.appendChild(el('p', 'comm-card-text', reason.blurb));
    const a = el('a', 'comm-btn', 'Compose');
    a.href = commMailto(reason);
    card.appendChild(a);
    grid.appendChild(card);
  });
  host.appendChild(grid);

  // ── The address, plainly ──────────────────────────────────────────────────
  const direct = el('div', 'comm-direct');
  direct.appendChild(el('span', 'comm-direct-label', 'Direct'));
  const plain = el('a', 'comm-direct-addr', CONTACT_EMAIL);
  plain.href = safeMailto(CONTACT_EMAIL);
  direct.appendChild(plain);
  host.appendChild(direct);

  // ── Security reporting ────────────────────────────────────────────────────
  const sec = el('section', 'comm-section');
  sec.appendChild(el('h3', 'comm-section-title', 'Reporting a vulnerability'));
  sec.appendChild(el('p', 'comm-card-text',
    'This project publishes vulnerability information about other people, so it '
    + 'publishes a way to report one here. Scope, safe harbour and what matters '
    + 'most are in the policy. There is no bounty and the policy says so.'));
  const secLinks = el('div', 'comm-linkrow');
  secLinks.appendChild(commExtLink(REPO_URL + '/blob/main/SECURITY.md',
    'Disclosure policy', 'comm-btn'));
  // Same-origin and a literal, so it needs no scheme check — safeUrl() would
  // reject a relative path anyway, by design.
  const stxt = el('a', 'comm-btn ghost', 'security.txt');
  stxt.href = '.well-known/security.txt';
  stxt.target = '_blank';
  stxt.rel = 'noopener noreferrer';
  secLinks.appendChild(stxt);
  secLinks.appendChild(commExtLink(REPO_URL + '/security/advisories/new',
    'Private advisory on GitHub', 'comm-btn ghost'));
  sec.appendChild(secLinks);
  host.appendChild(sec);

  // ── Discussions, and why it is not a forum here ──────────────────────────
  const disc = el('section', 'comm-section');
  disc.appendChild(el('h3', 'comm-section-title', 'Discussion'));
  disc.appendChild(el('p', 'comm-card-text',
    'Questions, ideas and show-and-tell live in GitHub Discussions. It is not '
    + 'embedded in this page on purpose: a forum needs accounts, storage and '
    + 'moderation, and this site has no back end to put them in. Discussions '
    + 'provides all three, and it means no message you write is stored by this '
    + 'site — because this site cannot store anything.'));
  const discLinks = el('div', 'comm-linkrow');
  discLinks.appendChild(commExtLink(DISCUSSIONS_URL, 'Open Discussions', 'comm-btn'));
  discLinks.appendChild(commExtLink(REPO_URL + '/issues', 'File an issue', 'comm-btn ghost'));
  disc.appendChild(discLinks);
  host.appendChild(disc);

  // ── Privacy, stated rather than promised ─────────────────────────────────
  const priv = el('section', 'comm-section');
  priv.appendChild(el('h3', 'comm-section-title', 'What this site knows about you'));
  const list = el('ul', 'comm-list');
  [
    'No account, no login, no cookie set by this site.',
    'No analytics, no tracking pixel, no third-party script.',
    'Your saved filters, notes and starred items live in your own browser’s '
      + 'localStorage and are never transmitted — there is no endpoint that '
      + 'would accept them.',
    'Tools under TOOLS query third-party APIs directly from your browser. Those '
      + 'providers see your IP and what you looked up. Each tool names its '
      + 'providers before you run it.',
    'GitHub Pages serves the files and keeps its own web logs. That is outside '
      + 'this project’s control and is the one place a request is recorded.',
  ].forEach((line) => list.appendChild(el('li', '', line)));
  priv.appendChild(list);
  host.appendChild(priv);
}
