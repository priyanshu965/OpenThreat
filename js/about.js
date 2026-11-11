/**
 * OPENTHREAT — js/about.js
 *
 * About view: the author profile reached from the avatar in the header.
 *
 * Moved out of app.js unchanged. Loaded as a classic script after it and
 * shares its top-level scope: store, el, $, svgEl and the other helpers are
 * defined there.
 */

'use strict';

// --- About / portfolio ------------------------------------------------------
// Reached from the avatar in the header. Rendered as a view inside the SPA so
// it shares the shell, the theme and the router with everything else.
//
// The phone number on the source CV is deliberately NOT here: this deploys to a
// public GitHub Pages site, and a personal mobile number on a public page is an
// invitation to spam and SIM-swap fishing. Email and LinkedIn are already
// public, so those stay.

const PROFILE = {
  name: 'Priyanshu',
  title: 'Cybersecurity Professional',
  location: 'Hyderabad, India',
  email: 'priyanshu.kumar9650@gmail.com',
  linkedin: 'https://www.linkedin.com/in/priyanshu12/',
  github: 'https://github.com/priyanshu965',
  summary:
    'Cybersecurity professional with 3+ years across Incident Response, Threat ' +
    'Intelligence, External Attack Surface Management, Vulnerability Management ' +
    'and Access Management. I work OSINT-driven risk analysis, manage external ' +
    'exposure, and push organisational cyber risk ratings up through disciplined ' +
    'internet hygiene. Hands-on with vulnerability identification, validation, ' +
    'remediation tracking and penetration testing, using SIEM, EDR and WAF for ' +
    'detection and response, and translating technical findings into risk ' +
    'insight the business can act on.',
  stats: [
    { v: '3+', l: 'years in security' },
    { v: 'M.Tech', l: 'Cybersecurity, NFSU' },
    { v: '8', l: 'certifications' },
  ],
  experience: [
    {
      org: 'Bank of America', role: 'Info Security Analyst',
      period: 'Oct 2025 — Present', current: true,
      points: [
        'Own the external attack surface across SecurityScorecard, RiskRecon, BitSight and Xpanse, improving cyber risk ratings through proactive internet hygiene.',
        'OSINT-driven analysis with Shodan, VirusTotal and similar to find perimeter risk: shadow IT, phishing domains, leaked data, credential exposure.',
        'Validate and triage vendor-reported findings, kill false positives, and escalate P1/P2 for timely remediation.',
        'Map external assets to applications and owners, working with Infrastructure, Application, Cloud, SOC and Vendor Risk to cut exposure.',
      ],
    },
    {
      org: 'Bank of America', role: 'Senior Tech Associate',
      period: 'Aug 2024 — Oct 2025',
      points: [
        'Vulnerability identification and validation across servers, applications and cloud using Qualys VMDR, Qualys TotalCloud and Tanium.',
        'Manual validation with Nmap, PowerShell and version verification to eliminate false positives.',
        'Partnered with application, infrastructure and cloud teams to track and validate remediation against risk priority and SLA.',
        'Automated vulnerability reporting; built weekly dashboards for scan coverage, remediation status, SLA adherence and risk trend.',
      ],
    },
    {
      org: 'Bank of America', role: 'Apprentice',
      period: 'Aug 2023 — Aug 2024',
      points: [
        'Global Access Operations Mainframe team: enterprise-wide mainframe access control.',
        'User access provisioning and deprovisioning on mainframe systems.',
        'Led training sessions on cyber attacks for the whole information security team, from attack vectors through to mitigation.',
      ],
    },
    {
      org: 'RAXA Techno Security Solutions, GMR Group', role: 'Cybersecurity Trainee',
      period: 'Dec 2022 — Aug 2023',
      points: [
        'Configured and managed WAF to harden web applications.',
        'Ran VAPT across diverse applications and systems, exploiting findings with a mix of automated tooling and manual technique.',
        'Real-time monitoring via CASM, SIEM and EDR; led red-team simulations to test control effectiveness.',
        'Led quarterly VM scans across servers, network and security devices with remediation plans.',
      ],
    },
  ],
  skills: [
    { group: 'Threat Intelligence', items: ['OSINT', 'SecurityScorecard', 'BitSight', 'Xpanse', 'RiskRecon'] },
    { group: 'Vulnerability Management', items: ['Nessus Professional', 'Qualys VMDR', 'Tanium', 'CASM (CloudSek)'] },
    { group: 'Security Operations', items: ['SIEM (Seceon)', 'EDR (CrowdStrike)', 'Incident Response', 'Threat Hunting'] },
    { group: 'Access & Identity', items: ['SailPoint IIQ', 'IBM z/OS Mainframe'] },
    { group: 'Tooling', items: ['Burp Suite', 'Prophaze WAF', 'FTK', 'FourCore', 'Nmap'] },
    { group: 'Programming & Analysis', items: ['Python', 'Malware Analysis', 'Digital Forensics'] },
  ],
  projects: [
    {
      name: 'OpenThreat', tag: 'this dashboard',
      desc: 'Self-updating threat-intelligence pipeline: 45 sources, SSVC-based prioritisation, ' +
            'an attacker-infrastructure map over ~160k geolocated hosts, sector segregation and ' +
            'geopolitical attribution. Python + vanilla JS, zero infrastructure, runs hourly on ' +
            'GitHub Actions.',
      link: 'https://github.com/priyanshu965/OpenThreat',
    },
    {
      name: 'ICS Vulnerability Assessment Tool',
      desc: 'Passive ICS assessment tool that parses PLC configuration files (L5X, CXT) to extract ' +
            'asset and configuration data and identify weaknesses without touching live operations.',
    },
    {
      name: 'Static Malware Analysis',
      desc: 'Python tool analysing multiple samples concurrently, automating the repetitive triage ' +
            'steps so analysts reach an assessment faster and more consistently.',
    },
  ],
  certs: [
    'Certificate of Cloud Security Knowledge v5 — CSA',
    'Certificate of Competence in Zero Trust — CSA',
    'Certified AppSec Practitioner — The SecOps Group',
    'Certified Network Security Practitioner — The SecOps Group',
    'Practical Malware Analysis & Triage — TCM Security',
    'Proofpoint Certified Email Authentication Specialist',
    'IBM z/OS Mainframe Practitioner — Coursera',
    'Fortinet NSE 1, NSE 2, NSE 3',
  ],
  education: [
    { deg: 'M.Tech, Cybersecurity', school: 'National Forensic Sciences University', period: '2021 — 2023', place: 'Gandhinagar' },
    { deg: 'B.Tech, Information Technology', school: 'PDM College of Engineering', period: '2016 — 2020', place: 'Bahadurgarh' },
  ],
  interests: ['Motorbiking', 'Trekking', 'Cricket', 'Competitive gaming'],
};

// A flat-illustration avatar, drawn rather than fetched: the CSP blocks remote
// images and a photo would be a bigger privacy call than a monogram figure.
function avatarSvg(size) {
  const s = svgEl('svg', {
    viewBox: '0 0 64 64', width: size, height: size,
    class: 'pf-avatar-svg', 'aria-hidden': 'true', focusable: 'false',
  });
  const defs = svgEl('defs', {});
  const grad = svgEl('linearGradient', { id: 'pf-g', x1: '0', y1: '0', x2: '0', y2: '1' });
  const st1 = svgEl('stop', { offset: '0', 'stop-color': '#1e4d73' });
  const st2 = svgEl('stop', { offset: '1', 'stop-color': '#0d2038' });
  grad.appendChild(st1); grad.appendChild(st2);
  defs.appendChild(grad);
  s.appendChild(defs);
  s.appendChild(svgEl('circle', { cx: 32, cy: 32, r: 31, fill: 'url(#pf-g)', stroke: '#00ffe1', 'stroke-opacity': '0.45', 'stroke-width': '1.5' }));
  // shoulders
  s.appendChild(svgEl('path', { d: 'M12 60c0-11 9-17 20-17s20 6 20 17z', fill: '#c9d8e8', 'fill-opacity': '0.92' }));
  // collar
  s.appendChild(svgEl('path', { d: 'M26 44l6 7 6-7-6-3z', fill: '#00ffe1', 'fill-opacity': '0.8' }));
  // head
  s.appendChild(svgEl('circle', { cx: 32, cy: 28, r: 12.5, fill: '#e8d4bd' }));
  // hair
  s.appendChild(svgEl('path', { d: 'M19.5 27c0-8 6-13 12.5-13S44.5 19 44.5 27c0-3-3-5-6-5.5-2.5-.5-4 .8-6.5.8s-4-1.3-6.5-.8c-3 .5-6 2.5-6 5.5z', fill: '#22303c' }));
  // glasses
  s.appendChild(svgEl('circle', { cx: 27, cy: 28.5, r: 3.6, fill: 'none', stroke: '#22303c', 'stroke-width': '1.2' }));
  s.appendChild(svgEl('circle', { cx: 37, cy: 28.5, r: 3.6, fill: 'none', stroke: '#22303c', 'stroke-width': '1.2' }));
  s.appendChild(svgEl('line', { x1: 30.6, y1: 28.5, x2: 33.4, y2: 28.5, stroke: '#22303c', 'stroke-width': '1.2' }));
  // smile
  s.appendChild(svgEl('path', { d: 'M28 34.5c1.6 1.8 6.4 1.8 8 0', fill: 'none', stroke: '#22303c', 'stroke-width': '1.3', 'stroke-linecap': 'round' }));
  return s;
}

function pfSection(title) {
  const sec = el('section', 'pf-section');
  sec.appendChild(el('h3', 'pf-h3', title));
  return sec;
}

function showAboutView() {
  hideAllViews();
  const host = $('about-view');
  if (!host) return;
  host.style.display = 'block';
  host.replaceChildren();

  // ---- hero ---------------------------------------------------------------
  const hero = el('div', 'pf-hero');
  const av = el('div', 'pf-hero-avatar');
  av.appendChild(avatarSvg(96));
  hero.appendChild(av);

  const idBlock = el('div', 'pf-id');
  idBlock.appendChild(el('h2', 'pf-name', PROFILE.name));
  idBlock.appendChild(el('p', 'pf-role', PROFILE.title));
  const meta = el('p', 'pf-meta', PROFILE.location);
  idBlock.appendChild(meta);

  const links = el('div', 'pf-links');
  const mail = el('a', 'pf-link', 'Email');
  mail.href = 'mailto:' + PROFILE.email;
  links.appendChild(mail);
  const li = el('a', 'pf-link', 'LinkedIn');
  li.href = PROFILE.linkedin; li.target = '_blank'; li.rel = 'noopener noreferrer';
  links.appendChild(li);
  const gh = el('a', 'pf-link', 'GitHub');
  gh.href = PROFILE.github; gh.target = '_blank'; gh.rel = 'noopener noreferrer';
  links.appendChild(gh);
  idBlock.appendChild(links);
  hero.appendChild(idBlock);

  const stats = el('div', 'pf-stats');
  PROFILE.stats.forEach((s) => {
    const box = el('div', 'pf-stat');
    box.appendChild(el('span', 'pf-stat-v', s.v));
    box.appendChild(el('span', 'pf-stat-l', s.l));
    stats.appendChild(box);
  });
  hero.appendChild(stats);
  host.appendChild(hero);

  host.appendChild(el('p', 'pf-summary', PROFILE.summary));

  const cols = el('div', 'pf-cols');

  // ---- experience ---------------------------------------------------------
  const expSec = pfSection('Experience');
  const timeline = el('div', 'pf-timeline');
  PROFILE.experience.forEach((job) => {
    const entry = el('div', 'pf-job' + (job.current ? ' is-current' : ''));
    const head = el('div', 'pf-job-head');
    head.appendChild(el('span', 'pf-job-role', job.role));
    head.appendChild(el('span', 'pf-job-period', job.period));
    entry.appendChild(head);
    entry.appendChild(el('div', 'pf-job-org', job.org));
    const ul = el('ul', 'pf-job-points');
    job.points.forEach((p) => ul.appendChild(el('li', '', p)));
    entry.appendChild(ul);
    timeline.appendChild(entry);
  });
  expSec.appendChild(timeline);
  cols.appendChild(expSec);

  // ---- right column -------------------------------------------------------
  const right = el('div', 'pf-right');

  const skillSec = pfSection('Skills');
  PROFILE.skills.forEach((g) => {
    const grp = el('div', 'pf-skill-group');
    grp.appendChild(el('div', 'pf-skill-label', g.group));
    const chips = el('div', 'pf-chips');
    g.items.forEach((it) => chips.appendChild(el('span', 'pf-chip', it)));
    grp.appendChild(chips);
    skillSec.appendChild(grp);
  });
  right.appendChild(skillSec);

  const certSec = pfSection('Certifications');
  const certList = el('ul', 'pf-certs');
  PROFILE.certs.forEach((c) => certList.appendChild(el('li', '', c)));
  certSec.appendChild(certList);
  right.appendChild(certSec);

  const eduSec = pfSection('Education');
  PROFILE.education.forEach((e) => {
    const row = el('div', 'pf-edu');
    row.appendChild(el('div', 'pf-edu-deg', e.deg));
    row.appendChild(el('div', 'pf-edu-school', e.school + ' · ' + e.place));
    row.appendChild(el('div', 'pf-edu-period', e.period));
    eduSec.appendChild(row);
  });
  right.appendChild(eduSec);

  cols.appendChild(right);
  host.appendChild(cols);

  // ---- projects -----------------------------------------------------------
  const projSec = pfSection('Projects');
  const projGrid = el('div', 'pf-projects');
  PROFILE.projects.forEach((p) => {
    const card = el('div', 'pf-project');
    const h = el('div', 'pf-project-head');
    h.appendChild(el('span', 'pf-project-name', p.name));
    if (p.tag) h.appendChild(el('span', 'pf-project-tag', p.tag));
    card.appendChild(h);
    card.appendChild(el('p', 'pf-project-desc', p.desc));
    if (p.link) {
      const a = el('a', 'pf-link pf-project-link', 'View repository');
      a.href = p.link; a.target = '_blank'; a.rel = 'noopener noreferrer';
      card.appendChild(a);
    }
    projGrid.appendChild(card);
  });
  projSec.appendChild(projGrid);
  host.appendChild(projSec);

  const intSec = pfSection('Outside work');
  const intChips = el('div', 'pf-chips');
  PROFILE.interests.forEach((i) => intChips.appendChild(el('span', 'pf-chip', i)));
  intSec.appendChild(intChips);
  host.appendChild(intSec);

  const back = el('button', 'pf-back', '← Back to the feed');
  back.type = 'button';
  back.addEventListener('click', () => { store.filter = 'all'; setView('feed'); });
  host.appendChild(back);
}
