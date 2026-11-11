/**
 * Tests for js/query.js — the structured query language and its
 * natural-language front end.
 *
 * Run: node --test tests/query.test.js
 *
 * query.js is a classic script (no build step, no modules anywhere in this
 * project), so it is loaded into a vm context with the few globals it reads
 * from app.js stubbed. That is enough: the parser and evaluator are pure.
 *
 * Every case in here is a bug that was actually found by hand-testing the
 * query box against the live feed. The NL layer is a pile of ordered rewrite
 * rules, and the failure mode of ordered rewrite rules is that a later rule
 * eats a token an earlier one produced — silently, with no error, returning a
 * plausible-looking wrong answer.
 */

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const source = fs.readFileSync(
  path.join(__dirname, '..', 'js', 'query.js'), 'utf8');

const sandbox = {
  // app.js globals query.js reaches for. Defaults keep the evaluator honest.
  store: { starred: new Set(), reviewed: new Set() },
  matchesStack: () => false,
  matchesWatchlist: () => false,
  isNewToYou: () => false,
  console,
};
vm.createContext(sandbox);
vm.runInContext(source, sandbox, { filename: 'query.js' });

const { parseQuery, queryMatches, queryExplain, queryFields, queryExamples } = sandbox;

const DAY = 86400000;
const ago = (days) => new Date(Date.now() - days * DAY).toISOString();

const ITEMS = [
  {
    _key: 'a', title: 'Critical Fortinet VPN flaw exploited', description: 'ssl-vpn',
    cve_id: 'CVE-2026-1000', source: 'CISA', severity: 'critical',
    priority_label: 'urgent', priority_score: 95, cvss_score: 9.8, epss_score: 0.62,
    cisa_kev: true, has_poc: true, sector: 'government', published: ago(2),
    threat_actors: ['Lazarus Group'], malware: ['Emotet'],
    ttps: [{ id: 'T1190' }], detection_rule_count: 4,
  },
  {
    _key: 'b', title: 'Healthcare provider breached', description: 'ransomware',
    cve_id: null, source: 'The Record', severity: 'high',
    priority_label: null, priority_score: null, sector: 'healthcare',
    published: ago(10), threat_actors: ['Qilin'], malware: [], ttps: [],
  },
  {
    _key: 'c', title: 'Zimbra command injection', description: 'smtp',
    cve_id: 'CVE-2026-2000', source: 'NVD', severity: 'high',
    priority_label: 'moderate', priority_score: 55, cvss_score: 7.5, epss_score: 0.02,
    cisa_kev: false, has_poc: true, sector: null, published: ago(3),
    threat_actors: [], malware: [], ttps: [{ id: 'T1059' }],
  },
  {
    _key: 'd', title: 'Old advisory', description: 'nothing much',
    cve_id: 'CVE-2024-3000', source: 'Fedora', severity: 'low',
    priority_label: 'low', priority_score: 20, cvss_score: 4.0, epss_score: 0.001,
    cisa_kev: false, has_poc: false, sector: 'corporate', published: ago(200),
    threat_actors: [], malware: [], ttps: [],
  },
];

const run = (query) => {
  const parsed = parseQuery(query);
  if (!parsed) return null;
  return {
    parsed,
    keys: ITEMS.filter((i) => queryMatches(parsed, i)).map((i) => i._key),
  };
};

// ─── Plain keywords must stay plain ───────────────────────────────────────────
test('a bare keyword does not become a query', () => {
  // Falling through to substring search is what keeps the query layer purely
  // additive: it can never make an ordinary search worse.
  assert.strictEqual(parseQuery('ransomware'), null);
  assert.strictEqual(parseQuery('fortinet'), null);
  assert.strictEqual(parseQuery('lazarus'), null);
  assert.strictEqual(parseQuery('analysis of gas pipeline attacks'), null);
});

test('too short to be anything is not a query', () => {
  assert.strictEqual(parseQuery(''), null);
  assert.strictEqual(parseQuery('a'), null);
});

// ─── Structured syntax ────────────────────────────────────────────────────────
test('comparison operators filter numerically', () => {
  assert.deepStrictEqual(run('epss > 0.5').keys, ['a']);
  assert.deepStrictEqual(run('cvss >= 7.5').keys, ['a', 'c']);
  assert.deepStrictEqual(run('score < 30').keys, ['d']);
});

test('percentages are read as fractions', () => {
  assert.deepStrictEqual(run('epss > 50%').keys, run('epss > 0.5').keys);
});

test('>= and <= keep their boundary', () => {
  // REGRESSION. The NL comparison rules matched `>=?` and unconditionally
  // emitted `>`, so `cvss >= 7.5` quietly became `cvss > 7.5` and dropped the
  // item sitting exactly on 7.5. Moving a threshold without saying so is the
  // worst thing a query language can do.
  assert.deepStrictEqual(run('cvss >= 7.5').keys, ['a', 'c']);
  assert.deepStrictEqual(run('cvss > 7.5').keys, ['a']);
  assert.deepStrictEqual(run('cvss <= 4').keys, ['d']);
});

test('spelled-out comparisons map to the right operator', () => {
  assert.deepStrictEqual(run('cvss at least 7.5').keys, ['a', 'c']);
  assert.deepStrictEqual(run('cvss at most 4').keys, ['d']);
  assert.deepStrictEqual(run('cvss above 7.5').keys, ['a']);
});

test('boolean fields work bare and negated', () => {
  assert.deepStrictEqual(run('kev').keys, ['a']);
  assert.deepStrictEqual(run('poc and not kev').keys, ['c']);
});

test('AND is implied by adjacency', () => {
  assert.deepStrictEqual(run('poc kev').keys, ['a']);
});

test('OR and parentheses', () => {
  assert.deepStrictEqual(run('(kev or sector = healthcare)').keys, ['a', 'b']);
});

test('list fields match any element', () => {
  assert.deepStrictEqual(run('actor:lazarus').keys, ['a']);
  assert.deepStrictEqual(run('technique:T1059').keys, ['c']);
});

test('age is measured in days and accepts h', () => {
  assert.deepStrictEqual(run('age <= 5d').keys, ['a', 'c']);
  assert.deepStrictEqual(run('age > 100d').keys, ['d']);
});

test('a bare field means "has a value"', () => {
  assert.deepStrictEqual(run('cve and verdict').keys, ['a', 'c', 'd']);
});

// ─── Natural language ─────────────────────────────────────────────────────────
test('the headline example resolves to the intended filter', () => {
  const out = run('actively exploited things affecting VPNs this week');
  assert.match(out.parsed.rewritten, /exploited/);
  assert.match(out.parsed.rewritten, /age <= 7d/);
  assert.deepStrictEqual(out.keys, ['a']);
});

test('"no KEV listing" negates KEV and nothing else', () => {
  // REGRESSION. The filler rule for "listing" was written as
  // `(?:kev\s+)?listing`, so it matched the "kev listing" that the negation
  // rule had just produced in "NOT kev listing" — deleting the negated term
  // and leaving a dangling NOT that bound to the NEXT clause. The query came
  // out meaning "NOT this week", the exact opposite of what was typed.
  const out = run('CVEs with EPSS over 1%, no KEV listing, first seen this month');
  assert.match(out.parsed.rewritten, /NOT kev/,
    'the KEV term was eaten by a filler rule');
  assert.doesNotMatch(out.parsed.rewritten, /NOT age/,
    'the NOT attached itself to the time window');
  assert.deepStrictEqual(out.keys, ['c']);
});

test('a dangling NOT is dropped rather than binding to the next clause', () => {
  const parsed = parseQuery('epss > 0.01 and not and age <= 5d');
  assert.doesNotMatch(parsed.rewritten, /NOT\s+and/);
});

test('a value after an operator is not re-expanded', () => {
  // REGRESSION. The `urgent` rule fired on the word it had itself produced,
  // turning "band = urgent" into "band = band = urgent".
  const out = run('band = urgent and not reviewed');
  assert.strictEqual(
    (out.parsed.rewritten.match(/band =/g) || []).length, 1,
    'the band rule re-expanded its own output');
  assert.deepStrictEqual(out.keys, ['a']);
});

test('de-pluralisation never mangles a value after a colon', () => {
  // REGRESSION. `actor:lazarus` became `actor:lazaru` and matched nothing.
  const out = run('actor:lazarus or malware:emotet');
  assert.match(out.parsed.rewritten, /lazarus/);
  assert.deepStrictEqual(out.keys, ['a']);
});

test('de-pluralisation leaves non-plural -s words alone', () => {
  for (const word of ['lazarus', 'analysis', 'kerberos']) {
    const parsed = parseQuery(`title:${word} and kev`);
    assert.match(parsed.rewritten, new RegExp(word),
      `${word} lost its final letter`);
  }
});

test('CVEs resolves to the cve field, not a literal', () => {
  const out = run('CVEs from this week');
  assert.match(out.parsed.rewritten, /\bCVE\b/);
  assert.deepStrictEqual(out.keys, ['a', 'c']);
});

test('stray prepositions do not become search terms', () => {
  // REGRESSION. "from" survived into the token stream as a text term and
  // matched nothing, silently emptying the whole result set.
  const out = run('CVEs from this week');
  assert.doesNotMatch(queryExplain(out.parsed), /"from"/);
});

test('commas do not become search terms', () => {
  const out = run('kev, this week');
  assert.doesNotMatch(queryExplain(out.parsed), /","/);
  assert.deepStrictEqual(out.keys, ['a']);
});

test('sector prepositions map onto the sector field', () => {
  const out = run('breaches in healthcare');
  assert.match(out.parsed.rewritten, /sector = healthcare/);
  assert.deepStrictEqual(out.keys, ['b']);
});

test('time phrases map to age windows', () => {
  assert.match(parseQuery('kev today').rewritten, /age <= 1d/);
  assert.match(parseQuery('kev this week').rewritten, /age <= 7d/);
  assert.match(parseQuery('kev this month').rewritten, /age <= 30d/);
  assert.match(parseQuery('kev in the last 3 days').rewritten, /age <= 3d/);
});

test('negation phrasings all reach NOT', () => {
  for (const phrase of ['not in kev', 'no kev', 'without kev', 'not in the kev catalogue']) {
    assert.match(parseQuery(`poc and ${phrase}`).rewritten, /NOT kev/, phrase);
  }
});

// ─── Robustness ───────────────────────────────────────────────────────────────
test('an unknown field degrades to a text term instead of throwing', () => {
  const out = run('bananas > 3 and kev');
  assert.ok(out, 'should still parse');
  assert.doesNotThrow(() => queryMatches(out.parsed, ITEMS[0]));
});

test('unbalanced quotes and parens do not throw', () => {
  for (const q of ['kev and "unclosed', 'kev and (poc', 'kev )and poc', '>>> kev']) {
    assert.doesNotThrow(() => {
      const parsed = parseQuery(q);
      if (parsed) ITEMS.forEach((i) => queryMatches(parsed, i));
    }, q);
  }
});

test('a null parse matches everything rather than nothing', () => {
  assert.strictEqual(queryMatches(null, ITEMS[0]), true);
});

test('the documented examples all parse', () => {
  for (const example of queryExamples()) {
    assert.ok(parseQuery(example.q), `documented example does not parse: ${example.q}`);
  }
});

test('every documented field is a real field', () => {
  for (const field of queryFields()) {
    const parsed = parseQuery(`${field.name} and kev`);
    assert.ok(parsed, `documented field does not parse: ${field.name}`);
    assert.doesNotThrow(() => ITEMS.forEach((i) => queryMatches(parsed, i)));
  }
});
