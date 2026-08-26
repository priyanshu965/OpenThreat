/**
 * CYBERWATCH — js/query.js
 * ========================
 * A real query layer over the loaded corpus, plus a natural-language front end.
 *
 * The dashboard had static endpoints and a substring search, which cannot
 * express the question anyone actually has:
 *
 *     CVEs with EPSS > 0.5, no KEV listing, affecting products we track,
 *     first seen this week
 *
 * So there are two layers here:
 *
 *   1. A small structured language. `epss > 0.5 and not kev and stack and
 *      age <= 7d` parses to an AST and runs over the in-memory items. Fields,
 *      comparison operators, AND/OR/NOT, parentheses, quoted phrases.
 *
 *   2. A natural-language front end that rewrites English into that language
 *      before parsing. "actively exploited things affecting VPNs this week"
 *      becomes `exploited AND "vpn" AND age <= 7d`.
 *
 * WHY THE NL LAYER IS LOCAL, AND NOT A MODEL CALL
 *
 * The obvious implementation is one Gemini call per query — the pipeline
 * already pays for Gemini. It cannot be done here. This is a static site with
 * no backend, so calling a model API from the page means shipping the API key
 * to every visitor: it would be extracted from the bundle within a day and
 * billed to the project. The alternative, a proxy, is a server, and the whole
 * architecture of this project is that there is no server.
 *
 * A phrase-rewriting front end handles the vocabulary this domain actually
 * uses, runs in under a millisecond, works offline, costs nothing and cannot
 * leak a key. When it does not understand something it returns null and the
 * search box falls back to substring matching, so it can only ever add.
 *
 * Everything is pure: no DOM, no fetch, no globals beyond the functions
 * app.js calls.
 */

'use strict';

// ─── Fields ───────────────────────────────────────────────────────────────────
// `get` pulls the comparable value off an item; `kind` decides how a bare
// mention of the field behaves (a boolean field alone means "is true").
const QUERY_FIELDS = {
  epss:        { kind: 'number', get: (i) => i.epss_score, note: 'exploit probability, 0-1 (accepts 50%)' },
  cvss:        { kind: 'number', get: (i) => i.cvss_score, note: 'CVSS base score, 0-10' },
  score:       { kind: 'number', get: (i) => i.priority_score, note: 'blended priority, 0-100' },
  priority:    { kind: 'number', get: (i) => i.priority_score, note: 'alias for score' },
  age:         { kind: 'age',    get: (i) => ageInDays(i), note: 'days since publication (7d, 24h)' },
  sigma:       { kind: 'number', get: (i) => i.detection_rule_count || 0, note: 'number of Sigma detection rules' },

  kev:         { kind: 'bool', get: (i) => !!i.cisa_kev, note: 'listed in CISA KEV' },
  poc:         { kind: 'bool', get: (i) => !!i.has_poc, note: 'a public PoC exists' },
  exploited:   { kind: 'bool', get: (i) => !!(i.cisa_kev || i.ssvc_exploitation === 'active'), note: 'KEV or SSVC exploitation active' },
  automatable: { kind: 'bool', get: (i) => i.ssvc_automatable === 'yes', note: 'SSVC: exploitable at scale' },
  stack:       { kind: 'bool', get: (i, ctx) => ctx.matchesStack(i), note: 'matches your saved stack' },
  watchlist:   { kind: 'bool', get: (i, ctx) => ctx.matchesWatchlist(i), note: 'matches a watchlist term' },
  starred:     { kind: 'bool', get: (i, ctx) => ctx.starred.has(i._key), note: 'you starred it' },
  reviewed:    { kind: 'bool', get: (i, ctx) => ctx.reviewed.has(i._key), note: 'you marked it reviewed' },
  fresh:       { kind: 'bool', get: (i, ctx) => ctx.isNewToYou(i), note: 'published since your last visit' },
  verdict:     { kind: 'bool', get: (i) => !!i.priority_label, note: 'the tool has an opinion about it' },
  ioc:         { kind: 'bool', get: (i) => !!(i.iocs && Object.keys(i.iocs).length), note: 'carries indicators' },
  human:       { kind: 'bool', get: (i) => !!i.human_authored, note: 'written by a person, not a feed' },
  cve:         { kind: 'text', get: (i) => i.cve_id || '', note: 'CVE id, or bare `cve` for any' },

  source:      { kind: 'text', get: (i) => i.source || '', note: 'publishing source' },
  sector:      { kind: 'text', get: (i) => i.sector || '', note: 'target sector' },
  severity:    { kind: 'text', get: (i) => i.severity || '', note: 'critical / high / medium / low' },
  band:        { kind: 'text', get: (i) => i.priority_label || '', note: 'urgent / elevated / moderate / low' },
  category:    { kind: 'text', get: (i) => i.category || '', note: 'cve / incident / advisory / news' },
  provenance:  { kind: 'text', get: (i) => i.provenance || '', note: 'who authored it' },
  actor:       { kind: 'list', get: (i) => i.threat_actors || [], note: 'named threat actor' },
  malware:     { kind: 'list', get: (i) => i.malware || [], note: 'named malware family' },
  technique:   { kind: 'list', get: (i) => (i.ttps || []).map((t) => t.id || t), note: 'ATT&CK technique id' },
  ttp:         { kind: 'list', get: (i) => (i.ttps || []).map((t) => t.id || t), note: 'alias for technique' },
  product:     { kind: 'list', get: (i) => [...(i.products || []), ...(i.affected_products || [])], note: 'affected product' },
  vendor:      { kind: 'list', get: (i) => i.vendors || [], note: 'affected vendor' },
  title:       { kind: 'text', get: (i) => i.title || '', note: 'headline only' },
};

// `cve` is odd: bare means "has a CVE id", with a value means "this CVE".
const BARE_TRUE_TEXT = { cve: (i) => !!i.cve_id };

function ageInDays(item) {
  const published = Date.parse(item.published || '');
  if (Number.isNaN(published)) return null;
  return (Date.now() - published) / 86400000;
}

// ─── Natural language → query language ────────────────────────────────────────
// Ordered: the longest, most specific phrases first, so "not in kev" is
// consumed before "kev" is. Every rule is a rewrite into the structured
// language below, which is the only thing that actually evaluates.
const NL_RULES = [
  // Negations first — they are the ones a naive pass gets wrong.
  [/\b(?:not|no|without|excluding|except)\s+(?:in\s+)?(?:the\s+)?kev(?:\s+catalog(?:ue)?)?\b/gi, ' NOT kev '],
  [/\b(?:not|no|without)\s+(?:a\s+)?(?:public\s+)?(?:poc|proof[- ]of[- ]concept|exploit\s+code)\b/gi, ' NOT poc '],
  [/\b(?:not|no|without)\s+(?:yet\s+)?exploited\b/gi, ' NOT exploited '],
  [/\bunexploited\b/gi, ' NOT exploited '],
  [/\bnot\s+reviewed\b/gi, ' NOT reviewed '],
  [/\bunreviewed\b/gi, ' NOT reviewed '],

  // Exploitation status.
  [/\b(?:actively\s+)?(?:being\s+)?exploited(?:\s+in\s+the\s+wild)?\b/gi, ' exploited '],
  [/\bknown\s+exploited\b/gi, ' exploited '],
  [/\bin\s+(?:the\s+)?kev(?:\s+catalog(?:ue)?)?\b/gi, ' kev '],
  [/\bkev[- ]listed\b/gi, ' kev '],
  [/\bwith\s+(?:a\s+)?(?:public\s+)?(?:poc|proof[- ]of[- ]concept|exploit\s+code)\b/gi, ' poc '],
  [/\bweaponi[sz]ed\b/gi, ' poc '],
  [/\bautomatable\b/gi, ' automatable '],

  // Numeric comparisons, spelled out.
  //
  // The operator is CAPTURED, not assumed. The first version of these rules
  // matched `>=?` and always emitted `>`, so typing `cvss >= 7.5` silently
  // became `cvss > 7.5` and dropped every item sitting exactly on the
  // boundary. Moving a threshold by one item without saying so is precisely
  // the kind of quiet wrongness a query language must not have.
  [/\b(epss|cvss|score|priority|sigma)\s*(?:score\s*)?(?:is\s*)?(>=|<=|>|<|at\s+least|at\s+most|above|over|greater\s+than|higher\s+than|more\s+than|below|under|less\s+than|lower\s+than)\s*([0-9.]+%?)/gi,
    (_m, field, op, value) => {
      const normalised = op.replace(/\s+/g, ' ').toLowerCase();
      const map = {
        '>=': '>=', '<=': '<=', '>': '>', '<': '<',
        'at least': '>=', 'at most': '<=',
        above: '>', over: '>', 'greater than': '>', 'higher than': '>', 'more than': '>',
        below: '<', under: '<', 'less than': '<', 'lower than': '<',
      };
      return ` ${field.toLowerCase()} ${map[normalised] || '>'} ${value} `;
    }],

  // Time windows.
  [/\b(?:in\s+the\s+)?(?:last|past)\s+(\d+)\s*(?:days?|d)\b/gi, (_m, n) => ` age <= ${n}d `],
  [/\b(?:in\s+the\s+)?(?:last|past)\s+(\d+)\s*(?:hours?|h)\b/gi, (_m, n) => ` age <= ${n}h `],
  [/\b(?:from\s+)?today\b/gi, ' age <= 1d '],
  [/\byesterday\b/gi, ' age <= 2d '],
  [/\b(?:this|past|last)\s+week\b/gi, ' age <= 7d '],
  [/\b(?:this|past|last)\s+(?:month|30\s+days)\b/gi, ' age <= 30d '],
  [/\b(?:this|past|last)\s+(?:quarter|90\s+days)\b/gi, ' age <= 90d '],
  [/\brecent(?:ly)?\b/gi, ' age <= 7d '],
  [/\bnew\s+to\s+me\b/gi, ' fresh '],
  [/\bsince\s+my\s+last\s+visit\b/gi, ' fresh '],

  // Ownership.
  [/\b(?:affecting|in|on|hitting)\s+(?:our|my|the)\s+(?:stack|estate|kit|environment|products?)\b/gi, ' stack '],
  [/\b(?:products?|things|kit)\s+(?:we|i)\s+(?:track|own|run|use)\b/gi, ' stack '],
  [/\b(?:our|my)\s+stack\b/gi, ' stack '],
  [/\bon\s+my\s+watchlist\b/gi, ' watchlist '],
  [/\bstarred\b/gi, ' starred '],

  // Bands and kinds.
  [/\b(?:needs?\s+)?patch(?:ing)?\s+now\b/gi, ' band = urgent '],
  // The lookbehind matters: without it "band = urgent" was rewritten into
  // "band = band = urgent", because the rule fired on the word it had just
  // produced. Any `urgent` that already follows an operator is a value.
  [/(?<![=:]\s{0,3})\burgent\b/gi, ' band = urgent '],
  [/\bcritical\s+severity\b/gi, ' severity = critical '],
  [/\b(?:with\s+)?(?:a\s+)?verdicts?\b/gi, ' verdict '],
  [/\bactionable\b/gi, ' verdict '],
  [/\b(?:with\s+)?(?:detection\s+)?(?:sigma\s+)?rules?\s+available\b/gi, ' sigma > 0 '],
  [/\bno\s+detection(?:s)?\b/gi, ' sigma = 0 '],
  [/\bindicators?\b/gi, ' ioc '],
  [/\bhuman[- ]written\b/gi, ' human '],

  // Sector shorthands — the taxonomy the pipeline already uses.
  [/\b(?:against|targeting|hitting|in|across)\s+(healthcare|government|financial|energy|water|defence|defense|aviation|maritime|telecom|education|manufacturing|transport|aerospace|corporate)\b/gi,
    (_m, sector) => ` sector = ${sector.toLowerCase() === 'defense' ? 'defence' : sector.toLowerCase()} `],

  // Filler. Removed last so earlier rules can still see the words they need.
  [/\b(?:show\s+me|find|list|give\s+me|search\s+for|what(?:'s| is)|are\s+there|any)\b/gi, ' '],
  [/\b(?:items?|things?|stuff|results?|entries|ones)\b/gi, ' '],
  [/\bfirst\s+seen\b/gi, ' '],
  // NOT `(?:kev\s+)?listing`. That version matched the "kev listing" in
  // "no KEV listing" AFTER the negation rule had already rewritten it to
  // "NOT kev listing" — deleting the very term being negated and leaving a
  // dangling NOT that then attached to the next clause. The query
  // "EPSS over 50%, no KEV listing, first seen this week" came out meaning
  // "NOT this week", which is the opposite of what was asked. A query language
  // that silently inverts a clause is worse than no query language.
  [/\blisting\b/gi, ' '],
  [/\b(?:that\s+are|which\s+are|that|which|with|about|for|the|a|an|of|is|was|were)\b/gi, ' '],
  // Prepositions, AFTER the sector rules above have had their chance at "in".
  // A surviving "from" or "on" becomes a text term that matches nothing, which
  // silently empties the result set.
  [/\b(?:from|on|at|since|during|within|into|by)\b/gi, ' '],
  [/\b(?:affecting|impacting|involving|related\s+to)\b/gi, ' '],
  [/\bplease\b/gi, ' '],
  // Sentence punctuation, last. English queries are written with commas, and
  // a comma reaching the tokeniser becomes a text term that matches nothing —
  // which silently turns the whole query into zero results.
  [/[,;]+/g, ' '],
];

/**
 * Rewrite English into the structured language. Returns the rewritten string.
 * Bare words that survive become substring terms, which is what makes
 * "VPNs this week" work without a vocabulary of every product on earth.
 */
function naturalise(text) {
  let out = ` ${text} `;
  for (const [pattern, replacement] of NL_RULES) {
    out = out.replace(pattern, replacement);
  }
  // "flaws" -> "flaw". Naive de-pluralisation, deliberately timid:
  //
  //   * never after ':' or a comparison operator, because that position holds
  //     a VALUE — this rule used to turn `actor:lazarus` into `actor:lazaru`
  //     and match nothing;
  //   * only when the letter before the final 's' is one that actually forms
  //     an English plural. Without that, "lazarus", "kerberos" and "analysis"
  //     all lose their last letter.
  // Stem of 2 rather than 3 so four-letter plurals reduce too: "CVEs" has to
  // become "cve", which is a FIELD ("has a CVE id"), not a text term. Left at
  // 3 it stayed a literal and quietly required the string "cves" to appear in
  // the item, which almost never does.
  out = out.replace(/(^|[^:=<>!\s])?\b([a-z]{2,})([bcdfgklmnprtvwxze])s\b/gi,
    (match, prefix, stem, tail) => {
      const whole = `${stem}${tail}s`;
      if (/^(?:this|was|has|its|kev|epss|cvss|ttps|less|news|analysis)$/i.test(whole)) {
        return match;
      }
      return `${prefix || ''}${stem}${tail}`;
    });

  // A NOT whose operand a later filler rule deleted is the most dangerous
  // failure this layer can have: it does not error, it silently binds to the
  // NEXT clause and returns the opposite of what was asked. Drop any NOT that
  // is not immediately followed by something to negate, and collapse a
  // doubled NOT rather than trusting rule ordering to prevent both.
  out = out.replace(/\bNOT\s+(?=and\b|or\b|NOT\b|$)/gi, ' ');
  out = out.replace(/\bNOT\s+NOT\b/gi, ' ');

  return out.replace(/\s+/g, ' ').trim();
}

// ─── Tokeniser ────────────────────────────────────────────────────────────────
const OPERATORS = ['>=', '<=', '!=', '>', '<', '=', ':'];

function tokenize(text) {
  const tokens = [];
  let i = 0;
  while (i < text.length) {
    const ch = text[i];
    if (/\s/.test(ch)) { i += 1; continue; }
    if (ch === '(' || ch === ')') { tokens.push({ t: ch }); i += 1; continue; }
    if (ch === '"' || ch === "'") {
      const end = text.indexOf(ch, i + 1);
      if (end === -1) { tokens.push({ t: 'word', v: text.slice(i + 1) }); break; }
      tokens.push({ t: 'word', v: text.slice(i + 1, end), quoted: true });
      i = end + 1;
      continue;
    }
    const op = OPERATORS.find((o) => text.startsWith(o, i));
    if (op) { tokens.push({ t: 'op', v: op }); i += op.length; continue; }
    let j = i;
    while (j < text.length && !/[\s()"']/.test(text[j])
           && !OPERATORS.some((o) => text.startsWith(o, j))) j += 1;
    const word = text.slice(i, j);
    if (word) tokens.push({ t: 'word', v: word });
    i = Math.max(j, i + 1);
  }
  return tokens;
}

// ─── Parser (recursive descent) ───────────────────────────────────────────────
function parseTokens(tokens) {
  let pos = 0;
  const peek = () => tokens[pos];
  const next = () => tokens[pos++];
  const isKeyword = (tok, word) => tok && tok.t === 'word' && !tok.quoted
    && tok.v.toLowerCase() === word;

  function parseExpr() {
    let left = parseAnd();
    while (isKeyword(peek(), 'or')) {
      next();
      const right = parseAnd();
      if (!right) break;
      left = { op: 'or', left, right };
    }
    return left;
  }

  function parseAnd() {
    let left = parseUnary();
    for (;;) {
      const tok = peek();
      if (!tok) break;
      if (isKeyword(tok, 'and')) { next(); }
      else if (isKeyword(tok, 'or') || tok.t === ')') break;
      // Adjacency is AND: `exploited vpn` means both.
      const right = parseUnary();
      if (!right) break;
      left = left ? { op: 'and', left, right } : right;
    }
    return left;
  }

  function parseUnary() {
    const tok = peek();
    if (!tok) return null;
    if (isKeyword(tok, 'not') || (tok.t === 'word' && !tok.quoted && tok.v === '-')) {
      next();
      const inner = parseUnary();
      return inner ? { op: 'not', node: inner } : null;
    }
    return parseAtom();
  }

  function parseAtom() {
    const tok = next();
    if (!tok) return null;
    if (tok.t === '(') {
      const inner = parseExpr();
      if (peek() && peek().t === ')') next();
      return inner;
    }
    if (tok.t === ')') return null;
    if (tok.t === 'op') return parseAtom();          // stray operator, skip it
    if (tok.quoted) return { op: 'text', value: tok.v.toLowerCase() };

    const name = tok.v.toLowerCase();
    const field = QUERY_FIELDS[name];
    const after = peek();
    if (field && after && after.t === 'op') {
      next();
      const valueTok = next();
      if (!valueTok || valueTok.t !== 'word') return { op: 'field', field: name };
      return {
        op: 'compare', field: name,
        cmp: after.v === ':' ? '~' : after.v,
        value: valueTok.v,
      };
    }
    if (field) return { op: 'field', field: name };
    return { op: 'text', value: name };
  }

  const ast = parseExpr();
  return { ast, consumed: pos };
}

// ─── Evaluation ───────────────────────────────────────────────────────────────
function coerceNumber(raw) {
  const text = String(raw).trim();
  if (text.endsWith('%')) {
    const n = parseFloat(text.slice(0, -1));
    return Number.isNaN(n) ? null : n / 100;
  }
  if (/^\d+(?:\.\d+)?[dh]$/i.test(text)) {
    const n = parseFloat(text);
    return text.toLowerCase().endsWith('h') ? n / 24 : n;
  }
  const n = parseFloat(text);
  return Number.isNaN(n) ? null : n;
}

function compare(actual, cmp, expected) {
  if (actual === null || actual === undefined) return cmp === '!=';
  switch (cmp) {
    case '>':  return actual > expected;
    case '>=': return actual >= expected;
    case '<':  return actual < expected;
    case '<=': return actual <= expected;
    case '!=': return actual !== expected;
    default:   return actual === expected;
  }
}

function textMatches(haystack, needle, cmp) {
  const hay = String(haystack || '').toLowerCase();
  const needleText = String(needle || '').toLowerCase();
  if (cmp === '=' ) return hay === needleText;
  if (cmp === '!=') return hay !== needleText;
  return hay.includes(needleText);
}

function evaluate(node, item, ctx) {
  if (!node) return true;
  switch (node.op) {
    case 'and': return evaluate(node.left, item, ctx) && evaluate(node.right, item, ctx);
    case 'or':  return evaluate(node.left, item, ctx) || evaluate(node.right, item, ctx);
    case 'not': return !evaluate(node.node, item, ctx);
    case 'text': {
      const hay = `${item.title || ''} ${item.description || ''} ${item.cve_id || ''} `
        + `${item.source || ''} ${(item.vendors || []).join(' ')} `
        + `${(item.products || []).join(' ')} ${(item.affected_products || []).join(' ')} `
        + `${(item.malware || []).join(' ')} ${(item.threat_actors || []).join(' ')}`;
      return hay.toLowerCase().includes(node.value);
    }
    case 'field': {
      const field = QUERY_FIELDS[node.field];
      if (!field) return true;
      if (field.kind === 'bool') return !!field.get(item, ctx);
      if (BARE_TRUE_TEXT[node.field]) return BARE_TRUE_TEXT[node.field](item);
      const value = field.get(item, ctx);
      if (field.kind === 'list') return Array.isArray(value) && value.length > 0;
      if (field.kind === 'number' || field.kind === 'age') {
        return value !== null && value !== undefined;
      }
      return !!value;
    }
    case 'compare': {
      const field = QUERY_FIELDS[node.field];
      if (!field) return true;
      const raw = field.get(item, ctx);
      if (field.kind === 'number' || field.kind === 'age') {
        const expected = coerceNumber(node.value);
        if (expected === null) return true;
        const actual = raw === null || raw === undefined ? null : Number(raw);
        return compare(actual, node.cmp === '~' ? '=' : node.cmp, expected);
      }
      if (field.kind === 'bool') {
        const wanted = /^(?:true|yes|1)$/i.test(node.value);
        return !!raw === wanted;
      }
      if (field.kind === 'list') {
        const list = Array.isArray(raw) ? raw : [];
        const hit = list.some((v) => textMatches(v, node.value, node.cmp === '~' ? '~' : node.cmp));
        return node.cmp === '!=' ? !hit : hit;
      }
      return textMatches(raw, node.value, node.cmp === '~' ? '~' : node.cmp);
    }
    default: return true;
  }
}

// ─── Public surface (used by app.js) ──────────────────────────────────────────

/**
 * Parse a search string. Returns an AST wrapper, or null when the string is
 * plain text with no structure worth the machinery — in which case app.js
 * falls back to substring search.
 */
function parseQuery(text) {                                    // eslint-disable-line no-unused-vars
  const raw = String(text || '').trim();
  if (raw.length < 2) return null;

  const rewritten = naturalise(raw);
  const tokens = tokenize(rewritten);
  if (!tokens.length) return null;

  const structural = tokens.some((tok) => (
    tok.t === 'op' || tok.t === '('
    || (tok.t === 'word' && !tok.quoted
        && (QUERY_FIELDS[tok.v.toLowerCase()]
            || ['and', 'or', 'not'].includes(tok.v.toLowerCase())))
  ));
  // No field, no operator, no boolean: this is a keyword search, and dressing
  // it up as a query would only make it slower and stranger.
  if (!structural) return null;

  const { ast } = parseTokens(tokens);
  if (!ast) return null;
  return { ast, source: raw, rewritten };
}

function queryMatches(parsed, item) {                          // eslint-disable-line no-unused-vars
  if (!parsed || !parsed.ast) return true;
  const ctx = {
    matchesStack: typeof matchesStack === 'function' ? matchesStack : () => false,
    matchesWatchlist: typeof matchesWatchlist === 'function' ? matchesWatchlist : () => false,
    isNewToYou: typeof isNewToYou === 'function' ? isNewToYou : () => false,
    starred: (typeof store !== 'undefined' && store.starred) || new Set(),
    reviewed: (typeof store !== 'undefined' && store.reviewed) || new Set(),
  };
  try {
    return evaluate(parsed.ast, item, ctx);
  } catch (_) {
    return true;
  }
}

/** A one-line, human-readable rendering of what the query is doing. */
function queryExplain(parsed) {                                // eslint-disable-line no-unused-vars
  if (!parsed || !parsed.ast) return '';
  const render = (node) => {
    if (!node) return '';
    switch (node.op) {
      case 'and': return `${render(node.left)} and ${render(node.right)}`;
      case 'or':  return `${render(node.left)} or ${render(node.right)}`;
      case 'not': return `not ${render(node.node)}`;
      case 'text': return `"${node.value}"`;
      case 'field': return node.field;
      case 'compare': return `${node.field} ${node.cmp === '~' ? 'contains' : node.cmp} ${node.value}`;
      default: return '';
    }
  };
  const text = render(parsed.ast).replace(/\s+/g, ' ').trim();
  return text ? `query: ${text}` : '';
}

function queryFields() {                                       // eslint-disable-line no-unused-vars
  return Object.entries(QUERY_FIELDS)
    .filter(([name]) => !['priority', 'ttp'].includes(name))
    .map(([name, def]) => ({ name, note: def.note }));
}

function queryExamples() {                                     // eslint-disable-line no-unused-vars
  return [
    { q: 'epss > 0.5 and not kev and stack and age <= 7d',
      note: 'the question the old search box could not ask' },
    { q: 'actively exploited things affecting VPNs this week',
      note: 'plain English, rewritten locally' },
    { q: 'kev and sector = healthcare',
      note: 'exploited, against healthcare' },
    { q: 'cvss >= 9 and poc and not exploited',
      note: 'high impact, exploit code out, not yet listed' },
    { q: 'verdict and sigma = 0',
      note: 'actionable, with no public detection rule' },
    { q: 'actor:lazarus or malware:emotet',
      note: 'named entities' },
    { q: 'band = urgent and not reviewed',
      note: "today's triage queue" },
  ];
}
