/**
 * OPENTHREAT — js/stack.js
 *
 * My Stack: the vendors and products you run, and what in the feed affects
 * them. The feed answers "what happened"; this answers "what happened to me",
 * which is the only one of the two anybody acts on.
 *
 * Everything here lives in the browser. The stack is stored in localStorage
 * and matched against a feed the page has already downloaded - there is no
 * server to send it to, so a list of the products an organisation runs never
 * leaves the machine it was typed on.
 *
 * Loaded as a classic script after app.js and shares its top-level scope:
 * store, el, $, readLS, writeLS, LS, update and showToast are defined there.
 */

'use strict';

const STACK_MAX_TERMS = 60;
const STACK_MAX_TERM_LENGTH = 60;
const STACK_NOTIFY_KEY = 'ot_stack_notify';

// ─── Matching ─────────────────────────────────────────────────────────────────

const stackPatterns = new Map();

/**
 * A whole-word matcher for one stack term.
 *
 * Matching used to be a bare substring test, so "go" matched every item that
 * mentioned Google and "ios" matched "curiosity" - on a feed of a few hundred
 * items that is most of them, and a stack filter that shows everything is a
 * filter nobody keeps on. The term is escaped before it reaches the RegExp,
 * and its length is capped where it is added, so nothing typed here can
 * become an expensive pattern.
 */
function stackPattern(term) {
  const key = String(term).toLowerCase();
  let pattern = stackPatterns.get(key);
  if (!pattern) {
    const escaped = key.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    pattern = new RegExp(`(^|[^a-z0-9])${escaped}($|[^a-z0-9])`);
    stackPatterns.set(key, pattern);
  }
  return pattern;
}

/** The text of an item that a stack term is tested against, built once. */
function stackHaystack(item) {
  if (item._stackHay === undefined) {
    item._stackHay = [item.title, item.description,
      ...(item.vendors || []), ...(item.products || []),
      ...(item.affected_products || [])].join(' ').toLowerCase();
  }
  return item._stackHay;
}

function stackMatchesTerm(item, term) {
  return stackPattern(term).test(stackHaystack(item));
}

/** The first stack term this item matches, or null. */
function stackHit(item) {
  if (!store.stack.length) return null;
  return store.stack.find((term) => stackMatchesTerm(item, term)) || null;
}

function matchesStack(item) {
  return stackHit(item) !== null;
}

/** What the STACK filter tab shows: the whole stack, or one focused product. */
function stackFilter(item) {
  if (store.stackFocus && store.stack.includes(store.stackFocus)) {
    return stackMatchesTerm(item, store.stackFocus);
  }
  return matchesStack(item);
}

// ─── Editing ──────────────────────────────────────────────────────────────────

/**
 * Add one or more terms. Accepts a comma- or newline-separated list, so a
 * stack can be pasted in one go rather than typed a product at a time.
 * Returns how many were actually added.
 */
function addStackTerms(raw) {
  const have = new Set(store.stack.map((t) => t.toLowerCase()));
  let added = 0;
  String(raw || '').split(/[,\n;]+/).forEach((part) => {
    const term = part.trim().replace(/\s+/g, ' ').slice(0, STACK_MAX_TERM_LENGTH);
    // Two characters is the floor: a one-letter term matches nothing useful
    // and everything accidental.
    if (term.length < 2 || have.has(term.toLowerCase())) return;
    if (store.stack.length >= STACK_MAX_TERMS) return;
    store.stack.push(term);
    have.add(term.toLowerCase());
    added += 1;
  });
  if (added) writeLS(LS.stack, store.stack);
  return added;
}

function removeStackTerm(value) {
  store.stack = store.stack.filter((s) => s !== value);
  if (store.stackFocus === value) store.stackFocus = null;
  writeLS(LS.stack, store.stack);
}

/**
 * Vendors and products that appear in today's feed and are not in the stack
 * yet, most-mentioned first. Typing a stack from memory is the step people
 * abandon; picking from what is actually in the news is not.
 */
function stackSuggestions(limit) {
  const have = new Set(store.stack.map((t) => t.toLowerCase()));
  const counts = new Map();
  store.items.forEach((item) => {
    new Set([...(item.vendors || []), ...(item.products || [])]).forEach((name) => {
      const key = String(name || '').trim().toLowerCase();
      if (key.length < 2 || key.length > STACK_MAX_TERM_LENGTH || have.has(key)) return;
      counts.set(key, (counts.get(key) || 0) + 1);
    });
  });
  return [...counts.entries()]
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .slice(0, limit)
    .map(([name]) => name);
}

// ─── Sidebar ──────────────────────────────────────────────────────────────────

function renderStack() {
  renderChips('stack-chips', store.stack, 'unstack');
  const hits = store.items.filter(matchesStack).length;
  const badge = $('stack-match-count');
  if (badge) {
    // "0 items affect your stack today" is a valuable, calming answer that the
    // old UI had no way to express.
    badge.textContent = store.stack.length ? `${hits} affect you` : '';
    badge.classList.toggle('all-clear', store.stack.length > 0 && hits === 0);
  }
  const list = $('stack-suggestions');
  if (list) {
    list.replaceChildren();
    stackSuggestions(40).forEach((name) => {
      const option = el('option');
      option.value = name;
      list.appendChild(option);
    });
  }
}

// ─── Panel (above the feed, on the MY STACK tab) ──────────────────────────────

function stackIsExploited(item) {
  return Boolean(item.cisa_kev) || item.ssvc_exploitation === 'active';
}

/** Per-product counts, worst first: exploited, then urgent, then volume. */
function stackBreakdown() {
  return store.stack.map((term) => {
    const items = store.items.filter((item) => stackMatchesTerm(item, term));
    return {
      term,
      total: items.length,
      urgent: items.filter((i) => i.priority_label === 'urgent').length,
      exploited: items.filter(stackIsExploited).length,
    };
  }).sort((a, b) => b.exploited - a.exploited || b.urgent - a.urgent
    || b.total - a.total || a.term.localeCompare(b.term));
}

function renderStackPanel() {
  const host = $('stack-panel');
  if (!host) return;
  host.replaceChildren();
  if (store.view !== 'feed' || store.filter !== 'stack') {
    host.style.display = 'none';
    return;
  }
  host.style.display = 'block';
  const inner = el('div', 'stack-panel-inner');
  host.appendChild(inner);

  const head = el('div', 'stack-panel-head');
  head.appendChild(el('span', 'stack-panel-label', 'MY STACK'));
  inner.appendChild(head);

  if (!store.stack.length) {
    inner.appendChild(el('p', 'stack-panel-text',
      'List the vendors and products you run, and this tab shows only what '
      + 'affects them. The list stays in this browser; nothing is sent anywhere.'));
    stackRenderSuggestions(inner, 'In today\'s feed — click to add:');
    return;
  }

  const rows = stackBreakdown();
  const affected = store.items.filter(matchesStack);
  const urgent = affected.filter((i) => i.priority_label === 'urgent').length;
  head.appendChild(el('span', 'stack-panel-stats',
    `${affected.length} of ${store.items.length} items affect you`
    + (urgent ? ` · ${urgent} urgent` : '')));
  head.appendChild(stackNotifyButton());

  const grid = el('div', 'stack-grid');
  rows.forEach((row) => {
    const focused = store.stackFocus === row.term;
    const btn = el('button', `stack-row${focused ? ' is-focused' : ''}${row.total ? '' : ' is-clear'}`);
    btn.type = 'button';
    btn.setAttribute('aria-pressed', focused ? 'true' : 'false');
    btn.title = focused ? 'Show the whole stack again' : `Show only ${row.term}`;
    btn.appendChild(el('span', 'stack-row-name', row.term));
    btn.appendChild(el('span', 'stack-row-count',
      row.total ? `${row.total} item${row.total === 1 ? '' : 's'}` : 'nothing today'));
    if (row.exploited) btn.appendChild(el('span', 'stack-row-flag is-exploited', `${row.exploited} exploited`));
    else if (row.urgent) btn.appendChild(el('span', 'stack-row-flag is-urgent', `${row.urgent} urgent`));
    btn.addEventListener('click', () => {
      store.stackFocus = focused ? null : row.term;
      update();
    });
    grid.appendChild(btn);
  });
  inner.appendChild(grid);
  stackRenderSuggestions(inner, 'Also in today\'s feed:');
}

function stackRenderSuggestions(parent, label) {
  const names = stackSuggestions(12);
  if (!names.length) return;
  const wrap = el('div', 'stack-suggest');
  wrap.appendChild(el('span', 'stack-suggest-label', label));
  names.forEach((name) => {
    const btn = el('button', 'stack-suggest-chip', `+ ${name}`);
    btn.type = 'button';
    btn.addEventListener('click', () => {
      if (addStackTerms(name)) update();
    });
    wrap.appendChild(btn);
  });
  parent.appendChild(wrap);
}

// ─── Notifications ────────────────────────────────────────────────────────────
// A desktop notification when a NEW item affects the stack. It can only fire
// while the dashboard is open in a tab - there is no server here to push from
// and no account to push to - so it is an alert for the tab you left open, not
// a replacement for a pager.

function stackNotifySupported() {
  return typeof Notification !== 'undefined';
}

function stackNotifyEnabled() {
  return stackNotifySupported() && Notification.permission === 'granted'
    && readLS(STACK_NOTIFY_KEY, false) === true;
}

function stackNotifyButton() {
  const on = stackNotifyEnabled();
  const btn = el('button', `stack-notify${on ? ' is-on' : ''}`,
    on ? '🔔 Notifying on new matches' : '🔔 Notify me of new matches');
  btn.type = 'button';
  btn.setAttribute('aria-pressed', on ? 'true' : 'false');
  if (!stackNotifySupported()) {
    btn.disabled = true;
    btn.title = 'This browser does not support notifications';
    return btn;
  }
  btn.title = 'Works while this tab is open';
  btn.addEventListener('click', async () => {
    if (on) {
      writeLS(STACK_NOTIFY_KEY, false);
      update();
      return;
    }
    let permission = Notification.permission;
    if (permission === 'default') {
      try { permission = await Notification.requestPermission(); } catch (_) { permission = 'denied'; }
    }
    if (permission !== 'granted') {
      showToast('Notifications are blocked for this site in your browser settings.');
      return;
    }
    writeLS(STACK_NOTIFY_KEY, true);
    update();
  });
  return btn;
}

/**
 * Called by the live poll with the items that just arrived. Returns how many
 * of them affect the stack, and raises one notification for the batch.
 */
function stackNotify(incoming) {
  const mine = (incoming || []).filter(matchesStack);
  if (!mine.length || !stackNotifyEnabled()) return mine.length;
  const worst = mine.find(stackIsExploited)
    || mine.find((i) => i.priority_label === 'urgent') || mine[0];
  const title = mine.length === 1
    ? `OpenThreat: ${stackHit(worst)} is affected`
    : `OpenThreat: ${mine.length} new items affect your stack`;
  try {
    const note = new Notification(title, {
      body: String(worst.title || '').slice(0, 180),
      tag: 'openthreat-stack',
    });
    note.onclick = () => {
      window.focus();
      store.filter = 'stack';
      update();
      note.close();
    };
  } catch (_) { /* some browsers only allow notifications from a worker */ }
  return mine.length;
}
