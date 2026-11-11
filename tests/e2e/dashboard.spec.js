// Browser tests: the page actually loading and working in a real browser.
//
// The Python suite checks the pipeline and reads the JavaScript as text; none
// of it would notice a ReferenceError that only fires when a view opens. These
// do. They run against a fixture feed (see server.js), with every third-party
// request blocked, so they are deterministic and need no network.
'use strict';

const { test, expect } = require('@playwright/test');

// Mirrors MODE_VIEWS in app.js. A view missing here is a view nobody opens in
// a browser before it ships; the last test fails if the two lists drift.
const MODE_VIEWS = {
  feed: ['feed'],
  library: ['library', 'graph', 'matrix', 'campaigns', 'malware', 'cve'],
  hunt: ['hunt', 'detections'],
  landscape: ['map', 'landscape', 'geopol', 'leaks', 'darkweb', 'kev', 'lifecycle', 'exposure'],
  research: ['research', 'trends'],
  tools: ['recon', 'ioc', 'phish', 'creds'],
};

/** Open the dashboard and collect everything that should never happen. */
async function open(page, path = '/') {
  const problems = [];
  page.on('pageerror', (err) => problems.push(`uncaught: ${err.message}`));
  page.on('console', (msg) => {
    if (msg.type() === 'error' && /Content Security Policy|Refused to/.test(msg.text())) {
      problems.push(`csp: ${msg.text()}`);
    }
  });
  // Hermetic: fonts and every live API are someone else's uptime.
  await page.route((url) => url.hostname !== '127.0.0.1', (route) => route.abort());
  await page.goto(path);
  return problems;
}

async function waitForFeed(page) {
  await expect(page.locator('#cards-container .intel-card').first()).toBeVisible();
}

test('the feed loads and renders a card per item', async ({ page }) => {
  const problems = await open(page);
  await waitForFeed(page);
  await page.locator('#filter-tabs [data-filter="all"]').click();
  await expect(page.locator('#cards-container .intel-card')).toHaveCount(17);
  await expect(page.locator('#count-total')).toHaveText('17');
  await expect(page.locator('#error-state')).toBeHidden();
  expect(problems).toEqual([]);
});

test('search narrows the feed', async ({ page }) => {
  const problems = await open(page);
  await waitForFeed(page);
  await page.locator('#filter-tabs [data-filter="all"]').click();
  await page.locator('#search-input').fill('chrome');
  await expect(page.locator('#cards-container .intel-card')).toHaveCount(2);
  await page.locator('#search-input').fill('no-such-thing-anywhere');
  await expect(page.locator('#cards-container .intel-card')).toHaveCount(0);
  await expect(page.locator('#no-results')).toBeVisible();
  expect(problems).toEqual([]);
});

test('a filter tab shows only what it names', async ({ page }) => {
  const problems = await open(page);
  await waitForFeed(page);
  await page.locator('#filter-tabs [data-filter="incident"]').click();
  await expect(page.locator('#cards-container .intel-card')).toHaveCount(3);
  expect(problems).toEqual([]);
});

const fs = require('fs');
const nodePath = require('path');

function fixtureFeed() {
  return JSON.parse(fs.readFileSync(nodePath.join(__dirname, 'fixtures', 'intel.json'), 'utf8'));
}

/** Serve a modified copy of the fixture feed, optionally after a delay. */
async function serveFeed(page, feed, delayMs = 0) {
  await page.route('**/data/intel.json', async (route) => {
    if (delayMs) await new Promise((done) => setTimeout(done, delayMs));
    await route.fulfill({ contentType: 'application/json', body: JSON.stringify(feed) });
  });
}

test('the first screen is painted from the head file before the full feed lands', async ({ page }) => {
  const feed = fixtureFeed();
  const verdicts = feed.items.filter((i) => i.priority_label);
  const head = { ...feed, items: verdicts.slice(0, 2), partial: true,
    head_counts: { total: 17, urgent: 9, critical: 8, high: 7, verdicts: verdicts.length } };
  const problems = await open(page, '/__blank');
  await serveFeed(page, feed, 1500);
  await page.route('**/data/feed-head.json', (route) => route.fulfill(
    { contentType: 'application/json', body: JSON.stringify(head) }));
  await page.goto('/');
  // Two cards, but the header already speaks for the whole feed.
  await expect(page.locator('#cards-container .intel-card')).toHaveCount(2);
  await expect(page.locator('#count-total')).toHaveText('17');
  await expect(page.locator('#count-urgent')).toHaveText('9');
  // Then the rest arrives and the counts come from the items themselves.
  await expect(page.locator('#cards-container .intel-card')).toHaveCount(verdicts.length);
  await expect(page.locator('#count-total')).toHaveText('17');
  expect(problems).toEqual([]);
});

test('a head file with no full feed behind it still shows the head', async ({ page }) => {
  const feed = fixtureFeed();
  const head = { ...feed, items: feed.items.filter((i) => i.priority_label).slice(0, 2),
    partial: true, head_counts: { total: 17, urgent: 9, critical: 8, high: 7, verdicts: 2 } };
  await open(page, '/__blank');
  await page.route('**/data/intel.json', (route) => route.fulfill({ status: 503, body: 'down' }));
  await page.route('**/data/feed-head.json', (route) => route.fulfill(
    { contentType: 'application/json', body: JSON.stringify(head) }));
  await page.goto('/');
  await expect(page.locator('#cards-container .intel-card')).toHaveCount(2);
  await expect(page.locator('#error-state')).toBeHidden();
  await expect(page.locator('#toast-host')).toContainText('top of the feed only');
});

test('repeats of one story fold behind a single card that lists them', async ({ page }) => {
  const feed = fixtureFeed();
  const [a, b, c] = feed.items;
  [a, b, c].forEach((item) => Object.assign(item, { story_id: 'abc123', story_size: 3, story_sources: 3 }));
  a.story_lead = true;
  const problems = await open(page, '/__blank');
  await serveFeed(page, feed);
  await page.goto('/');
  await waitForFeed(page);
  await page.locator('#filter-tabs [data-filter="all"]').click();
  await expect(page.locator('#cards-container .intel-card')).toHaveCount(15);
  await expect(page.locator('#feed-count')).toContainText('2 repeats of the same story folded');
  const lead = page.locator('#cards-container .intel-card', { has: page.locator('.story-badge') });
  await expect(lead).toHaveCount(1);
  await expect(lead.locator('.story-badge')).toHaveText('3 SOURCES');
  await lead.locator('.card-verdict').click();
  await expect(lead.locator('.card-story .story-row')).toHaveCount(2);
  expect(problems).toEqual([]);
});

test('a CVE whose EPSS is climbing says so', async ({ page }) => {
  const feed = fixtureFeed();
  const item = feed.items.find((i) => i.epss_score != null);
  Object.assign(item, { epss_delta: 0.184, epss_rising: true });
  const problems = await open(page, '/__blank');
  await serveFeed(page, feed);
  await page.goto('/');
  await waitForFeed(page);
  await page.locator('#filter-tabs [data-filter="all"]').click();
  const card = page.locator('#cards-container .intel-card', { has: page.locator('.rising-badge') });
  await expect(card).toHaveCount(1);
  await card.locator('.card-verdict').click();
  await expect(card.locator('.meta-epss-trend')).toHaveText('▲ 18.4 pts / 7d');
  await page.locator('#search-input').fill('rising');
  await expect(page.locator('#cards-container .intel-card')).toHaveCount(1);
  expect(problems).toEqual([]);
});

test('the time machine searches every archived day, not just today', async ({ page }) => {
  const index = {
    generated: '2026-11-11T00:00:00+00:00', days: 3, from: '2026-08-14', to: '2026-11-11', count: 3,
    columns: ['title', 'url', 'source', 'cve', 'label', 'first', 'last'],
    rows: [
      ['Ivanti Connect Secure zero-day exploited', 'https://example.com/ivanti', 'Rapid7', 'CVE-2026-1111', 'urgent', '2026-08-14', '2026-08-20'],
      ['Ivanti EPMM advisory', 'javascript:alert(1)', 'Ivanti', '', '', '2026-08-15', '2026-08-15'],
      ['Chrome stable update', 'https://example.com/chrome', 'Chrome Releases', '', '', '2026-11-10', '2026-11-11'],
    ],
  };
  const problems = await open(page, '/__blank');
  let fetched = 0;
  await page.route('**/data/api/search_index.json', (route) => {
    fetched += 1;
    return route.fulfill({ contentType: 'application/json', body: JSON.stringify(index) });
  });
  await page.goto('/');
  await waitForFeed(page);
  await page.locator('#timemachine-open').click();
  await expect(page.locator('#tm-search-input')).toBeVisible();
  // Nothing is downloaded until somebody actually searches.
  expect(fetched).toBe(0);
  await page.locator('#tm-search-input').fill('ivanti');
  await expect(page.locator('#tm-search-results .tm-search-row')).toHaveCount(2);
  await expect(page.locator('#tm-search-status')).toContainText('2 items between 2026-08-14 and 2026-11-11');
  // A hostile link in the index is shown as text, never as an anchor.
  await expect(page.locator('#tm-search-results a')).toHaveCount(1);
  await page.locator('#tm-search-input').fill('ivanti zero-day');
  await expect(page.locator('#tm-search-results .tm-search-row')).toHaveCount(1);
  await page.locator('#tm-search-input').fill('nothing-like-this');
  await expect(page.locator('#tm-search-status')).toContainText('Nothing matching');
  expect(fetched).toBe(1);
  expect(problems).toEqual([]);
});

/** Type into the My Stack box in the filter panel, then close the panel. */
async function addToStack(page, text) {
  await page.locator('#filters-open').click();
  await page.locator('#stack-input').fill(text);
  await page.locator('#stack-input').press('Enter');
  await page.locator('#filter-panel button[data-close="filters"]').click();
}

test('adding a product to My Stack flags and filters matching items', async ({ page }) => {
  const problems = await open(page);
  await waitForFeed(page);
  await addToStack(page, 'chrome');
  await expect(page.locator('#stack-chips')).toContainText('chrome');
  await expect(page.locator('#stack-match-count')).toHaveText('2 affect you');
  await page.locator('#filter-tabs [data-filter="stack"]').click();
  await expect(page.locator('#cards-container .intel-card')).toHaveCount(2);
  await expect(page.locator('#cards-container .stack-badge')).toHaveCount(2);
  // …and it survives a reload, because a stack you retype is not a stack.
  await page.reload();
  await expect(page.locator('#stack-chips')).toContainText('chrome');
  expect(problems).toEqual([]);
});

test('My Stack matches whole words, not fragments', async ({ page }) => {
  const problems = await open(page);
  await waitForFeed(page);
  // "chrom" is inside "Chrome" in two titles. As a substring it matched both;
  // as a word it matches neither, which is the difference between a stack
  // filter and a search box.
  await addToStack(page, 'chrom');
  await expect(page.locator('#stack-match-count')).toHaveText('0 affect you');
  expect(problems).toEqual([]);
});

test('the My Stack panel breaks the feed down per product and can focus one', async ({ page }) => {
  const problems = await open(page);
  await waitForFeed(page);
  await page.locator('#filter-tabs [data-filter="stack"]').click();
  // Empty stack: the panel explains itself and offers what is in the feed.
  await expect(page.locator('#stack-panel')).toContainText('nothing is sent anywhere');
  await expect(page.locator('#stack-panel .stack-suggest-chip').first()).toBeVisible();

  // A pasted, comma-separated list adds several products at once.
  await addToStack(page, 'chrome, no-such-product-anywhere');
  await expect(page.locator('#stack-panel .stack-row')).toHaveCount(2);
  await expect(page.locator('#stack-panel .stack-panel-stats')).toContainText('2 of 17 items affect you');
  const chrome = page.locator('#stack-panel .stack-row', { hasText: 'chrome' });
  await expect(chrome).toContainText('2 items');
  await expect(page.locator('#stack-panel .stack-row.is-clear')).toContainText('nothing today');

  // Focusing a product with nothing against it empties the feed; clearing the
  // focus brings the whole stack back.
  const clear = page.locator('#stack-panel .stack-row.is-clear');
  await clear.click();
  await expect(page.locator('#cards-container .intel-card')).toHaveCount(0);
  await page.locator('#stack-panel .stack-row.is-focused').click();
  await expect(page.locator('#cards-container .intel-card')).toHaveCount(2);

  // The panel belongs to the stack tab and leaves with it.
  await page.locator('#filter-tabs [data-filter="all"]').click();
  await expect(page.locator('#stack-panel')).toBeHidden();
  expect(problems).toEqual([]);
});

test('a suggestion chip adds that product to the stack', async ({ page }) => {
  const problems = await open(page);
  await waitForFeed(page);
  await page.locator('#filter-tabs [data-filter="stack"]').click();
  const chip = page.locator('#stack-panel .stack-suggest-chip').first();
  const name = (await chip.textContent()).replace(/^\+\s*/, '');
  await chip.click();
  await expect(page.locator('#stack-panel .stack-row').first()).toContainText(name);
  expect(problems).toEqual([]);
});

for (const [mode, views] of Object.entries(MODE_VIEWS)) {
  test(`${mode} mode: every view opens without a script error`, async ({ page }) => {
    const problems = await open(page);
    await waitForFeed(page);
    await page.locator(`#mode-switcher [data-mode="${mode}"]`).click();
    for (const view of views) {
      if (views.length > 1) {
        await page.locator(`#view-switcher .view-btn[data-view="${view}"]`).click();
      }
      const container = view === 'feed' ? '#cards-container' : `#${view}-view`;
      await expect(page.locator(container), `${view} view`).toBeVisible();
      // Views fetch their own data; give a rejected promise time to surface.
      await page.waitForTimeout(150);
      expect(problems, `${view} view`).toEqual([]);
    }
  });
}

// Two views are reached from header buttons rather than the mode switcher, so
// the loop above never opens them.
for (const [button, container] of [['#about-open', '#about-view'], ['#contact-open', '#contact-view']]) {
  test(`${container} opens from its header button without a script error`, async ({ page }) => {
    const problems = await open(page);
    await waitForFeed(page);
    await page.locator(button).click();
    await expect(page.locator(container)).toBeVisible();
    await page.waitForTimeout(150);
    expect(problems).toEqual([]);
  });
}

test('the page refuses to render inside another site\'s frame', async ({ page }) => {
  await open(page, '/__framer');
  const frame = page.frameLocator('#victim');
  await expect(frame.locator('html')).toHaveCSS('display', 'none');
});

test('this file covers every view the app defines', async ({ page }) => {
  await open(page);
  await waitForFeed(page);
  const defined = await page.evaluate(() => {
    // eslint-disable-next-line no-undef
    return Object.fromEntries(Object.entries(MODE_VIEWS).map(([m, v]) => [m, v.map((x) => x[0])]));
  });
  expect(defined).toEqual(MODE_VIEWS);
});
