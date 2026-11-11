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
