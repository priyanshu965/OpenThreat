// Browser tests for the dashboard. Run with `npm test` from tests/e2e.
//
// CHROMIUM_PATH points Playwright at an already-installed browser instead of
// its own download - useful on a machine that has Chromium and no wish for a
// second copy. CI leaves it unset and uses `npx playwright install chromium`.
'use strict';

const { defineConfig } = require('@playwright/test');

const PORT = Number(process.env.E2E_PORT || 8766);

module.exports = defineConfig({
  testDir: '.',
  testMatch: '*.spec.js',
  timeout: 30000,
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? 'github' : 'list',
  use: {
    baseURL: `http://127.0.0.1:${PORT}`,
    // The service worker would cache the fixture feed across tests and answer
    // for the network; these tests are about the page, not the cache.
    serviceWorkers: 'block',
    launchOptions: process.env.CHROMIUM_PATH
      ? { executablePath: process.env.CHROMIUM_PATH }
      : {},
  },
  webServer: {
    command: 'node server.js',
    url: `http://127.0.0.1:${PORT}/index.html`,
    reuseExistingServer: !process.env.CI,
    timeout: 20000,
  },
});
