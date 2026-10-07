import { defineConfig, devices } from '@playwright/test';
import { release } from 'node:os';

// Playwright 1.63's Firefox cannot access its profile on macOS 27 without
// Full Disk Access. Linux CI still runs Firefox; override locally if fixed.
// https://github.com/microsoft/playwright/issues/42768
const firefoxBlockedOnHost = process.platform === 'darwin'
  && release().startsWith('27.')
  && process.env.CLOVSHELL_FORCE_FIREFOX !== '1';

export default defineConfig({
  testDir: './e2e',
  timeout: 60_000,
  expect: { timeout: 30_000 },
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? 'github' : 'list',
  use: { baseURL: 'http://127.0.0.1:4174', trace: 'retain-on-failure' },
  projects: [
    { name: 'chromium', use: { ...devices['Desktop Chrome'] } },
    ...(!firefoxBlockedOnHost ? [{ name: 'firefox', use: { ...devices['Desktop Firefox'] } }] : []),
    { name: 'webkit', use: { ...devices['Desktop Safari'] } },
    { name: 'mobile-chromium', use: { ...devices['Pixel 7'] } },
    { name: 'mobile-webkit', use: { ...devices['iPhone 15'] } },
  ],
  webServer: {
    command: 'npm run preview -- --host 127.0.0.1 --port 4174 --strictPort',
    url: 'http://127.0.0.1:4174',
    reuseExistingServer: false,
    timeout: 30_000,
  },
});
