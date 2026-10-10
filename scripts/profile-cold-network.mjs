import { writeFile } from 'node:fs/promises';
import { chromium } from '@playwright/test';

const defaults = {
  url: 'https://atulhacks.github.io/clovshell/',
  samples: 3,
  mbps: 8,
  latencyMs: 80,
  output: '',
};

function optionsFrom(args) {
  const options = { ...defaults };
  for (let index = 0; index < args.length; index += 2) {
    const key = args[index]?.replace(/^--/, '');
    const value = args[index + 1];
    if (!key || value === undefined || !Object.hasOwn(options, key)) {
      throw new Error(`unknown or incomplete option: ${args[index] ?? '(empty)'}`);
    }
    options[key] = key === 'samples' || key === 'mbps' || key === 'latencyMs' ? Number(value) : value;
  }
  new URL(options.url);
  if (!Number.isInteger(options.samples) || options.samples < 1 || options.samples > 20) {
    throw new Error('--samples must be an integer from 1 to 20');
  }
  if (!Number.isFinite(options.mbps) || options.mbps <= 0 || options.mbps > 1000) {
    throw new Error('--mbps must be greater than 0 and at most 1000');
  }
  if (!Number.isFinite(options.latencyMs) || options.latencyMs < 0 || options.latencyMs > 5000) {
    throw new Error('--latencyMs must be from 0 to 5000');
  }
  return options;
}

function median(values) {
  const sorted = [...values].sort((a, b) => a - b);
  const middle = Math.floor(sorted.length / 2);
  return sorted.length % 2 ? sorted[middle] : (sorted[middle - 1] + sorted[middle]) / 2;
}

const options = optionsFrom(process.argv.slice(2));
const throughput = options.mbps * 1_000_000 / 8;
const browser = await chromium.launch();
const samples = [];

try {
  for (let index = 0; index < options.samples; index++) {
    const context = await browser.newContext({ serviceWorkers: 'block' });
    try {
      const page = await context.newPage();
      const errors = [];
      page.on('pageerror', (error) => errors.push(error.message));
      const cdp = await context.newCDPSession(page);
      await cdp.send('Network.enable');
      await cdp.send('Network.setCacheDisabled', { cacheDisabled: true });
      await cdp.send('Network.setBypassServiceWorker', { bypass: true });
      await cdp.send('Network.emulateNetworkConditionsByRule', {
        matchedNetworkConditions: [{
          urlPattern: '',
          latency: options.latencyMs,
          downloadThroughput: throughput,
          uploadThroughput: throughput,
          offline: false,
        }],
      });
      await page.goto(options.url, { waitUntil: 'domcontentloaded', timeout: 90_000 });
      await page.waitForFunction(() => {
        const button = document.querySelector('#btn-assemble');
        return button instanceof HTMLButtonElement && !button.disabled;
      }, null, { timeout: 90_000 });
      const timing = await page.evaluate(() => {
        const navigation = performance.getEntriesByType('navigation')[0];
        const assets = performance.getEntriesByType('resource')
          .filter((entry) => /\.wasm(?:$|\?)|\/assets\//.test(entry.name))
          .map((entry) => ({
            name: entry.name.split('/').at(-1),
            startMs: Math.round(entry.startTime),
            endMs: Math.round(entry.responseEnd),
            transferBytes: entry.transferSize,
            encodedBodyBytes: entry.encodedBodySize,
            decodedBodyBytes: entry.decodedBodySize,
          }));
        return {
          readyMs: Math.round(performance.now()),
          domContentLoadedMs: Math.round(navigation?.domContentLoadedEventEnd ?? 0),
          assets,
        };
      });
      samples.push({ ...timing, pageErrors: errors });
    } finally {
      await context.close();
    }
  }
} finally {
  await browser.close();
}

const report = {
  url: options.url,
  sampledAt: new Date().toISOString(),
  profile: { samples: options.samples, mbps: options.mbps, latencyMs: options.latencyMs,
    browser: 'Playwright Chromium', cache: 'disabled', serviceWorkers: 'blocked' },
  medianReadyMs: median(samples.map((sample) => sample.readyMs)),
  samples,
};
const json = JSON.stringify(report, null, 2) + '\n';
if (options.output) await writeFile(options.output, json);
process.stdout.write(json);
