import { expect, test } from '@playwright/test';
import { readFile } from 'node:fs/promises';

const portable = (name: string): boolean => name.startsWith('mobile-') || name.startsWith('tablet-');

test('desktop Laboratory keeps one editor and restores its layout', async ({ page }, testInfo) => {
  test.skip(portable(testInfo.project.name), 'desktop layout');
  await page.goto('/');
  await expect(page.locator('#btn-assemble')).toBeEnabled();
  await expect(page.locator('#lab-shell')).toBeVisible();
  await expect(page.locator('#device-handoff')).toBeHidden();
  expect(await page.locator('#asm-editor-host textarea').count()).toBe(1);
  expect(await page.evaluate(() => {
    const ids = [...document.querySelectorAll('[id]')].map((node) => node.id);
    return ids.length === new Set(ids).size;
  })).toBe(true);

  await page.locator('#asm-editor-host textarea').evaluate((node) => { (node as HTMLTextAreaElement).dataset.identity = 'original'; });
  await page.locator('#lab-tab-trace').focus();
  await page.keyboard.press('ArrowRight');
  await expect(page.locator('#lab-tab-flow')).toHaveAttribute('aria-selected', 'true');
  await page.keyboard.press('End');
  await expect(page.locator('#lab-tab-reference')).toHaveAttribute('aria-selected', 'true');
  await expect(page.locator('#asm-editor-host textarea')).toHaveAttribute('data-identity', 'original');

  await page.locator('#lab-source-splitter').focus();
  const before = Number(await page.locator('#lab-source-splitter').getAttribute('aria-valuenow'));
  await page.keyboard.press('ArrowRight');
  const resized = Number(await page.locator('#lab-source-splitter').getAttribute('aria-valuenow'));
  expect(resized).toBeGreaterThan(before);
  await page.reload();
  await expect(page.locator('#btn-assemble')).toBeEnabled();
  await expect(page.locator('#lab-source-splitter')).toHaveAttribute('aria-valuenow', String(resized));
  await expect(page.locator('#lab-tab-reference')).toHaveAttribute('aria-selected', 'true');
  await page.locator('#lab-reset-layout').click();
  await expect(page.locator('#lab-tab-trace')).toHaveAttribute('aria-selected', 'true');
});

test('narrow desktop keeps the Laboratory and reveals evidence/inspector on demand', async ({ page }, testInfo) => {
  test.skip(portable(testInfo.project.name), 'desktop reflow');
  await page.setViewportSize({ width: 660, height: 760 });
  await page.goto('/');
  await expect(page.locator('#btn-assemble')).toBeEnabled();
  await expect(page.locator('#device-handoff')).toBeHidden();
  await page.locator('#lab-evidence-toggle').click();
  await expect(page.locator('#shellcode-out')).toBeVisible();
  await page.locator('#lab-inspector-toggle').click();
  await expect(page.locator('#btn-run-emu')).toBeVisible();
  await expect(page.locator('#lab-inspector-toggle')).toHaveAttribute('aria-expanded', 'true');
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  await page.setViewportSize({ width: 380, height: 480 });
  await expect(page.locator('#theme-picker')).toBeVisible();
  await page.locator('#lab-tab-tools').click();
  await expect(page.locator('#lab-tab-tools')).toHaveAttribute('aria-selected', 'true');
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
});

test('phones and tablets show the handoff without loading engines', async ({ page }, testInfo) => {
  test.skip(!portable(testInfo.project.name), 'portable device handoff');
  const requests: string[] = [];
  page.on('request', (request) => requests.push(request.url()));
  await page.goto('/#s=abc123');
  await expect(page.locator('#device-handoff')).toBeVisible();
  await expect(page.locator('#device-handoff')).toContainText('desktop computer');
  await expect(page.locator('#boot')).toBeHidden();
  await expect(page.locator('#btn-assemble')).toBeHidden();
  await expect(page.locator('#handoff-copy')).toBeVisible();
  expect(page.url()).toContain('#s=abc123');
  expect(requests.filter((url) => /\.wasm(?:$|\?)/.test(url))).toEqual([]);
});

test('iPadOS desktop-site fingerprint still gets the handoff', async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== 'chromium', 'one fingerprint regression');
  await page.addInitScript(() => {
    Object.defineProperty(navigator, 'platform', { configurable: true, value: 'MacIntel' });
    Object.defineProperty(navigator, 'maxTouchPoints', { configurable: true, value: 5 });
  });
  await page.goto('/');
  await expect(page.locator('#device-handoff')).toBeVisible();
  await expect(page.locator('#boot')).toBeHidden();
});

test('touchscreen desktop is admitted', async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== 'chromium', 'one desktop-touch regression');
  await page.addInitScript(() => {
    Object.defineProperty(navigator, 'platform', { configurable: true, value: 'Win32' });
    Object.defineProperty(navigator, 'maxTouchPoints', { configurable: true, value: 10 });
  });
  await page.goto('/');
  await expect(page.locator('#btn-assemble')).toBeEnabled();
});

test('legacy document state migrates and new fixture fields persist', async ({ page }, testInfo) => {
  test.skip(portable(testInfo.project.name), 'desktop session persistence');
  await page.addInitScript(() => {
    localStorage.setItem('clovshell:session:v2', '{malformed');
    localStorage.setItem('clovshell:v1', JSON.stringify({ arch: 'arm64', a: 'mov x0, #1\nret', h: 'c0 03 5f d6', bc: '00 0a' }));
  });
  await page.goto('/');
  await expect(page.locator('#btn-assemble')).toBeEnabled();
  await expect(page.locator('#arch-select')).toHaveValue('arm64');
  await expect(page.locator('#asm-editor-host textarea')).toHaveValue('mov x0, #1\nret');
  await page.locator('#lab-tab-scenarios').click();
  await page.locator('#scenario-input').fill('41 42');
  await page.locator('#scenario-args').fill('0, 2');
  await page.locator('#emu-arg').fill('0x2');
  const state = await page.evaluate(() => JSON.parse(localStorage.getItem('clovshell:session:v2') || 'null'));
  expect(state).toMatchObject({ v: 2, arch: 'arm64', fixture: '41 42', scenarios: '0, 2', arg: '0x2' });
});

test('a desktop run can be cancelled during assembly', async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== 'chromium', 'run cancellation regression');
  await page.goto('/');
  await expect(page.locator('#btn-assemble')).toBeEnabled();
  await page.evaluate(() => {
    document.querySelector<HTMLButtonElement>('#lab-run')!.click();
    document.querySelector<HTMLButtonElement>('#lab-cancel-run')!.click();
  });
  await expect(page.locator('#emu-msg')).toContainText('run cancelled');
  await expect(page.locator('#lab-run-state')).toContainText('CANCELLED');
  await expect(page.locator('#lab-cancel-run')).toBeHidden();
});

test('run history restores original architecture, evidence, and selection', async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== 'chromium', 'run-history browser regression runs once');
  await page.goto('/');
  await expect(page.locator('#btn-assemble')).toBeEnabled();
  const editor = page.locator('#asm-editor-host textarea');
  await editor.fill('nop\nret');
  await page.locator('#lab-run').click();
  await expect(page.locator('#lab-run-history-list .lab-run-row')).toHaveCount(1);
  await expect(page.locator('#lab-run-state')).toContainText('R1 / X86-64 / CURRENT');
  await page.locator('#trace-list .trace-row').nth(1).click();
  await expect(page.locator('#lab-selection')).toHaveText('TRACE #2');

  await page.locator('#arch-select').selectOption('arm64');
  await expect(page.locator('#lab-run-state')).toContainText('R1 / X86-64 / HISTORIC');
  await editor.fill('mov x0, #1\nret');
  await page.locator('#lab-run').click();
  await expect(page.locator('#lab-run-history-list .lab-run-row')).toHaveCount(2);
  await expect(page.locator('#lab-run-state')).toContainText('R2 / ARM64 / CURRENT');

  await page.locator('#lab-run-history-list [data-run-id="R1"]').click();
  await expect(page.locator('#lab-run-state')).toContainText('R1 / X86-64 / HISTORIC');
  await expect(page.locator('#lab-selection')).toHaveText('TRACE #2');
  await expect(page.locator('#trace-list .trace-row').nth(1)).toHaveAttribute('aria-current', 'step');
  const download = page.waitForEvent('download');
  await page.locator('#trace-download').click();
  const report = JSON.parse(await readFile(await (await download).path(), 'utf8')) as { architecture: string };
  expect(report.architecture).toBe('x86-64');

  await page.locator('#lab-tab-flow').click();
  await page.locator('#flow-filter').selectOption('all');
  await page.locator('#flow-list .flow-row').first().click();
  await expect(page.locator('#lab-selection')).toHaveText('FLOW #1');
  await expect(page.locator('#trace-list .trace-row.linked')).not.toHaveCount(0);
  await page.locator('#lab-run-history-list [data-run-id="R2"]').click();
  await page.locator('#lab-run-history-list [data-run-id="R1"]').click();
  await expect(page.locator('#lab-selection')).toHaveText('FLOW #1');
  await page.locator('#lab-clear-history').click();
  await expect(page.locator('#lab-run-state')).toHaveText('NO RUN');
  await expect(page.locator('#lab-run-history-list .lab-run-row')).toHaveCount(0);
});

test('syscall reference loads on demand and tracks the active architecture', async ({ page }, testInfo) => {
  test.skip(testInfo.project.name.startsWith('mobile-') || testInfo.project.name.startsWith('tablet-'), 'desktop reference');
  await page.goto('/');
  await expect(page.locator('#btn-assemble')).toBeEnabled();
  await expect(page.locator('#syscall-list .syscall-item')).toHaveCount(0);
  await page.locator('#arch-select').selectOption('arm64');
  await page.locator('#lab-tab-reference').click();
  await page.locator('#syscall-search').fill('exit');
  await expect(page.locator('#syscall-list .syscall-item').first()).toContainText('93');
  await page.locator('#syscall-list .syscall-item').first().click();
  await expect(page.locator('#asm-editor-host textarea')).toHaveValue(/mov x8, 93/);
  await page.locator('#arch-select').selectOption('x86-64');
  await expect(page.locator('#syscall-list .syscall-item').first()).toContainText('60');
});

test('small boot source assembles inline while later edits keep the worker path', async ({ browser }, testInfo) => {
  test.skip(testInfo.project.name !== 'chromium', 'cold-start assembly path regression');
  const context = await browser.newContext({ serviceWorkers: 'block' });
  try {
    const page = await context.newPage();
    const workerRequests: string[] = [];
    page.on('request', (request) => {
      if (request.url().includes('asm-worker')) workerRequests.push(request.url());
    });
    await page.goto('/');
    await expect(page.locator('#btn-assemble')).toBeEnabled();
    await expect(page.locator('#asm-msg')).toContainText('assembled');
    expect(workerRequests).toHaveLength(0);
    await page.locator('#asm-editor-host textarea').fill('nop\nret');
    await expect.poll(() => workerRequests.length).toBeGreaterThan(0);
    await expect(page.locator('#asm-msg')).toContainText('assembled 2 instructions');
  } finally {
    await context.close();
  }
});

test('large restored source uses the assembly worker at boot', async ({ browser }, testInfo) => {
  test.skip(testInfo.project.name !== 'chromium', 'cold-start assembly threshold regression');
  const context = await browser.newContext({ serviceWorkers: 'block' });
  try {
    const page = await context.newPage();
    await page.addInitScript(() => {
      localStorage.setItem('clovshell:session:v2', JSON.stringify({
        v: 2,
        arch: 'x86-64',
        a: 'nop\n'.repeat(200),
      }));
    });
    const workerRequests: string[] = [];
    page.on('request', (request) => {
      if (request.url().includes('asm-worker')) workerRequests.push(request.url());
    });
    await page.goto('/');
    await expect(page.locator('#asm-msg')).toContainText('assembled 200 instructions');
    expect(workerRequests.length).toBeGreaterThan(0);
  } finally {
    await context.close();
  }
});

test('desktop WASM preload is browser-specific and does not duplicate downloads', async ({ browser }, testInfo) => {
  test.skip(!['chromium', 'webkit'].includes(testInfo.project.name), 'desktop preload regression');
  const context = await browser.newContext({ serviceWorkers: 'block' });
  try {
    const page = await context.newPage();
    const wasmRequests: string[] = [];
    page.on('request', (request) => {
      const name = request.url().split('/').at(-1);
      if (name === 'keystone.wasm' || name === 'capstone.wasm') wasmRequests.push(name);
    });
    await page.goto('/');
    await expect(page.locator('#btn-assemble')).toBeEnabled();
    expect(wasmRequests.sort()).toEqual(['capstone.wasm', 'keystone.wasm']);
    const preloads = page.locator('link[rel="preload"][as="fetch"][type="application/wasm"]');
    await expect(preloads).toHaveCount(testInfo.project.name === 'chromium' ? 2 : 0);
  } finally {
    await context.close();
  }
});
