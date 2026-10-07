import { expect, test } from '@playwright/test';
import type { Page } from '@playwright/test';

async function openWorkbench(page: Page): Promise<void> {
  await page.goto('/');
  await expect(page.locator('#btn-assemble')).toBeEnabled();
  await expect(page.locator('#btn-disassemble')).toBeEnabled();
}

test('assembles and disassembles every supported mode', async ({ page }) => {
  await openWorkbench(page);
  const cases = [
    { arch: 'x86-64', source: 'mov eax, 42\nret' },
    { arch: 'x86-32', source: 'mov eax, 42\nret' },
    { arch: 'arm', source: 'mov r0, #42\nbx lr' },
    { arch: 'arm64', source: 'mov x0, #42\nret' },
  ];
  for (const item of cases) {
    await page.locator('#arch-select').selectOption(item.arch);
    await page.locator('#asm-editor-host textarea').fill(item.source);
    await page.locator('#btn-assemble').click();
    await expect(page.locator('#asm-msg')).toContainText('assembled');
    await page.locator('#btn-use-asm').click();
    await expect(page.locator('#hex-msg')).toContainText('decoded');
    await expect(page.locator('#disasm-listing .row')).toHaveCount(2);
  }
});

test('maximum-size input decodes without blocking the listing', async ({ page, browserName }) => {
  test.skip(browserName !== 'chromium', 'large-input browser regression runs once in Chromium');
  await openWorkbench(page);
  await page.locator('#hex-input').fill('90'.repeat(64 * 1024));
  await expect(page.locator('#hex-msg')).toContainText('65536 instructions');
  await expect(page.locator('#disasm-listing .row')).toHaveCount(500);
  await page.locator('#disasm-listing .listing-more').click();
  await expect(page.locator('#disasm-listing .row')).toHaveCount(1000);
});

test('superseded decode cannot overwrite newer input', async ({ page, browserName }) => {
  test.skip(browserName !== 'chromium', 'worker cancellation regression runs once in Chromium');
  await openWorkbench(page);
  await page.locator('#hex-input').fill('90'.repeat(64 * 1024));
  await page.locator('#hex-input').fill('c3');
  await expect(page.locator('#hex-msg')).toContainText('decoded 1 instruction');
  await expect(page.locator('#disasm-listing .row')).toHaveCount(1);
});

test('reloads and runs offline after installation', async ({ page, context, browserName }) => {
  // Playwright 1.63 WebKit aborts SW-served navigations after setOffline(true):
  // https://github.com/microsoft/playwright/issues/42775
  test.skip(browserName !== 'chromium', 'offline navigation is verified in Chromium');
  await openWorkbench(page);
  await page.waitForFunction(() => navigator.serviceWorker?.controller != null);
  await context.setOffline(true);
  await page.reload();
  await expect(page.locator('#btn-assemble')).toBeEnabled();
  await page.locator('#hex-input').fill('90 c3');
  await expect(page.locator('#hex-msg')).toContainText('decoded 2 instructions');
});
