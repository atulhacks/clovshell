import { expect, test } from '@playwright/test';
import type { Page } from '@playwright/test';
import { readFile } from 'node:fs/promises';

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
    { arch: 'arm-thumb', source: 'movs r0, #42\nbx lr' },
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

test('superseded assembly cannot overwrite newer source', async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== 'chromium', 'worker cancellation regression runs once on desktop Chromium');
  await openWorkbench(page);
  const editor = page.locator('#asm-editor-host textarea');
  await editor.fill('nop\n'.repeat(500));
  await page.locator('#btn-assemble').click();
  await editor.fill('ret');
  await page.locator('#btn-assemble').click();
  await expect(page.locator('#asm-msg')).toContainText('assembled 1 instruction');
  await expect(page.locator('#shellcode-out')).toContainText('c3');
});

test('large assembly source keeps the editor window bounded while scrolling', async ({ page }) => {
  await openWorkbench(page);
  const editor = page.locator('#asm-editor-host textarea');
  const source = 'nop\n'.repeat(11_999) + 'ret';
  await page.evaluate((value) => {
    const input = document.querySelector<HTMLTextAreaElement>('#asm-editor-host textarea')!;
    input.value = value;
    input.dispatchEvent(new Event('input', { bubbles: true }));
  }, source);
  await expect.poll(() => page.locator('#asm-editor-host .gutter-scroll > div').count()).toBeLessThan(60);
  expect(await editor.evaluate((node) => node.value.length)).toBe(source.length);
  await editor.evaluate((node) => { node.scrollTop = node.scrollHeight; node.dispatchEvent(new Event('scroll')); });
  await expect(page.locator('#asm-editor-host .gutter-scroll > div').last()).toHaveText('12000');
  await expect(page.locator('#asm-editor-host .hl-window')).toContainText('ret');
  await expect.poll(() => page.locator('#asm-editor-host .gutter-scroll > div').count()).toBeLessThan(60);
  await editor.evaluate((node) => { node.focus(); node.setSelectionRange(node.value.length, node.value.length); });
  await page.keyboard.insertText('\nnop');
  await expect(page.locator('#asm-editor-host .gutter-scroll > div').last()).toHaveText('12001');
  expect(await editor.evaluate((node) => node.value.endsWith('\nnop'))).toBe(true);
});

test('runs assembled code through the emulator on every architecture', async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== 'chromium', 'emulator browser regression runs once on desktop Chromium');
  await openWorkbench(page);
  const cases = [
    { arch: 'x86-64', source: 'mov rdi, 42\nmov rax, 60\nsyscall' },
    { arch: 'x86-32', source: 'xor ebx, ebx\nmov al, 1\nint 0x80' },
    { arch: 'arm', source: 'mov r7, #1\nmov r0, #0\nsvc 0' },
    { arch: 'arm-thumb', source: 'movs r7, #1\nmovs r0, #0\nsvc #0' },
    { arch: 'arm64', source: 'mov x8, #94\nmov x0, #0\nsvc 0' },
  ];
  for (const item of cases) {
    await page.locator('#arch-select').selectOption(item.arch);
    await page.locator('#asm-editor-host textarea').fill(item.source);
    await page.locator('#btn-run-emu').click();
    await expect(page.locator('#emu-msg')).toContainText('steps ·');
    await expect(page.locator('#emu-msg')).not.toContainText('✗');
  }
});

test('Thumb execution reports its mode and decodes an in-place payload', async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== 'chromium', 'Thumb decoder browser regression runs once on desktop Chromium');
  await openWorkbench(page);
  await page.locator('#arch-select').selectOption('arm-thumb');
  await page.locator('#asm-editor-host textarea').fill('movs r0, #0\nmovs r7, #1\nsvc #0');
  await page.locator('#btn-assemble').click();
  await expect(page.locator('#asm-msg')).toContainText('assembled');
  await page.locator('#btn-encode').click();
  await expect(page.locator('#enc-preview')).toContainText('decode_loop');
  await page.locator('#btn-encode-load').click();
  await expect(page.locator('#emu-msg')).toContainText('exit(0)');
  await expect(page.locator('#stage-after-disasm')).toContainText('addw r4, pc');
  const evidencePromise = page.waitForEvent('download');
  await page.locator('#trace-download').click();
  const evidence = await evidencePromise;
  const report = JSON.parse(await readFile(await evidence.path(), 'utf8')) as {
    trace: { mode: string }[]; stages: { mode: string }[]; mutations: unknown[];
  };
  expect(report.trace.every((step) => step.mode === 'thumb')).toBe(true);
  expect(report.stages[0]?.mode).toBe('thumb');
  expect(report.mutations.length).toBeGreaterThan(0);
});

test('shows decoder writes and exports the reconstructed runtime stage', async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== 'chromium', 'mutation atlas browser regression runs once on desktop Chromium');
  await openWorkbench(page);
  await page.locator('#asm-editor-host textarea').fill('xor edi, edi\nmov eax, 60\nsyscall');
  await page.locator('#btn-assemble').click();
  await expect(page.locator('#asm-msg')).toContainText('assembled');
  await page.locator('#btn-encode').click();
  await expect(page.locator('#enc-preview')).not.toHaveClass(/empty/);
  await page.locator('#btn-encode-load').click();
  await expect(page.locator('#emu-msg')).toContainText('exit(0)');
  await expect(page.locator('#mutation-stats')).toContainText('executed');
  await expect(page.locator('#mutation-list .mutation-row').first()).toBeVisible();
  await expect(page.locator('#mutation-detail')).toContainText('original image');
  await expect(page.locator('#mutation-detail')).toContainText('first execution');
  const stagePromise = page.waitForEvent('download');
  await page.locator('#stage-download').click();
  const stage = await stagePromise;
  expect(stage.suggestedFilename()).toBe('runtime-stage-x86-64.bin');
  expect((await readFile(await stage.path())).toString('hex')).toContain('31ffb83c0000000f05');
  const evidencePromise = page.waitForEvent('download');
  await page.locator('#trace-download').click();
  const evidence = await evidencePromise;
  expect(evidence.suggestedFilename()).toBe('trace-x86-64.json');
  const report = JSON.parse(await readFile(await evidence.path(), 'utf8')) as {
    mutations: { writerStep: number; firstExecutionStep: number | null }[];
    finalCode: string;
  };
  expect(report.mutations.length).toBeGreaterThan(0);
  expect(report.mutations.some((mutation) => mutation.writerStep > 0 && mutation.firstExecutionStep != null)).toBe(true);
  expect(report.finalCode).toContain('31ffb83c0000000f05');
});

test('shows mapped-code provenance and downloads its first-execution snapshot', async ({ page }, testInfo) => {
  test.skip(testInfo.project.name.startsWith('mobile-'), 'stage graph download regression runs on desktop browsers');
  await openWorkbench(page);
  const source = [
    'xor edi, edi', 'mov esi, 4096', 'mov edx, 3', 'mov r10d, 0x22',
    'mov r8d, -1', 'xor r9d, r9d', 'mov eax, 9', 'syscall',
    'mov rbx, rax', 'lea rsi, [rip + payload]', 'mov rdi, rbx', 'mov ecx, 9',
    'rep movsb', 'mov rdi, rbx', 'mov esi, 4096', 'mov edx, 5',
    'mov eax, 10', 'syscall', 'jmp rbx',
    'payload:', 'xor edi, edi', 'mov eax, 60', 'syscall',
  ].join('\n');
  await page.locator('#asm-editor-host textarea').fill(source);
  await page.locator('#btn-run-emu').click();
  await expect(page.locator('#emu-msg')).toContainText('exit(0)');
  const mapped = page.locator('#stage-list .stage-row').filter({ hasText: 'mapped' });
  await expect(mapped).toHaveCount(1);
  await mapped.click();
  await expect(page.locator('#stage-detail')).toContainText('mmap');
  await expect(page.locator('#stage-detail')).toContainText('mprotect');
  await expect(page.locator('#stage-detail')).toContainText('r-x');
  await expect(page.locator('#stage-diff-stats')).toContainText('changed bytes');
  await expect(page.locator('#stage-before-disasm')).toContainText('zero-filled page');
  await expect(page.locator('#stage-after-disasm')).toContainText('xor edi, edi');
  await expect(page.locator('#stage-writer-context .stage-context-row.key')).toContainText('rep movsb');
  await expect(page.locator('#stage-execution-context .stage-context-row.key')).toContainText('xor edi, edi');
  const snapshotPromise = page.waitForEvent('download');
  await page.locator('#stage-snapshot-download').click();
  const snapshot = await snapshotPromise;
  expect(snapshot.suggestedFilename()).toMatch(/^stage-x86-64-S\d+-30000000\.bin$/);
  expect((await readFile(await snapshot.path())).subarray(0, 9).toString('hex')).toBe('31ffb83c0000000f05');
  const evidencePromise = page.waitForEvent('download');
  await page.locator('#trace-download').click();
  const evidence = await evidencePromise;
  const report = JSON.parse(await readFile(await evidence.path(), 'utf8')) as {
    stages: { origin: string; snapshot: string; writerStep: number | null }[];
    mapEvents: { operation: string }[];
  };
  expect(report.stages.find((stage) => stage.origin === 'mapped')).toMatchObject({
    snapshot: expect.stringContaining('31ffb83c0000000f05'),
    writerStep: expect.any(Number),
  });
  expect(report.mapEvents.map((event) => event.operation)).toEqual(['mmap', 'mprotect']);
});

test('retains post-cap writer and execution context in the Stage Explorer', async ({ page }, testInfo) => {
  test.skip(testInfo.project.name.startsWith('mobile-'), 'stage explorer evidence regression runs on desktop browsers');
  await openWorkbench(page);
  const source = [
    'mov ecx, 500', 'wait_loop:', 'dec ecx', 'jne wait_loop',
    'xor edi, edi', 'mov esi, 4096', 'mov edx, 3', 'mov r10d, 0x22',
    'mov r8d, -1', 'xor r9d, r9d', 'mov eax, 9', 'syscall',
    'mov rbx, rax', 'lea rsi, [rip + payload]', 'mov rdi, rbx', 'mov ecx, 9',
    'rep movsb', 'mov rdi, rbx', 'mov esi, 4096', 'mov edx, 5',
    'mov eax, 10', 'syscall', 'jmp rbx',
    'payload:', 'xor edi, edi', 'mov eax, 60', 'syscall',
  ].join('\n');
  await page.locator('#asm-editor-host textarea').fill(source);
  await page.locator('#btn-run-emu').click();
  await expect(page.locator('#emu-msg')).toContainText('exit(0)');
  await page.locator('#stage-list .stage-row').filter({ hasText: 'mapped' }).click();
  await expect(page.locator('#stage-writer-context .stage-context-row.key')).toContainText('rep movsb');
  await expect(page.locator('#stage-execution-context .stage-context-row.key')).toContainText('xor edi, edi');
  await expect(page.locator('#stage-diff-stats')).toContainText('changed bytes');
  await page.locator('#stage-writer-context .stage-context-row.key').click();
  await expect(page.locator('#stage-context-detail')).toContainText('rep movsb');
  await expect(page.locator('#stage-context-detail')).toContainText('rdi');
  await page.locator('#stage-execution-context .stage-context-row.key').click();
  await expect(page.locator('#stage-context-detail')).toContainText('xor edi, edi');
  const download = page.waitForEvent('download');
  await page.locator('#trace-download').click();
  const report = JSON.parse(await readFile(await (await download).path(), 'utf8')) as {
    stages: { origin: string; writerStep: number | null; firstExecutionStep: number;
      beforeSnapshot: string | null; writerContext: { number: number }[];
      executionContext: { number: number }[]; diff: { changedBytes: number } | null }[];
  };
  const mapped = report.stages.find((stage) => stage.origin === 'mapped')!;
  expect(mapped.writerStep).toBeGreaterThan(400);
  expect(mapped.writerContext.at(-1)?.number).toBe(mapped.writerStep);
  expect(mapped.executionContext.some((step) => step.number === mapped.firstExecutionStep)).toBe(true);
  expect(mapped.beforeSnapshot?.slice(0, 18)).toBe('000000000000000000');
  expect(mapped.diff?.changedBytes).toBeGreaterThan(0);
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
