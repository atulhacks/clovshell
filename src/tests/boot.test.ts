// Boot loader integrity: index.html markup ↔ boot.ts milestones ↔ style.css.
// The loader is pure HTML + CSS so it animates from first paint (main.ts is
// deferred); these checks keep the three sides from drifting apart.

import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

const read = (rel: string): string =>
  readFileSync(new URL(`../../${rel}`, import.meta.url), 'utf8');

const html = read('index.html');
const css = read('src/style.css');
const main = read('src/main.ts');
const engines = read('src/engines.ts');

describe('boot loader markup', () => {
  it('overlay sits at the top of body with clover, wordmark, hex line, status', () => {
    expect(html).toContain('id="boot"');
    expect(html).toContain('class="boot-clover"');
    expect(html).toContain('class="boot-word"');
    expect(html).toContain('id="boot-hex"');
    expect(html).toContain('id="boot-status"');
    expect(html.indexOf('id="boot"')).toBeLessThan(html.indexOf('class="rail"'));
  });

  it('the hex line spells "clovshell" as nine placeholder cells', () => {
    const hexRow = html.match(/id="boot-hex"[^>]*>\s*([\s\S]*?)<\/div>/)![1]!;
    const cells = hexRow.match(/<b>··<\/b>/g) ?? [];
    expect(cells).toHaveLength(9); // "clovshell".length — boot.ts asserts the same
  });

  it('is hidden entirely when JavaScript is off', () => {
    expect(html).toMatch(/<noscript>\s*<style>#boot \{ display: none; \}<\/style>/);
  });

  it('status line opens on the keystone stage', () => {
    expect(html).toContain('// loading keystone.wasm');
  });
});

describe('boot loader module + wiring', () => {
  it('milestones lock cells monotonically and cover every engine stage', () => {
    const boot = read('src/boot.ts');
    const locks = boot.match(/LOCKS: Record<string, number> = \{([\s\S]*?)\}/)![1]!;
    const keystone = Number(locks.match(/keystone: (\d+)/)![1]);
    const capstone = Number(locks.match(/capstone: (\d+)/)![1]);
    // the final stage locks the whole name, derived not hard-coded
    expect(locks).toContain('assemble: NAME_BYTES.length');
    expect(keystone).toBeGreaterThan(0);
    expect(capstone).toBeGreaterThan(keystone);
    // status text exists for every lockable stage
    for (const stage of ['keystone', 'capstone', 'assemble']) {
      expect(boot).toContain(`${stage}: '`);
    }
  });

  it('boot.ts derives the hex line from the name, not a hand-typed list', () => {
    const boot = read('src/boot.ts');
    expect(boot).toContain(`'clovshell'.split('')`);
    // bytes must be lowercase two-digit hex, e.g. 63 6c 6f 76 73 68 65 6c 6c
    const expected = [...'clovshell'].map((c) => c.charCodeAt(0).toString(16).padStart(2, '0'));
    expect(boot).toContain(`NAME_BYTES`);
    expect(expected).toEqual([
      '63', '6c', '6f', '76', '73', '68', '65', '6c', '6c',
    ]);
  });

  it('main.ts starts the loader before initEngines and dismisses it on both paths', () => {
    expect(main).toContain('initBoot();');
    expect(main).toContain('initEngines((stage) => bootStage(stage))');
    expect(main).toContain('bootStage(\'assemble\')');
    expect(main).toContain('bootDone();');
    expect(main).toContain('bootFail();'); // fatal engine error must reveal the page
    expect(main.indexOf('initBoot();')).toBeLessThan(main.indexOf('initEngines('));
    // first paint order: theme, then loader, then engine boot
    expect(main.indexOf('initTheme();')).toBeLessThan(main.indexOf('initBoot();'));
  });

  it('engines.ts reports a stage after each wasm engine lands', () => {
    expect(engines).toMatch(/onStage\?\.\('keystone'\)/);
    expect(engines).toMatch(/onStage\?\.\('capstone'\)/);
  });
});

describe('boot loader styling', () => {
  it('overlay is opaque, above everything, and fades out via .done', () => {
    const rule = css.match(/\.boot \{[^}]*\}/)![0];
    expect(rule).toContain('position: fixed');
    expect(rule).toContain('inset: 0');
    expect(rule).toContain('background: var(--bg)'); // theme-aware, opaque
    expect(rule).toContain('z-index: 200');
    const done = css.match(/\.boot\.done \{[^}]*\}/)![0];
    expect(done).toContain('opacity: 0');
    expect(done).toContain('visibility: hidden');
  });

  it('every layer stays under the loader z-index', () => {
    const zis = [...css.matchAll(/z-index: (\d+)/g)].map((m) => Number(m[1]));
    expect(Math.max(...zis)).toBe(200);
  });

  it('styled only through theme tokens — no hardcoded colors', () => {
    const block = css.slice(css.search(/\/\* -+ boot loader/));
    expect(block).not.toMatch(/#[0-9a-f]{3,8}\b/i);
    for (const tok of ['var(--accent)', 'var(--fg)', 'var(--fg-faint)', 'var(--fg-dim)', 'var(--bg)']) {
      expect(block).toContain(tok);
    }
  });

  it('respects reduced motion: no entrance, pulse, pop or cursor blink', () => {
    const reduce = css.match(/@media \(prefers-reduced-motion: reduce\) \{[\s\S]*?\n\}/)![0];
    expect(reduce).toContain('.boot-clover { animation: none; }');
    expect(reduce).toContain('.boot-hex b.on { animation: none; }');
    expect(reduce).toContain('.boot-status::after { animation: none;');
  });

  it('service worker cache is derived from the built assets', () => {
    expect(read('public/sw.js')).toContain("CACHE = '__BUILD_CACHE__'");
    expect(read('scripts/finalize-sw.mjs')).toContain('PRECACHE_ASSETS');
  });
});
