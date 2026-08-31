// Theme system integrity: THEMES registry ↔ style.css ↔ index.html ↔ static
// assets. Everything reads the real source files, so a palette edit that
// forgets one side fails here.

import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import {
  DEFAULT_THEME, THEMES, THEME_KEY, faviconHref, getTheme, isThemeId,
} from '../themes';

const read = (rel: string): string =>
  readFileSync(new URL(`../../${rel}`, import.meta.url), 'utf8');

const css = read('src/style.css');
const html = read('index.html');

describe('THEMES registry', () => {
  it('has the five themes with unique ids, mono first', () => {
    expect(THEMES.map((t) => t.id)).toEqual(['mono', 'purple', 'orange', 'red', 'green']);
    expect(DEFAULT_THEME).toBe('mono');
    expect(THEME_KEY).toBe('clovshell:theme');
  });

  it('carries well-formed labels and colors', () => {
    for (const t of THEMES) {
      expect(t.label.length).toBeGreaterThan(0);
      expect(t.accent).toMatch(/^#[0-9a-f]{6}$/);
      expect(t.bg).toMatch(/^#[0-9a-f]{6}$/);
    }
  });
});

describe('style.css tokens per theme', () => {
  const BASE_TOKENS = [
    '--bg', '--bg-panel', '--bg-inset', '--bg-hover',
    '--border', '--border-bright', '--accent',
    '--fg', '--fg-dim', '--fg-faint',
  ] as const;

  // mono IS the :root default — no data-theme block exists for it
  for (const theme of THEMES.filter((t) => t.id !== DEFAULT_THEME)) {
    it(`html[data-theme="${theme.id}"] defines all base tokens with its palette`, () => {
      // the shared syntax-palette rule also selects these ids — take the
      // block that actually defines --accent
      const blocks = css.match(
        new RegExp(`html\\[data-theme="${theme.id}"\\]\\s*\\{[^}]*\\}`, 'g'),
      ) ?? [];
      const body = blocks.find((b) => b.includes('--accent:')) ?? '';
      expect(body, `missing html[data-theme="${theme.id}"] palette block`).not.toBe('');
      for (const tok of BASE_TOKENS) {
        expect(body, `${theme.id}: missing ${tok}`).toContain(`${tok}:`);
      }
      // the accent + bg from themes.ts must be the ones style.css ships
      expect(body).toContain(`--accent: ${theme.accent}`);
      expect(body).toContain(`--bg: ${theme.bg}`);
    });
  }

  it(':root is the mono default and defines derived tints via color-mix', () => {
    const root = css.match(/:root\s*\{([^}]*)\}/)![1];
    expect(root).toContain('--accent: #ffffff');
    for (const tok of BASE_TOKENS) expect(root).toContain(`${tok}:`);
    for (const tok of ['--tok-num', '--tok-reg', '--tok-str', '--tok-label', '--tok-dir']) {
      expect(root).toContain(`${tok}:`);
    }
    expect(root).toContain('--accent-soft: color-mix(in srgb, var(--accent) 12%, transparent)');
    expect(root).toContain('--bg-glow: color-mix(in srgb, var(--accent) 5%, transparent)');
  });

  it('no green-era remnants: --green tokens or hardcoded green rgba()', () => {
    expect(css).not.toContain('--green');
    expect(css).not.toContain('rgba(74, 222, 128');
    expect(css).not.toContain('rgba(27, 38, 27');
  });

  it('syntax tokens resolve through the --tok-* variables', () => {
    for (const cls of ['tok-num', 'tok-reg', 'tok-str', 'tok-label', 'tok-dir']) {
      const rule = css.match(new RegExp(`\\.${cls}\\s*\\{[^}]*\\}`))![0];
      expect(rule).toContain('var(--tok-');
      expect(rule).toContain('!important');
    }
  });
});

describe('faviconHref', () => {
  it('returns a data URI with the colors url-encoded', () => {
    const href = faviconHref('#a78bfa', '#080609');
    expect(href.startsWith('data:image/svg+xml,')).toBe(true);
    expect(href).toContain('%23a78bfa');
    expect(href).toContain('%23080609');
    expect(href).not.toContain('#'); // a raw # would truncate the URL
  });

  it('embeds the clover glyph (all four petals + stem)', () => {
    const href = decodeURIComponent(faviconHref('#ffffff', '#080808'));
    const petals = href.match(/rotate\(90\)|rotate\(180\)|rotate\(270\)/g) ?? [];
    expect(petals).toHaveLength(3); // + the un-rotated first petal
    expect(href).toContain('stroke-width="1.6"');
  });

  it('matches the mono fallback public/favicon.svg colors', () => {
    const mono = THEMES[0]!;
    const favicon = read('public/favicon.svg');
    expect(favicon).toContain(`fill="${mono.bg}"`);
    expect(favicon).toContain(`fill="${mono.accent}"`);
  });
});

describe('wiring: index.html + assets', () => {
  it('head script validates against every theme id before first paint', () => {
    expect(html).toContain('clovshell:theme');
    const whitelist = html.match(/\^\(mono\|purple\|orange\|red\|green\)\$/) ?? [];
    for (const t of THEMES) {
      expect(whitelist.join()).toContain(t.id);
    }
  });

  it('has the picker container and mono meta theme-color', () => {
    expect(html).toContain('id="theme-picker"');
    expect(html).toContain('role="radiogroup"');
    expect(html).toMatch(/<meta name="theme-color" content="#080808"/);
  });

  it('service worker cache and manifest are bumped to the mono palette', () => {
    expect(read('public/sw.js')).toContain("CACHE = 'clovshell-v1.2'");
    const manifest = read('public/manifest.webmanifest');
    expect(manifest).toContain('"background_color": "#080808"');
    expect(manifest).toContain('"theme_color": "#080808"');
  });
});

describe('getTheme / isThemeId', () => {
  it('falls back to mono for unknown ids', () => {
    expect(getTheme('bogus').id).toBe('mono');
    expect(getTheme('red').accent).toBe('#ef4444');
  });

  it('isThemeId accepts the five ids and rejects anything else', () => {
    for (const t of THEMES) expect(isThemeId(t.id)).toBe(true);
    expect(isThemeId('bogus')).toBe(false);
    expect(isThemeId(null)).toBe(false);
  });
});
