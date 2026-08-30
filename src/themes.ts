// Theme registry + wiring for the five color themes.
// The values live in style.css under `html[data-theme="…"]`; this module only
// flips the attribute, re-tints the favicon + <meta name="theme-color"> and
// renders the picker. Theme persists under its own localStorage key — it is
// deliberately not part of the shareable state (recipients keep their own).

import { el } from './ui';

export type ThemeId = 'mono' | 'purple' | 'orange' | 'red' | 'green';

export interface Theme {
  id: ThemeId;
  label: string;
  /** accent color — drives the favicon glyph and the picker dot */
  accent: string;
  /** page background — drives <meta name="theme-color"> and the favicon bg */
  bg: string;
}

export const DEFAULT_THEME: ThemeId = 'mono';
export const THEME_KEY = 'clovshell:theme';

export const THEMES: readonly Theme[] = [
  { id: 'mono', label: 'black & white', accent: '#ffffff', bg: '#080808' },
  { id: 'purple', label: 'purple', accent: '#a78bfa', bg: '#080609' },
  { id: 'orange', label: 'orange', accent: '#fb923c', bg: '#0a0705' },
  { id: 'red', label: 'red', accent: '#ef4444', bg: '#0a0505' },
  { id: 'green', label: 'green', accent: '#4ade80', bg: '#060806' },
];

export function isThemeId(v: unknown): v is ThemeId {
  return typeof v === 'string' && THEMES.some((t) => t.id === v);
}

export function getTheme(id: string): Theme {
  return THEMES.find((t) => t.id === id) ?? THEMES[0]!;
}

// the clover glyph — keep in sync with public/favicon.svg (the no-JS fallback)
const CLOVER =
  '<g transform="translate(16 17) rotate(45)" fill="{accent}">' +
  '<path d="M0 0 C -0.5 -5, -6 -9, -10 -5 C -13 -1, -8 3, 0 0 Z"/>' +
  '<path d="M0 0 C -0.5 -5, -6 -9, -10 -5 C -13 -1, -8 3, 0 0 Z" transform="rotate(90)"/>' +
  '<path d="M0 0 C -0.5 -5, -6 -9, -10 -5 C -13 -1, -8 3, 0 0 Z" transform="rotate(180)"/>' +
  '<path d="M0 0 C -0.5 -5, -6 -9, -10 -5 C -13 -1, -8 3, 0 0 Z" transform="rotate(270)"/>' +
  '</g>' +
  '<path d="M16 17 C 16 21, 17 24, 20 27" stroke="{accent}" stroke-width="1.6" fill="none" stroke-linecap="round"/>';

/** themed favicon as a data: URI (encodeURIComponent keeps `#` out of the URL) */
export function faviconHref(accent: string, bg: string): string {
  const svg =
    `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">` +
    `<rect width="32" height="32" rx="6" fill="${bg}"/>` +
    CLOVER.replaceAll('{accent}', accent) +
    `</svg>`;
  return `data:image/svg+xml,${encodeURIComponent(svg)}`;
}

export function loadSavedTheme(): ThemeId {
  try {
    const v = localStorage.getItem(THEME_KEY);
    return isThemeId(v) ? v : DEFAULT_THEME;
  } catch {
    return DEFAULT_THEME;
  }
}

function saveTheme(id: ThemeId): void {
  try {
    localStorage.setItem(THEME_KEY, id);
  } catch {
    /* storage unavailable — theme still applies for this visit */
  }
}

export function applyTheme(theme: Theme): void {
  // no `html[data-theme="mono"]` block exists — :root defaults apply
  document.documentElement.dataset.theme = theme.id;
  const meta = document.querySelector<HTMLMetaElement>('meta[name="theme-color"]');
  if (meta) meta.content = theme.bg;
  const icon = document.querySelector<HTMLLinkElement>('link[rel="icon"]');
  if (icon) icon.href = faviconHref(theme.accent, theme.bg);
}

/** apply the saved theme, render the dot picker and wire it up */
export function initTheme(): void {
  const current = loadSavedTheme();
  applyTheme(getTheme(current));

  const picker = document.getElementById('theme-picker');
  if (!picker) return;

  const dots = THEMES.map((t) =>
    el(
      'button',
      {
        class: 'theme-dot',
        type: 'button',
        role: 'radio',
        'aria-label': `${t.label} theme`,
        'aria-checked': String(t.id === current),
        tabindex: t.id === current ? '0' : '-1',
        style: `--dot:${t.accent}`,
        'data-theme-id': t.id,
      },
    ),
  );
  picker.append(...dots);

  const select = (id: ThemeId, focus = false): void => {
    applyTheme(getTheme(id));
    saveTheme(id);
    for (const d of dots) {
      const on = d.dataset.themeId === id;
      d.setAttribute('aria-checked', String(on));
      d.tabIndex = on ? 0 : -1;
      if (on && focus) d.focus();
    }
  };

  for (const d of dots) {
    d.addEventListener('click', () => select(d.dataset.themeId as ThemeId));
    d.addEventListener('keydown', (e) => {
      const delta =
        e.key === 'ArrowRight' || e.key === 'ArrowDown' ? 1
          : e.key === 'ArrowLeft' || e.key === 'ArrowUp' ? -1
            : 0;
      if (!delta) return;
      e.preventDefault();
      const next = dots[(dots.indexOf(d) + delta + dots.length) % dots.length]!;
      select(next.dataset.themeId as ThemeId, true);
    });
  }
}
