// Boot loader: the overlay that covers the app until the engines are up.
// The hex line is "clovshell" itself as machine code — cells flicker like an
// assembler working and lock in as each engine milestone lands. Everything is
// driven through the same CSS custom properties as the rest of the app, so the
// loader is born already wearing the saved theme (the pre-paint script in
// index.html runs before this module does).

const NAME_BYTES = 'clovshell'.split('').map((c) => c.charCodeAt(0).toString(16).padStart(2, '0'));

/** cells locked per milestone — keystone lands 6, capstone 8, first assemble all 9 */
const LOCKS: Record<string, number> = { keystone: 6, capstone: 8, assemble: NAME_BYTES.length };

const STATUS: Record<string, string> = {
  keystone: '// loading keystone.wasm · 4.3 MB',
  capstone: '// loading capstone.wasm · 1.8 MB',
  assemble: '// assembling',
};

const HEX_DIGITS = '0123456789abcdef';

let boot: HTMLElement | null = null;
let cells: HTMLElement[] = [];
let statusEl: HTMLElement | null = null;
let flicker: ReturnType<typeof setInterval> | null = null;
let locked = 0;

const randByte = (): string =>
  HEX_DIGITS[Math.floor(Math.random() * 16)]! + HEX_DIGITS[Math.floor(Math.random() * 16)]!;

function lock(to: number): void {
  locked = Math.max(locked, to);
  for (let i = 0; i < cells.length; i++) {
    const cell = cells[i]!;
    if (i < locked) {
      if (cell.textContent !== NAME_BYTES[i]) {
        cell.textContent = NAME_BYTES[i]!;
        cell.classList.add('on');
      }
    } else {
      // unlocked: random byte while flickering, quiet placeholder otherwise
      cell.textContent = flicker === null ? '··' : randByte();
    }
  }
}

function dismiss(): void {
  if (flicker !== null) {
    clearInterval(flicker);
    flicker = null;
  }
  if (!boot) return;
  boot.classList.add('done');
  const node = boot;
  setTimeout(() => node.remove(), 600);
  boot = null; // later calls (fail after done, double-done) are no-ops
}

/** find the overlay and start the flicker — called first thing in main.ts */
export function initBoot(): void {
  boot = document.getElementById('boot');
  if (!boot) return;
  cells = [...boot.querySelectorAll<HTMLElement>('.boot-hex b')];
  statusEl = document.getElementById('boot-status');
  if (cells.length !== NAME_BYTES.length) return; // markup drifted — show static loader

  lock(0);
  const reduce = window.matchMedia?.('(prefers-reduced-motion: reduce)').matches ?? false;
  if (reduce) return; // no flicker — cells stay '··' until they lock
  flicker = setInterval(() => {
    for (let i = locked; i < cells.length; i++) cells[i]!.textContent = randByte();
  }, 90);
}

/** engine milestone: keystone | capstone | assemble */
export function bootStage(stage: 'keystone' | 'capstone' | 'assemble'): void {
  if (!boot || !statusEl) return;
  statusEl.textContent = STATUS[stage] ?? statusEl.textContent;
  lock(LOCKS[stage] ?? 0);
}

/** engines up, first assemble done — fade the loader away */
export function bootDone(): void {
  if (boot) lock(NAME_BYTES.length);
  dismiss();
}

/** engines failed — get out of the way so the fatal error is visible */
export function bootFail(): void {
  dismiss();
}
