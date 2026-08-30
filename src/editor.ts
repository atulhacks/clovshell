// Code editor: transparent <textarea> over a syntax-highlighted <pre>,
// plus a scroll-synced line-number gutter.

import type { ArchDef } from './engines';
import { highlightAsm } from './highlight';

export interface EditorHandle {
  getValue(): string;
  setValue(v: string): void;
  setArch(arch: ArchDef): void;
  onChange(cb: () => void): void;
  /** insert text at the caret (replacing the selection), keeping focus */
  insertAtCursor(text: string): void;
}

export function createEditor(root: HTMLElement, initial: string, arch: ArchDef): EditorHandle {
  const gutter = root.querySelector<HTMLElement>('.gutter-scroll')!;
  const hl = root.querySelector<HTMLElement>('.hl')!;
  const ta = root.querySelector<HTMLTextAreaElement>('textarea')!;

  let currentArch = arch;
  let changeCb: (() => void) | null = null;

  function renderGutter(lineCount: number): void {
    const frag = document.createDocumentFragment();
    for (let i = 1; i <= Math.max(lineCount, 1); i++) {
      const d = document.createElement('div');
      d.textContent = String(i);
      frag.append(d);
    }
    gutter.replaceChildren(frag);
  }

  function refresh(): void {
    const value = ta.value;
    hl.innerHTML = highlightAsm(value, currentArch) + '\n';
    renderGutter(value.split('\n').length);
  }

  function syncScroll(): void {
    hl.scrollTop = ta.scrollTop;
    hl.scrollLeft = ta.scrollLeft;
    gutter.style.transform = `translateY(${-ta.scrollTop}px)`;
  }

  ta.addEventListener('input', () => {
    refresh();
    changeCb?.();
  });
  ta.addEventListener('scroll', syncScroll);

  // tab inserts spaces instead of moving focus
  ta.addEventListener('keydown', (e) => {
    if (e.key === 'Tab' && !e.shiftKey && !e.metaKey && !e.ctrlKey) {
      e.preventDefault();
      const { selectionStart: s, selectionEnd: en, value } = ta;
      ta.value = value.slice(0, s) + '    ' + value.slice(en);
      ta.selectionStart = ta.selectionEnd = s + 4;
      refresh();
      changeCb?.();
    }
  });

  ta.value = initial;
  currentArch = arch;
  refresh();

  return {
    getValue: () => ta.value,
    setValue(v: string) {
      ta.value = v;
      refresh();
      syncScroll();
    },
    setArch(a: ArchDef) {
      currentArch = a;
      refresh();
    },
    onChange(cb: () => void) {
      changeCb = cb;
    },
    insertAtCursor(text: string) {
      const { selectionStart: s, selectionEnd: en, value } = ta;
      // tidy separation from what's already there
      const before = value.slice(0, s);
      const needsNl = before.length > 0 && !before.endsWith('\n');
      const insert = (needsNl ? '\n' : '') + text;
      ta.value = before + insert + value.slice(en);
      ta.selectionStart = ta.selectionEnd = s + insert.length;
      refresh();
      changeCb?.();
      ta.focus();
    },
  };
}

// convenience: build the editor DOM skeleton into a container
export function editorTemplate(ariaLabel: string): HTMLElement {
  const wrap = document.createElement('div');
  wrap.className = 'editor';
  wrap.innerHTML = `
    <div class="gutter" aria-hidden="true"><div class="gutter-scroll"></div></div>
    <div class="code-area">
      <pre class="hl" aria-hidden="true"></pre>
      <textarea class="code-input" spellcheck="false" autocapitalize="off"
        autocomplete="off" autocorrect="off" wrap="off"
        aria-label="${ariaLabel}"></textarea>
    </div>`;
  return wrap;
}
