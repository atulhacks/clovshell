// The textarea owns the complete source and native editing/scrolling. Only its
// highlight backdrop and line-number gutter are windowed into the visible range.

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
  const editor = root.querySelector<HTMLElement>('.editor')!;
  const gutter = root.querySelector<HTMLElement>('.gutter-scroll')!;
  const hl = root.querySelector<HTMLElement>('.hl')!;
  const ta = root.querySelector<HTMLTextAreaElement>('textarea')!;
  const hlWindow = document.createElement('span');
  hlWindow.className = 'hl-window';
  hl.append(hlWindow);

  let currentArch = arch;
  let changeCb: (() => void) | null = null;
  let lines: string[] = [];
  let renderedStart = -1;
  let renderedEnd = -1;
  const OVERSCAN_LINES = 6;

  function renderGutter(start: number, end: number): void {
    const frag = document.createDocumentFragment();
    for (let i = start; i < end; i++) {
      const d = document.createElement('div');
      d.textContent = String(i + 1);
      frag.append(d);
    }
    gutter.replaceChildren(frag);
  }

  function metrics(): { lineHeight: number; paddingTop: number; paddingBottom: number } {
    const style = getComputedStyle(ta);
    return {
      lineHeight: parseFloat(style.lineHeight),
      paddingTop: parseFloat(style.paddingTop),
      paddingBottom: parseFloat(style.paddingBottom),
    };
  }

  function renderWindow(force = false): void {
    const { lineHeight } = metrics();
    const start = Math.max(0, Math.floor(ta.scrollTop / lineHeight) - OVERSCAN_LINES);
    const end = Math.min(lines.length, Math.ceil((ta.scrollTop + ta.clientHeight) / lineHeight) + OVERSCAN_LINES);
    if (force || start !== renderedStart || end !== renderedEnd) {
      hlWindow.innerHTML = highlightAsm(lines.slice(start, end).join('\n'), currentArch) + '\n';
      renderGutter(start, end);
      renderedStart = start;
      renderedEnd = end;
    }
    hlWindow.style.transform = `translate3d(${-ta.scrollLeft}px, ${start * lineHeight - ta.scrollTop}px, 0)`;
    gutter.style.transform = `translateY(${start * lineHeight - ta.scrollTop}px)`;
  }

  function refresh(): void {
    lines = ta.value.split('\n');
    const { lineHeight, paddingTop, paddingBottom } = metrics();
    const editorStyle = getComputedStyle(editor);
    const minHeight = parseFloat(editorStyle.minHeight);
    const maxHeight = parseFloat(editorStyle.maxHeight);
    editor.style.height = `${Math.min(maxHeight, Math.max(minHeight, lines.length * lineHeight + paddingTop + paddingBottom))}px`;
    renderWindow(true);
  }

  ta.addEventListener('input', () => {
    refresh();
    changeCb?.();
  });
  ta.addEventListener('scroll', () => renderWindow(), { passive: true });

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
