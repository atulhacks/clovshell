// Small DOM + clipboard helpers.

export function $<T extends HTMLElement = HTMLElement>(sel: string, root: ParentNode = document): T {
  const found = root.querySelector(sel);
  if (!found) throw new Error(`missing element: ${sel}`);
  return found as T;
}

export function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  attrs: Record<string, string> = {},
  ...children: (Node | string)[]
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, v);
  for (const child of children) {
    node.append(typeof child === 'string' ? document.createTextNode(child) : child);
  }
  return node;
}

// --- downloads ----------------------------------------------------------

function downloadBlob(name: string, blob: Blob): void {
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = name;
  document.body.append(a);
  a.click();
  a.remove();
  // give the click time to start before the URL goes away
  setTimeout(() => URL.revokeObjectURL(a.href), 2000);
}

export function downloadBytes(name: string, bytes: Uint8Array): void {
  downloadBlob(name, new Blob([bytes as BlobPart], { type: 'application/octet-stream' }));
}

export function downloadText(name: string, text: string, type = 'text/plain'): void {
  downloadBlob(name, new Blob([text], { type: `${type};charset=utf-8` }));
}

export async function copyText(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    // clipboard API unavailable (insecure context) — fall back
    try {
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.append(ta);
      ta.select();
      const ok = document.execCommand('copy');
      ta.remove();
      return ok;
    } catch {
      return false;
    }
  }
}

/** flash a copy button's label as confirmation */
export function flashCopyFeedback(button: HTMLElement, label = 'copy'): void {
  if (button.dataset.busy) return;
  button.dataset.busy = '1';
  const original = button.textContent;
  button.textContent = 'copied ✓';
  button.classList.add('copied');
  setTimeout(() => {
    button.textContent = original ?? label;
    button.classList.remove('copied');
    delete button.dataset.busy;
  }, 1200);
}

export function toast(message: string): void {
  const t = el('div', { class: 'toast', role: 'status' }, message);
  document.body.append(t);
  requestAnimationFrame(() => t.classList.add('show'));
  setTimeout(() => {
    t.classList.remove('show');
    setTimeout(() => t.remove(), 300);
  }, 2200);
}

// --- base64url helpers for shareable state -------------------------------

export function encodeState(obj: Record<string, string>): string {
  const json = JSON.stringify(obj);
  const b64 = btoa(String.fromCharCode(...new TextEncoder().encode(json)));
  return b64.replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
}

export function decodeState<T>(s: string): T | null {
  try {
    const b64 = s.replaceAll('-', '+').replaceAll('_', '/');
    const bin = atob(b64 + '='.repeat((4 - (b64.length % 4)) % 4));
    const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
    return JSON.parse(new TextDecoder().decode(bytes)) as T;
  } catch {
    return null;
  }
}
