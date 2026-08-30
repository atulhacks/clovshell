// Lightweight assembly syntax highlighter producing HTML for the editor's
// backdrop layer. Per-arch register sets, numbers, strings, labels,
// directives and comments.

import type { ArchDef } from './engines';
import { findCommentIndex } from './comments';

export function escapeHtml(s: string): string {
  return s
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;');
}

interface TokenSpec {
  re: string;
  cls: string;
}

function operandRegex(arch: ArchDef): RegExp {
  const specs: TokenSpec[] = [
    { re: String.raw`"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'`, cls: 'tok-str' },
    { re: arch.registerRe, cls: 'tok-reg' },
    { re: String.raw`0[xX][0-9a-fA-F]+`, cls: 'tok-num' },
    { re: String.raw`#(?:0[xX][0-9a-fA-F]+|-?\d+)`, cls: 'tok-num' },
    { re: String.raw`-?\b\d+\b`, cls: 'tok-num' },
    { re: String.raw`[.\w$]+`, cls: 'tok-id' },
  ];
  return new RegExp(specs.map((s) => `(${s.re})`).join('|'), 'g');
}

function highlightCode(code: string, arch: ArchDef): string {
  const re = operandRegex(arch);
  let out = '';
  let last = 0;
  for (const m of code.matchAll(re)) {
    const idx = m.index ?? 0;
    out += escapeHtml(code.slice(last, idx));
    const groups = m.slice(1);
    const gi = groups.findIndex((g) => g !== undefined);
    const cls = gi === -1 ? '' : ['tok-str', 'tok-reg', 'tok-num', 'tok-num', 'tok-num', 'tok-id'][gi];
    out += `<span class="${cls}">${escapeHtml(m[0])}</span>`;
    last = idx + m[0].length;
  }
  out += escapeHtml(code.slice(last));
  return out;
}

export function highlightAsm(source: string, arch: ArchDef): string {
  const lines = source.split('\n');
  const html = lines.map((line) => {
    const ci = findCommentIndex(line, arch);
    const codePart = ci === -1 ? line : line.slice(0, ci);
    const commentPart = ci === -1 ? '' : line.slice(ci);

    let out = '';
    let rest = codePart;

    // leading whitespace
    const ws = rest.match(/^\s*/)?.[0] ?? '';
    out += escapeHtml(ws);
    rest = rest.slice(ws.length);

    // directive or label
    const label = rest.match(/^([.\w$]+:)/);
    if (label) {
      out += `<span class="tok-label">${escapeHtml(label[1]!)}</span>`;
      rest = rest.slice(label[1]!.length);
    } else {
      const mnem = rest.match(/^([.\w$]+)/);
      if (mnem) {
        const cls = mnem[1]!.startsWith('.') ? 'tok-dir' : 'tok-mnem';
        out += `<span class="${cls}">${escapeHtml(mnem[1]!)}</span>`;
        rest = rest.slice(mnem[1]!.length);
      }
    }

    out += highlightCode(rest, arch);
    if (commentPart) out += `<span class="tok-comment">${escapeHtml(commentPart)}</span>`;
    return out || '&nbsp;';
  });
  return html.join('\n');
}

/** Highlight disassembler output text (mnemonic + operands) for the listing. */
export function highlightInstruction(mnemonic: string, opStr: string, arch: ArchDef): string {
  const mnemHtml = `<span class="tok-mnem">${escapeHtml(mnemonic)}</span>`;
  if (!opStr) return mnemHtml;
  return `${mnemHtml} ${highlightCode(opStr, arch)}`;
}
