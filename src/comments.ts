// Comment detection shared by the syntax highlighter and the assembler
// preprocessor. One source of truth so what you SEE as a comment is exactly
// what gets STRIPPED before keystone sees the source.
//
// keystone's parser is gas-flavoured: `#` and `//` are comments, `;` is a
// statement *separator* and chokes on ordinary comment text — so clovshell
// treats `;` as a comment (NASM-style, what people actually type) and strips
// all comments before assembling. On ARM `#` also prefixes immediates.

import type { ArchDef } from './engines';

/**
 * Whether a comment starts at index `i` in `line`.
 * - `;`, `//` — comment on every arch (clovshell semantics)
 * - `#` — comment on x86; on ARM/ARM64 only when not an immediate (#1, #0x10, #-4, # 4)
 * - `@` — comment on ARM32 (gas syntax)
 */
export function commentStartAt(line: string, i: number, arch: ArchDef): boolean {
  if (line.startsWith('//', i)) return true;
  const c = line[i]!;
  if (c === ';') return true;
  if (c === '#') {
    if (arch.id === 'arm' || arch.id === 'arm64') {
      return !/^#\s*(0[xX][0-9a-fA-F]+|-?\d)/.test(line.slice(i));
    }
    return true;
  }
  if (c === '@' && arch.id === 'arm') return true;
  return false;
}

/** Index where the line's comment begins (-1 if none). Quote-aware. */
export function findCommentIndex(line: string, arch: ArchDef): number {
  let inStr: string | null = null;
  for (let i = 0; i < line.length; i++) {
    const c = line[i]!;
    if (inStr) {
      if (c === '\\') i++;
      else if (c === inStr) inStr = null;
      continue;
    }
    if (c === '"' || c === "'") {
      inStr = c;
      continue;
    }
    if (commentStartAt(line, i, arch)) return i;
  }
  return -1;
}

/**
 * Remove comments from every line (keeping line structure intact so line
 * numbers still match the source the user sees). keystone never sees comment
 * text, so unicode, parens, dashes or anything else inside a comment cannot
 * break the assembler.
 */
export function stripComments(source: string, arch: ArchDef): string {
  return source
    .split('\n')
    .map((line) => {
      const cut = findCommentIndex(line, arch);
      return cut === -1 ? line : line.slice(0, cut);
    })
    .join('\n');
}
