// Assembler-directive handling. keystone is a pure instruction assembler:
// it ignores some directives, rejects others (`_type_` on ARM32) and crashes
// its wasm heap outright on `.text` / `.data` (section switching touches memory
// it doesn't own in the wasm build). Directives are therefore removed before
// the source reaches keystone — line-preserving, so error positions survive.

/** directives that emit raw bytes and assemble fine — pass them through */
const DATA_DIRECTIVES = new Set([
  'ascii', 'asciz', 'byte', 'fill', 'long', 'octa', 'quad', 'short',
  'skip', 'space', 'string', 'word', 'xword', 'zero',
]);

/** label definition (`loop:`, `.L1:`) — survives even though `.L1:` starts with a dot */
const LABEL_RE = /^\s*\.?[A-Za-z_$][\w$]*\s*:/;

/**
 * Blank out assembler directives keystone can't assemble (`.global`, `.type`,
 * `.section`, `.cfi_*`…), keeping data-emitting directives (`.byte`, `.asciz`…)
 * and label definitions. Unrecognized dot-directives are dropped silently —
 * in practice they are compiler metadata, never code.
 */
export function stripDirectives(src: string): string {
  return src
    .split('\n')
    .map((line) => {
      const trimmed = line.trimStart();
      if (!trimmed.startsWith('.') || LABEL_RE.test(line)) return line;
      const name = trimmed.slice(1).match(/^[A-Za-z_][\w-]*/)?.[0] ?? '';
      return DATA_DIRECTIVES.has(name.toLowerCase()) ? line : '';
    })
    .join('\n');
}
