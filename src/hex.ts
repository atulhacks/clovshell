// Hex parsing / formatting helpers.

export interface HexParseResult {
  bytes: Uint8Array;
  error: string | null;
}

export const MAX_HEX_BYTES = 64 * 1024;

/**
 * Lenient hex parser for the disassembly input box.
 * Accepts (and ignores) whitespace, commas, colons and dashes, strips
 * `0x` prefixes and understands `\xNN` escape sequences, so all of
 * these parse to the same bytes:
 *
 *   "b8736b6964"  "b8 73 6b 69 64"  "\\xb8\\x73..."  "0xb8, 0x73"
 */
export function parseHexInput(text: string): HexParseResult {
  if (text.length > MAX_HEX_BYTES * 4) {
    return { bytes: new Uint8Array(0), error: `hex input exceeds the ${MAX_HEX_BYTES}-byte limit` };
  }
  // expand \xNN escapes into plain hex pairs first
  let s = text.replace(/\\x([0-9a-fA-F]{2})/g, (_m, h: string) => h);
  // strip 0x / 0X prefixes
  s = s.replace(/0[xX]/g, '');
  // drop separators
  s = s.replace(/[\s,;:.\-]+/g, '');

  if (s.length === 0) return { bytes: new Uint8Array(0), error: null };
  if (s.length > MAX_HEX_BYTES * 2) {
    return { bytes: new Uint8Array(0), error: `hex input exceeds the ${MAX_HEX_BYTES}-byte limit` };
  }

  const bad = s.match(/[^0-9a-fA-F]/);
  if (bad && bad.index !== undefined) {
    const pos = bad.index;
    return {
      bytes: new Uint8Array(0),
      error: `invalid hex character "${s[pos]}" at position ${pos}`,
    };
  }
  if (s.length % 2 !== 0) {
    return {
      bytes: new Uint8Array(0),
      error: `odd number of hex digits (${s.length}) — need full bytes`,
    };
  }

  const bytes = new Uint8Array(s.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  }
  return { bytes, error: null };
}

/**
 * Parse a bad-character spec like "00 0a 20", "\\x00\\x0a", "0x00, 0x0a"
 * or "000a20" into a boolean[256] table. Returns null on garbage input
 * (any run of characters that isn't a byte value or a separator).
 */
export function parseBadChars(text: string): { bad: boolean[] } | null {
  const t = text.trim();
  if (!t) return { bad: new Array(256).fill(false) };
  const tokenRe = /(?:\\x|0[xX])?[0-9a-fA-F]{1,2}/g;
  const tokens = t.match(tokenRe);
  if (!tokens) return null;
  // whatever sits between the valid tokens must be pure separators
  const leftovers = t.replace(tokenRe, '').replace(/[\s,;]+/g, '');
  if (leftovers.length > 0) return null;
  const bad = new Array(256).fill(false);
  for (const tok of tokens) {
    const h = tok.replace(/\\x|0[xX]/gi, '');
    const v = parseInt(h, 16);
    if (!Number.isInteger(v) || v > 0xff) return null;
    bad[v] = true;
  }
  return { bad };
}

/** continuous lowercase hex, e.g. "b8736b6964" */
export function toHex(bytes: Uint8Array): string {
  let out = '';
  for (const b of bytes) out += b.toString(16).padStart(2, '0');
  return out;
}

/** space-separated hex, e.g. "b8 73 6b 69 64" */
export function toSpacedHex(bytes: Uint8Array): string {
  const parts: string[] = [];
  for (const b of bytes) parts.push(b.toString(16).padStart(2, '0'));
  return parts.join(' ');
}

export function countNullBytes(bytes: Uint8Array): number {
  let n = 0;
  for (const b of bytes) if (b === 0) n++;
  return n;
}

/** count bytes matching the bad-character table */
export function countBadBytes(bytes: Uint8Array, bad: boolean[]): number {
  let n = 0;
  for (const b of bytes) if (bad[b]) n++;
  return n;
}

/** human summary of the bad-char set, e.g. "00 0a 20" */
export function describeBadChars(bad: boolean[]): string {
  const parts: string[] = [];
  for (let i = 0; i < 256; i++) if (bad[i]) parts.push(i.toString(16).padStart(2, '0'));
  return parts.join(' ') || 'none';
}

export function formatAddress(addr: number): string {
  return addr.toString(16).padStart(8, '0');
}
