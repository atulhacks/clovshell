import { describe, expect, it } from 'vitest';
import {
  countBadBytes,
  countNullBytes,
  describeBadChars,
  formatAddress,
  parseBadChars,
  parseHexInput,
  toHex,
  toSpacedHex,
} from '../hex';

describe('parseHexInput', () => {
  it('accepts every common spelling of the same bytes', () => {
    for (const text of ['b8736b6964', 'b8 73 6b 69 64', 'B8736B6964', 'b8,73,6b,69,64', 'b8-73-6b-69-64']) {
      expect(toHex(parseHexInput(text).bytes)).toBe('b8736b6964');
    }
  });

  it('expands \\xNN escapes', () => {
    expect(toHex(parseHexInput('\\xb8\\x73\\x6b').bytes)).toBe('b8736b');
  });

  it('strips 0x prefixes and separators', () => {
    expect(toHex(parseHexInput('0xb8, 0x73 - 0x6b: 69 64').bytes)).toBe('b8736b6964');
  });

  it('returns empty bytes for empty input', () => {
    const res = parseHexInput('   ');
    expect(res.bytes.length).toBe(0);
    expect(res.error).toBeNull();
  });

  it('rejects non-hex characters with a position', () => {
    const res = parseHexInput('b8 zz');
    expect(res.error).toMatch(/invalid hex character/);
  });

  it('rejects an odd number of digits', () => {
    expect(parseHexInput('b873').error).toBeNull(); // even
    expect(parseHexInput('b873f').error).toMatch(/odd number/);
  });
});

describe('parseBadChars', () => {
  it('parses plain hex pairs', () => {
    const res = parseBadChars('00 0a 20');
    expect(res).not.toBeNull();
    expect(res!.bad[0x00]).toBe(true);
    expect(res!.bad[0x0a]).toBe(true);
    expect(res!.bad[0x20]).toBe(true);
    expect(res!.bad[0x41]).toBe(false);
  });

  it('parses \\xNN and 0xNN spellings', () => {
    expect(parseBadChars('\\x00\\x0a')!.bad[0x0a]).toBe(true);
    expect(parseBadChars('0x00, 0x0a')!.bad[0x0a]).toBe(true);
  });

  it('parses run-together hex', () => {
    const res = parseBadChars('000a20');
    expect(res!.bad[0x00]).toBe(true);
    expect(res!.bad[0x0a]).toBe(true);
    expect(res!.bad[0x20]).toBe(true);
  });

  it('empty input means no bad characters', () => {
    const res = parseBadChars('');
    expect(res!.bad.every((b) => !b)).toBe(true);
  });

  it('rejects garbage', () => {
    expect(parseBadChars('zz qw')).toBeNull();
    expect(parseBadChars('00 zz')).toBeNull();
    expect(parseBadChars('x0')).toBeNull();
  });

  it('single-digit values are valid bytes', () => {
    expect(parseBadChars('0 a f')!.bad[0x0f]).toBe(true);
  });
});

describe('counters and formatters', () => {
  const bytes = Uint8Array.from([0x00, 0x0a, 0x20, 0x41, 0x00]);

  it('countNullBytes counts zeroes', () => {
    expect(countNullBytes(bytes)).toBe(2);
  });

  it('countBadBytes counts table hits', () => {
    const { bad } = parseBadChars('00 0a')!;
    expect(countBadBytes(bytes, bad)).toBe(3);
  });

  it('describeBadChars lists the set in hex', () => {
    expect(describeBadChars(parseBadChars('00 0a 20')!.bad)).toBe('00 0a 20');
    expect(describeBadChars(parseBadChars('')!.bad)).toBe('none');
  });

  it('toHex / toSpacedHex format bytes', () => {
    expect(toHex(Uint8Array.from([0xb8, 0x73]))).toBe('b873');
    expect(toSpacedHex(Uint8Array.from([0xb8, 0x73]))).toBe('b8 73');
  });

  it('formatAddress pads to 8 hex digits', () => {
    expect(formatAddress(4)).toBe('00000004');
  });
});
