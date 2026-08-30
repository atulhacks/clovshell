import { describe, expect, it } from 'vitest';
import { FORMATS } from '../formats';

const BYTES = Uint8Array.from([0xb8, 0x73, 0x6b, 0x69, 0x64, 0x00, 0x22, 0x5c]);

describe('FORMATS', () => {
  it('every format has a unique id and a file extension', () => {
    const ids = new Set<string>();
    for (const fmt of FORMATS) {
      expect(ids.has(fmt.id)).toBe(false);
      ids.add(fmt.id);
      expect(fmt.ext).toMatch(/^[a-z0-9]{1,4}$/);
    }
    expect(FORMATS.length).toBeGreaterThanOrEqual(14);
  });

  it('python: escaped byte string with quote/backslash escaping', () => {
    const out = FORMATS.find((f) => f.id === 'python')!.make(BYTES);
    expect(out).toBe('b"\\xb8\\x73\\x6b\\x69\\x64\\x00\\"\\\\"');
  });

  it('c / csharp / java / rust emit braced byte arrays', () => {
    expect(FORMATS.find((f) => f.id === 'c')!.make(BYTES)).toContain('unsigned char shellcode[] = {');
    expect(FORMATS.find((f) => f.id === 'c')!.make(BYTES)).toContain('0xb8');
    expect(FORMATS.find((f) => f.id === 'csharp')!.make(BYTES)).toContain('byte[] shellcode');
    expect(FORMATS.find((f) => f.id === 'java')!.make(BYTES)).toContain('(byte) 0xb8');
    expect(FORMATS.find((f) => f.id === 'rust')!.make(BYTES)).toContain('[u8; 8]');
  });

  it('c-string escapes specials and terminates with a nul', () => {
    // 0x22 -> \" and 0x5c -> \\ inside the literal, then the terminator \x00
    expect(FORMATS.find((f) => f.id === 'c-string')!.make(BYTES)).toBe('"\\xb8\\x73\\x6b\\x69\\x64\\x00\\"\\\\\\x00"');
  });

  it('base64 round-trips', () => {
    const b64 = FORMATS.find((f) => f.id === 'base64')!.make(BYTES);
    const back = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
    expect(Array.from(back)).toEqual(Array.from(BYTES));
  });

  it('nasm uses db', () => {
    expect(FORMATS.find((f) => f.id === 'nasm')!.make(BYTES)).toContain('shellcode: db 0xb8');
  });

  it('yara wraps bytes in a rule', () => {
    const out = FORMATS.find((f) => f.id === 'yara')!.make(BYTES);
    expect(out).toContain('rule shellcode {');
    expect(out).toContain('B8 73 6B 69 64 00 22 5C');
  });

  it('empty bytes never produce garbage', () => {
    const empty = new Uint8Array(0);
    // escaped / base64 are legitimately '' — the app never calls make() with
    // empty bytes (renderExports guards), the contract is just "no garbage"
    expect(FORMATS.find((f) => f.id === 'escaped')!.make(empty)).toBe('');
    expect(FORMATS.find((f) => f.id === 'base64')!.make(empty)).toBe('');
    for (const fmt of FORMATS) {
      const out = fmt.make(empty);
      expect(typeof out).toBe('string');
      expect(out).not.toContain('undefined');
      expect(out).not.toContain('NaN');
    }
  });
});
