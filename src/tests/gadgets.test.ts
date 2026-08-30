import { beforeAll, describe, expect, it } from 'vitest';
import { assemble, initEngines } from '../engines';
import { findGadgets, gadgetRows } from '../gadgets';

beforeAll(async () => {
  await initEngines();
});

describe('findGadgets', () => {
  it('finds pop/call/ret sequences inside a gadget soup', () => {
    // 5f 5e 5a 59 58 c3 | 48 89 e7 c3 | 0f 05 c3 | 5b c9 c3
    const bytes = Uint8Array.from([0x5f, 0x5e, 0x5a, 0x59, 0x58, 0xc3, 0x48, 0x89, 0xe7, 0xc3, 0x0f, 0x05, 0xc3, 0x5b, 0xc9, 0xc3]);
    const res = findGadgets('x86-64', bytes);
    expect(Array.isArray(res)).toBe(true);
    if (!Array.isArray(res)) return;
    const texts = res.map((g) => g.text);
    expect(texts).toContain('ret');
    // the stream has 5f 5e 5a 59 58 c3 — a "pop rdi ; ret" would need 5f c3
    // adjacency, which isn't there; what IS there is the five-pop chain
    expect(texts).toContain('pop rdi ; pop rsi ; pop rdx ; pop rcx ; pop rax ; ret');
    expect(texts).toContain('pop rsi ; pop rdx ; pop rcx ; pop rax ; ret');
    expect(texts.some((t) => t.startsWith('syscall'))).toBe(true);
    // leave is itself a terminator, so a gadget ENDS at it — from 5b c9 c3 the
    // gadgets are "pop rbx ; leave" and "leave", never "leave ; ret"
    expect(texts).toContain('pop rbx ; leave');
    expect(texts).toContain('leave');
  });

  it('finds arm64 control-flow gadgets', () => {
    // ldr x0,[sp,#8] / ret / br x1 / blr x2 / ret
    const src = 'ldr x0, [sp, #8]\nret\nbr x1\nblr x2\nret';
    const bytes = assemble('arm64', src).bytes!;
    const res = findGadgets('arm64', bytes);
    expect(Array.isArray(res)).toBe(true);
    if (!Array.isArray(res)) return;
    const texts = res.map((g) => g.text);
    expect(texts).toContain('ret');
    expect(texts).toContain('br x1');
    expect(texts.some((t) => t.startsWith('ldr x0'))).toBe(true);
  });

  it('deduplicates identical instruction sequences', () => {
    // two separate `ret` bytes at different offsets — one gadget text
    const bytes = Uint8Array.from([0xc3, 0x90, 0x90, 0xc3]);
    const res = findGadgets('x86-64', bytes);
    expect(Array.isArray(res)).toBe(true);
    if (!Array.isArray(res)) return;
    const rets = res.filter((g) => g.text === 'ret');
    expect(rets).toHaveLength(1);
  });

  it('refuses empty input', () => {
    expect(findGadgets('x86-64', new Uint8Array(0))).toMatchObject({ error: expect.any(String) });
  });

  it('refuses unknown arches', () => {
    expect(findGadgets('riscv', Uint8Array.from([0xc3]))).toMatchObject({ error: expect.any(String) });
  });

  it('gadgetRows renders addr + text lines', () => {
    const bytes = Uint8Array.from([0xc3]);
    const res = findGadgets('x86-64', bytes);
    if (!Array.isArray(res)) throw new Error('expected gadgets');
    expect(gadgetRows(res)).toBe('0x00000000  ret');
  });
});
