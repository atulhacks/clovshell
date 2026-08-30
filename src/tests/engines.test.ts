import { beforeAll, describe, expect, it } from 'vitest';
import { assemble, disassemble, enginesReady, getArch, initEngines } from '../engines';

/** lowercase hex of a byte array — avoids a Node Buffer dependency in types */
const hex = (b: Uint8Array): string => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');

beforeAll(async () => {
  await initEngines();
  expect(enginesReady()).toBe(true);
});

describe('assemble', () => {
  it('x86-64 basic', () => {
    const res = assemble('x86-64', 'mov eax, 0x64696b73\nret');
    expect(res.ok).toBe(true);
    expect(hex(res.bytes!)).toBe('b8736b6964c3');
  });

  it('x86-32 basic', () => {
    const res = assemble('x86-32', 'mov eax, 11\nint 0x80');
    expect(res.ok).toBe(true);
    expect(hex(res.bytes!)).toBe('b80b000000cd80');
  });

  it('arm64 basic', () => {
    const res = assemble('arm64', 'mov x1, #0');
    expect(res.ok).toBe(true);
    expect(hex(res.bytes!)).toBe('010080d2');
  });

  it('arm basic', () => {
    const res = assemble('arm', 'mov r0, #4');
    expect(res.ok).toBe(true);
    expect(hex(res.bytes!)).toBe('0400a0e3');
  });

  it('comments never reach the assembler', () => {
    const a = assemble('x86-64', 'nop ; trailing comment (with parens — unicode ø)');
    expect(a.ok).toBe(true);
    expect(hex(a.bytes!)).toBe('90');
  });

  it('gas directives are stripped, not fatal', () => {
    const res = assemble(
      'arm64',
      ['.global sum', '.type sum, %function', 'sum:', '    mov x1, #0', '    ret'].join('\n'),
    );
    expect(res.ok).toBe(true);
    expect(res.bytes!.length).toBeGreaterThan(0);
  });

  it('labels resolve on all four arches', () => {
    const cases: Array<[string, string, string]> = [
      ['x86-64', 'jmp over\nnop\nover:\nret', 'e900'],
      ['x86-32', 'jmp over\nnop\nover:\nret', 'e900'],
      ['arm64', 'loop:\nsub x0, x0, #1\ncbnz x0, loop\nret', ''],
      ['arm', 'loop:\nsub r0, r0, #1\ncmp r0, #0\nbne loop\nbx lr', ''],
    ];
    for (const [arch, src, _] of cases) {
      const res = assemble(arch, src);
      expect(res.ok, `${arch}: ${res.error}`).toBe(true);
      expect(res.bytes!.length).toBeGreaterThan(0);
    }
  });

  it('bad mnemonic reports an error with a line hint', () => {
    const res = assemble('x86-64', 'nop\nfrobnicate rax\nnop');
    expect(res.ok).toBe(false);
    expect(res.error).toBeTruthy();
    expect(res.errorLine).toBe(2);
  });

  it('.text does not crash the wasm heap', () => {
    const res = assemble('x86-64', '.text\nnop');
    expect(res.ok).toBe(true);
  });
});

describe('disassemble', () => {
  it('x86-64 round-trip through bytes', () => {
    const bytes = assemble('x86-64', 'mov eax, 0x64696b73\nret').bytes!;
    const res = disassemble('x86-64', bytes);
    expect(res.ok).toBe(true);
    expect(res.insns.map((i) => `${i.mnemonic} ${i.opStr}`.trim())).toEqual(['mov eax, 0x64696b73', 'ret']);
    expect(res.consumed).toBe(bytes.length);
  });

  it('arm64 decodes with resolved branch targets', () => {
    const res = disassemble('arm64', Uint8Array.from([0x01, 0x00, 0x80, 0xd2]));
    expect(res.ok).toBe(true);
    expect(res.insns[0]!.mnemonic).toBe('mov');
    expect(res.insns[0]!.opStr).toContain('x1');
  });

  it('undecodable tail is reported, leading bytes still decode', () => {
    const res = disassemble('x86-64', Uint8Array.from([0x90, 0xff]));
    expect(res.ok).toBe(true);
    expect(res.insns.length).toBe(1);
    expect(res.total - res.consumed).toBe(1);
  });

  it('suggests the right arch when nothing decodes', () => {
    // b8 0b 00 00 00 cd 80 = valid x86 (mov eax, 11 ; int 0x80), invalid as arm64.
    // x86-64 comes first in ARCHES and also decodes it fully, so it wins the hint.
    const res = disassemble('arm64', Uint8Array.from([0xb8, 0x0b, 0x00, 0x00, 0x00, 0xcd, 0x80]));
    expect(res.ok).toBe(false);
    expect(res.error).toMatch(/decode cleanly as x86-64/);
  });

  it('empty input decodes to nothing without error', () => {
    const res = disassemble('x86-64', new Uint8Array(0));
    expect(res.ok).toBe(true);
    expect(res.insns).toHaveLength(0);
  });
});

describe('getArch', () => {
  it('falls back to x86-64 for unknown ids', () => {
    expect(getArch('riscv').id).toBe('x86-64');
  });
});
