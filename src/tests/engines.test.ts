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
  it('decodes the full maximum-size one-byte-instruction input without exhausting WASM memory', () => {
    const bytes = new Uint8Array(64 * 1024).fill(0x90);
    const res = disassemble('x86-64', bytes);
    expect(res.ok, res.error ?? '').toBe(true);
    expect(res.insns).toHaveLength(bytes.length);
    expect(res.consumed).toBe(bytes.length);
    expect(res.insns[255]?.address).toBe(255);
    expect(res.insns[256]?.address).toBe(256);
    expect(res.insns.at(-1)?.address).toBe(bytes.length - 1);
    expect(Array.from(res.insns[0]!.bytes)).toEqual([0x90]);
    expect(Array.from(res.insns.at(-1)!.bytes)).toEqual([0x90]);
  });

  it('decodes maximum-size fixed-width ARM buffers across multiple batches', () => {
    for (const [arch, nop] of [
      ['arm', [0x00, 0xf0, 0x20, 0xe3]],
      ['arm64', [0x1f, 0x20, 0x03, 0xd5]],
    ] as const) {
      const bytes = Uint8Array.from(Array.from({ length: 16 * 1024 }, () => nop).flat());
      const res = disassemble(arch, bytes);
      expect(res.ok, `${arch}: ${res.error}`).toBe(true);
      expect(res.insns).toHaveLength(16 * 1024);
      expect(res.consumed).toBe(bytes.length);
    }
  });

  it('preserves instruction boundaries and the caller count across batches', () => {
    const bytes = new Uint8Array(600 * 2 + 1);
    for (let i = 0; i < 600; i++) {
      bytes[i * 2] = 0x66;
      bytes[i * 2 + 1] = 0x90;
    }
    bytes[bytes.length - 1] = 0xc3;
    const limited = disassemble('x86-64', bytes, 300, 0x1000);
    expect(limited.ok).toBe(true);
    expect(limited.insns).toHaveLength(300);
    expect(limited.consumed).toBe(600);
    expect(limited.insns[256]?.address).toBe(0x1200);

    const full = disassemble('x86-64', bytes, undefined, 0x1000);
    expect(full.ok).toBe(true);
    expect(full.insns).toHaveLength(601);
    expect(full.consumed).toBe(bytes.length);
    expect(full.insns.at(-1)?.address).toBe(0x1000 + 1200);
    expect(disassemble('x86-64', bytes, 0, 0x1000).insns).toHaveLength(601);
  });

  it('reports an undecodable tail after several complete batches', () => {
    const bytes = Uint8Array.from([...new Array<number>(600).fill(0x90), 0xff]);
    const res = disassemble('x86-64', bytes);
    expect(res.ok).toBe(true);
    expect(res.insns).toHaveLength(600);
    expect(res.consumed).toBe(600);
    expect(res.total).toBe(601);
  });

  it('x86-64 round-trip through bytes', () => {
    const bytes = assemble('x86-64', 'mov eax, 0x64696b73\nret').bytes!;
    const res = disassemble('x86-64', bytes);
    expect(res.ok).toBe(true);
    expect(res.insns.map((i) => `${i.mnemonic} ${i.opStr}`.trim())).toEqual(['mov eax, 0x64696b73', 'ret']);
    expect(res.consumed).toBe(bytes.length);
  });

  it('decodes at the executed address while keeping consumed relative to input', () => {
    const bytes = assemble('x86-64', 'jmp target\nnop\ntarget:\nret').bytes!;
    const res = disassemble('x86-64', bytes, 1, 0x10000);
    expect(res.ok).toBe(true);
    expect(res.insns).toHaveLength(1);
    expect(res.insns[0]?.address).toBe(0x10000);
    expect(res.insns[0]?.opStr).toBe('0x10003');
    expect(res.consumed).toBe(res.insns[0]?.bytes.length);
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
    // A lone x86 ret is shorter than any ARM64 instruction.
    const res = disassemble('arm64', Uint8Array.from([0xc3]));
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
