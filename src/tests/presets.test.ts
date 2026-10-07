import { beforeAll, describe, expect, it } from 'vitest';
import { assemble, initEngines } from '../engines';
import { PRESETS } from '../presets';
import { syscallScaffold, tableFor } from '../syscalls';

// Every preset claims to be working shellcode for its arch — prove it:
// assemble it and disassemble the bytes back. (Emulation is covered by the
// browser drive; here we prove the source assembles at all.)
beforeAll(async () => {
  await initEngines();
});

describe('PRESETS', () => {
  it('every preset assembles cleanly for its arch', () => {
    for (const p of PRESETS) {
      const res = assemble(p.arch, p.src);
      expect(res.ok, `${p.id} (${p.arch}): ${res.error}`).toBe(true);
      expect(res.bytes!.length, `${p.id}: emitted nothing`).toBeGreaterThan(0);
    }
  });

  it('presets exist for every arch', () => {
    for (const arch of ['x86-64', 'x86-32', 'arm', 'arm64']) {
      expect(PRESETS.some((p) => p.arch === arch), `no presets for ${arch}`).toBe(true);
    }
  });

  it('every preset disassembles back to instructions', async () => {
    const { disassemble } = await import('../engines');
    for (const p of PRESETS) {
      const bytes = assemble(p.arch, p.src).bytes!;
      const dis = disassemble(p.arch, bytes);
      expect(dis.ok, `${p.id}: ${dis.error}`).toBe(true);
      expect(dis.insns.length, `${p.id}: no instructions decoded`).toBeGreaterThan(0);
    }
  });

  it('null-free presets contain no 00 bytes', () => {
    for (const p of PRESETS.filter((x) => /null-free/i.test(x.note))) {
      const bytes = assemble(p.arch, p.src).bytes!;
      expect([...bytes].some((b) => b === 0), `${p.id} claims null-free but has 00`).toBe(false);
    }
  });

  it('advertised byte lengths match assembled bytes', () => {
    const mismatches: string[] = [];
    for (const p of PRESETS) {
      const advertised = Number(p.note.match(/^(\d+) B/)?.[1]);
      expect(advertised, `${p.id} has no size claim`).toBeGreaterThan(0);
      const actual = assemble(p.arch, p.src).bytes?.length;
      if (actual !== advertised) mismatches.push(`${p.id}: ${advertised} B advertised, ${actual} B assembled`);
    }
    expect(mismatches).toEqual([]);
  });

  it('every syscall scaffold assembles for its arch', () => {
    const failures: string[] = [];
    for (const arch of ['x86-64', 'x86-32', 'arm', 'arm64']) {
      for (const entry of tableFor(arch)) {
        const scaffold = syscallScaffold(arch, entry);
        const res = assemble(arch, scaffold);
        if (!res.ok) failures.push(`${arch} ${entry.num} ${entry.name}: ${res.error}`);
      }
    }
    expect(failures).toEqual([]);
  });
});
