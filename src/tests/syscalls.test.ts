import { describe, expect, it } from 'vitest';
import { syscallScaffold, tableFor } from '../syscalls';
import type { SyscallEntry } from '../syscalls-data';

const byNum = (arch: string, num: number): SyscallEntry | undefined =>
  tableFor(arch).find((e) => e.num === num);
const byName = (arch: string, name: string): SyscallEntry | undefined =>
  tableFor(arch).find((e) => e.name === name);

describe('syscall tables (ground truth: torvalds/linux)', () => {
  it('x86-64 numbers', () => {
    expect(byName('x86-64', 'read')?.num).toBe(0);
    expect(byName('x86-64', 'write')?.num).toBe(1);
    expect(byName('x86-64', 'mprotect')?.num).toBe(10);
    expect(byName('x86-64', 'execve')?.num).toBe(59);
    expect(byName('x86-64', 'exit')?.num).toBe(60);
    expect(byName('x86-64', 'exit_group')?.num).toBe(231);
    expect(byName('x86-64', 'openat')?.num).toBe(257);
  });

  it('x86-32 numbers (int 0x80 era)', () => {
    expect(byName('x86-32', 'exit')?.num).toBe(1);
    expect(byName('x86-32', 'read')?.num).toBe(3);
    expect(byName('x86-32', 'write')?.num).toBe(4);
    expect(byName('x86-32', 'execve')?.num).toBe(11);
    expect(byName('x86-32', 'socketcall')?.num).toBe(102);
  });

  it('ARM EABI numbers', () => {
    expect(byName('arm', 'exit')?.num).toBe(1);
    expect(byName('arm', 'write')?.num).toBe(4);
    expect(byName('arm', 'execve')?.num).toBe(11);
  });

  it('arm64 numbers (asm-generic table)', () => {
    expect(byName('arm64', 'openat')?.num).toBe(56);
    expect(byName('arm64', 'close')?.num).toBe(57);
    expect(byName('arm64', 'read')?.num).toBe(63);
    expect(byName('arm64', 'write')?.num).toBe(64);
    expect(byName('arm64', 'exit')?.num).toBe(93);
    expect(byName('arm64', 'exit_group')?.num).toBe(94);
    expect(byName('arm64', 'execve')?.num).toBe(221);
    expect(byName('arm64', 'mmap')?.num).toBe(222);
  });

  it('curated args for common calls', () => {
    expect(byNum('x86-64', 1)?.args).toBe('fd, buf, count');
    expect(byNum('x86-64', 59)?.args).toBe('filename, argv, envp');
  });

  it('every table is sorted by number and has unique names', () => {
    for (const arch of ['x86-64', 'x86-32', 'arm', 'arm64']) {
      const table = tableFor(arch);
      const names = new Set(table.map((e) => e.name));
      expect(names.size).toBe(table.length);
      for (let i = 1; i < table.length; i++) {
        expect(table[i]!.num).toBeGreaterThan(table[i - 1]!.num);
      }
      expect(table.length).toBeGreaterThan(300);
    }
  });
});

describe('syscallScaffold', () => {
  const write64 = byName('x86-64', 'write')!;

  it('x86-64: rax + syscall', () => {
    const out = syscallScaffold('x86-64', write64);
    expect(out).toContain('mov rax, 1');
    expect(out).toContain('syscall');
  });

  it('x86-32: eax + int 0x80', () => {
    const out = syscallScaffold('x86-32', byName('x86-32', 'write')!);
    expect(out).toContain('mov eax, 4');
    expect(out).toContain('int 0x80');
  });

  it('arm: r7 + svc 0', () => {
    const out = syscallScaffold('arm', byName('arm', 'write')!);
    expect(out).toContain('mov r7, #4');
    expect(out).toContain('svc 0');
  });

  it('arm64: x8 + svc 0', () => {
    const out = syscallScaffold('arm64', byName('arm64', 'write')!);
    expect(out).toContain('mov x8, 64');
    expect(out).toContain('svc 0');
  });
});
