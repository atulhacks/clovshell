import { beforeAll, describe, expect, it } from 'vitest';
import { assemble, disassemble, initEngines } from '../engines';
import { runEmulation } from '../emu';
import { xorEncode } from '../encoder';
import { PRESETS } from '../presets';

beforeAll(async () => {
  await initEngines();
});

describe('runEmulation', () => {
  it.each(PRESETS)('$id executes its expected syscall on $arch', async (preset) => {
    const assembled = assemble(preset.arch, preset.src);
    expect(assembled.ok, assembled.error ?? undefined).toBe(true);
    const result = await runEmulation(preset.arch, assembled.bytes!);
    expect(result.ok, result.error ?? undefined).toBe(true);
    expect(result.steps).toBeGreaterThan(0);
    expect(result.trace).toHaveLength(result.steps);
    expect(result.trace[0]?.addr).toBe(0x10000);
    expect(result.trace[0]?.bytes.length).toBe(result.trace[0]?.size);
    expect(result.trace[0]?.registers).toHaveLength(result.registers.length);
    expect(result.traceTruncated).toBe(false);
    expect(result.mutations).toHaveLength(0);
    expect(result.finalCode).toEqual(result.initialCode);
    expect(result.syscalls).toHaveLength(1);
    expect(result.exit).toMatch(preset.id.startsWith('execve') ? /execve/ : /exit/);
  });

  it('reports unsupported syscalls instead of inventing success', async () => {
    const bytes = assemble('x86-64', 'mov eax, 0x7fffffff\nsyscall\nret').bytes!;
    const result = await runEmulation('x86-64', bytes);
    expect(result.syscalls[0]?.call).toContain('syscall_2147483647');
    expect(result.syscalls[0]?.ret).toContain('-38');
    expect(result.registers.find((r) => r.name === 'rax')?.value).toBe('0xffffffffffffffda');
  });

  it('captures pre-instruction registers and actual instruction bytes', async () => {
    const bytes = assemble('x86-64', 'mov eax, 42\nmov edi, eax\nmov eax, 60\nsyscall').bytes!;
    const result = await runEmulation('x86-64', bytes);
    const rax = result.registers.findIndex((reg) => reg.name === 'rax');
    expect(result.trace[0]?.bytes).toEqual(bytes.slice(0, 5));
    expect(result.trace[0]?.registers[rax]).toBe('0x0');
    expect(result.trace[1]?.registers[rax]).toBe('0x2a');
    expect(result.trace[1]?.addr).toBe(0x10005);
  });

  it('does not report a code write when the bytes do not change', async () => {
    const source = [
      'mov byte ptr [rip + target], 0x90',
      'target:', 'nop',
      'xor edi, edi', 'mov eax, 60', 'syscall',
    ].join('\n');
    const assembled = assemble('x86-64', source);
    expect(assembled.ok, assembled.error ?? undefined).toBe(true);
    const result = await runEmulation('x86-64', assembled.bytes!);
    expect(result.exit).toBe('exit(0)');
    expect(result.mutations).toHaveLength(0);
  });

  it('bounds long traces without stopping execution', async () => {
    const source = [
      'mov ecx, 500', 'loop_start:', 'dec ecx', 'jne loop_start',
      'xor edi, edi', 'mov eax, 60', 'syscall',
    ].join('\n');
    const result = await runEmulation('x86-64', assemble('x86-64', source).bytes!);
    expect(result.trace).toHaveLength(400);
    expect(result.traceTruncated).toBe(true);
    expect(result.steps).toBeGreaterThan(400);
    expect(result.exit).toBe('exit(0)');
  });

  it('decodes x86-32 socketcall arguments from emulated memory', async () => {
    const src = [
      'push 0', 'push 1', 'push 2', 'mov ecx, esp',
      'mov ebx, 1', 'mov eax, 102', 'int 0x80',
      'mov ebx, eax', 'mov eax, 1', 'int 0x80',
    ].join('\n');
    const result = await runEmulation('x86-32', assemble('x86-32', src).bytes!);
    expect(result.syscalls[0]).toMatchObject({ call: expect.stringContaining('socket('), ret: '3' });
    expect(result.syscalls[1]?.call).toBe('exit(3)');
  });

  it('decodes the old x86-32 mmap argument block', async () => {
    const src = [
      'push 0', 'push -1', 'push 0x22', 'push 7', 'push 4096', 'push 0',
      'mov ebx, esp', 'mov eax, 90', 'int 0x80',
      'mov ebx, eax', 'mov eax, 1', 'int 0x80',
    ].join('\n');
    const result = await runEmulation('x86-32', assemble('x86-32', src).bytes!);
    expect(result.syscalls[0]).toMatchObject({ call: expect.stringContaining('mmap(0x0, 4096, 7'), ret: '0x30000000' });
    expect(result.syscalls[1]?.call).toBe('exit(805306368)');
  });

  it('maps ARM mmap2 pages and returns the mapped address', async () => {
    const src = [
      'mov r0, #0', 'mov r1, #4096', 'mov r2, #7', 'mov r3, #0x22',
      'mov r4, #0', 'mov r5, #0', 'mov r7, #192', 'svc 0',
      'mov r7, #1', 'svc 0',
    ].join('\n');
    const assembled = assemble('arm', src);
    expect(assembled.ok, assembled.error ?? undefined).toBe(true);
    const result = await runEmulation('arm', assembled.bytes!);
    expect(result.syscalls[0]).toMatchObject({ call: expect.stringContaining('mmap2('), ret: '0x30000000' });
    expect(result.syscalls[1]?.call).toBe('exit(805306368)');
  });

  it('places ARM64 syscall results in x0, not x8', async () => {
    const src = [
      'mov x0, #0', 'mov x1, #4096', 'mov x2, #7', 'mov x3, #0x22',
      'mov x8, #222', 'svc 0', 'mov x8, #93', 'svc 0',
    ].join('\n');
    const assembled = assemble('arm64', src);
    expect(assembled.ok, assembled.error ?? undefined).toBe(true);
    const result = await runEmulation('arm64', assembled.bytes!);
    expect(result.syscalls[0]).toMatchObject({ call: expect.stringContaining('mmap('), ret: '0x30000000' });
    expect(result.syscalls[1]?.call).toBe('exit(805306368)');
  });

  it('renders execveat pathname from the second argument', async () => {
    const src = [
      'push 0', 'mov rbx, 0x68732f6e69622f2f', 'push rbx',
      'mov rsi, rsp', 'mov rdi, -100', 'mov eax, 322', 'syscall',
    ].join('\n');
    const result = await runEmulation('x86-64', assemble('x86-64', src).bytes!);
    expect(result.syscalls[0]?.call).toContain('"//bin/sh"');
    expect(result.exit).toContain('execveat("//bin/sh")');
  });

  it('returns the number of bytes in writev, not the iovec count', async () => {
    const src = [
      'push 0x2169', 'mov rbx, rsp', 'push 2', 'push rbx',
      'mov rsi, rsp', 'mov edi, 1', 'mov edx, 1',
      'mov eax, 20', 'syscall', 'mov edi, eax', 'mov eax, 60', 'syscall',
    ].join('\n');
    const result = await runEmulation('x86-64', assemble('x86-64', src).bytes!);
    expect(result.syscalls[0]?.ret).toContain('2');
    expect(result.syscalls[0]?.call).toContain('i!');
    expect(result.syscalls[1]?.call).toBe('exit(2)');
  });

  it('reports invalid write buffers as EFAULT', async () => {
    const src = 'mov edi, 1\nmov esi, 1\nmov edx, 4\nmov eax, 1\nsyscall\nret';
    const result = await runEmulation('x86-64', assemble('x86-64', src).bytes!);
    expect(result.syscalls[0]?.ret).toContain('-14 (EFAULT)');
  });

  it('applies mprotect to mapped pages', async () => {
    const src = [
      'mov edi, 0x10000', 'mov esi, 4096', 'mov edx, 7',
      'mov eax, 10', 'syscall', 'mov edi, eax', 'mov eax, 60', 'syscall',
    ].join('\n');
    const result = await runEmulation('x86-64', assemble('x86-64', src).bytes!);
    expect(result.syscalls[0]).toMatchObject({ call: expect.stringContaining('mprotect('), ret: '0' });
    expect(result.syscalls[1]?.call).toBe('exit(0)');
  });

  it('unmaps pages returned by mmap', async () => {
    const src = [
      'xor edi, edi', 'mov esi, 4096', 'mov edx, 7', 'mov r10d, 0x22',
      'mov eax, 9', 'syscall', 'mov rdi, rax', 'mov esi, 4096',
      'mov eax, 11', 'syscall', 'mov edi, eax', 'mov eax, 60', 'syscall',
    ].join('\n');
    const result = await runEmulation('x86-64', assemble('x86-64', src).bytes!);
    expect(result.syscalls[0]?.ret).toBe('0x30000000');
    expect(result.syscalls[1]).toMatchObject({ call: expect.stringContaining('munmap('), ret: '0' });
    expect(result.syscalls[2]?.call).toBe('exit(0)');
  });

  it.each(['x86-64', 'x86-32', 'arm', 'arm64'])(
    '%s XOR decoder restores and executes its payload',
    async (arch) => {
      const preset = PRESETS.find((p) => p.arch === arch && p.id.startsWith('exit-'))!;
      const payload = assemble(arch, preset.src).bytes!;
      const encoded = xorEncode(arch, payload, 0x5a);
      expect('error' in encoded).toBe(false);
      if ('error' in encoded) return;
      const program = assemble(arch, encoded.source);
      expect(program.ok, program.error ?? undefined).toBe(true);
      const result = await runEmulation(arch, program.bytes!);
      expect(result.exit, `${arch}: ${result.error ?? ''}`).toMatch(/^exit/);
      expect(result.syscalls).toHaveLength(1);
      const firstPayloadInsn = disassemble(arch, payload, 1).insns[0]!;
      expect(result.trace.some((step) =>
        step.bytes.length === firstPayloadInsn.bytes.length
        && step.bytes.every((byte, i) => byte === firstPayloadInsn.bytes[i]),
      ), `${arch}: trace should contain decoded payload bytes`).toBe(true);
      expect(result.mutations.length, `${arch}: decoder must mutate code`).toBeGreaterThan(0);
      expect(result.mutationsTruncated).toBe(false);
      expect(result.mutations.some((change) => change.firstExecutionStep !== null),
        `${arch}: mutated bytes must execute`).toBe(true);
      expect(result.mutations.every((change) => change.writerStep > 0 && change.writerAddr >= result.codeBase),
        `${arch}: every change has a writer`).toBe(true);
      expect(result.finalCode).not.toEqual(result.initialCode);
      expect(result.finalCode?.slice(-payload.length)).toEqual(payload);
    },
  );
});
