import { beforeAll, describe, expect, it } from 'vitest';
import { assemble, initEngines } from '../engines';
import { runEmulation } from '../emu';
import type { EmuResult } from '../emu';
import { compareScenario, flowKeys, parseScenarioArgs } from '../scenarios';

beforeAll(async () => { await initEngines(); });

describe('scenario inputs', () => {
  it('reuses immutable flow fingerprints for repeat comparisons', () => {
    const result = { flow: { nodes: [], edges: [], path: [] }, stages: [] } as unknown as EmuResult;
    expect(flowKeys(result)).toBe(flowKeys(result));
  });
  it('parses and bounds entry values by architecture', () => {
    expect(parseScenarioArgs('0, 0x1, -1', 'arm')).toEqual([0n, 1n, 0xffffffffn]);
    expect(parseScenarioArgs('0, -1', 'x86-64')).toEqual([0n, 0xffffffffffffffffn]);
    expect(parseScenarioArgs('0, -1', 'x86-32')).toEqual([0n, 0xffffffffn]);
    expect(() => parseScenarioArgs('0, nope', 'arm64')).toThrow('invalid argument');
    expect(() => parseScenarioArgs('0 1 2 3 4 5 6 7 8', 'arm64')).toThrow('limit scenarios');
  });

  it('finds a divergent branch and new edges without confusing stage numbering', async () => {
    const source = 'cmp rdi, 1\nje one\nxor edi, edi\njmp done\none:\nmov edi, 1\ndone:\nmov eax, 60\nsyscall';
    const code = assemble('x86-64', source).bytes!;
    const zero = await runEmulation('x86-64', code, 0n);
    const one = await runEmulation('x86-64', code, 1n);
    expect(zero.exit).toBe('exit(0)');
    expect(one.exit).toBe('exit(1)');
    const compare = compareScenario(zero, one, flowKeys(zero).edges);
    expect(compare.newEdges).toBeGreaterThan(0);
    expect(compare.firstDifferentStep).toBe(3);
    expect(compare.prefixLimited).toBe(false);
    expect(compareScenario(zero, zero, flowKeys(zero).edges).firstDifferentStep).toBeNull();
  });

  it('explores x86-32 cdecl arguments on the entry stack', async () => {
    const source = 'mov ebx, [esp+4]\nmov eax, 1\nint 0x80';
    const code = assemble('x86-32', source).bytes!;
    const result = await runEmulation('x86-32', code, 7n);
    expect(result.exit).toBe('exit(7)');
  });

  it.each([
    ['x86-64', 'sub rsp, 16\nxor edi, edi\nmov rsi, rsp\nmov edx, 1\nxor eax, eax\nsyscall\nmovzx edi, byte ptr [rsp]\nmov eax, 60\nsyscall'],
    ['x86-32', 'sub esp, 16\nxor ebx, ebx\nmov ecx, esp\nmov edx, 1\nmov eax, 3\nint 0x80\nmovzx ebx, byte ptr [esp]\nmov eax, 1\nint 0x80'],
    ['arm', 'sub sp, sp, #16\nmov r0, #0\nmov r1, sp\nmov r2, #1\nmov r7, #3\nsvc 0\nldrb r0, [sp]\nmov r7, #1\nsvc 0'],
    ['arm-thumb', 'sub sp, #16\nmovs r0, #0\nmov r1, sp\nmovs r2, #1\nmovs r7, #3\nsvc #0\nldrb r0, [sp]\nmovs r7, #1\nsvc #0'],
    ['arm64', 'sub sp, sp, #16\nmov x0, #0\nmov x1, sp\nmov x2, #1\nmov x8, #63\nsvc 0\nldrb w0, [sp]\nmov x8, #93\nsvc 0'],
  ])('%s consumes the input fixture through read', async (arch, source) => {
    const assembled = assemble(arch, source);
    expect(assembled.ok, assembled.error ?? '').toBe(true);
    const result = await runEmulation(arch, assembled.bytes!, null, Uint8Array.of(0x41));
    expect(result.exit, result.error ?? '').toBe('exit(65)');
    expect(result.syscalls[0]?.ret).toBe('1 (input fixture)');
  });

  it('returns EFAULT without consuming the fixture, and enforces its size cap', async () => {
    const source = [
      'xor edi, edi', 'mov esi, 1', 'mov edx, 1', 'xor eax, eax', 'syscall',
      'sub rsp, 16', 'mov rsi, rsp', 'xor eax, eax', 'syscall',
      'movzx edi, byte ptr [rsp]', 'mov eax, 60', 'syscall',
    ].join('\n');
    const result = await runEmulation('x86-64', assemble('x86-64', source).bytes!, null, Uint8Array.of(0x42));
    expect(result.syscalls[0]?.ret).toBe('-14 (EFAULT)');
    expect(result.syscalls[1]?.ret).toBe('1 (input fixture)');
    expect(result.exit).toBe('exit(66)');
    await expect(runEmulation('x86-64', Uint8Array.of(0xc3), null, new Uint8Array(4097)))
      .rejects.toThrow('input fixture exceeds 4096 bytes');
  });

  it('feeds recvfrom and consumes the stream over successive calls', async () => {
    const source = [
      'sub rsp, 16', 'mov edi, 3', 'mov rsi, rsp', 'mov edx, 1',
      'mov eax, 45', 'syscall', 'inc rsi', 'mov eax, 45', 'syscall',
      'movzx edi, byte ptr [rsp+1]', 'mov eax, 60', 'syscall',
    ].join('\n');
    const result = await runEmulation('x86-64', assemble('x86-64', source).bytes!, null, Uint8Array.of(0x41, 0x42));
    expect(result.syscalls.slice(0, 2).map((item) => item.ret)).toEqual(['1 (input fixture)', '1 (input fixture)']);
    expect(result.exit).toBe('exit(66)');
  });
});
