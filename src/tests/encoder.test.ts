import { beforeAll, describe, expect, it } from 'vitest';
import { assemble, initEngines } from '../engines';
import { runEmulation } from '../emu';
import { xorEncode } from '../encoder';

beforeAll(async () => {
  await initEngines();
});

describe('xorEncode', () => {
  it('x86-64: encoded payload is input ^ key, stub assembles', () => {
    const payload = Uint8Array.from([0xb8, 0x73, 0x6b, 0x69, 0x64, 0xc3]);
    const res = xorEncode('x86-64', payload, 0x2a);
    expect('error' in res).toBe(false);
    if ('error' in res) return;
    expect(Array.from(res.encoded)).toEqual(Array.from(payload, (b) => b ^ 0x2a));
    expect(res.source).toContain('decode_loop');
    expect(res.source).toContain('xor byte ptr [rsi], 0x2a');
    expect(res.source).toContain('.byte 0x');
    // the whole generated program must assemble — that is the product
    const asm = assemble('x86-64', res.source);
    expect(asm.ok, asm.error ?? undefined).toBe(true);
    expect(asm.bytes!.length).toBeGreaterThan(payload.length);
  });

  it('x86-32 stub uses esi', () => {
    const res = xorEncode('x86-32', Uint8Array.from([0x90]), 0x11);
    expect('error' in res).toBe(false);
    if ('error' in res) return;
    expect(res.source).toContain('pop esi');
    expect(assemble('x86-32', res.source).ok).toBe(true);
  });

  it('arm stub uses adr + bx, assembles', () => {
    const res = xorEncode('arm', Uint8Array.from([0x01, 0x02, 0x03, 0x04]), 0x5a);
    expect('error' in res).toBe(false);
    if ('error' in res) return;
    expect(res.source).toContain('adr r0, shellcode');
    expect(res.source).toContain('bx r0');
    expect(assemble('arm', res.source).ok).toBe(true);
  });

  it('Thumb decoder restores the payload and executes it', async () => {
    const payload = assemble('arm-thumb', 'movs r0, #0\nmovs r7, #1\nsvc #0').bytes!;
    const encoded = xorEncode('arm-thumb', payload, 0x5a);
    expect('error' in encoded).toBe(false);
    if ('error' in encoded) return;
    const assembled = assemble('arm-thumb', encoded.source);
    expect(assembled.ok, assembled.error ?? '').toBe(true);
    const result = await runEmulation('arm-thumb', assembled.bytes!);
    expect(result.exit, result.error ?? '').toBe('exit(0)');
    expect(result.mutations.length).toBeGreaterThan(0);
  });

  it('arm64 stub uses adr + br, assembles', () => {
    const res = xorEncode('arm64', Uint8Array.from([0x01, 0x02, 0x03, 0x04]), 0x5a);
    expect('error' in res).toBe(false);
    if ('error' in res) return;
    expect(res.source).toContain('adr x0, shellcode');
    expect(res.source).toContain('br x0');
    expect(assemble('arm64', res.source).ok).toBe(true);
  });

  it('rejects key 0 and out-of-range keys', () => {
    expect(xorEncode('x86-64', Uint8Array.from([0x90]), 0)).toMatchObject({ error: expect.any(String) });
    expect(xorEncode('x86-64', Uint8Array.from([0x90]), 256)).toMatchObject({ error: expect.any(String) });
    expect(xorEncode('x86-64', Uint8Array.from([0x90]), 1.5)).toMatchObject({ error: expect.any(String) });
  });

  it('rejects empty payloads', () => {
    expect(xorEncode('x86-64', new Uint8Array(0), 0x2a)).toMatchObject({ error: expect.any(String) });
  });

  it('rejects oversized payloads per arch', () => {
    const big = new Uint8Array(300);
    expect(xorEncode('x86-64', big, 1)).toMatchObject({ error: /255/ });
    expect(xorEncode('arm', big, 1)).toMatchObject({ error: /255/ });
    // arm64's length travels as an imm12 — 300 is fine there, 5000 is not
    const arm64Ok = xorEncode('arm64', new Uint8Array(300), 1);
    expect('error' in arm64Ok).toBe(false);
    expect(xorEncode('arm64', new Uint8Array(5000), 1)).toMatchObject({ error: /4095/ });
  });

  it('unknown arch is an error', () => {
    expect(xorEncode('riscv', Uint8Array.from([0x90]), 1)).toMatchObject({ error: expect.any(String) });
  });
});
