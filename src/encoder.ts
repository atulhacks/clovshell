// XOR encoder: wraps assembled shellcode in a self-decoding stub.
// The output is ordinary asm source — stub instructions + the encoded payload
// as `.byte` data — so it flows through the normal assemble / emulate / export
// pipeline, and the emulator can prove the decoder works.

export interface EncodedPayload {
  source: string;
  /** bytes of the encoded payload (original ^ key) */
  encoded: Uint8Array;
  /** caveats worth surfacing in the UI */
  note: string;
}

export type EncodeResult = EncodedPayload | { error: string };

const MAX_LEN = {
  'x86-64': 255, // length travels in cl
  'x86-32': 255,
  arm: 255, // imm8-rotated immediate
  'arm-thumb': 255, // 8-bit loop count and rewind
  arm64: 4095, // sub imm12
} as const;

/** render the encoded bytes as .byte lines, 16 values per line */
function dataLines(bytes: Uint8Array, indent = '    '): string {
  const lines: string[] = [];
  for (let i = 0; i < bytes.length; i += 16) {
    lines.push(indent + '.byte ' + Array.from(bytes.slice(i, i + 16))
      .map((b) => '0x' + b.toString(16).padStart(2, '0'))
      .join(', '));
  }
  return lines.join('\n');
}

/**
 * Generate a stub + payload source for `key` (1..255, nonzero — 0 would make
 * the encoding a no-op and `xor …, 0` is not a real instruction anyway).
 */
export function xorEncode(archId: string, bytes: Uint8Array, key: number): EncodeResult {
  if (!Number.isInteger(key) || key < 1 || key > 255) {
    return { error: `key must be a byte 0x01..0xff (got 0x${(key ?? 0).toString(16)})` };
  }
  const max = MAX_LEN[archId as keyof typeof MAX_LEN];
  if (max === undefined) return { error: `no encoder for arch "${archId}"` };
  if (bytes.length === 0) return { error: 'nothing to encode — assemble some shellcode first' };
  if (bytes.length > max) {
    return { error: `payload is ${bytes.length} bytes — this arch's stub tops out at ${max}` };
  }

  const encoded = new Uint8Array(bytes.length);
  for (let i = 0; i < bytes.length; i++) encoded[i] = bytes[i]! ^ key;

  const n = bytes.length;
  const k = '0x' + key.toString(16).padStart(2, '0');
  const head =
    `; clovshell xor-encoded shellcode — key ${k}, payload ${n} bytes\n` +
    '; the stub decodes the payload in place, then jumps to it\n';
  const data = dataLines(encoded);

  let body: string;
  if (archId === 'x86-64') {
    body = `    jmp getpc
decode:
    pop rsi
    push rsi
    xor rcx, rcx
    mov cl, ${n}
decode_loop:
    xor byte ptr [rsi], ${k}
    inc rsi
    loop decode_loop
    ret
getpc:
    call decode
shellcode:
${data}
`;
  } else if (archId === 'x86-32') {
    body = `    jmp getpc
decode:
    pop esi
    push esi
    xor ecx, ecx
    mov cl, ${n}
decode_loop:
    xor byte ptr [esi], ${k}
    inc esi
    loop decode_loop
    ret
getpc:
    call decode
shellcode:
${data}
`;
  } else if (archId === 'arm-thumb') {
    body = `    adr r4, shellcode
    movs r1, #${n}
    movs r2, #${k}
decode_loop:
    ldrb r3, [r4]
    eors r3, r2
    strb r3, [r4]
    adds r4, #1
    subs r1, #1
    bne decode_loop
    subs r4, #${n}
    adds r4, #1
    bx r4
    .byte 0xc0, 0x46
shellcode:
${data}
`;
  } else if (archId === 'arm64') {
    body = `    adr x0, shellcode
    mov x1, #${n}
    mov x2, #${k}
decode_loop:
    ldrb w3, [x0]
    eor w3, w3, w2
    strb w3, [x0]
    add x0, x0, #1
    subs x1, x1, #1
    b.ne decode_loop
    sub x0, x0, #${n}
    br x0
shellcode:
${data}
`;
  } else {
    body = `    adr r0, shellcode
    mov r1, #${n}
    mov r2, #${k}
decode_loop:
    ldrb r3, [r0]
    eor r3, r3, r2
    strb r3, [r0]
    add r0, r0, #1
    subs r1, r1, #1
    bne decode_loop
    sub r0, r0, #${n}
    bx r0
shellcode:
${data}
`;
  }

  const note = 'pick a key that keeps the encoded bytes clear of your bad characters — the stats line after assembling tells you';
  return { source: head + body, encoded, note };
}
