// ROP gadget finder: slides capstone across the byte stream from every offset
// (not just instruction boundaries) and keeps short sequences that end in a
// branch — the classic ROPgadget/ropper technique, in the browser.

import { disassemble } from './engines';
import type { DisasmLine } from './engines';

export interface Gadget {
  address: number;
  /** "pop rdi ; ret" */
  text: string;
}

/** terminal instructions that make a sequence usable as a gadget */
const TERMINATORS: Record<string, Set<string>> = {
  'x86-64': new Set(['ret', 'jmp', 'call', 'syscall', 'leave', 'iretd', 'iretq', 'sysexit', 'sysret']),
  'x86-32': new Set(['ret', 'jmp', 'call', 'int', 'leave', 'iretd', 'sysexit', 'sysret']),
  arm: new Set(['bx', 'blx', 'b', 'bl', 'ldr', 'mov', 'sub', 'add', 'pop']),
  arm64: new Set(['ret', 'br', 'blr', 'b', 'bl', 'ldr', 'drps']),
};

const MAX_GADGET_INSNS = 8;
const MAX_GADGETS = 400;
/** inputs above this are refused — the scan is quadratic-ish */
const MAX_INPUT = 64 * 1024;

export function findGadgets(archId: string, bytes: Uint8Array): Gadget[] | { error: string } {
  if (bytes.length === 0) return { error: 'no bytes to scan' };
  if (bytes.length > MAX_INPUT) {
    return { error: `input too large for a gadget scan (${bytes.length} bytes > ${MAX_INPUT})` };
  }
  const terms = TERMINATORS[archId];
  if (!terms) return { error: `gadget scanning is not supported for "${archId}"` };

  const seen = new Set<string>();
  const gadgets: Gadget[] = [];

  for (let start = 0; start < bytes.length && gadgets.length < MAX_GADGETS; start++) {
    // disassemble from this offset; stop once a terminator appears
    const res = disassemble(archId, bytes.subarray(start));
    if (!res.ok || res.insns.length === 0) continue;
    const seq: DisasmLine[] = [];
    for (const insn of res.insns) {
      if (seq.length >= MAX_GADGET_INSNS) break;
      seq.push(insn);
      if (terms.has(insn.mnemonic)) {
        const text = seq.map((i) => (i.opStr ? `${i.mnemonic} ${i.opStr}` : i.mnemonic)).join(' ; ');
        if (!seen.has(text)) {
          seen.add(text);
          gadgets.push({ address: start, text });
        }
        break;
      }
      // don't let one offset walk the whole stream when nothing terminates
      if (seq.length >= MAX_GADGET_INSNS) break;
    }
  }
  return gadgets;
}

/** gadget rows render as "0x00000000  pop rdi ; ret" */
export function gadgetRows(gadgets: Gadget[]): string {
  return gadgets.map((g) => `0x${g.address.toString(16).padStart(8, '0')}  ${g.text}`).join('\n');
}
