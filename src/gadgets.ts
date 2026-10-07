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

/** A terminator must actually redirect control, not merely move data. */
function isTerminator(archId: string, insn: DisasmLine): boolean {
  const m = insn.mnemonic.toLowerCase();
  const op = insn.opStr.toLowerCase();
  if (archId.startsWith('x86')) {
    if (['ret', 'retf', 'iretd', 'iretq', 'syscall', 'sysexit', 'sysret'].includes(m)) return true;
    if (m === 'int') return archId === 'x86-32' && op === '0x80';
    if (m === 'jmp' || m === 'call') return !/^0x[0-9a-f]+$/.test(op);
    return false;
  }
  if (archId === 'arm') {
    if (['bx', 'blx', 'b', 'bl'].includes(m)) return true;
    if (m === 'pop') return /\bpc\b/.test(op);
    if (['ldr', 'mov', 'sub', 'add'].includes(m)) return /^pc\b/.test(op);
    return false;
  }
  return ['ret', 'br', 'blr', 'b', 'bl', 'drps'].includes(m);
}

const MAX_GADGET_INSNS = 8;
const MAX_GADGETS = 400;
/** inputs above this are refused — the scan is quadratic-ish */
const MAX_INPUT = 64 * 1024;

export function findGadgets(archId: string, bytes: Uint8Array): Gadget[] | { error: string } {
  if (bytes.length === 0) return { error: 'no bytes to scan' };
  if (bytes.length > MAX_INPUT) {
    return { error: `input too large for a gadget scan (${bytes.length} bytes > ${MAX_INPUT})` };
  }
  if (!['x86-64', 'x86-32', 'arm', 'arm64'].includes(archId)) {
    return { error: `gadget scanning is not supported for "${archId}"` };
  }

  const seen = new Set<string>();
  const gadgets: Gadget[] = [];

  for (let start = 0; start < bytes.length && gadgets.length < MAX_GADGETS; start++) {
    // Decode only enough bytes for eight instructions; never copy/disassemble
    // the entire remaining input at each offset.
    const maxBytes = archId.startsWith('x86') ? MAX_GADGET_INSNS * 15 : MAX_GADGET_INSNS * 4;
    const res = disassemble(archId, bytes.subarray(start, start + maxBytes), MAX_GADGET_INSNS);
    if (!res.ok || res.insns.length === 0) continue;
    const seq: DisasmLine[] = [];
    for (const insn of res.insns) {
      if (seq.length >= MAX_GADGET_INSNS) break;
      seq.push(insn);
      if (isTerminator(archId, insn)) {
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
