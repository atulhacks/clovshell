// Engine layer: loads keystone (assembler) and capstone (disassembler)
// as WebAssembly modules in the browser and exposes a small typed API.

import MKeystone from '@alexaltea/keystone-js';
import type { KeystoneInstance, KeystoneModule } from '@alexaltea/keystone-js';
import { loadCapstone, Capstone } from 'capstone-wasm';
import type { Insn } from 'capstone-wasm';
import { stripComments } from './comments';
import { stripDirectives } from './directives';

// wasm binaries live in public/wasm (copied from node_modules by scripts/copy-wasm.mjs)
const WASM_BASE = 'wasm/';

export interface ArchDef {
  id: string;
  label: string;
  /** keystone arch + mode constants */
  ksArch: number;
  ksMode: number;
  /** capstone arch + mode constants */
  csArch: number;
  csMode: number;
  /** register tokens for syntax highlighting */
  registerRe: string;
}

export const ARCHES: ArchDef[] = [
  {
    id: 'x86-64',
    label: 'x86-64',
    ksArch: 4,
    ksMode: 8,
    csArch: 3,
    csMode: 8,
    registerRe:
      String.raw`(?:r(?:ax|bx|cx|dx|si|di|sp|bp|ip|8|9|1[0-5])|e(?:ax|bx|cx|dx|si|di|sp|bp|ip)|` +
      String.raw`[a-d][lh]|sil|dil|spl|bpl|cs|ds|es|fs|gs|ss|` +
      String.raw`(?:xmm|ymm|zmm)(?:[0-9]|[12][0-9]|3[01]))`,
  },
  {
    id: 'x86-32',
    label: 'x86-32',
    ksArch: 4,
    ksMode: 4,
    csArch: 3,
    csMode: 4,
    registerRe:
      String.raw`(?:e(?:ax|bx|cx|dx|si|di|sp|bp|ip)|[a-d][lh]|si|di|sp|bp|` +
      String.raw`cs|ds|es|fs|gs|ss|(?:xmm|ymm)(?:[0-9]|[12][0-9]|3[01]))`,
  },
  {
    id: 'arm',
    label: 'ARM',
    ksArch: 1,
    ksMode: 1, // KS_MODE_ARM
    csArch: 0,
    csMode: 0, // CS_MODE_ARM / little endian
    registerRe: String.raw`(?:r\d{1,2}|pc|lr|sp|ip|fp|sl|sb|cpsr|spsr)`,
  },
  {
    id: 'arm64',
    label: 'ARM64',
    ksArch: 2,
    ksMode: 0, // KS_MODE_LITTLE_ENDIAN
    csArch: 1,
    csMode: 0,
    registerRe: String.raw`(?:x\d{1,2}|w\d{1,2}|xzr|wzr|sp|pc|lr|fp|(?:v|q|d|s|h|b)(?:[0-9]|[12][0-9]|3[01]))`,
  },
];

export function getArch(id: string): ArchDef {
  return ARCHES.find((a) => a.id === id) ?? ARCHES[0]!;
}

// ---------------------------------------------------------------------------
// state

let keystoneMod: KeystoneModule | null = null;
let capstoneReady = false;
const ksInstances = new Map<string, KeystoneInstance>();
const csInstances = new Map<string, Capstone>();

export async function initEngines(
  onStage?: (stage: 'keystone' | 'capstone') => void,
): Promise<void> {
  if (keystoneMod && capstoneReady) return;
  const locate = (path: string) => new URL(WASM_BASE + path, document.baseURI).href;
  keystoneMod = await MKeystone({ locateFile: locate });
  onStage?.('keystone');
  await loadCapstone({ locateFile: locate });
  capstoneReady = true;
  onStage?.('capstone');
}

export function enginesReady(): boolean {
  return keystoneMod !== null && capstoneReady;
}

// ---------------------------------------------------------------------------
// assemble

export interface AssembleResult {
  ok: boolean;
  bytes: Uint8Array | null;
  count: number;
  error: string | null;
  /** 1-based line number of the first offending line, when found */
  errorLine: number | null;
  /** the offending source line, when found */
  errorSource: string | null;
}

function ksInstance(arch: ArchDef): KeystoneInstance {
  let ks = ksInstances.get(arch.id);
  if (!ks) {
    if (!keystoneMod) throw new Error('keystone not loaded');
    ks = new keystoneMod.Keystone(arch.ksArch, arch.ksMode);
    ksInstances.set(arch.id, ks);
  }
  return ks;
}

export function assemble(archId: string, source: string): AssembleResult {
  const arch = getArch(archId);
  const ks = ksInstance(arch);
  const normalized = source.replace(/\r\n?/g, '\n');
  // comments are stripped (quote-aware, line-preserving) so their content can
  // never reach — or break — keystone's parser; directives are stripped for
  // the same reason (some of them crash keystone's wasm heap outright)
  const stripped = stripDirectives(stripComments(normalized, arch));
  let res: ReturnType<KeystoneInstance['asm']>;
  try {
    res = ks.asm(stripped, 0);
  } catch (err) {
    // a wasm crash inside keystone must never escape into the UI
    const msg = err instanceof Error ? err.message.split('\n')[0]! : String(err);
    return {
      ok: false, bytes: null, count: 0,
      error: `internal assembler error — ${msg}`,
      errorLine: null, errorSource: null,
    };
  }

  if (res.failed) {
    const code = ks.errno();
    const msg = (keystoneMod?.strerror(code) ?? `keystone error ${code}`).replace(/\s*\(KS_[A-Z_0-9]+\)$/, '');
    const lines = normalized.split('\n');
    const located = locateError(ks, stripped.split('\n'), lines);
    return { ok: false, bytes: null, count: 0, error: msg, ...located };
  }
  return { ok: true, bytes: res.mc, count: res.count, error: null, errorLine: null, errorSource: null };
}

/** keystone symbol-resolution error codes (forward refs look like this) */
function isSymbolError(code: number): boolean {
  const k = keystoneMod;
  const modifier = k?.ERR_ASM_SYMBOL_MODIFIER ?? 142;
  const redefined = k?.ERR_ASM_SYMBOL_REDEFINED ?? 143;
  const missing = k?.ERR_ASM_SYMBOL_MISSING ?? 144;
  return code === modifier || code === redefined || code === missing;
}

/**
 * keystone reports no position for assembly errors. Re-assemble progressively
 * longer prefixes of the source and attribute the error to the first line
 * where the prefix stops assembling. Forward references (a `jmp label` whose
 * label appears later) also stop a prefix, but resolve in the full source —
 * those are remembered as a fallback and skipped in favor of a hard error.
 * Callers word the result as "near line N" since it is a hint, not a proof.
 */
function locateError(
  ks: KeystoneInstance,
  strippedLines: string[],
  originalLines: string[],
): { errorLine: number | null; errorSource: string | null } {
  if (strippedLines.length > 500) return { errorLine: null, errorSource: null };
  let symbolOnly: { line: number; src: string } | null = null;
  for (let i = 0; i < strippedLines.length; i++) {
    if (!strippedLines[i]!.trim()) continue;
    let r: ReturnType<KeystoneInstance['asm']>;
    try {
      r = ks.asm(strippedLines.slice(0, i + 1).join('\n'), 0);
    } catch {
      // keystone's wasm crashed on this prefix — the new line is the offender
      return { errorLine: i + 1, errorSource: (originalLines[i] ?? strippedLines[i]!).trim() };
    }
    if (!r.failed) continue;
    const src = (originalLines[i] ?? strippedLines[i]!).trim();
    if (isSymbolError(ks.errno())) {
      symbolOnly ??= { line: i + 1, src };
      continue;
    }
    return { errorLine: i + 1, errorSource: src };
  }
  return symbolOnly ? { errorLine: symbolOnly.line, errorSource: symbolOnly.src } : { errorLine: null, errorSource: null };
}

// ---------------------------------------------------------------------------
// disassemble

export interface DisasmLine {
  address: number;
  bytes: Uint8Array;
  mnemonic: string;
  opStr: string;
}

export interface DisassembleResult {
  ok: boolean;
  insns: DisasmLine[];
  error: string | null;
  /** number of leading bytes that were decoded */
  consumed: number;
  total: number;
}

function csInstance(arch: ArchDef): Capstone {
  let cs = csInstances.get(arch.id);
  if (!cs) {
    cs = new Capstone(arch.csArch, arch.csMode);
    csInstances.set(arch.id, cs);
  }
  return cs;
}

/**
 * When bytes fail to decode, check whether another arch decodes them fully —
 * stale hex left over from an arch switch is the usual cause, and pointing at
 * it saves a dead end.
 */
function decodingArchHint(arch: ArchDef, bytes: Uint8Array): string | null {
  for (const other of ARCHES) {
    if (other.id === arch.id) continue;
    let insns: Insn[];
    try {
      insns = csInstance(other).disasm(bytes, { address: 0 });
    } catch {
      continue;
    }
    if (insns.length > 0) {
      const last = insns.at(-1)!;
      if (Number(last.address) + last.bytes.length === bytes.length) return other.label;
    }
  }
  return null;
}

function decodeFailure(arch: ArchDef, bytes: Uint8Array): DisassembleResult {
  const hint = decodingArchHint(arch, bytes);
  const why = hint
    ? ` — but they decode cleanly as ${hint}: switch the arch selector above?`
    : '';
  return {
    ok: false,
    insns: [],
    error: `no instructions decoded as ${arch.label}${why}`,
    consumed: 0,
    total: bytes.length,
  };
}

export function disassemble(archId: string, bytes: Uint8Array): DisassembleResult {
  const arch = getArch(archId);
  if (bytes.length === 0) {
    return { ok: true, insns: [], error: null, consumed: 0, total: 0 };
  }
  const cs = csInstance(arch);
  let raw: Insn[];
  try {
    raw = cs.disasm(bytes, { address: 0 });
  } catch {
    // capstone-wasm throws when zero instructions decode
    return decodeFailure(arch, bytes);
  }
  if (raw.length === 0) {
    return decodeFailure(arch, bytes);
  }
  const insns: DisasmLine[] = raw.map((i) => ({
    address: Number(i.address),
    bytes: i.bytes,
    mnemonic: i.mnemonic,
    opStr: i.opStr,
  }));
  const consumed = insns.at(-1)!.address + insns.at(-1)!.bytes.length;
  return { ok: true, insns, error: null, consumed, total: bytes.length };
}
