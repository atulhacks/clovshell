// Emulation layer: runs shellcode under the Unicorn CPU emulator (WASM)
// in a sandboxed memory space, intercepts syscalls, and reports a trace.

import type { UnicornInstance } from '@alexaltea/unicorn-js/x86';

import { x8664, x8632, arm as armTable, arm64 as arm64Table } from './syscalls-data';

export type { UnicornInstance };

// ---------------------------------------------------------------------------
// lazy engine loading (per-arch single-arch builds, ~0.8-1.5 MB each)

type Loaded = 'x86' | 'arm' | 'aarch64';
const modules = new Map<Loaded, Promise<unknown>>();

function loadUnicorn(which: Loaded): Promise<unknown> {
  let m = modules.get(which);
  if (!m) {
    m =
      which === 'x86' ? import('@alexaltea/unicorn-js/x86')
      : which === 'arm' ? import('@alexaltea/unicorn-js/arm')
      : import('@alexaltea/unicorn-js/aarch64');
    // interop: the UMD module default is the Emscripten factory
    m = m.then((mod) => (mod as { default: (arg?: unknown) => Promise<unknown> }).default());
    modules.set(which, m);
  }
  return m;
}

export function emuEngineFor(archId: string): Loaded {
  return archId === 'arm' ? 'arm' : archId === 'arm64' ? 'aarch64' : 'x86';
}

export async function preloadEmu(archId: string): Promise<void> {
  await loadUnicorn(emuEngineFor(archId));
}

/** name of the register the entry argument lands in, for UI labels */
export function entryArgReg(archId: string): string | null {
  if (archId === 'x86-64') return 'rdi';
  if (archId === 'arm') return 'r0';
  if (archId === 'arm64') return 'x0';
  return null; // x86-32: cdecl, args arrive on the stack
}

// ---------------------------------------------------------------------------
// results

export interface EmuSyscall {
  /** rendered call line, e.g. `execve("/bin/sh", 0x0, 0x0)` */
  call: string;
  /** rendered return value */
  ret: string;
}

export interface EmuReg {
  name: string;
  /** hex string, e.g. "0x2f" */
  value: string;
  changed: boolean;
}

export interface EmuStep {
  addr: number;
  size: number;
}

export interface EmuResult {
  ok: boolean;
  steps: number;
  syscalls: EmuSyscall[];
  registers: EmuReg[];
  /** why emulation stopped */
  exit: string;
  /** instruction trace (first TRACE_CAP instructions) */
  trace: EmuStep[];
  traceTruncated: boolean;
  error?: string;
}

// ---------------------------------------------------------------------------
// memory layout

const CODE = 0x10000; // code page region base
const CODE_MAP = 0xf000; // mapped from (slack below for rip-relative etc.)
const CODE_SPAN = 0x21000; // .. to (code + slack above)
const STACK = 0x7fff0000; // 1 MiB stack
const STACK_TOP = 0x7fff8000; // initial sp (middle of the stack region)
const SENTINEL = 0xdead0000; // return address pushed on the stack
const MMAP_BASE = 0x30000000; // where fake mmap() allocations live

const STEP_LIMIT = 100_000;
const TRACE_CAP = 400;
// NOTE: emu_start's timeout parameter must stay 0 — unicorn implements timeouts
// with a QEMU timer thread, which aborts under WASM ("qemu_thread_create: Not
// supported"). Runaway loops are caught by the HOOK_CODE step counter instead.

function hex(n: bigint | number, pad = 0): string {
  const v = typeof n === 'bigint' ? n : BigInt(Math.trunc(n));
  const h = (v >= 0n ? v : v & 0xffffffffffffffffn).toString(16);
  return '0x' + (h.length < pad ? h.padStart(pad, '0') : h);
}

// ---------------------------------------------------------------------------
// register plumbing per arch

interface ArchGlue {
  /** (uc, instance) -> { get(regName): bigint } */
  regs: Record<string, number>;
  regOrder: string[];
  syscallNumReg: string;
  argRegs: string[];
  /** register carrying the first argument (SysV ABI) — x86-32 takes args on the stack */
  argReg: string | null;
  /** syscall entry registers: number reg first, then args */
  width: 32 | 64;
}

function glueFor(archId: string, uc: Record<string, number>): ArchGlue {
  if (archId === 'x86-64') {
    return {
      regs: {
        rax: uc.X86_REG_RAX!, rbx: uc.X86_REG_RBX!, rcx: uc.X86_REG_RCX!, rdx: uc.X86_REG_RDX!,
        rsi: uc.X86_REG_RSI!, rdi: uc.X86_REG_RDI!, rbp: uc.X86_REG_RBP!, rsp: uc.X86_REG_RSP!,
        rip: uc.X86_REG_RIP!, r8: uc.X86_REG_R8!, r9: uc.X86_REG_R9!, r10: uc.X86_REG_R10!,
        r11: uc.X86_REG_R11!, r12: uc.X86_REG_R12!, r13: uc.X86_REG_R13!, r14: uc.X86_REG_R14!,
        r15: uc.X86_REG_R15!,
      },
      regOrder: ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15', 'rip'],
      syscallNumReg: 'rax',
      argRegs: ['rdi', 'rsi', 'rdx', 'r10', 'r8', 'r9'],
      argReg: 'rdi',
      width: 64,
    };
  }
  if (archId === 'x86-32') {
    return {
      regs: {
        eax: uc.X86_REG_EAX!, ebx: uc.X86_REG_EBX!, ecx: uc.X86_REG_ECX!, edx: uc.X86_REG_EDX!,
        esi: uc.X86_REG_ESI!, edi: uc.X86_REG_EDI!, ebp: uc.X86_REG_EBP!, esp: uc.X86_REG_ESP!,
        eip: uc.X86_REG_EIP!,
      },
      regOrder: ['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp', 'esp', 'eip'],
      syscallNumReg: 'eax',
      argRegs: ['ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp'],
      argReg: null, // cdecl: arguments arrive on the stack
      width: 32,
    };
  }
  if (archId === 'arm') {
    const r: Record<string, number> = {};
    for (let i = 0; i <= 12; i++) r['r' + i] = uc['ARM_REG_R' + i]!;
    r.sp = uc.ARM_REG_SP!;
    r.lr = uc.ARM_REG_LR!;
    r.pc = uc.ARM_REG_PC!;
    return {
      regs: r,
      regOrder: [...Array.from({ length: 13 }, (_, i) => 'r' + i), 'sp', 'lr', 'pc'],
      syscallNumReg: 'r7',
      argRegs: ['r0', 'r1', 'r2', 'r3', 'r4', 'r5'],
      argReg: 'r0',
      width: 32,
    };
  }
  const x: Record<string, number> = {};
  for (let i = 0; i <= 30; i++) x['x' + i] = uc['ARM64_REG_X' + i]!;
  x.sp = uc.ARM64_REG_SP!;
  x.pc = uc.ARM64_REG_PC!;
  return {
    regs: x,
    regOrder: [...Array.from({ length: 31 }, (_, i) => 'x' + i), 'sp', 'pc'],
    syscallNumReg: 'x8',
    argRegs: ['x0', 'x1', 'x2', 'x3', 'x4', 'x5'],
    argReg: 'x0',
    width: 64,
  };
}

function syscallTable(archId: string): { num: number; name: string; args?: string }[] {
  if (archId === 'x86-64') return x8664;
  if (archId === 'x86-32') return x8632;
  if (archId === 'arm') return armTable;
  return arm64Table;
}

// ---------------------------------------------------------------------------
// syscall emulation

interface SyscallCtx {
  e: UnicornInstance;
  glue: ArchGlue;
  getReg(name: string): bigint;
  setReg(name: string, v: bigint): void;
  readStr(addr: bigint, max?: number): string | null;
  readBytes(addr: bigint, n: number): Uint8Array | null;
  syscalls: EmuSyscall[];
  mmapCursor: number;
  nextFd: number;
  stop(reason: string): void;
}

const RET = {
  fd: (ctx: SyscallCtx) => {
    const fd = ctx.nextFd++;
    return BigInt(fd);
  },
};

function emulateSyscall(ctx: SyscallCtx, name: string, args: bigint[]): bigint | null {
  const dec = (s: string) => s.replace(/[^\x20-\x7e]/g, (c) => '\\x' + c.charCodeAt(0).toString(16).padStart(2, '0'));
  const strArg = (i: number, max = 64): string => {
    const s = ctx.readStr(args[i] ?? 0n, max);
    return s === null ? hex(args[i] ?? 0n) : `"${dec(s)}"`;
  };

  switch (name) {
    case 'execve':
    case 'execveat':
      ctx.syscalls.push({ call: `${name}(${strArg(0)}, ${hex(args[1] ?? 0n)}, ${hex(args[2] ?? 0n)})`, ret: '—' });
      ctx.stop(`execve(${strArg(0)}) — process replaced`);
      return null;
    case 'exit':
    case 'exit_group':
      ctx.syscalls.push({ call: `${name}(${args[0] ?? 0n})`, ret: '—' });
      ctx.stop(`${name}(${args[0] ?? 0n})`);
      return null;
    case 'write':
    case 'pwrite64':
    case 'writev': {
      // write(fd, buf, count) — show the bytes being written
      let buf = '';
      const n = Number(args[2] ?? 0n);
      if (name !== 'writev' && n > 0 && n <= 4096) {
        const bytes = ctx.readBytes(args[1] ?? 0n, Math.min(n, 32));
        if (bytes) buf = ` "${dec(new TextDecoder('latin1').decode(bytes)).slice(0, 32)}"`;
      }
      ctx.syscalls.push({ call: `${name}(${args[0] ?? 0n}${buf ? ',' + buf : `, ${hex(args[1] ?? 0n)}`}, ${args[2] ?? 0n})`, ret: `${args[2] ?? 0n}` });
      return args[2] ?? 0n;
    }
    case 'open':
    case 'openat':
    case 'creat': {
      const fd = RET.fd(ctx);
      ctx.syscalls.push({
        call: name === 'openat'
          ? `openat(${args[0] ?? 0n}, ${strArg(1)}, ${args[2] ?? 0n}, ${args[3] ?? 0n})`
          : `${name}(${strArg(0)}, ${args[1] ?? 0n}, ${args[2] ?? 0n})`,
        ret: String(fd),
      });
      return BigInt(fd);
    }
    case 'socket':
    case 'accept':
    case 'accept4': {
      const r = RET.fd(ctx);
      ctx.syscalls.push({ call: `${name}(${args.join(', ')})`, ret: String(r) });
      return r;
    }
    case 'dup2':
    case 'dup3':
      ctx.syscalls.push({ call: `${name}(${args[0] ?? 0n}, ${args[1] ?? 0n})`, ret: String(args[1] ?? 0n) });
      return args[1] ?? 0n;
    case 'mmap': {
      // hand out a fresh RWX page
      const len = Number(args[1] ?? 0n) || 0x1000;
      const page = ctx.mmapCursor;
      ctx.mmapCursor += (len + 0xfff) & ~0xfff;
      try {
        (ctx.e as unknown as { mem_map(a: number, s: number, p: number): void }).mem_map(page, (len + 0xfff) & ~0xfff, 7);
      } catch {
        /* already mapped — reuse */
      }
      ctx.syscalls.push({ call: `mmap(${hex(args[0] ?? 0n)}, ${args[1] ?? 0n}, ${args[2] ?? 0n}, …)`, ret: hex(page) });
      return BigInt(page);
    }
    case 'read':
    case 'recv':
    case 'recvfrom':
      ctx.syscalls.push({ call: `${name}(${args[0] ?? 0n}, ${hex(args[1] ?? 0n)}, ${args[2] ?? 0n})`, ret: '0' });
      return 0n;
    default: {
      ctx.syscalls.push({ call: `${name}(${args.map((a) => hex(a)).join(', ')})`, ret: '0' });
      return 0n;
    }
  }
}

// ---------------------------------------------------------------------------
// main entry

export async function runEmulation(
  archId: string,
  bytes: Uint8Array,
  entryArg?: bigint | null,
): Promise<EmuResult> {
  const which = emuEngineFor(archId);
  const uc = (await loadUnicorn(which)) as Record<string, number> & {
    Unicorn: new (arch: number, mode: number) => UnicornInstance;
  };

  const mode =
    archId === 'x86-64' ? uc.MODE_64! : archId === 'x86-32' ? uc.MODE_32!
    : archId === 'arm' ? uc.MODE_ARM!
    : uc.MODE_LITTLE_ENDIAN!;
  const archConst = which === 'x86' ? uc.ARCH_X86! : which === 'arm' ? uc.ARCH_ARM! : uc.ARCH_ARM64!;

  const e = new uc.Unicorn(archConst, mode);
  const glue = glueFor(archId, uc);

  const table = syscallTable(archId);
  const byNum = new Map(table.map((s) => [s.num, s.name]));

  const trace: EmuStep[] = [];
  let steps = 0;
  let traceTruncated = false;
  let exitReason = 'fell off the end of the shellcode';
  let stopped = false;

  // --- memory
  e.mem_map(CODE_MAP, CODE_SPAN, uc.PROT_ALL!);
  e.mem_map(STACK, 0x100000, uc.PROT_ALL!);
  e.mem_map(SENTINEL, 0x1000, uc.PROT_ALL!);
  e.mem_write(CODE, bytes);
  // landing pad for shellcodes that `ret`/return: ud2 = clean "invalid
  // instruction" stop instead of executing whatever zeros are there
  e.mem_write(SENTINEL, [0x0f, 0x0b]);

  const width = glue.width;
  const getReg = (name: string): bigint => {
    const id = glue.regs[name]!;
    return width === 64 ? e.reg_read_i64(id) : BigInt(e.reg_read_i32(id) >>> 0);
  };
  const setReg = (name: string, v: bigint): void => {
    const id = glue.regs[name]!;
    if (width === 64) e.reg_write_i64(id, v);
    else e.reg_write_i32(id, Number(v & 0xffffffffn));
  };

  // sentinel return address: shellcodes that `ret` land here cleanly
  const spName = archId === 'x86-64' ? 'rsp' : archId === 'x86-32' ? 'esp' : 'sp';
  const pcName = archId === 'x86-64' ? 'rip' : archId === 'x86-32' ? 'eip' : 'pc';
  setReg(spName, BigInt(STACK_TOP));
  // entry argument (SysV first-arg register) — functions like `sum_to_n` take
  // their input here; running them with the default 0 usually just spins
  if (entryArg != null && glue.argReg) setReg(glue.argReg, entryArg);
  if (archId === 'arm') setReg('lr', BigInt(SENTINEL));
  else if (archId === 'arm64') setReg('x30', BigInt(SENTINEL)); // x30 is LR
  else {
    // x86: push the sentinel so `ret` pops it
    const newsp = BigInt(STACK_TOP) - BigInt(width === 64 ? 8 : 4);
    setReg(spName, newsp);
    e.mem_write(Number(newsp), width === 64
      ? Array.from({ length: 8 }, (_, i) => Number((BigInt(SENTINEL) >> BigInt(8 * i)) & 0xffn))
      : Array.from({ length: 4 }, (_, i) => Number((BigInt(SENTINEL) >> BigInt(8 * i)) & 0xffn)));
  }

  // initial register snapshot (for `changed` highlighting)
  const initial = new Map(glue.regOrder.map((n) => [n, getReg(n)]));

  // --- helpers for syscall rendering
  const readStr = (addr: bigint, max = 64): string | null => {
    if (addr < 0x1000n) return null;
    try {
      const chunk = e.mem_read(Number(addr), max);
      const end = chunk.indexOf(0);
      const s = new TextDecoder('latin1').decode(end === -1 ? chunk : chunk.subarray(0, end));
      return s.length > 0 ? s : '\0';
    } catch {
      return null;
    }
  };
  const readBytes = (addr: bigint, n: number): Uint8Array | null => {
    try {
      return e.mem_read(Number(addr), n);
    } catch {
      return null;
    }
  };

  const syscalls: EmuSyscall[] = [];
  const ctx: SyscallCtx = {
    e,
    glue,
    getReg,
    setReg,
    readStr,
    readBytes,
    syscalls,
    mmapCursor: MMAP_BASE,
    nextFd: 3,
    stop(reason) {
      exitReason = reason;
      stopped = true;
      e.emu_stop();
    },
  };

  // --- syscall hooks
  const handleSyscall = (): void => {
    const num = Number(getReg(glue.syscallNumReg));
    const name = byNum.get(num) ?? `syscall_${num}`;
    const args = glue.argRegs.map((r) => getReg(r));
    const ret = emulateSyscall(ctx, name, args);
    if (ret !== null) setReg(glue.syscallNumReg, ret);
  };

  if (archId === 'x86-64') {
    e.hook_add(uc.HOOK_INSN!, handleSyscall, null, 1, 0, uc.X86_INS_SYSCALL!);
  } else {
    // x86-32 int 0x80 / arm svc / arm64 svc → interrupt hook
    e.hook_add(uc.HOOK_INTR!, (_h: unknown, intno: number) => {
      if (archId === 'x86-32' && intno !== 0x80) return;
      if ((archId === 'arm' || archId === 'arm64') && intno !== 0 && intno !== 2) return;
      handleSyscall();
    });
  }

  // --- code trace + limits
  let limitReached = false;
  e.hook_add(uc.HOOK_CODE!, (_h: unknown, addr: bigint, size: number) => {
    const a = Number(addr);
    if (a === SENTINEL) {
      ctx.stop('returned from the shellcode');
      return;
    }
    steps++;
    if (trace.length < TRACE_CAP) trace.push({ addr: a, size });
    else traceTruncated = true;
    if (steps >= STEP_LIMIT) {
      limitReached = true;
      ctx.stop(`instruction limit (${STEP_LIMIT}) hit — infinite loop?`);
    }
  });

  // --- fault reporting
  const memType = (t: number): string =>
    t === uc.MEM_WRITE_UNMAPPED ? 'write to'
    : t === uc.MEM_READ_UNMAPPED ? 'read from'
    : t === uc.MEM_FETCH_UNMAPPED ? 'fetch from'
    : 'access to';
  let fault: { kind: string; addr: number } | null = null;
  e.hook_add(uc.HOOK_MEM_INVALID!, (_h: unknown, type: number, addr: bigint) => {
    fault = { kind: memType(type), addr: Number(addr) };
    ctx.stop('');
    return 0;
  });

  // --- run
  let error: string | undefined;
  try {
    e.emu_start(CODE, CODE + bytes.length, 0, STEP_LIMIT + 1);
  } catch (err) {
    if (!fault && !stopped) {
      error = err instanceof Error ? err.message : String(err);
      exitReason = 'emulation error';
    }
  }

  // registers after the run
  const registers: EmuReg[] = glue.regOrder.map((n) => {
    const v = getReg(n);
    return { name: n, value: hex(v), changed: v !== initial.get(n) };
  });

  const f = fault as { kind: string; addr: number } | null;
  if (f) {
    exitReason = `⚠ ${f.kind} unmapped address ${hex(f.addr)} at ${hex(getReg(pcName))}`;
  } else if (error) {
    exitReason = `✗ ${error}`;
  } else if (limitReached) {
    exitReason = `⚠ instruction limit (${STEP_LIMIT}) hit — possible infinite loop`;
  }

  const result: EmuResult = {
    ok: !error || !!f,
    steps,
    syscalls,
    registers,
    exit: exitReason,
    trace,
    traceTruncated,
    error,
  };
  // a hook-aborted run can leave the wasm instance in a state where close()
  // throws — the result is already collected, so ignore cleanup failures
  try {
    e.close();
  } catch {
    /* already torn down */
  }
  return result;
}
