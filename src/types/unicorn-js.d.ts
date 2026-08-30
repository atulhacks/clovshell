// Type shim for @alexaltea/unicorn-js (ships without .d.ts).
// Each subpath export ('/x86', '/arm', '/aarch64') is an Emscripten factory:
// calling it resolves to the initialized Module with unicorn constants and
// the Unicorn class attached. The WASM is embedded in each single-arch build.

declare module '@alexaltea/unicorn-js/x86' {
  export interface UnicornHookApi {
    hook_add(
      type: number,
      cb: (...args: any[]) => number | void,
      userData?: unknown,
      begin?: number,
      end?: number,
      extra?: number,
    ): unknown;
    hook_del(handle: unknown): void;
  }

  export interface UnicornInstance extends UnicornHookApi {
    reg_write_i64(reg: number, value: bigint): void;
    reg_write_i32(reg: number, value: number): void;
    reg_read_i64(reg: number): bigint;
    reg_read_i32(reg: number): number;
    mem_map(addr: number, size: number, perms: number): void;
    mem_write(addr: number, bytes: Uint8Array | number[]): void;
    mem_read(addr: number, size: number): Uint8Array;
    emu_start(begin: number, until: number, timeoutUs: number, count: number): void;
    emu_stop(): void;
    close(): void;
  }

  export interface UnicornX86Module {
    // arch/mode
    ARCH_X86: number;
    MODE_16: number;
    MODE_32: number;
    MODE_64: number;
    // hooks
    HOOK_INTR: number;
    HOOK_INSN: number;
    HOOK_CODE: number;
    HOOK_MEM_INVALID: number;
    // x86 insn ids for HOOK_INSN
    X86_INS_SYSCALL: number;
    // registers
    X86_REG_RAX: number;
    X86_REG_RBX: number;
    X86_REG_RCX: number;
    X86_REG_RDX: number;
    X86_REG_RSI: number;
    X86_REG_RDI: number;
    X86_REG_RBP: number;
    X86_REG_RSP: number;
    X86_REG_RIP: number;
    X86_REG_R8: number;
    X86_REG_R9: number;
    X86_REG_R10: number;
    X86_REG_R11: number;
    X86_REG_R12: number;
    X86_REG_R13: number;
    X86_REG_R14: number;
    X86_REG_R15: number;
    X86_REG_EAX: number;
    X86_REG_EBX: number;
    X86_REG_ECX: number;
    X86_REG_EDX: number;
    X86_REG_ESI: number;
    X86_REG_EDI: number;
    X86_REG_EBP: number;
    X86_REG_ESP: number;
    X86_REG_EIP: number;
    // memory event types (passed to HOOK_MEM_INVALID cb)
    MEM_READ_UNMAPPED: number;
    MEM_WRITE_UNMAPPED: number;
    MEM_FETCH_UNMAPPED: number;
    PROT_ALL: number;
    Unicorn: new (arch: number, mode: number) => UnicornInstance;
  }

  const MUnicorn: (moduleArg?: Record<string, unknown>) => Promise<UnicornX86Module>;
  export default MUnicorn;
}

declare module '@alexaltea/unicorn-js/arm' {
  import type { UnicornInstance } from '@alexaltea/unicorn-js/x86';

  export interface UnicornArmModule {
    ARCH_ARM: number;
    MODE_ARM: number;
    MODE_THUMB: number;
    MODE_LITTLE_ENDIAN: number;
    HOOK_INTR: number;
    HOOK_CODE: number;
    HOOK_MEM_INVALID: number;
    ARM_REG_R0: number;
    ARM_REG_R1: number;
    ARM_REG_R2: number;
    ARM_REG_R3: number;
    ARM_REG_R4: number;
    ARM_REG_R5: number;
    ARM_REG_R6: number;
    ARM_REG_R7: number;
    ARM_REG_R8: number;
    ARM_REG_R9: number;
    ARM_REG_R10: number;
    ARM_REG_R11: number;
    ARM_REG_R12: number;
    ARM_REG_SP: number;
    ARM_REG_LR: number;
    ARM_REG_PC: number;
    ARM_REG_CPSR: number;
    MEM_READ_UNMAPPED: number;
    MEM_WRITE_UNMAPPED: number;
    MEM_FETCH_UNMAPPED: number;
    PROT_ALL: number;
    Unicorn: new (arch: number, mode: number) => UnicornInstance;
  }

  const MUnicorn: (moduleArg?: Record<string, unknown>) => Promise<UnicornArmModule>;
  export default MUnicorn;
}

declare module '@alexaltea/unicorn-js/aarch64' {
  import type { UnicornInstance } from '@alexaltea/unicorn-js/x86';

  export interface UnicornA64Module {
    ARCH_ARM64: number;
    MODE_LITTLE_ENDIAN: number;
    MODE_ARM: number;
    HOOK_INTR: number;
    HOOK_CODE: number;
    HOOK_MEM_INVALID: number;
    ARM64_REG_X0: number;
    ARM64_REG_X1: number;
    ARM64_REG_X2: number;
    ARM64_REG_X3: number;
    ARM64_REG_X4: number;
    ARM64_REG_X5: number;
    ARM64_REG_X8: number;
    ARM64_REG_X9: number;
    ARM64_REG_X10: number;
    ARM64_REG_X11: number;
    ARM64_REG_X12: number;
    ARM64_REG_X13: number;
    ARM64_REG_X14: number;
    ARM64_REG_X15: number;
    ARM64_REG_X16: number;
    ARM64_REG_X17: number;
    ARM64_REG_X18: number;
    ARM64_REG_X19: number;
    ARM64_REG_X20: number;
    ARM64_REG_X21: number;
    ARM64_REG_X22: number;
    ARM64_REG_X23: number;
    ARM64_REG_X24: number;
    ARM64_REG_X25: number;
    ARM64_REG_X26: number;
    ARM64_REG_X27: number;
    ARM64_REG_X28: number;
    ARM64_REG_X29: number;
    ARM64_REG_X30: number;
    ARM64_REG_SP: number;
    ARM64_REG_PC: number;
    MEM_READ_UNMAPPED: number;
    MEM_WRITE_UNMAPPED: number;
    MEM_FETCH_UNMAPPED: number;
    PROT_ALL: number;
    Unicorn: new (arch: number, mode: number) => UnicornInstance;
  }

  const MUnicorn: (moduleArg?: Record<string, unknown>) => Promise<UnicornA64Module>;
  export default MUnicorn;
}
