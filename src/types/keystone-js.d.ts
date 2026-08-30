// Type shim for @alexaltea/keystone-js (ships without .d.ts).
// The module is the Emscripten factory: calling it returns a promise that
// resolves to the initialized Module with keystone constants and the
// Keystone class attached.

declare module '@alexaltea/keystone-js' {
  export interface KeystoneAsmResult {
    /** encoded machine code (empty when assembly failed) */
    mc: Uint8Array;
    /** number of instructions successfully assembled */
    count: number;
    /** true when keystone reported an error */
    failed: boolean;
  }

  export interface KeystoneInstance {
    asm(assembly: string, address?: number | bigint): KeystoneAsmResult;
    errno(): number;
    option(option: number, value: number): void;
    close(): void;
  }

  export interface KeystoneModule {
    // arches
    ARCH_ARM: number;
    ARCH_ARM64: number;
    ARCH_MIPS: number;
    ARCH_X86: number;
    // modes
    MODE_LITTLE_ENDIAN: number;
    MODE_BIG_ENDIAN: number;
    MODE_ARM: number;
    MODE_16: number;
    MODE_32: number;
    MODE_64: number;
    // errors
    ERR_OK: number;
    ERR_ASM_SYMBOL_MODIFIER: number;
    ERR_ASM_SYMBOL_REDEFINED: number;
    ERR_ASM_SYMBOL_MISSING: number;
    strerror(code: number): string;
    Keystone: new (arch: number, mode: number) => KeystoneInstance;
  }

  const MKeystone: (moduleArg?: Record<string, unknown>) => Promise<KeystoneModule>;
  export default MKeystone;
}
