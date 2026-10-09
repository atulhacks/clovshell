declare module '@alexaltea/capstone-js' {
  export interface CapstoneInstruction {
    address: bigint;
    size: number;
    bytes: number[];
    mnemonic: string;
    op_str: string;
  }

  export interface CapstoneInstance {
    disasm(bytes: Uint8Array | number[], address?: number, count?: number): CapstoneInstruction[];
    close(): void;
  }

  export interface CapstoneModule {
    Capstone: new (arch: number, mode: number) => CapstoneInstance;
  }

  export default function MCapstone(options?: { locateFile?: (path: string) => string }): Promise<CapstoneModule>;
}
