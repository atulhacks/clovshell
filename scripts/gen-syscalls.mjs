// Generates src/syscalls-data.ts from Linux kernel sources fetched via gh api.
// Ground truth: torvalds/linux @ master — syscall_64.tbl, syscall_32.tbl,
// syscall_arm.tbl (EABI), include/uapi/asm-generic/unistd.h (arm64).
import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { execFileSync } from 'node:child_process';

const SRC = new URL('./kernel-src/', import.meta.url).pathname;
mkdirSync(SRC, { recursive: true });

const SOURCES = {
  'syscall_64.tbl': 'arch/x86/entry/syscalls/syscall_64.tbl',
  'syscall_32.tbl': 'arch/x86/entry/syscalls/syscall_32.tbl',
  'syscall_arm.tbl': 'arch/arm/tools/syscall.tbl',
  'unistd_generic.h': 'include/uapi/asm-generic/unistd.h',
};

// fetch from torvalds/linux via gh api when not already on disk
for (const [file, path] of Object.entries(SOURCES)) {
  if (existsSync(SRC + file)) continue;
  const b64 = execFileSync(
    'gh', ['api', `repos/torvalds/linux/contents/${path}`, '--jq', '.content'],
    { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] },
  );
  writeFileSync(SRC + file, Buffer.from(b64, 'base64'));
  console.log(`fetched ${path}`);
}

function parseTbl(text) {
  const out = [];
  for (const line of text.split('\n')) {
    if (!line || line.startsWith('#')) continue;
    const m = line.match(/^(\d+)\s+(\S+)\s+(\S+)/);
    if (!m) continue;
    const [, num, abi, name] = m;
    if (abi === 'x32' || name.startsWith('unused') || name.startsWith('reserved')) continue;
    if (out.some((e) => e.num === Number(num))) continue;
    out.push({ num: Number(num), name: name.replace(/^__arm_syscalls\W*/,'') });
  }
  return out;
}

// asm-generic (arm64/riscv-style): __NR_foo N and __NR_foo (__NR_arch_specific_syscall + K)
function parseGeneric(text) {
  const out = [];
  let archSpecific = 244; // __NR_arch_specific_syscall base in asm-generic
  const archBase = text.match(/#define __NR_arch_specific_syscall\s+(\d+)/);
  if (archBase) archSpecific = Number(archBase[1]);
  // collect the 3264 indirections first — on 64-bit arches __NR_fcntl is
  // spelled `#define __NR_fcntl __NR3264_fcntl`, not a number
  const nr3264 = new Map();
  for (const m of text.matchAll(/^#define __NR3264_(\w+)\s+(\d+)\s*$/gm)) {
    nr3264.set(m[1], Number(m[2]));
  }
  for (const line of text.split('\n')) {
    let m = line.match(/^#define __NR_(\w+)\s+(\d+)\s*$/);
    if (m && !/^(arch_specific_syscall)$/.test(m[1])) {
      out.push({ num: Number(m[2]), name: m[1] });
      continue;
    }
    m = line.match(/^#define __NR_(\w+)\s+\(__NR_arch_specific_syscall\s*\+\s*(\d+)\)/);
    if (m) out.push({ num: archSpecific + Number(m[2]), name: m[1] });
  }
  // 64-bit alias block: __NR_foo __NR3264_foo (the #else branch is 32-bit-only)
  const aliasBlock = text.match(
    /#if __BITS_PER_LONG == 64([\s\S]*?)#else([\s\S]*?)#endif/,
  );
  if (aliasBlock) {
    for (const m of aliasBlock[1].matchAll(/^#define __NR_(\w+)\s+__NR3264_(\w+)\s*$/gm)) {
      const num = nr3264.get(m[2]);
      if (num !== undefined) out.push({ num, name: m[1] });
    }
  }
  // de-dup by num (later wins), drop stale compat entries
  const seen = new Map();
  for (const e of out) seen.set(e.num, e);
  return [...seen.entries()].map(([num, e]) => ({ num, name: e.name })).sort((a, b) => a.num - b.num);
}

const x64 = parseTbl(readFileSync(SRC + 'syscall_64.tbl', 'utf8'));
const x32 = parseTbl(readFileSync(SRC + 'syscall_32.tbl', 'utf8'));
const arm = parseTbl(readFileSync(SRC + 'syscall_arm.tbl', 'utf8'));
const arm64 = parseGeneric(readFileSync(SRC + 'unistd_generic.h', 'utf8'));

// Hand-curated argument signatures for the syscalls that matter in shellcode.
// Format: arch -> name -> "proto" (Linux kernel arg names).
const SIGS = {
  'x86-64': {
    read: 'fd, buf, count', write: 'fd, buf, count', open: 'filename, flags, mode',
    close: 'fd', execve: 'filename, argv, envp', exit: 'code', exit_group: 'code',
    mmap: 'addr, len, prot, flags, fd, off', mprotect: 'addr, len, prot',
    socket: 'family, type, protocol', connect: 'fd, addr, addrlen',
    dup2: 'oldfd, newfd', dup3: 'oldfd, newfd, flags', fork: 'void', vfork: 'void',
    clone: 'flags, stack, parent_tid, child_tid, tls', kill: 'pid, sig',
    setuid: 'uid', setgid: 'gid', chroot: 'filename', mount: 'src, target, fstype, flags, data',
    chmod: 'filename, mode', ptrace: 'request, pid, addr, data',
  },
  'x86-32': {
    read: 'fd, buf, count', write: 'fd, buf, count', open: 'filename, flags, mode',
    close: 'fd', execve: 'filename, argv, envp', exit: 'code', exit_group: 'code',
    mmap: 'addr, len, prot, flags, fd, off', mprotect: 'addr, len, prot',
    socketcall: 'call, args', dup2: 'oldfd, newfd', fork: 'void',
    kill: 'pid, sig', setuid: 'uid', setgid: 'gid', chroot: 'filename',
    mount: 'src, target, fstype, flags, data', chmod: 'filename, mode',
  },
  arm: {
    read: 'fd, buf, count', write: 'fd, buf, count', open: 'filename, flags, mode',
    close: 'fd', execve: 'filename, argv, envp', exit: 'code', exit_group: 'code',
    mmap2: 'addr, len, prot, flags, fd, pgoff', mprotect: 'addr, len, prot',
    socket: 'family, type, protocol', connect: 'fd, addr, addrlen',
    dup2: 'oldfd, newfd', fork: 'void', kill: 'pid, sig',
    setuid: 'uid', setgid: 'gid', chroot: 'filename', chmod: 'filename, mode',
  },
  'arm64': {
    read: 'fd, buf, count', write: 'fd, buf, count', openat: 'dirfd, filename, flags, mode',
    close: 'fd', execve: 'filename, argv, envp', exit: 'code', exit_group: 'code',
    mmap: 'addr, len, prot, flags, fd, off', mprotect: 'addr, len, prot',
    socket: 'family, type, protocol', connect: 'fd, addr, addrlen',
    dup3: 'oldfd, newfd, flags', clone: 'flags, stack, parent_tid, child_tid, tls',
    kill: 'pid, sig', setuid: 'uid', setgid: 'gid', chroot: 'filename',
    chmod: 'filename, mode',
  },
};

function emit(id, entries) {
  const sigs = SIGS[id] ?? {};
  const rows = entries
    .map((e) => `  { num: ${e.num}, name: '${e.name}'${sigs[e.name] ? `, args: '${sigs[e.name]}'` : ''} },`)
    .join('\n');
  return `export const ${id.replace(/-/g, '')}: SyscallEntry[] = [\n${rows}\n];\n`;
}

const ts = `// AUTO-GENERATED by scripts/gen-syscalls.mjs — Linux syscall name/number tables.
// Source: torvalds/linux (arch/x86/entry/syscalls/*.tbl, arch/arm/tools/syscall.tbl,
// include/uapi/asm-generic/unistd.h). Args are hand-curated for common calls.
// Do not edit by hand — regenerate after refreshing the kernel sources.

export interface SyscallEntry {
  num: number;
  name: string;
  /** kernel argument names, curated for common calls */
  args?: string;
}

${emit('x86-64', x64)}${emit('x86-32', x32)}${emit('arm', arm)}${emit('arm64', arm64)}
`;

writeFileSync(new URL('../src/syscalls-data.ts', import.meta.url).pathname, ts);
console.log(`x86-64: ${x64.length}  x86-32: ${x32.length}  arm: ${arm.length}  arm64: ${arm64.length}`);
console.log('spot checks:',
  'execve x64 =', x64.find(e => e.name === 'execve')?.num,
  '| execve x32 =', x32.find(e => e.name === 'execve')?.num,
  '| execve arm =', arm.find(e => e.name === 'execve')?.num,
  '| execve arm64 =', arm64.find(e => e.name === 'execve')?.num,
  '| write arm64 =', arm64.find(e => e.name === 'write')?.num,
  '| socket arm =', arm.find(e => e.name === 'socket')?.num,
  '| connect arm64 =', arm64.find(e => e.name === 'connect')?.num);
