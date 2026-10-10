// Syscall reference panel: filterable table of Linux syscall numbers per arch,
// with click-to-insert. Numbers generated from torvalds/linux (see
// scripts/gen-syscalls.mjs).

import type { SyscallEntry } from './syscalls-data';
import { x8664, x8632, arm as armTable, arm64 as arm64Table } from './syscalls-data';

export function tableFor(archId: string): SyscallEntry[] {
  if (archId === 'x86-64') return x8664;
  if (archId === 'x86-32') return x8632;
  if (archId === 'arm' || archId === 'arm-thumb') return armTable;
  return arm64Table;
}

const SHOW = 40;

export interface SyscallPanelOpts {
  listEl: HTMLElement;
  searchEl: HTMLInputElement;
  initialArch?: string;
  /** called with the syscall entry the user clicked */
  onPick: (entry: SyscallEntry) => void;
}

export function createSyscallPanel({ listEl, searchEl, initialArch = 'x86-64', onPick }: SyscallPanelOpts): void {
  let currentArch = initialArch;
  let filter = searchEl.value;

  const render = (): void => {
    const table = tableFor(currentArch);
    const q = filter.trim().toLowerCase();
    const matches = q
      ? table.filter((e) => e.name.includes(q) || String(e.num) === q)
      : table;
    const shown = matches.slice(0, SHOW);

    listEl.replaceChildren();
    if (shown.length === 0) {
      listEl.append(
        Object.assign(document.createElement('div'), {
          className: 'listing-empty',
          textContent: `no syscall matches “${filter}” on this arch`,
        }),
      );
      return;
    }

    for (const e of shown) {
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'syscall-item';
      btn.title = e.args ? `${e.name}(${e.args})` : `insert ${e.name}`;
      const num = document.createElement('span');
      num.className = 'syscall-num';
      num.textContent = String(e.num);
      const name = document.createElement('span');
      name.className = 'syscall-name';
      name.textContent = e.name;
      const args = document.createElement('span');
      args.className = 'syscall-args';
      args.textContent = e.args ? `(${e.args})` : '';
      btn.append(num, name, args);
      btn.addEventListener('click', () => onPick(e));
      listEl.append(btn);
    }

    if (matches.length > shown.length) {
      listEl.append(
        Object.assign(document.createElement('div'), {
          className: 'listing-truncated',
          textContent: `… ${matches.length - shown.length} more — keep typing to narrow down`,
        }),
      );
    }
  };

  searchEl.addEventListener('input', () => {
    filter = searchEl.value;
    render();
  });

  render();
  // arch changes re-render via setArch
  (listEl as HTMLElement & { __setArch?: (id: string) => void }).__setArch = (id: string) => {
    currentArch = id;
    render();
  };
}

/** assembly snippet that loads a syscall number, per arch convention */
export function syscallScaffold(archId: string, entry: SyscallEntry): string {
  const n = entry.num;
  if (archId === 'x86-64') {
    return `; ${entry.name}${entry.args ? `(${entry.args})` : ''} — syscall #${n}\nmov rax, ${n}\n; rdi, rsi, rdx, r10, r8, r9 = args\nsyscall`;
  }
  if (archId === 'x86-32') {
    return `; ${entry.name}${entry.args ? `(${entry.args})` : ''} — syscall #${n}\nmov eax, ${n}\n; ebx, ecx, edx, esi, edi, ebp = args\nint 0x80`;
  }
  if (archId === 'arm' || archId === 'arm-thumb') {
    return `; ${entry.name}${entry.args ? `(${entry.args})` : ''} — syscall #${n}\nmov r7, #${n}\n; r0-r5 = args\nsvc 0`;
  }
  return `; ${entry.name}${entry.args ? `(${entry.args})` : ''} — syscall #${n}\nmov x8, ${n}\n; x0-x5 = args\nsvc 0`;
}
