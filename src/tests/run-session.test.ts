import { describe, expect, it } from 'vitest';
import type { EmuResult } from '../emu';
import { MAX_RUN_HISTORY, RunSessionStore } from '../run-session';

function result(): EmuResult {
  return {
    ok: true, steps: 1, syscalls: [], registers: [], exit: 'done',
    trace: [{ addr: 0x10000, size: 1, bytes: Uint8Array.from([0x90]), registers: [] }],
    traceTruncated: false, mutations: [], mutationsTruncated: false,
    stages: [], stagesTruncated: false, mapEvents: [], mapEventsTruncated: false,
    flow: { nodes: [], edges: [], path: [], truncated: false, pathTruncated: false },
    codeBase: 0x10000, initialCode: Uint8Array.from([0x90]), finalCode: Uint8Array.from([0x90]),
  };
}

const document = { revision: 3, arch: 'x86-64', source: 'nop', entryArg: '', scenarioArgs: '', fixture: '', kind: 'direct' as const, label: 'direct run' };

describe('RunSessionStore', () => {
  it('captures independent source and typed-array evidence snapshots', () => {
    const store = new RunSessionStore();
    const input = result();
    const metadata = { ...document };
    const run = store.record(metadata, input);
    metadata.arch = 'arm64';
    input.trace[0]!.bytes[0] = 0xcc;
    input.initialCode[0] = 0xcc;
    expect(run.document.arch).toBe('x86-64');
    expect(run.result.trace[0]!.bytes[0]).toBe(0x90);
    expect(run.result.initialCode[0]).toBe(0x90);
    expect(Object.isFrozen(run)).toBe(true);
    expect(Object.isFrozen(run.document)).toBe(true);
  });

  it('retains per-run selection and rejects invalid evidence', () => {
    const store = new RunSessionStore();
    const first = store.record(document, result());
    expect(store.selectRun(first.id)?.id).toBe(first.id);
    expect(store.selectEvidence({ kind: 'trace', index: 0 })).toBe(true);
    expect(store.selectEvidence({ kind: 'trace', index: 1 })).toBe(false);
    const second = store.record({ ...document, revision: 4, arch: 'arm64' }, result());
    store.selectRun(second.id);
    expect(store.selection()).toBeNull();
    store.selectRun(first.id);
    expect(store.selection()).toEqual({ kind: 'trace', index: 0 });
    store.clearSelection();
    expect(store.active()).toBeNull();
    expect(store.list()).toHaveLength(2);
  });

  it('evicts oldest runs and their selections at the fixed cap', () => {
    const store = new RunSessionStore();
    const first = store.record(document, result());
    store.selectRun(first.id);
    store.selectEvidence({ kind: 'trace', index: 0 });
    for (let index = 0; index < MAX_RUN_HISTORY; index++) {
      store.record({ ...document, revision: index + 4 }, result());
    }
    expect(store.list()).toHaveLength(MAX_RUN_HISTORY);
    expect(store.selectRun(first.id)).toBeNull();
    expect(store.active()).toBeNull();
    store.clear();
    expect(store.list()).toHaveLength(0);
  });
});
