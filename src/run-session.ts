import type { EmuResult } from './emu';

export const MAX_RUN_HISTORY = 12;

export interface RunDocument {
  revision: number;
  arch: string;
  source: string;
  entryArg: string;
  scenarioArgs: string;
  fixture: string;
  kind: 'direct' | 'scenario';
  label: string;
}

export interface RunRecord {
  readonly id: string;
  readonly sequence: number;
  readonly capturedAt: number;
  readonly document: Readonly<RunDocument>;
  readonly result: EmuResult;
}

export type EvidenceSelection =
  | { kind: 'trace' | 'flow' | 'mutation' | 'stage'; index: number }
  | { kind: 'context'; stageId: number; step: number };

export class RunSessionStore {
  private runs: RunRecord[] = [];
  private activeId: string | null = null;
  private selections = new Map<string, EvidenceSelection>();
  private serial = 0;

  record(document: RunDocument, result: EmuResult): RunRecord {
    const sequence = ++this.serial;
    const record: RunRecord = Object.freeze({
      id: `R${sequence}`,
      sequence,
      capturedAt: Date.now(),
      document: Object.freeze({ ...document }),
      result: structuredClone(result),
    });
    this.runs.unshift(record);
    while (this.runs.length > MAX_RUN_HISTORY) {
      const removed = this.runs.pop()!;
      this.selections.delete(removed.id);
      if (this.activeId === removed.id) this.activeId = null;
    }
    return record;
  }

  list(): readonly RunRecord[] { return this.runs; }
  active(): RunRecord | null { return this.runs.find((run) => run.id === this.activeId) ?? null; }

  selectRun(id: string): RunRecord | null {
    const record = this.runs.find((run) => run.id === id) ?? null;
    if (record) this.activeId = id;
    return record;
  }

  clearSelection(): void { this.activeId = null; }

  selectEvidence(selection: EvidenceSelection): boolean {
    const run = this.active();
    if (!run) return false;
    const { result } = run;
    const valid = selection.kind === 'context'
      ? result.stages.some((stage) => stage.id === selection.stageId &&
        [...stage.writerContext, ...stage.executionContext].some((step) => step.step === selection.step))
      : selection.kind === 'trace' ? selection.index >= 0 && selection.index < result.trace.length
        : selection.kind === 'flow' ? selection.index >= 0 && selection.index < result.flow.edges.length
          : selection.kind === 'mutation' ? selection.index >= 0 && selection.index < result.mutations.length
            : selection.index >= 0 && selection.index < result.stages.length;
    if (valid) this.selections.set(run.id, { ...selection });
    return valid;
  }

  selection(): EvidenceSelection | null {
    const run = this.active();
    return run ? this.selections.get(run.id) ?? null : null;
  }

  clear(): void {
    this.runs = [];
    this.activeId = null;
    this.selections.clear();
  }
}
