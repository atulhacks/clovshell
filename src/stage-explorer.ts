export interface StageDiffSpan {
  offset: number;
  before: Uint8Array;
  after: Uint8Array;
}

export interface StageDiff {
  changedBytes: number;
  spans: StageDiffSpan[];
  totalSpans: number;
}

/** Compare equal-address page snapshots without losing discontiguous edits. */
export function diffStagePages(before: Uint8Array, after: Uint8Array, maxSpans = 12): StageDiff {
  const length = Math.min(before.length, after.length);
  const spans: StageDiffSpan[] = [];
  let changedBytes = 0;
  let totalSpans = 0;
  for (let offset = 0; offset < length;) {
    if (before[offset] === after[offset]) {
      offset++;
      continue;
    }
    const start = offset;
    while (offset < length && before[offset] !== after[offset]) offset++;
    changedBytes += offset - start;
    totalSpans++;
    if (spans.length < maxSpans) {
      spans.push({ offset: start, before: before.slice(start, offset), after: after.slice(start, offset) });
    }
  }
  return { changedBytes, spans, totalSpans };
}
