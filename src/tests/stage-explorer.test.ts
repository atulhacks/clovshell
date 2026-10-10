import { describe, expect, it } from 'vitest';
import { diffStagePages } from '../stage-explorer';

describe('diffStagePages', () => {
  it('keeps separate edits and their exact original bytes', () => {
    const before = Uint8Array.from([0, 1, 2, 3, 4, 5, 6]);
    const after = Uint8Array.from([0, 9, 8, 3, 4, 7, 6]);
    const diff = diffStagePages(before, after);
    expect(diff.changedBytes).toBe(3);
    expect(diff.totalSpans).toBe(2);
    expect(diff.spans).toEqual([
      { offset: 1, before: Uint8Array.from([1, 2]), after: Uint8Array.from([9, 8]) },
      { offset: 5, before: Uint8Array.from([5]), after: Uint8Array.from([7]) },
    ]);
  });

  it('bounds displayed spans without misreporting totals', () => {
    const diff = diffStagePages(Uint8Array.from([0, 1, 0, 1, 0, 1]),
      Uint8Array.from([2, 1, 2, 1, 2, 1]), 1);
    expect(diff).toMatchObject({ changedBytes: 3, totalSpans: 3 });
    expect(diff.spans).toHaveLength(1);
  });
});
