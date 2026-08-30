import { describe, expect, it } from 'vitest';
import { findCommentIndex, stripComments } from '../comments';
import { getArch } from '../engines';

const X64 = getArch('x86-64');
const ARM = getArch('arm');
const ARM64 = getArch('arm64');

describe('commentStartAt / findCommentIndex', () => {
  it('treats ; and // as comments on every arch', () => {
    expect(findCommentIndex('mov eax, 1 ; hi', X64)).toBe(11);
    expect(findCommentIndex('mov eax, 1 // hi', X64)).toBe(11);
    expect(findCommentIndex('mov r0, #1 ; hi', ARM)).toBe(11);
  });

  it('treats # as a comment on x86 but as an immediate on ARM', () => {
    expect(findCommentIndex('mov eax, 1 # hi', X64)).toBe(11);
    expect(findCommentIndex('mov r0, #1', ARM)).toBe(-1);
    expect(findCommentIndex('mov r0, #0x10', ARM64)).toBe(-1);
    expect(findCommentIndex('sub r0, r0, #1', ARM)).toBe(-1);
    expect(findCommentIndex('mov r0, # comment', ARM)).toBe(8); // space then word → comment
  });

  it('treats @ as a comment on ARM32 only', () => {
    expect(findCommentIndex('mov r0, #1 @ hi', ARM)).toBe(11);
    expect(findCommentIndex('mov x0, #1 @ hi', ARM64)).toBe(-1);
  });

  it('is quote-aware', () => {
    expect(findCommentIndex('mov rax, "; not a comment"', X64)).toBe(-1);
    expect(findCommentIndex("mov rax, '; x'", X64)).toBe(-1);
    expect(findCommentIndex('mov rax, "a" ; real', X64)).toBe(13);
  });
});

describe('stripComments', () => {
  it('strips comments but preserves line structure', () => {
    const out = stripComments('mov eax, 1 ; a\n\nnop // b', X64);
    expect(out.split('\n')).toHaveLength(3);
    // slicing at the comment start keeps the space before it — harmless to keystone
    expect(out).toBe('mov eax, 1 \n\nnop ');
  });

  it('leaves immediates on ARM intact', () => {
    expect(stripComments('mov r0, #4\nadd r1, r1, #-2', ARM)).toBe('mov r0, #4\nadd r1, r1, #-2');
  });

  it('keeps instructions with # inside strings on x86', () => {
    expect(stripComments('mov rax, 0x22 ; "# inside"', X64)).toBe('mov rax, 0x22 ');
  });
});
