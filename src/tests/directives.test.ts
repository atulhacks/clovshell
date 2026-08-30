import { describe, expect, it } from 'vitest';
import { stripDirectives } from '../directives';

describe('stripDirectives', () => {
  it('blanks non-emitting directives, line-preserving', () => {
    const src = ['.global main', '.type main, %function', 'main:', '    mov eax, 1'].join('\n');
    const out = stripDirectives(src).split('\n');
    expect(out).toHaveLength(4);
    expect(out[0]).toBe('');
    expect(out[1]).toBe('');
    expect(out[2]).toBe('main:');
    expect(out[3]).toBe('    mov eax, 1');
  });

  it('keeps data-emitting directives', () => {
    for (const line of ['    .byte 0x44', '.short 2', '.word 4', '.long 8', '.quad 16', '.asciz "hi"', '.ascii "hi"', '.skip 4', '.zero 8', '.xword 16']) {
      expect(stripDirectives(line)).toBe(line);
    }
  });

  it('drops section directives that would crash keystone', () => {
    expect(stripDirectives('.text')).toBe('');
    expect(stripDirectives('.data')).toBe('');
    expect(stripDirectives('.section .text')).toBe('');
  });

  it('keeps labels, including .L local labels', () => {
    expect(stripDirectives('loop:')).toBe('loop:');
    expect(stripDirectives('.L1:')).toBe('.L1:');
    expect(stripDirectives('.Llocal_label_2:')).toBe('.Llocal_label_2:');
  });

  it('drops cfi / compiler metadata', () => {
    expect(stripDirectives('    .cfi_startproc')).toBe('');
    expect(stripDirectives('    .cfi_def_cfa_offset 16')).toBe('');
    expect(stripDirectives('.file 1 "x.c"')).toBe('');
  });

  it('leaves plain instructions untouched', () => {
    expect(stripDirectives('    mov eax, 1')).toBe('    mov eax, 1');
    expect(stripDirectives('')).toBe('');
  });
});
