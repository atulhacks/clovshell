// clovshell — application wiring.

import './style.css';
import {
  ARCHES,
  assemble,
  disassemble,
  enginesReady,
  getArch,
  initEngines,
} from './engines';
import type { AssembleResult, DisassembleResult } from './engines';
import {
  countBadBytes,
  countNullBytes,
  describeBadChars,
  formatAddress,
  MAX_HEX_BYTES,
  parseBadChars,
  parseHexInput,
  toHex,
  toSpacedHex,
} from './hex';
import { FORMATS } from './formats';
import { highlightInstruction } from './highlight';
import { createEditor, editorTemplate } from './editor';
import { entryArgReg } from './emu';
import type { EmuContextStep, EmuMutation, EmuResult, EmuStage } from './emu';
import { diffStagePages } from './stage-explorer';
import { xorEncode } from './encoder';
import { gadgetRows } from './gadgets';
import type { Gadget } from './gadgets';
import { createSyscallPanel, syscallScaffold } from './syscalls';
import { PRESETS } from './presets';
import { initTheme } from './themes';
import { bootDone, bootFail, bootStage, initBoot } from './boot';
import {
  $, copyText, decodeState, downloadBytes, downloadText, el, encodeState,
  flashCopyFeedback, toast,
} from './ui';

const STORAGE_KEY = 'clovshell:v1';
const MAX_ASM_CHARS = 64 * 1024;

const SAMPLE = `; clovshell — assemble me (ctrl/cmd + enter)
mov eax, 0x64696b73
mov ebx, 0x37333331
xor ecx, ecx
nop`;

// --- state ------------------------------------------------------------------

let archId = 'x86-64';
let currentBytes: Uint8Array | null = null; // drives the exports section
let currentBytesSource: 'assembler' | 'hex input' | null = null;
let lastAssembled: Uint8Array | null = null;

function clearBytesFrom(source: 'assembler' | 'hex input'): void {
  if (currentBytesSource !== source) return;
  currentBytes = null;
  currentBytesSource = null;
  invalidateDerivedViews();
  renderExports();
}

function setCurrentBytes(bytes: Uint8Array, source: 'assembler' | 'hex input'): void {
  currentBytes = bytes;
  currentBytesSource = source;
  invalidateDerivedViews();
  renderExports();
}

// --- elements ----------------------------------------------------------------

const archSelect = $<HTMLSelectElement>('#arch-select');
const asmMsg = $('#asm-msg');
const hexMsg = $('#hex-msg');
const hexInput = $<HTMLTextAreaElement>('#hex-input');
const shellcodeOut = $('#shellcode-out');
const shellcodeStats = $('#shellcode-stats');
const disasmListing = $('#disasm-listing');
const disasmStats = $('#disasm-stats');
const exportsGrid = $('#exports-grid');
const exportsSource = $('#exports-source');
const btnAssemble = $<HTMLButtonElement>('#btn-assemble');
const btnDisassemble = $<HTMLButtonElement>('#btn-disassemble');
const chipKeystone = $('#chip-keystone');
const chipCapstone = $('#chip-capstone');
const chipUnicorn = $('#chip-unicorn');
const fatalMsg = $('#fatal-msg');
const emuLog = $('#emu-log');
const emuRegs = $('#emu-regs');
const emuMsg = $('#emu-msg');
const tracePanel = $('#trace-panel');
const traceStats = $('#trace-stats');
const traceList = $('#trace-list');
const traceRegisters = $('#trace-registers');
const traceSelected = $('#trace-selected');
const tracePosition = $('#trace-position');
const tracePrev = $<HTMLButtonElement>('#trace-prev');
const traceNext = $<HTMLButtonElement>('#trace-next');
const traceDownload = $<HTMLButtonElement>('#trace-download');
const stageDownload = $<HTMLButtonElement>('#stage-download');
const mutationStats = $('#mutation-stats');
const mutationList = $('#mutation-list');
const mutationDetail = $('#mutation-detail');
const stageStats = $('#stage-stats');
const stageList = $('#stage-list');
const stageDetail = $('#stage-detail');
const stageSnapshotDownload = $<HTMLButtonElement>('#stage-snapshot-download');
const stageDiffStats = $('#stage-diff-stats');
const stageDiffSpans = $('#stage-diff-spans');
const stageBeforeLabel = $('#stage-before-label');
const stageBeforeBytes = $('#stage-before-bytes');
const stageBeforeDisasm = $('#stage-before-disasm');
const stageAfterLabel = $('#stage-after-label');
const stageAfterBytes = $('#stage-after-bytes');
const stageAfterDisasm = $('#stage-after-disasm');
const stageWriterContext = $('#stage-writer-context');
const stageExecutionContext = $('#stage-execution-context');
const stageContextDetail = $('#stage-context-detail');
const btnRunEmu = $<HTMLButtonElement>('#btn-run-emu');
const emuArgInput = $<HTMLInputElement>('#emu-arg');
const emuArgLabel = $('#emu-arg-label');
const emuArgWrap = $('#emu-arg-wrap');
const badCharsInput = $<HTMLInputElement>('#bad-chars');
const badCharsMsg = $('#bad-chars-msg');

// bad-character table shared by the shellcode view, the listing and the stats
let badChars = new Array<boolean>(256).fill(false);

/** parse the entry-arg box: hex (0x…) or decimal; empty → null, garbage → error */
function parseEntryArg(): { value: bigint } | { error: string } | null {
  const raw = emuArgInput.value.trim();
  if (!raw) return null;
  const reg = entryArgReg(archId) ?? 'arg';
  try {
    const v = BigInt(raw.toLowerCase());
    const mask = archId === 'x86-64' || archId === 'arm64' ? 0xffffffffffffffffn : 0xffffffffn;
    return { value: v & mask };
  } catch {
    return { error: `entry ${reg}: "${raw}" is not a hex (0x…) or decimal number` };
  }
}

function updateEmuArgUi(): void {
  const reg = entryArgReg(archId);
  emuArgWrap.classList.toggle('hidden', reg === null);
  if (reg) emuArgLabel.textContent = reg;
}

// editor lives inside the ASSEMBLY section
$('#asm-editor-host').append(editorTemplate('Assembly source'));
const editor = createEditor($('#asm-editor-host'), SAMPLE, getArch(archId));

// --- export cards -------------------------------------------------------------

interface ExportCard {
  pre: HTMLPreElement;
  copyBtn: HTMLButtonElement;
  saveBtn: HTMLButtonElement;
}
const exportCards = new Map<string, ExportCard>();

for (const fmt of FORMATS) {
  const pre = el('pre', { class: 'export-pre' });
  const copyBtn = el('button', { class: 'btn ghost', type: 'button' }, 'copy');
  copyBtn.addEventListener('click', async () => {
    if (await copyText(pre.textContent ?? '')) flashCopyFeedback(copyBtn);
    else toast('copy failed — select the text manually');
  });
  const saveBtn = el('button', {
    class: 'btn ghost',
    type: 'button',
    title: `save as shellcode.${fmt.ext}`,
  }, '⭳');
  saveBtn.addEventListener('click', () => {
    const text = pre.textContent ?? '';
    if (!text || pre.classList.contains('empty')) {
      toast('nothing to save yet');
      return;
    }
    downloadText(`shellcode.${fmt.ext}`, text);
  });
  const card = el('div', { class: 'export-card' },
    el('div', { class: 'export-head' },
      el('span', { class: 'export-label' }, fmt.label),
      el('span', { class: 'export-head-actions' }, saveBtn, copyBtn),
    ),
    pre,
  );
  exportsGrid.append(card);
  exportCards.set(fmt.id, { pre, copyBtn, saveBtn });
}

// --- rendering -----------------------------------------------------------------

function setMsg(node: HTMLElement, text: string, kind: 'ok' | 'err' | 'warn' | ''): void {
  node.textContent = text;
  node.className = 'msg' + (kind ? ' ' + kind : '');
}

/** render hex bytes with bad characters flagged; output is plain hex text so
 *  the markup only ever contains [0-9a-f<i clas="…">] — no escaping needed */
function hexWithBadFlags(bytes: Uint8Array, sep = ''): string {
  const parts: string[] = [];
  for (const b of bytes) {
    const h = b.toString(16).padStart(2, '0');
    parts.push(badChars[b] ? `<i class="bad">${h}</i>` : h);
  }
  return parts.join(sep);
}

function renderShellcode(bytes: Uint8Array | null, count: number, fromError = false): void {
  if (!bytes || bytes.length === 0) {
    shellcodeOut.textContent = fromError ? '— assembly failed —' : '// assembled bytes appear here';
    shellcodeOut.classList.toggle('empty', !fromError);
    shellcodeStats.innerHTML = '';
    return;
  }
  shellcodeOut.classList.remove('empty');
  shellcodeOut.innerHTML = hexWithBadFlags(bytes);
  const nulls = countNullBytes(bytes);
  const badCount = countBadBytes(bytes, badChars);
  const parts = [`${bytes.length} bytes`, `${count} insn`];
  if (badCount > 0) {
    const what = describeBadChars(badChars);
    parts.push(`<span class="stat-bad">⚠ ${badCount} bad byte${badCount > 1 ? 's' : ''} (${what})</span>`);
  } else {
    parts.push(`<span class="stat-ok">✓ 0 bad bytes (${describeBadChars(badChars)})</span>`);
  }
  // nulls are only worth their own callout when they aren't already flagged
  if (nulls > 0 && !badChars[0]) parts.push(`<span class="stat-bad">⚠ ${nulls} null byte${nulls > 1 ? 's' : ''}</span>`);
  shellcodeStats.innerHTML = parts.join(' · ');
}

const DISASM_PAGE_SIZE = 500;
let shownDisassembly: DisassembleResult | null = null;
let shownInsns = 0;

function appendDisassemblyPage(): void {
  const result = shownDisassembly;
  if (!result?.ok) return;
  disasmListing.querySelector('.listing-more')?.remove();
  const end = Math.min(shownInsns + DISASM_PAGE_SIZE, result.insns.length);
  const arch = getArch(archId);
  const fragment = document.createDocumentFragment();
  for (let i = shownInsns; i < end; i++) {
    const insn = result.insns[i]!;
    const bytesHtml = hexWithBadFlags(insn.bytes, ' ');
    const row = el('div', { class: 'row' });
    row.innerHTML =
      `<span class="addr">${formatAddress(insn.address)}</span>` +
      `<span class="bytes">${bytesHtml}</span>` +
      `<span class="insn">${highlightInstruction(insn.mnemonic, insn.opStr, arch)}</span>`;
    fragment.append(row);
  }
  shownInsns = end;
  disasmListing.append(fragment);
  if (end < result.insns.length) {
    const more = el('button', { class: 'listing-more', type: 'button' },
      `show next ${Math.min(DISASM_PAGE_SIZE, result.insns.length - end)} · ${end} of ${result.insns.length}`);
    more.addEventListener('click', appendDisassemblyPage);
    disasmListing.append(more);
  } else {
    const undecoded = result.total - result.consumed;
    if (undecoded > 0) {
      disasmListing.append(el('div', { class: 'listing-truncated' },
        `⚠ stopped at 0x${formatAddress(result.consumed)} — ${undecoded} undecodable byte${undecoded > 1 ? 's' : ''}`));
    }
  }
}

function renderDisassembly(result: DisassembleResult): void {
  shownDisassembly = result;
  shownInsns = 0;
  disasmListing.replaceChildren();
  if (!result.ok) {
    disasmListing.append(el('div', { class: 'listing-empty' }, result.error ?? 'nothing to decode'));
    disasmStats.innerHTML = '';
    return;
  }
  if (result.insns.length === 0) {
    disasmListing.append(el('div', { class: 'listing-empty' }, '// paste hex bytes above — listing appears here'));
    disasmStats.innerHTML = '';
    return;
  }
  appendDisassemblyPage();
  const undecoded = result.total - result.consumed;
  if (undecoded > 0) {
    disasmStats.innerHTML = `<span class="stat-bad">${result.insns.length} insn · ${undecoded} bytes undecoded</span>`;
  } else {
    disasmStats.textContent = `${result.insns.length} insn · ${result.total} bytes`;
  }
}

function renderExports(): void {
  const bytes = currentBytes;
  for (const fmt of FORMATS) {
    const card = exportCards.get(fmt.id)!;
    if (bytes && bytes.length > 0) {
      card.pre.textContent = fmt.make(bytes);
      card.pre.classList.remove('empty');
      card.copyBtn.disabled = false;
      card.saveBtn.disabled = false;
    } else {
      card.pre.textContent = '// no bytes yet';
      card.pre.classList.add('empty');
      card.copyBtn.disabled = true;
      card.saveBtn.disabled = true;
    }
  }
  exportsSource.textContent = currentBytesSource ? `· from ${currentBytesSource}` : '';
}

// --- actions ---------------------------------------------------------------------

interface AssemblyOutput { result: AssembleResult; insnCount: number }

function assembleInWorker(arch: string, source: string, signal?: AbortSignal): Promise<AssemblyOutput> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) { reject(new DOMException('aborted', 'AbortError')); return; }
    const worker = new Worker(new URL('./asm-worker.ts', import.meta.url), { type: 'module' });
    const cleanup = (): void => {
      clearTimeout(timer);
      signal?.removeEventListener('abort', abort);
      worker.terminate();
    };
    const abort = (): void => { cleanup(); reject(new DOMException('aborted', 'AbortError')); };
    const timer = setTimeout(() => { cleanup(); reject(new Error('assembly timed out after 30 seconds')); }, 30_000);
    signal?.addEventListener('abort', abort, { once: true });
    worker.onmessage = (event: MessageEvent<AssemblyOutput | { error: string }>) => {
      cleanup();
      if ('error' in event.data) reject(new Error(event.data.error));
      else resolve(event.data);
    };
    worker.onerror = (event) => { cleanup(); reject(new Error(event.message || 'assembly worker failed')); };
    worker.postMessage({ archId: arch, source, baseURI: document.baseURI });
  });
}

let asmGeneration = 0;
let asmAbort: AbortController | null = null;
let autoAssembleTimer: ReturnType<typeof setTimeout> | null = null;

function cancelAssembly(): void {
  asmGeneration++;
  asmAbort?.abort();
  asmAbort = null;
}

async function runAssemble(): Promise<void> {
  if (autoAssembleTimer !== null) clearTimeout(autoAssembleTimer);
  autoAssembleTimer = null;
  cancelAssembly();
  const generation = asmGeneration;
  const src = editor.getValue().trim();
  if (!src) {
    lastAssembled = null;
    clearBytesFrom('assembler');
    renderShellcode(null, 0);
    setMsg(asmMsg, '', '');
    return;
  }
  if (src.length > MAX_ASM_CHARS) {
    lastAssembled = null;
    clearBytesFrom('assembler');
    renderShellcode(null, 0, true);
    setMsg(asmMsg, `✗ assembly source exceeds the ${MAX_ASM_CHARS}-character limit`, 'err');
    return;
  }
  const runArch = archId;
  const controller = new AbortController();
  asmAbort = controller;
  lastAssembled = null;
  clearBytesFrom('assembler');
  setMsg(asmMsg, 'assembling…', '');
  let output: AssemblyOutput;
  try {
    output = await assembleInWorker(runArch, src, controller.signal);
  } catch (error) {
    if (generation !== asmGeneration) return;
    asmAbort = null;
    renderShellcode(null, 0, true);
    setMsg(asmMsg, `✗ ${error instanceof Error ? error.message : String(error)}`, 'err');
    return;
  }
  if (generation !== asmGeneration || archId !== runArch || editor.getValue().trim() !== src) return;
  asmAbort = null;
  const { result: res, insnCount } = output;
  if (res.ok && res.bytes) {
    lastAssembled = res.bytes;
    setCurrentBytes(res.bytes, 'assembler');
    renderShellcode(res.bytes, insnCount);
    setMsg(
      asmMsg,
      res.bytes.length > 0
        ? `✓ assembled ${insnCount} instruction${insnCount === 1 ? '' : 's'}`
        : '✓ assembled — no code emitted (comments/directives only?)',
      'ok',
    );
  } else {
    lastAssembled = null;
    clearBytesFrom('assembler');
    renderShellcode(null, 0, true);
    const where = res.errorLine
      ? ` — near line ${res.errorLine}${res.errorSource ? `: \`${res.errorSource}\`` : ''}`
      : '';
    setMsg(asmMsg, `✗ ${res.error}${where}`, 'err');
  }
  renderExports();
}

let disasmGeneration = 0;
let disasmWorker: Worker | null = null;
let disasmTimer: ReturnType<typeof setTimeout> | null = null;

function cancelDisassembly(): void {
  disasmGeneration++;
  disasmWorker?.terminate();
  disasmWorker = null;
  if (disasmTimer !== null) clearTimeout(disasmTimer);
  disasmTimer = null;
}

function runDisassemble(): void {
  cancelDisassembly();
  const text = hexInput.value.trim();
  if (!text) {
    disassembleClear();
    return;
  }
  const parsed = parseHexInput(text);
  if (parsed.error) {
    clearBytesFrom('hex input');
    setMsg(hexMsg, `✗ ${parsed.error}`, 'err');
    renderDisassembly({ ok: false, insns: [], error: parsed.error, consumed: 0, total: 0 });
    return;
  }
  const bytes = parsed.bytes;
  if (bytes.length === 0) {
    disassembleClear();
    return;
  }
  setCurrentBytes(bytes, 'hex input');
  setMsg(hexMsg, `decoding ${bytes.length} bytes…`, '');
  disasmListing.replaceChildren(el('div', { class: 'listing-empty' }, '// decoding…'));
  disasmStats.textContent = '';
  const generation = disasmGeneration;
  const worker = new Worker(new URL('./disasm-worker.ts', import.meta.url), { type: 'module' });
  disasmWorker = worker;
  const finish = (): void => {
    if (disasmWorker !== worker) return;
    worker.terminate();
    disasmWorker = null;
    if (disasmTimer !== null) clearTimeout(disasmTimer);
    disasmTimer = null;
  };
  const fail = (message: string): void => {
    if (generation !== disasmGeneration) return;
    finish();
    setMsg(hexMsg, `✗ ${message}`, 'err');
    renderDisassembly({ ok: false, insns: [], error: message, consumed: 0, total: bytes.length });
  };
  disasmTimer = setTimeout(() => fail('disassembly timed out after 30 seconds'), 30_000);
  worker.onmessage = (event: MessageEvent<{ result?: DisassembleResult; error?: string }>) => {
    if (generation !== disasmGeneration) return;
    finish();
    if (!event.data.result) {
      fail(event.data.error ?? 'disassembly worker failed');
      return;
    }
    const res = event.data.result;
    renderDisassembly(res);
    if (!res.ok) {
      setMsg(hexMsg, `✗ ${res.error}`, 'err');
      return;
    }
    const undecoded = res.total - res.consumed;
    setMsg(hexMsg, undecoded > 0
      ? `⚠ decoded ${res.insns.length} instructions, then hit undecodable bytes`
      : `✓ decoded ${res.insns.length} instruction${res.insns.length === 1 ? '' : 's'}`,
    undecoded > 0 ? 'warn' : 'ok');
  };
  worker.onerror = (event) => fail(event.message || 'disassembly worker failed');
  const copy = bytes.slice();
  worker.postMessage({ archId, bytes: copy, baseURI: document.baseURI }, [copy.buffer]);
}

function disassembleClear(): void {
  cancelDisassembly();
  clearBytesFrom('hex input');
  renderDisassembly({ ok: true, insns: [], error: null, consumed: 0, total: 0 });
  setMsg(hexMsg, '', '');
}

// --- emulation --------------------------------------------------------------------

const EMU_PLACEHOLDER =
  '// press ▶ run to execute the assembled shellcode\n// under the unicorn engine — syscalls, buffers and exit state appear here';

let activeTrace: EmuResult | null = null;
let traceArch = '';
let selectedTraceStep = 0;
let traceRows: HTMLButtonElement[] = [];
let traceInstructions: string[] = [];
let mutationRows: HTMLButtonElement[] = [];
let selectedMutation = 0;
let stageRows: HTMLButtonElement[] = [];
let selectedStage = 0;

function imageSlice(image: Uint8Array | null, base: number, address: number, size: number): Uint8Array | null {
  const offset = address - base;
  return image && offset >= 0 && offset + size <= image.length
    ? image.slice(offset, offset + size) : null;
}

function mutationField(label: string, value: string): HTMLElement {
  return el('div', { class: 'mutation-field' },
    el('span', { class: 'mutation-label' }, label),
    el('code', {}, value));
}

function selectMutation(index: number, focus = false): void {
  if (!activeTrace || index < 0 || index >= activeTrace.mutations.length) return;
  mutationRows[selectedMutation]?.classList.remove('active');
  selectedMutation = index;
  const row = mutationRows[index]!;
  row.classList.add('active');
  if (focus) row.scrollIntoView({ block: 'nearest' });
  const mutation = activeTrace.mutations[index]!;
  const original = imageSlice(activeTrace.initialCode, activeTrace.codeBase, mutation.addr, mutation.after.length);
  const final = imageSlice(activeTrace.finalCode, activeTrace.codeBase, mutation.addr, mutation.after.length);
  const first = mutation.firstExecutionStep;
  const executed = first != null ? activeTrace.trace[first - 1] : null;
  const jump = (label: string, step: number | null): HTMLElement => {
    if (step == null) return el('span', { class: 'dim' }, `${label}: not observed`);
    if (step > activeTrace!.trace.length) return el('span', { class: 'dim' }, `${label}: #${step} (beyond trace cap)`);
    const button = el('button', { class: 'btn ghost', type: 'button' }, `${label} #${step}`);
    button.addEventListener('click', () => selectTraceStep(step - 1, true));
    return button;
  };
  mutationDetail.replaceChildren(
    el('div', { class: 'mutation-title' }, `write ${index + 1} · ${formatAddress(mutation.addr)} · ${mutation.after.length} changed byte${mutation.after.length === 1 ? '' : 's'}`),
    mutationField('original image', original ? toSpacedHex(original) : 'outside loaded image'),
    mutationField('before write', toSpacedHex(mutation.before)),
    mutationField('after write', toSpacedHex(mutation.after)),
    mutationField('final image', final ? toSpacedHex(final) : 'unavailable'),
    executed
      ? mutationField('first execution', `${formatAddress(executed.addr)} · ${toSpacedHex(executed.bytes)} · ${traceInstructions[first! - 1] ?? '(undecoded)'}`)
      : mutationField('first execution', first == null ? 'not observed' : `instruction #${first} (beyond trace cap)`),
    el('div', { class: 'mutation-jumps' }, jump('writer', mutation.writerStep), jump('execution', first)),
  );
}

function renderMutations(result: EmuResult | null): void {
  mutationRows = [];
  mutationList.replaceChildren();
  mutationDetail.replaceChildren();
  if (!result) {
    mutationStats.textContent = '';
    return;
  }
  const executed = result.mutations.filter((mutation) => mutation.firstExecutionStep !== null).length;
  mutationStats.textContent = `${result.mutations.length} writes · ${executed} executed${result.mutationsTruncated ? ' · capture limited' : ''}`;
  stageDownload.disabled = result.finalCode === null;
  if (!result.mutations.length) {
    mutationList.append(el('div', { class: 'listing-empty' }, '// no changes to the loaded code region'));
    mutationDetail.append(el('div', { class: 'listing-empty' }, 'No changes to the loaded code image were observed.'));
    return;
  }
  const fragment = document.createDocumentFragment();
  result.mutations.forEach((mutation: EmuMutation, index) => {
    const row = el('button', { class: 'mutation-row', type: 'button',
      'aria-label': `Mutation ${index + 1} at ${formatAddress(mutation.addr)}, written by instruction ${mutation.writerStep}` },
      el('span', { class: 'trace-num' }, `#${index + 1}`),
      el('span', { class: 'trace-address' }, formatAddress(mutation.addr)),
      el('span', { class: 'mutation-transition' }, `${toSpacedHex(mutation.before)} → ${toSpacedHex(mutation.after)}`),
      el('span', { class: mutation.firstExecutionStep == null ? 'dim' : 'mutation-executed' },
        mutation.firstExecutionStep == null ? 'not run' : `ran #${mutation.firstExecutionStep}`),
    );
    row.addEventListener('click', () => selectMutation(index));
    fragment.append(row);
    mutationRows.push(row);
  });
  mutationList.append(fragment);
  selectedMutation = 0;
  selectMutation(0);
}

function permissionLabel(permissions: number | null): string {
  if (permissions === null) return 'unknown';
  return `${permissions & 1 ? 'r' : '-'}${permissions & 2 ? 'w' : '-'}${permissions & 4 ? 'x' : '-'}`;
}

function stageDisassembly(bytes: Uint8Array, address: number): string {
  if (!bytes.length) return 'bytes unavailable';
  if (bytes.every((byte) => byte === 0)) return 'zero-filled page';
  const decoded = disassemble(traceArch, bytes, 7, address);
  return decoded.insns.length
    ? decoded.insns.map((insn) => `${formatAddress(insn.address)}  ${insn.mnemonic} ${insn.opStr}`.trim()).join('\n')
    : '(undecoded)';
}

function showContextStep(step: EmuContextStep, context: EmuContextStep[], row: HTMLElement, jump: boolean): void {
  stageWriterContext.querySelector('.active')?.classList.remove('active');
  stageExecutionContext.querySelector('.active')?.classList.remove('active');
  row.classList.add('active');
  const decoded = step.bytes.length ? disassemble(traceArch, step.bytes, 1, step.addr).insns[0] : null;
  const instruction = decoded ? `${decoded.mnemonic} ${decoded.opStr}`.trim() : '(undecoded)';
  const prior = context.find((candidate) => candidate.step === step.step - 1);
  stageContextDetail.replaceChildren(
    el('div', { class: 'mutation-title' },
      `instruction #${step.step} · ${formatAddress(step.addr)} · ${toSpacedHex(step.bytes)} · ${instruction}`),
    el('div', { class: 'emu-regs stage-context-registers' },
      ...activeTrace!.registers.map((reg, index) =>
        el('div', { class: `emu-reg${prior && prior.registers[index] !== step.registers[index] ? ' changed' : ''}` },
          el('span', { class: 'emu-reg-name' }, reg.name),
          el('span', { class: 'emu-reg-val' }, step.registers[index] ?? '—')))),
  );
  if (jump && activeTrace && step.step <= activeTrace.trace.length) selectTraceStep(step.step - 1);
}

function renderContextRows(target: HTMLElement, context: EmuContextStep[], activeStep: number | null): void {
  target.replaceChildren();
  if (!context.length) {
    target.append(el('div', { class: 'listing-empty' }, 'No context was retained.'));
    return;
  }
  for (const step of context) {
    const decoded = step.bytes.length ? disassemble(traceArch, step.bytes, 1, step.addr).insns[0] : null;
    const instruction = decoded ? `${decoded.mnemonic} ${decoded.opStr}`.trim() : '(undecoded)';
    const attrs = { class: `stage-context-row${step.step === activeStep ? ' key' : ''}` };
    const content = [
      el('span', { class: 'trace-num' }, `#${step.step}`),
      el('span', { class: 'trace-address' }, formatAddress(step.addr)),
      el('span', { class: 'trace-bytes' }, toSpacedHex(step.bytes) || '—'),
      el('span', { class: 'trace-insn' }, instruction),
    ];
    const row = el('button', { ...attrs, type: 'button', 'data-step': String(step.step),
      title: step.step <= (activeTrace?.trace.length ?? 0) ? 'Inspect here and in main trace' : 'Inspect post-cap context' }, ...content);
    row.addEventListener('click', () => showContextStep(step, context, row, true));
    target.append(row);
  }
}

function renderStageExplorer(stage: EmuStage): void {
  const before = stage.beforeSnapshot;
  const after = stage.snapshot;
  const diff = before && before.length === after.length ? diffStagePages(before, after) : null;
  stageDiffStats.textContent = diff
    ? `${diff.changedBytes} changed bytes · ${diff.totalSpans} span${diff.totalSpans === 1 ? '' : 's'}${stage.contextTruncated ? ' · context limited' : ''}`
    : `baseline unavailable${stage.contextTruncated ? ' · context limited' : ''}`;
  stageDiffSpans.replaceChildren();
  if (diff) {
    for (const span of diff.spans) {
      const preview = Math.min(span.before.length, 24);
      stageDiffSpans.append(el('div', { class: 'stage-diff-row' },
        el('span', { class: 'trace-address' }, `${formatAddress(stage.pageBase + span.offset)} · ${span.before.length} B`),
        el('code', {}, `${toSpacedHex(span.before.slice(0, preview))}${span.before.length > preview ? ' …' : ''}`),
        el('span', { class: 'dim' }, '→'),
        el('code', {}, `${toSpacedHex(span.after.slice(0, preview))}${span.after.length > preview ? ' …' : ''}`),
      ));
    }
    if (diff.totalSpans > diff.spans.length) {
      stageDiffSpans.append(el('div', { class: 'listing-empty' },
        `${diff.totalSpans - diff.spans.length} more spans in the downloadable snapshots`));
    }
    if (!diff.totalSpans) stageDiffSpans.append(el('div', { class: 'listing-empty' }, 'No net byte change in this page.'));
  } else stageDiffSpans.append(el('div', { class: 'listing-empty' }, 'No before-write page snapshot was available.'));

  const offset = Math.max(0, Math.min(after.length - 1, stage.entryAddr - stage.pageBase));
  const address = stage.pageBase + offset;
  let pathEnd = stage.entryAddr;
  for (const step of stage.executionContext) {
    if (step.step < stage.firstExecutionStep) continue;
    if (step.addr !== pathEnd || step.addr >= stage.pageBase + after.length) break;
    pathEnd += step.bytes.length;
    if (pathEnd - address >= 48) break;
  }
  const previewEnd = Math.min(after.length, Math.max(offset + 1, pathEnd - stage.pageBase), offset + 48);
  const beforeView = before?.slice(offset, previewEnd) ?? new Uint8Array(0);
  const afterView = after.slice(offset, previewEnd);
  stageBeforeLabel.textContent = before ? formatAddress(address) : '(initial stage)';
  stageAfterLabel.textContent = formatAddress(address);
  stageBeforeBytes.textContent = before ? toSpacedHex(beforeView) : 'baseline unavailable';
  stageAfterBytes.textContent = toSpacedHex(afterView) || 'snapshot unavailable';
  stageBeforeDisasm.textContent = before ? stageDisassembly(beforeView, address) : 'initial loaded image';
  stageAfterDisasm.textContent = stageDisassembly(afterView, address);
  renderContextRows(stageWriterContext, stage.writerContext, stage.writerStep);
  renderContextRows(stageExecutionContext, stage.executionContext, stage.firstExecutionStep);
  const selected = stageExecutionContext.querySelector<HTMLElement>(`[data-step="${stage.firstExecutionStep}"]`);
  if (selected) showContextStep(stage.executionContext.find((step) => step.step === stage.firstExecutionStep)!,
    stage.executionContext, selected, false);
  else stageContextDetail.replaceChildren();
}

function selectStage(index: number, focus = false): void {
  if (!activeTrace || index < 0 || index >= activeTrace.stages.length) return;
  stageRows[selectedStage]?.classList.remove('active');
  selectedStage = index;
  const row = stageRows[index]!;
  row.classList.add('active');
  if (focus) row.scrollIntoView({ block: 'nearest' });
  const stage = activeTrace.stages[index]!;
  const decoded = stage.instructionBytes.length
    ? disassemble(traceArch, stage.instructionBytes, 1, stage.entryAddr).insns[0] : null;
  const instruction = decoded ? `${decoded.mnemonic} ${decoded.opStr}`.trim() : '(undecoded)';
  const offset = stage.entryAddr - stage.pageBase;
  const preview = stage.snapshot.slice(Math.max(0, offset), Math.max(0, offset) + 64);
  const transitions = activeTrace.mapEvents
    .filter((event) => event.addr <= stage.pageBase && stage.pageBase < event.addr + event.size && event.step < stage.firstExecutionStep)
    .map((event) => `${event.operation} #${event.step} ${permissionLabel(event.permissions)}`);
  const actions: HTMLElement[] = [];
  if (stage.fromStageId !== null) {
    const button = el('button', { class: 'btn ghost', type: 'button' }, `source S${stage.fromStageId}`);
    button.addEventListener('click', () => selectStage(stage.fromStageId!, true));
    actions.push(button);
  }
  if (stage.writerStep !== null && stage.writerStep <= activeTrace.trace.length) {
    const button = el('button', { class: 'btn ghost', type: 'button' }, `writer #${stage.writerStep}`);
    button.addEventListener('click', () => selectTraceStep(stage.writerStep! - 1, true));
    actions.push(button);
  }
  if (stage.firstExecutionStep <= activeTrace.trace.length) {
    const button = el('button', { class: 'btn ghost', type: 'button' }, `execution #${stage.firstExecutionStep}`);
    button.addEventListener('click', () => selectTraceStep(stage.firstExecutionStep - 1, true));
    actions.push(button);
  }
  stageDetail.replaceChildren(
    el('div', { class: 'mutation-title' }, `S${stage.id} · ${stage.origin} · ${formatAddress(stage.pageBase)}`),
    mutationField('first execution', `#${stage.firstExecutionStep} at ${formatAddress(stage.entryAddr)}`),
    mutationField('instruction', `${toSpacedHex(stage.instructionBytes)} · ${instruction}`),
    mutationField('writer', stage.writerStep == null ? 'original or unobserved' : `#${stage.writerStep} at ${formatAddress(stage.writerAddr!)}`),
    mutationField('permissions', permissionLabel(stage.permissions)),
    mutationField('map timeline', transitions.join(' → ') || 'initial mapping'),
    mutationField('snapshot bytes', toSpacedHex(preview) || 'snapshot unavailable'),
    el('div', { class: 'mutation-jumps' }, ...actions),
  );
  stageSnapshotDownload.disabled = stage.snapshot.length === 0;
  renderStageExplorer(stage);
}

function renderStages(result: EmuResult | null): void {
  stageRows = [];
  stageList.replaceChildren();
  stageDetail.replaceChildren();
  stageDiffStats.textContent = '';
  stageDiffSpans.replaceChildren();
  stageBeforeBytes.textContent = '';
  stageBeforeDisasm.textContent = '';
  stageAfterBytes.textContent = '';
  stageAfterDisasm.textContent = '';
  stageWriterContext.replaceChildren();
  stageExecutionContext.replaceChildren();
  stageContextDetail.replaceChildren();
  stageSnapshotDownload.disabled = true;
  if (!result) {
    stageStats.textContent = '';
    return;
  }
  const generated = result.stages.filter((stage) => stage.origin !== 'image').length;
  stageStats.textContent = `${result.stages.length} stage${result.stages.length === 1 ? '' : 's'} · ${generated} outside image${result.stagesTruncated || result.mapEventsTruncated ? ' · capture limited' : ''}`;
  const fragment = document.createDocumentFragment();
  for (const stage of result.stages) {
    const row = el('button', { class: 'stage-row', type: 'button',
      'aria-label': `Stage ${stage.id}, ${stage.origin}, first executed at ${formatAddress(stage.entryAddr)}` },
      el('span', { class: 'stage-id' }, `S${stage.id}`),
      el('span', { class: 'stage-edge' }, stage.fromStageId == null ? 'entry' : `S${stage.fromStageId} →`),
      el('span', { class: 'stage-origin' }, stage.origin),
      el('span', { class: 'trace-address' }, formatAddress(stage.entryAddr)),
      el('span', { class: 'dim' }, `#${stage.firstExecutionStep}`),
    );
    row.addEventListener('click', () => selectStage(stage.id));
    fragment.append(row);
    stageRows.push(row);
  }
  stageList.append(fragment);
  if (!result.stages.length) {
    stageDetail.append(el('div', { class: 'listing-empty' }, 'No executed stages were captured.'));
    return;
  }
  selectedStage = 0;
  selectStage(0);
}

function selectTraceStep(index: number, focus = false): void {
  if (!activeTrace || index < 0 || index >= activeTrace.trace.length) return;
  traceRows[selectedTraceStep]?.classList.remove('active');
  traceRows[selectedTraceStep]?.removeAttribute('aria-current');
  selectedTraceStep = index;
  const row = traceRows[index]!;
  row.classList.add('active');
  row.setAttribute('aria-current', 'step');
  tracePosition.textContent = `${index + 1} / ${activeTrace.trace.length}`;
  tracePrev.disabled = index === 0;
  traceNext.disabled = index === activeTrace.trace.length - 1;
  if (focus) {
    row.focus();
    row.scrollIntoView({ block: 'nearest' });
  }

  const step = activeTrace.trace[index]!;
  const prior = activeTrace.trace[index - 1];
  traceSelected.replaceChildren(
    el('div', {},
      el('span', { class: 'trace-address' }, formatAddress(step.addr)),
      ' · ',
      el('span', { class: 'trace-bytes' }, toSpacedHex(step.bytes) || 'bytes unavailable')),
    el('div', {}, traceInstructions[index] ?? '(undecoded)'),
  );
  traceRegisters.replaceChildren();
  for (const [i, reg] of activeTrace.registers.entries()) {
    const value = step.registers[i] ?? '—';
    const changed = prior != null && prior.registers[i] !== value;
    traceRegisters.append(
      el('div', { class: 'emu-reg' + (changed ? ' changed' : '') },
        el('span', { class: 'emu-reg-name' }, reg.name),
        el('span', { class: 'emu-reg-val' }, value)),
    );
  }
}

function renderTrace(result: EmuResult | null): void {
  activeTrace = result;
  tracePanel.classList.toggle('hidden', !result || result.trace.length === 0);
  traceList.replaceChildren();
  traceRegisters.replaceChildren();
  traceSelected.replaceChildren();
  traceRows = [];
  traceInstructions = [];
  if (!result || result.trace.length === 0) {
    renderMutations(result);
    renderStages(result);
    return;
  }

  traceArch = archId;
  traceStats.textContent = result.traceTruncated
    ? `first ${result.trace.length} of ${result.steps} instructions captured`
    : `${result.trace.length} instructions captured`;
  const fragment = document.createDocumentFragment();
  for (const [index, step] of result.trace.entries()) {
    const decoded = step.bytes.length ? disassemble(traceArch, step.bytes, 1, step.addr) : null;
    const insn = decoded?.insns[0];
    const text = insn ? `${insn.mnemonic} ${insn.opStr}`.trim() : '(undecoded)';
    traceInstructions.push(text);
    const row = el('button', { class: 'trace-row', type: 'button', title: text,
      'aria-label': `Instruction ${index + 1} at ${formatAddress(step.addr)}: ${text}` },
      el('span', { class: 'trace-num' }, String(index + 1)),
      el('span', { class: 'trace-address' }, formatAddress(step.addr)),
      el('span', { class: 'trace-bytes' }, toSpacedHex(step.bytes) || '—'),
      el('span', { class: 'trace-insn' }, text),
    );
    row.addEventListener('click', () => selectTraceStep(index));
    fragment.append(row);
    traceRows.push(row);
  }
  traceList.append(fragment);
  selectedTraceStep = 0;
  selectTraceStep(0);
  renderMutations(result);
  renderStages(result);
}

tracePrev.addEventListener('click', () => selectTraceStep(selectedTraceStep - 1, true));
traceNext.addEventListener('click', () => selectTraceStep(selectedTraceStep + 1, true));
traceList.addEventListener('keydown', (event) => {
  if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
    event.preventDefault();
    selectTraceStep(selectedTraceStep + (event.key === 'ArrowDown' ? 1 : -1), true);
  }
});
traceDownload.addEventListener('click', () => {
  if (!activeTrace) return;
  const names = activeTrace.registers.map((reg) => reg.name);
  const data = {
    architecture: traceArch,
    steps: activeTrace.steps,
    traceTruncated: activeTrace.traceTruncated,
    exit: activeTrace.exit,
    syscalls: activeTrace.syscalls,
    finalRegisters: Object.fromEntries(activeTrace.registers.map((reg) => [reg.name, reg.value])),
    codeBase: formatAddress(activeTrace.codeBase),
    initialCode: toHex(activeTrace.initialCode),
    finalCode: activeTrace.finalCode ? toHex(activeTrace.finalCode) : null,
    mutationsTruncated: activeTrace.mutationsTruncated,
    mutations: activeTrace.mutations.map((mutation) => ({
      writerStep: mutation.writerStep,
      writerAddress: formatAddress(mutation.writerAddr),
      address: formatAddress(mutation.addr),
      before: toHex(mutation.before),
      after: toHex(mutation.after),
      firstExecutionStep: mutation.firstExecutionStep,
      firstExecutionAddress: mutation.firstExecutionAddr == null ? null : formatAddress(mutation.firstExecutionAddr),
    })),
    stagesTruncated: activeTrace.stagesTruncated,
    mapEventsTruncated: activeTrace.mapEventsTruncated,
    mapEvents: activeTrace.mapEvents.map((event) => ({
      step: event.step,
      operation: event.operation,
      address: formatAddress(event.addr),
      size: event.size,
      permissions: permissionLabel(event.permissions),
    })),
    stages: activeTrace.stages.map((stage) => ({
      id: stage.id,
      fromStageId: stage.fromStageId,
      origin: stage.origin,
      pageBase: formatAddress(stage.pageBase),
      entryAddress: formatAddress(stage.entryAddr),
      firstExecutionStep: stage.firstExecutionStep,
      instructionBytes: toHex(stage.instructionBytes),
      snapshot: toHex(stage.snapshot),
      beforeSnapshot: stage.beforeSnapshot ? toHex(stage.beforeSnapshot) : null,
      diff: stage.beforeSnapshot && stage.beforeSnapshot.length === stage.snapshot.length
        ? (() => { const diff = diffStagePages(stage.beforeSnapshot!, stage.snapshot, 0); return {
          changedBytes: diff.changedBytes, totalSpans: diff.totalSpans,
        }; })() : null,
      permissions: permissionLabel(stage.permissions),
      writerStep: stage.writerStep,
      writerAddress: stage.writerAddr == null ? null : formatAddress(stage.writerAddr),
      contextTruncated: stage.contextTruncated,
      writerContext: stage.writerContext.map((step) => ({
        number: step.step, address: formatAddress(step.addr), bytes: toHex(step.bytes),
        registersBefore: Object.fromEntries(names.map((name, i) => [name, step.registers[i]])),
      })),
      executionContext: stage.executionContext.map((step) => ({
        number: step.step, address: formatAddress(step.addr), bytes: toHex(step.bytes),
        registersBefore: Object.fromEntries(names.map((name, i) => [name, step.registers[i]])),
      })),
    })),
    trace: activeTrace.trace.map((step, index) => ({
      number: index + 1,
      address: formatAddress(step.addr),
      bytes: toHex(step.bytes),
      instruction: traceInstructions[index],
      registersBefore: Object.fromEntries(names.map((name, i) => [name, step.registers[i]])),
    })),
  };
  downloadText(`trace-${traceArch}.json`, JSON.stringify(data, null, 2), 'application/json');
});
stageDownload.addEventListener('click', () => {
  if (activeTrace?.finalCode) downloadBytes(`runtime-stage-${traceArch}.bin`, activeTrace.finalCode);
});
stageSnapshotDownload.addEventListener('click', () => {
  const stage = activeTrace?.stages[selectedStage];
  if (stage?.snapshot.length) {
    downloadBytes(`stage-${traceArch}-S${stage.id}-${formatAddress(stage.pageBase)}.bin`, stage.snapshot);
  }
});

function renderEmu(result: EmuResult | null): void {
  renderTrace(result);
  if (!result) {
    emuLog.replaceChildren(el('div', { class: 'listing-empty' }, EMU_PLACEHOLDER));
    emuRegs.replaceChildren();
    setMsg(emuMsg, '', '');
    return;
  }
  // syscall log
  emuLog.replaceChildren();
  if (result.syscalls.length === 0) {
    emuLog.append(el('div', { class: 'listing-empty' }, '// no syscalls were made'));
  } else {
    for (const s of result.syscalls) {
      const row = el('div', { class: 'emu-call' });
      row.append(el('span', { class: 'emu-call-text' }, `${s.call}`));
      row.append(el('span', { class: 'emu-call-ret' }, s.ret === '—' ? '→ ends' : `= ${s.ret}`));
      emuLog.append(row);
    }
  }
  // registers grid
  emuRegs.replaceChildren();
  for (const r of result.registers) {
    emuRegs.append(
      el('div', { class: 'emu-reg' + (r.changed ? ' changed' : '') },
        el('span', { class: 'emu-reg-name' }, r.name),
        el('span', { class: 'emu-reg-val' }, r.value)),
    );
  }
  const kind = result.exit.startsWith('⚠') ? 'warn' : result.exit.startsWith('✗') ? 'err' : 'ok';
  setMsg(emuMsg, `${result.steps} steps · ${result.exit}`, kind);
}

let emuBusy = false;

function runEmulationInWorker(arch: string, bytes: Uint8Array, entryArg: bigint | null): Promise<EmuResult> {
  return new Promise((resolve, reject) => {
    const worker = new Worker(new URL('./emu-worker.ts', import.meta.url), { type: 'module' });
    const timer = setTimeout(() => {
      worker.terminate();
      reject(new Error('emulation timed out after 30 seconds'));
    }, 30_000);
    const finish = (): void => {
      clearTimeout(timer);
      worker.terminate();
    };
    worker.onmessage = (event: MessageEvent<{ result?: EmuResult; error?: string }>) => {
      finish();
      if (event.data.result) resolve(event.data.result);
      else reject(new Error(event.data.error ?? 'emulation worker failed'));
    };
    worker.onerror = (event) => {
      finish();
      reject(new Error(event.message || 'emulation worker failed'));
    };
    const copy = bytes.slice();
    worker.postMessage({ archId: arch, bytes: copy, entryArg }, [copy.buffer]);
  });
}

async function runEmu(): Promise<void> {
  if (emuBusy) return;
  const src = editor.getValue().trim();
  const runArch = archId;
  if (!src) {
    toast('nothing to run — the editor is empty');
    return;
  }
  if (src.length > MAX_ASM_CHARS) {
    toast(`assembly source exceeds the ${MAX_ASM_CHARS}-character limit`);
    return;
  }
  emuBusy = true;
  btnRunEmu.disabled = true;
  btnRunEmu.textContent = '… running';
  setMsg(emuMsg, 'assembling…', '');
  try {
    const { result: res } = await assembleInWorker(runArch, src);
    if (archId !== runArch || editor.getValue().trim() !== src) return;
    if (!res.ok || !res.bytes) {
      toast('fix the assembly errors first');
      return;
    }
    if (res.bytes.length === 0) {
      toast('source emits no bytes');
      return;
    }
    const arg = parseEntryArg();
    if (arg && 'error' in arg) {
      setMsg(emuMsg, `✗ ${arg.error}`, 'err');
      return;
    }
    setMsg(emuMsg, 'loading unicorn engine (first run downloads ~1 MB)…', '');
    const result = await runEmulationInWorker(runArch, res.bytes, arg ? arg.value : null);
    if (archId === runArch && editor.getValue().trim() === src) {
      setChip(chipUnicorn, 'ok');
      renderEmu(result);
    }
  } catch (err) {
    if (archId === runArch && editor.getValue().trim() === src) {
      setMsg(emuMsg, `✗ ${err instanceof Error ? err.message : String(err)}`, 'err');
    }
  } finally {
    emuBusy = false;
    btnRunEmu.disabled = false;
    btnRunEmu.textContent = '▶ run';
  }
}

btnRunEmu.addEventListener('click', () => void runEmu());
$('#btn-clear-emu').addEventListener('click', () => {
  renderEmu(null);
  saveState();
});

// --- bad characters ----------------------------------------------------------

function applyBadChars(): void {
  const parsed = parseBadChars(badCharsInput.value);
  if (!parsed) {
    setMsg(badCharsMsg, `✗ can't read that — try "00 0a 20", "\\x00" or "0x0a"`, 'err');
    return;
  }
  setMsg(badCharsMsg, '', '');
  badChars = parsed.bad;
  // every view that flags bad bytes needs a repaint
  if (enginesReady()) {
    runAssemble();
    runDisassemble();
  }
}

badCharsInput.addEventListener('input', () => {
  saveState();
  applyBadChars();
});

// --- raw shellcode downloads ---------------------------------------------------

$('#btn-download-bin').addEventListener('click', () => {
  if (!currentBytes || currentBytes.length === 0) {
    toast('nothing to download — assemble or paste some bytes first');
    return;
  }
  downloadBytes(`shellcode-${archId}.bin`, currentBytes);
});

// --- xor encoder -----------------------------------------------------------------

const encKeyInput = $<HTMLInputElement>('#enc-key');
const encMsg = $('#enc-msg');
const encPreview = $('#enc-preview');
const encNote = $('#enc-note');
let encodedSource: string | null = null;

/** key box accepts hex (0x2a) or decimal (42); null when unreadable */
function parseEncKey(): number | null {
  const raw = encKeyInput.value.trim();
  if (!raw) return null;
  try {
    return Number(BigInt(raw.toLowerCase()) & 0xffn);
  } catch {
    return null;
  }
}

function runEncode(): void {
  encodedSource = null;
  const key = parseEncKey();
  if (key === null) {
    encPreview.textContent = '// the decoder stub + encoded payload appear here';
    encPreview.classList.add('empty');
    encNote.textContent = '';
    setMsg(encMsg, key === null && encKeyInput.value.trim() ? '✗ key: not a hex (0x…) or decimal number' : '', 'err');
    return;
  }
  const bytes = currentBytes;
  if (!bytes || bytes.length === 0) {
    encPreview.textContent = '// assemble some shellcode first — the encoder wraps those bytes';
    encPreview.classList.add('empty');
    encNote.textContent = '';
    setMsg(encMsg, '✗ nothing to encode — assemble some shellcode first', 'err');
    return;
  }
  const res = xorEncode(archId, bytes, key);
  if ('error' in res) {
    encPreview.textContent = '// no decoder generated';
    encPreview.classList.add('empty');
    encNote.textContent = '';
    setMsg(encMsg, `✗ ${res.error}`, 'err');
    return;
  }
  encodedSource = res.source;
  encPreview.classList.remove('empty');
  encPreview.textContent = res.source;
  encNote.textContent = res.note;
  // prove the generated program is sound: assemble it and bad-char-check the
  // whole thing (stub + payload), not just the encoded bytes
  const asm = assemble(archId, res.source);
  if (asm.ok && asm.bytes) {
    const badCount = countBadBytes(asm.bytes, badChars);
    if (badCount === 0) {
      setMsg(encMsg, `✓ assembles to ${asm.bytes.length} bytes (stub + payload) · 0 bad bytes`, 'ok');
    } else {
      setMsg(encMsg, `⚠ assembles to ${asm.bytes.length} bytes · ${badCount} bad byte${badCount > 1 ? 's' : ''} (${describeBadChars(badChars)})`, 'warn');
    }
  } else {
    setMsg(encMsg, `✗ stub failed to assemble: ${asm.error}`, 'err');
  }
}

/** try every key and adopt the first whose full program avoids all bad bytes */
function autoKey(): void {
  const bytes = currentBytes;
  if (!bytes || bytes.length === 0) {
    toast('assemble something first');
    return;
  }
  if (!badChars.some((b) => b)) {
    toast('no bad characters set — every key works');
    return;
  }
  for (let key = 1; key <= 255; key++) {
    const res = xorEncode(archId, bytes, key);
    if ('error' in res) break; // arch/length problem — no key will fix it
    // cheap check first: the encoded payload alone
    if (countBadBytes(res.encoded, badChars) > 0) continue;
    // full check: payload + stub bytes
    const asm = assemble(archId, res.source);
    if (asm.ok && asm.bytes && countBadBytes(asm.bytes, badChars) === 0) {
      encKeyInput.value = '0x' + key.toString(16).padStart(2, '0');
      runEncode();
      saveState();
      toast(`key 0x${key.toString(16).padStart(2, '0')} — the whole program avoids your bad bytes`);
      return;
    }
  }
  setMsg(encMsg, '✗ no key in 0x01..0xff avoids all bad bytes — the stub itself contains one, or the payload is unlucky', 'err');
}

$('#btn-encode').addEventListener('click', () => {
  runEncode();
  saveState();
});
$('#btn-encode-auto').addEventListener('click', autoKey);
$('#btn-encode-load').addEventListener('click', () => {
  if (!encodedSource) {
    toast('encode something first');
    return;
  }
  editor.setValue(encodedSource);
  runAssemble();
  saveState();
  void runEmu();
  toast('loaded into the editor — the emulator is proving the decoder works');
  window.scrollTo({ top: 0, behavior: 'smooth' });
});

// --- rop gadgets ----------------------------------------------------------------

const gadgetsPanel = $('#gadgets-panel');
const gadgetList = $('#gadget-list');
const gadgetStats = $('#gadget-stats');
const gadgetFilter = $<HTMLInputElement>('#gadget-filter');
const btnGadgets = $<HTMLButtonElement>('#btn-gadgets');
let currentGadgets: Gadget[] = [];
let gadgetGeneration = 0;

function invalidateDerivedViews(): void {
  gadgetGeneration++;
  encodedSource = null;
  encPreview.textContent = '// the decoder stub + encoded payload appear here';
  encPreview.classList.add('empty');
  encNote.textContent = '';
  setMsg(encMsg, '', '');
  currentGadgets = [];
  gadgetsPanel.classList.add('hidden');
  gadgetFilter.value = '';
}

function renderGadgetList(): void {
  const q = gadgetFilter.value.trim().toLowerCase();
  const shown = q ? currentGadgets.filter((g) => g.text.toLowerCase().includes(q)) : currentGadgets;
  gadgetList.replaceChildren();
  if (shown.length === 0) {
    gadgetList.append(el('div', { class: 'listing-empty' },
      currentGadgets.length === 0 ? '// no gadgets found in these bytes' : '// no gadgets match the filter'));
  } else {
    for (const g of shown) {
      const row = el('div', { class: 'gadget-row', role: 'button', tabindex: '0', title: 'click to copy this gadget' });
      row.append(el('span', { class: 'addr' }, '0x' + g.address.toString(16).padStart(8, '0')));
      row.append(el('span', { class: 'gadget-text' }, g.text));
      const copy = async (): Promise<void> => {
        if (await copyText(g.text)) toast('gadget copied');
      };
      row.addEventListener('click', () => void copy());
      row.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          void copy();
        }
      });
      gadgetList.append(row);
    }
  }
  gadgetStats.textContent = `${shown.length}${q && shown.length !== currentGadgets.length ? ` of ${currentGadgets.length}` : ''} gadgets`;
}

function findGadgetsInWorker(arch: string, bytes: Uint8Array): Promise<Gadget[]> {
  return new Promise((resolve, reject) => {
    const worker = new Worker(new URL('./gadget-worker.ts', import.meta.url), { type: 'module' });
    const timer = setTimeout(() => {
      worker.terminate();
      reject(new Error('gadget scan timed out after 30 seconds'));
    }, 30_000);
    const finish = (): void => {
      clearTimeout(timer);
      worker.terminate();
    };
    worker.onmessage = (event: MessageEvent<{ gadgets?: Gadget[]; error?: string }>) => {
      finish();
      if (event.data.gadgets) resolve(event.data.gadgets);
      else reject(new Error(event.data.error ?? 'gadget worker failed'));
    };
    worker.onerror = (event) => {
      finish();
      reject(new Error(event.message || 'gadget worker failed'));
    };
    const copy = bytes.slice();
    worker.postMessage({ archId: arch, bytes: copy, baseURI: document.baseURI }, [copy.buffer]);
  });
}

async function runGadgets(): Promise<void> {
  if (btnGadgets.disabled) return;
  // scan whatever is in the hex box; fall back to the assembled bytes
  let bytes: Uint8Array | null = null;
  if (hexInput.value.trim()) {
    const parsed = parseHexInput(hexInput.value);
    if (parsed.error) {
      setMsg(hexMsg, `✗ ${parsed.error}`, 'err');
      return;
    }
    bytes = parsed.bytes;
  } else if (lastAssembled && lastAssembled.length > 0) {
    bytes = lastAssembled;
  }
  if (!bytes) {
    toast('nothing to scan — paste hex bytes or assemble something');
    return;
  }
  const runArch = archId;
  const generation = gadgetGeneration;
  btnGadgets.disabled = true;
  setMsg(hexMsg, 'scanning for gadgets…', '');
  try {
    const res = await findGadgetsInWorker(runArch, bytes);
    if (generation !== gadgetGeneration || archId !== runArch) return;
    currentGadgets = res;
    gadgetsPanel.classList.remove('hidden');
    renderGadgetList();
    setMsg(hexMsg, `✓ found ${res.length} gadgets`, 'ok');
  } catch (error) {
    if (generation === gadgetGeneration && archId === runArch) {
      setMsg(hexMsg, `✗ ${error instanceof Error ? error.message : String(error)}`, 'err');
    }
  } finally {
    btnGadgets.disabled = false;
  }
}

btnGadgets.addEventListener('click', () => void runGadgets());
gadgetFilter.addEventListener('input', renderGadgetList);
$('#btn-gadgets-copy').addEventListener('click', async () => {
  if (currentGadgets.length === 0) {
    toast('no gadgets to copy yet');
    return;
  }
  if (await copyText(gadgetRows(currentGadgets))) toast('gadget list copied');
  else toast('copy failed — select the text manually');
});

// --- drag & drop a file in --------------------------------------------------------

function readDroppedFile(file: File): void {
  if (/\.(asm|s)$/i.test(file.name)) {
    if (file.size > MAX_ASM_CHARS) {
      toast(`assembly file exceeds the ${MAX_ASM_CHARS}-byte limit`);
      return;
    }
    void file.text().then((src) => {
      editor.setValue(src);
      runAssemble();
      saveState();
      toast(`${file.name} → loaded into the editor`);
    });
    return;
  }
  if (file.size > MAX_HEX_BYTES) {
    toast(`binary file exceeds the ${MAX_HEX_BYTES}-byte limit`);
    return;
  }
  void file.arrayBuffer().then((buf) => {
    const bytes = new Uint8Array(buf);
    hexInput.value = toSpacedHex(bytes);
    runDisassemble();
    saveState();
    toast(`${file.name} → ${bytes.length} bytes loaded as hex`);
  });
}

let dragDepth = 0;
document.addEventListener('dragenter', (e) => {
  e.preventDefault();
  dragDepth++;
  document.body.classList.add('dragging');
});
document.addEventListener('dragleave', () => {
  dragDepth--;
  if (dragDepth <= 0) {
    dragDepth = 0;
    document.body.classList.remove('dragging');
  }
});
document.addEventListener('dragover', (e) => e.preventDefault());
document.addEventListener('drop', (e) => {
  e.preventDefault();
  dragDepth = 0;
  document.body.classList.remove('dragging');
  const file = e.dataTransfer?.files?.[0];
  if (file) readDroppedFile(file);
});

// --- offline (production only) ----------------------------------------------------

if ('serviceWorker' in navigator && import.meta.env.PROD) {
  window.addEventListener('load', () => {
    navigator.serviceWorker
      .register('sw.js')
      .then(async (reg) => {
        // hand the worker every same-origin resource this page already
        // fetched — they were loaded before the worker controlled the page,
        // so its fetch handler never had a chance to cache them
        await navigator.serviceWorker.ready;
        const urls = performance
          .getEntriesByType('resource')
          .map((e) => e.name)
          .filter((u) => {
            try {
              return new URL(u, location.href).origin === location.origin;
            } catch {
              return false;
            }
          });
        reg.active?.postMessage({ type: 'precache', urls });
      })
      .catch(() => {
        /* offline support is best-effort */
      });
  });
}

// --- syscall reference --------------------------------------------------------------

createSyscallPanel({
  listEl: $('#syscall-list'),
  searchEl: $<HTMLInputElement>('#syscall-search'),
  onPick: (entry) => {
    editor.insertAtCursor(syscallScaffold(archId, entry));
  },
});

// --- presets --------------------------------------------------------------------------

const presetsRow = $('#presets-row');

function renderPresets(): void {
  presetsRow.replaceChildren();
  const shown = PRESETS.filter((p) => p.arch === archId);
  for (const p of shown) {
    const btn = el('button', { class: 'btn ghost preset-btn', type: 'button', title: p.note }, p.label);
    btn.append(el('span', { class: 'preset-note' }, p.note));
    btn.addEventListener('click', () => {
      editor.setValue(p.src);
      runAssemble();
      saveState();
      void runEmu();
    });
    presetsRow.append(btn);
  }
  if (shown.length === 0) {
    presetsRow.append(el('span', { class: 'dim' }, 'no presets for this arch yet'));
  }
}
renderPresets();

function debounce<A extends unknown[]>(fn: (...args: A) => void, ms: number): (...args: A) => void {
  let t: ReturnType<typeof setTimeout> | undefined;
  return (...args: A) => {
    clearTimeout(t);
    t = setTimeout(() => fn(...args), ms);
  };
}

const autoDisassemble = debounce(() => {
  if (enginesReady()) runDisassemble();
}, 350);

editor.onChange(() => {
  cancelAssembly();
  lastAssembled = null;
  clearBytesFrom('assembler');
  renderShellcode(null, 0);
  setMsg(asmMsg, 'source changed — assembling…', '');
  saveState();
  renderEmu(null);
  invalidateDerivedViews();
  if (autoAssembleTimer !== null) clearTimeout(autoAssembleTimer);
  autoAssembleTimer = setTimeout(() => {
    autoAssembleTimer = null;
    if (enginesReady()) void runAssemble();
  }, 350);
});

hexInput.addEventListener('input', () => {
  cancelDisassembly();
  saveState();
  invalidateDerivedViews();
  autoDisassemble();
});

btnAssemble.addEventListener('click', runAssemble);
btnDisassemble.addEventListener('click', runDisassemble);

$('#btn-clear-asm').addEventListener('click', () => {
  editor.setValue('');
  runAssemble();
  renderEmu(null);
  saveState();
});

$('#btn-clear-hex').addEventListener('click', () => {
  hexInput.value = '';
  disassembleClear();
  saveState();
});

$('#btn-use-asm').addEventListener('click', () => {
  if (!lastAssembled || lastAssembled.length === 0) {
    toast('nothing assembled yet');
    return;
  }
  hexInput.value = toSpacedHex(lastAssembled);
  runDisassemble();
  saveState();
});

$('#btn-copy-shellcode').addEventListener('click', async () => {
  const btn = $<HTMLButtonElement>('#btn-copy-shellcode');
  if (!currentBytes || currentBytes.length === 0) {
    toast('nothing to copy');
    return;
  }
  if (await copyText(toHex(currentBytes))) flashCopyFeedback(btn);
  else toast('copy failed — select the hex text manually');
});

archSelect.addEventListener('change', () => {
  cancelAssembly();
  lastAssembled = null;
  clearBytesFrom('assembler');
  renderShellcode(null, 0);
  setMsg(asmMsg, 'architecture changed — assembling…', '');
  archId = archSelect.value;
  invalidateDerivedViews();
  editor.setArch(getArch(archId));
  saveState();
  updateEmuArgUi();
  ($('#syscall-list') as HTMLElement & { __setArch?: (id: string) => void }).__setArch?.(archId);
  renderPresets();
  renderEmu(null); // stale register dump would be misleading after an arch switch
  if (enginesReady()) {
    runAssemble();
    runDisassemble();
  }
});

// ctrl/cmd+enter: assemble from the editor, disassemble from the hex box
document.addEventListener('keydown', (e) => {
  if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') {
    e.preventDefault();
    if (document.activeElement === hexInput) runDisassemble();
    else runAssemble();
  }
});

$('#btn-share').addEventListener('click', async () => {
  const shared = { a: editor.getValue(), h: hexInput.value, arch: archId, bc: badCharsInput.value };
  if (new TextEncoder().encode(JSON.stringify(shared)).length > 8192) {
    toast('state is too large for a reliable share link');
    return;
  }
  const hash = '#s=' + encodeState(shared);
  const url = location.origin + location.pathname + hash;
  history.replaceState(null, '', hash);
  if (await copyText(url)) toast('share link copied to clipboard');
  else toast('url updated — copy it from the address bar');
});

// --- persistence --------------------------------------------------------------------

interface PersistedState {
  arch?: string;
  a?: string;
  h?: string;
  bc?: string;
}

function saveState(): void {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify({
      arch: archId,
      a: editor.getValue(),
      h: hexInput.value,
      bc: badCharsInput.value,
    }));
  } catch {
    /* storage unavailable — fine */
  }
}

function loadState(): void {
  const hash = location.hash.match(/^#s=([\w-]+)/);
  let state: PersistedState | null = null;
  if (hash) state = decodeState<PersistedState>(hash[1]!);
  if (!state) {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      if (raw) state = JSON.parse(raw) as PersistedState;
    } catch {
      /* ignore */
    }
  }
  if (!state) return;
  if (state.arch && ARCHES.some((a) => a.id === state.arch)) {
    archId = state.arch;
    archSelect.value = archId;
    editor.setArch(getArch(archId));
  }
  if (typeof state.a === 'string' && state.a.trim() && state.a.length <= MAX_ASM_CHARS) editor.setValue(state.a);
  if (typeof state.h === 'string' && state.h.length <= MAX_HEX_BYTES * 4) hexInput.value = state.h;
  if (typeof state.bc === 'string') badCharsInput.value = state.bc;
}

// --- boot ----------------------------------------------------------------------------

function setChip(chip: HTMLElement, state: 'loading' | 'ok' | 'err'): void {
  chip.classList.remove('loading', 'ok', 'err');
  chip.classList.add(state);
}

initTheme();
initBoot();

setChip(chipKeystone, 'loading');
setChip(chipCapstone, 'loading');
renderShellcode(null, 0);
disassembleClear();
renderExports();
loadState();
updateEmuArgUi();
($('#syscall-list') as HTMLElement & { __setArch?: (id: string) => void }).__setArch?.(archId);
renderPresets();
applyBadChars();

initEngines((stage) => bootStage(stage))
  .then(async () => {
    setChip(chipKeystone, 'ok');
    setChip(chipCapstone, 'ok');
    btnAssemble.disabled = false;
    btnDisassemble.disabled = false;
    await runAssemble();
    runDisassemble();
    bootStage('assemble');
    bootDone();
  })
  .catch((err: unknown) => {
    setChip(chipKeystone, 'err');
    setChip(chipCapstone, 'err');
    fatalMsg.textContent =
      `✗ failed to load engines: ${err instanceof Error ? err.message : String(err)} — ` +
      'check that public/wasm/*.wasm exists (npm run postinstall)';
    fatalMsg.classList.remove('hidden');
    bootFail();
  });
