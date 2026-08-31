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
import {
  countBadBytes,
  countNullBytes,
  describeBadChars,
  formatAddress,
  parseBadChars,
  parseHexInput,
  toHex,
  toSpacedHex,
} from './hex';
import { FORMATS } from './formats';
import { highlightInstruction } from './highlight';
import { createEditor, editorTemplate } from './editor';
import { runEmulation, preloadEmu, entryArgReg } from './emu';
import { xorEncode } from './encoder';
import { findGadgets, gadgetRows } from './gadgets';
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

function renderDisassembly(result: ReturnType<typeof disassemble>): void {
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
  const arch = getArch(archId);
  for (const insn of result.insns) {
    const bytesHtml = hexWithBadFlags(insn.bytes, ' ');
    const row = el('div', { class: 'row' });
    row.innerHTML =
      `<span class="addr">${formatAddress(insn.address)}</span>` +
      `<span class="bytes">${bytesHtml}</span>` +
      `<span class="insn">${highlightInstruction(insn.mnemonic, insn.opStr, arch)}</span>`;
    disasmListing.append(row);
  }
  const undecoded = result.total - result.consumed;
  if (undecoded > 0) {
    disasmListing.append(el('div', { class: 'listing-truncated' },
      `⚠ stopped at 0x${formatAddress(result.consumed)} — ${undecoded} undecodable byte${undecoded > 1 ? 's' : ''}`));
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

function runAssemble(): void {
  const src = editor.getValue().trim();
  if (!src) {
    lastAssembled = null;
    currentBytes = null;
    currentBytesSource = null;
    renderShellcode(null, 0);
    setMsg(asmMsg, '', '');
    renderExports();
    return;
  }
  const res = assemble(archId, src);
  if (res.ok && res.bytes) {
    lastAssembled = res.bytes;
    currentBytes = res.bytes;
    currentBytesSource = 'assembler';
    // keystone's instruction count is unreliable around comments —
    // count real instructions by disassembling the emitted bytes
    const dis = disassemble(archId, res.bytes);
    const insnCount = dis.ok ? dis.insns.length : 0;
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
    renderShellcode(null, 0, true);
    const where = res.errorLine
      ? ` — near line ${res.errorLine}${res.errorSource ? `: \`${res.errorSource}\`` : ''}`
      : '';
    setMsg(asmMsg, `✗ ${res.error}${where}`, 'err');
  }
  renderExports();
}

function runDisassemble(): void {
  const text = hexInput.value.trim();
  if (!text) {
    disassembleClear();
    return;
  }
  const parsed = parseHexInput(text);
  if (parsed.error) {
    setMsg(hexMsg, `✗ ${parsed.error}`, 'err');
    renderDisassembly({ ok: false, insns: [], error: parsed.error, consumed: 0, total: 0 });
    return;
  }
  const bytes = parsed.bytes;
  const res = disassemble(archId, bytes);
  renderDisassembly(res);
  if (!res.ok) {
    setMsg(hexMsg, `✗ ${res.error}`, 'err');
    return;
  }
  const undecoded = res.total - res.consumed;
  if (undecoded > 0) {
    setMsg(hexMsg, `⚠ decoded ${res.insns.length} instructions, then hit undecodable bytes`, 'warn');
  } else {
    setMsg(hexMsg, `✓ decoded ${res.insns.length} instruction${res.insns.length === 1 ? '' : 's'}`, 'ok');
  }
  if (bytes.length > 0) {
    currentBytes = bytes;
    currentBytesSource = 'hex input';
    renderExports();
  }
}

function disassembleClear(): void {
  renderDisassembly({ ok: true, insns: [], error: null, consumed: 0, total: 0 });
  setMsg(hexMsg, '', '');
}

// --- emulation --------------------------------------------------------------------

const EMU_PLACEHOLDER =
  '// press ▶ run to execute the assembled shellcode\n// under the unicorn engine — syscalls, buffers and exit state appear here';

function renderEmu(result: Awaited<ReturnType<typeof runEmulation>> | null): void {
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
async function runEmu(): Promise<void> {
  if (emuBusy) return;
  const src = editor.getValue().trim();
  if (!src) {
    toast('nothing to run — the editor is empty');
    return;
  }
  const res = assemble(archId, src);
  if (!res.ok || !res.bytes) {
    toast('fix the assembly errors first');
    return;
  }
  emuBusy = true;
  btnRunEmu.disabled = true;
  btnRunEmu.textContent = '… running';
  setMsg(emuMsg, 'loading unicorn engine (first run downloads ~1 MB)…', '');
  try {
    await preloadEmu(archId);
    setChip(chipUnicorn, 'ok');
    const arg = parseEntryArg();
    if (arg && 'error' in arg) {
      setMsg(emuMsg, `✗ ${arg.error}`, 'err');
      return;
    }
    const result = await runEmulation(archId, res.bytes, arg ? arg.value : null);
    renderEmu(result);
  } catch (err) {
    setMsg(emuMsg, `✗ ${err instanceof Error ? err.message : String(err)}`, 'err');
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
let currentGadgets: Gadget[] = [];

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

function runGadgets(): void {
  // scan whatever is in the hex box; fall back to the assembled bytes
  let bytes: Uint8Array | null = null;
  const parsed = parseHexInput(hexInput.value);
  if (!parsed.error && parsed.bytes.length > 0) bytes = parsed.bytes;
  else if (lastAssembled && lastAssembled.length > 0) bytes = lastAssembled;
  if (!bytes) {
    toast('nothing to scan — paste hex bytes or assemble something');
    return;
  }
  const res = findGadgets(archId, bytes);
  if ('error' in res) {
    setMsg(hexMsg, `✗ ${res.error}`, 'err');
    return;
  }
  currentGadgets = res;
  gadgetsPanel.classList.remove('hidden');
  renderGadgetList();
}

$('#btn-gadgets').addEventListener('click', runGadgets);
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
  if (/\.(asm|s|S)$/i.test(file.name) && file.size < 64 * 1024) {
    void file.text().then((src) => {
      editor.setValue(src);
      runAssemble();
      saveState();
      toast(`${file.name} → loaded into the editor`);
    });
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

const autoAssemble = debounce(() => {
  if (enginesReady()) runAssemble();
}, 350);

const autoDisassemble = debounce(() => {
  if (enginesReady()) runDisassemble();
}, 350);

editor.onChange(() => {
  saveState();
  autoAssemble();
});

hexInput.addEventListener('input', () => {
  saveState();
  autoDisassemble();
});

btnAssemble.addEventListener('click', runAssemble);
btnDisassemble.addEventListener('click', runDisassemble);

$('#btn-clear-asm').addEventListener('click', () => {
  editor.setValue('');
  runAssemble();
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
  archId = archSelect.value;
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
  const hash = '#s=' + encodeState({ a: editor.getValue(), h: hexInput.value, arch: archId, bc: badCharsInput.value });
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
  if (typeof state.a === 'string' && state.a.trim()) editor.setValue(state.a);
  if (typeof state.h === 'string') hexInput.value = state.h;
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
applyBadChars();

initEngines((stage) => bootStage(stage))
  .then(() => {
    setChip(chipKeystone, 'ok');
    setChip(chipCapstone, 'ok');
    btnAssemble.disabled = false;
    btnDisassemble.disabled = false;
    runAssemble();
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
