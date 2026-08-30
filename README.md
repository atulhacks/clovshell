# clovshell 🍀

**▶ try it live: <https://atulhacks.github.io/clovshell/>**

**shellcode workbench** — assemble, disassemble, **run** and extract x86 / ARM shellcode, entirely in your browser.

Asm goes in, raw bytes come out. Bytes go in, a disassembly listing comes out. Press ▶ run and the shellcode
actually executes — under a CPU emulator in the page — with syscalls intercepted, buffers shown and register
deltas flagged. Everything runs as WebAssembly locally: **your shellcode never leaves the page** — no server,
no telemetry, no network calls.

![clovshell](public/favicon.svg)

## features

### assemble / disassemble

- **assemble** x86-64 / x86-32 / ARM (A32) / ARM64 (AArch64) assembly to raw shellcode
  ([keystone](https://www.keystone-engine.org/) compiled to WASM)
- **disassemble** hex bytes back to a address / bytes / instruction listing
  ([capstone](https://www.capstone-engine.org/) compiled to WASM)
- **bad-character checker** 🆕 — type the bytes your target can't stomach (`00 0a 0d ff`) and every
  offending byte is highlighted in red in the shellcode box *and* the disassembly listing, with a
  count in the stats line — the classic exploit-writing workflow
- **null-byte awareness** — nulls are counted, flagged and highlighted (they break string-based
  injection, you want to know)
- **drag & drop** 🆕 — drop a `.bin`/raw file onto the page to load it into the hex box; drop
  `.asm`/`.s` to load it into the editor
- **download** 🆕 — the raw shellcode as `.bin`, and every export format as its natural file
  type (`.py`, `.c`, `.rs`, …) via the ⭳ button on each export card

### run it (emulation) 🆕

- **in-browser execution** under [Unicorn](https://www.unicorn-engine.org/) (QEMU's CPU cores
  compiled to WASM): your shellcode runs in a sandboxed memory space — code page, 1 MiB stack,
  mmap region — nothing touches the host
- **syscall interception** per arch (x86-64 `syscall`, x86-32 `int 0x80`, ARM/ARM64 `svc`):
  `write` shows the bytes being written, `execve` reads the filename out of emulated memory and
  stops ("process replaced"), `open`/`socket` hand out fds, `mmap` maps fresh pages, `exit` /
  `exit_group` report the exit code
- **register dump** after the run, with registers the shellcode touched highlighted
- **entry argument** — set the initial value of the first-arg register (`rdi`/`r0`/`x0`)
  before running, so function-style shellcode like `sum_to_n` can be tested with real input
- **fault reporting** — unmapped reads/writes/fetches stop emulation with the faulting address;
  runaway loops hit a 100 000-instruction limit instead of hanging the tab
- shellcodes that `ret` land on a `ud2` sentinel — a clean stop instead of executing garbage

### xor encoder 🆕

- wraps assembled shellcode in a **self-decoding stub** for all four arches: x86-64/x86-32
  (`call`/`pop` getpc + `xor byte ptr [rsi], key` loop), ARM (`adr`+`bx`), ARM64 (`adr`+`br`)
- **auto-pick key** scans 0x01..0xff and reports every key whose *complete program* (stub +
  encoded payload) avoids your bad characters
- **verified in the emulator** — "→ editor & run" loads the encoded source, assembles it and runs
  it, so you watch the decoder decode and the payload execute, not just trust the generator
- length limits are honest per arch (255 B where the counter is a byte/cl, 4095 B on ARM64's imm12)

### ROP gadget finder 🆕

- **find ROP gadgets** straight from the disassembly panel — the classic
  [ROPgadget](https://github.com/JonathanSalwan/ROPgadget)/ropper technique in the browser:
  capstone slides over the byte stream from *every* offset (not just instruction boundaries) and
  keeps short sequences (≤ 8 insns) ending in a control-flow instruction
- deduplicated by instruction text, capped at 400 gadgets, filter box, click a row to copy it

### reference

- **syscall browser** — all 1 634 Linux syscalls across the four arches (x86-64: 386, x86-32: 462,
  ARM: 437, ARM64: 349), generated straight from the
  [Linux kernel's syscall tables](https://github.com/torvalds/linux/tree/master/arch). Search,
  click, and a ready-to-assemble scaffold (`mov rax, 59` + `syscall`, or the per-arch equivalent)
  is inserted at your cursor
- **presets** — classic shellcodes per arch (x86-64/x86-32 null-free `execve("/bin/sh")`, exits)
  with notes; one click loads, assembles *and* runs them

### extraction

- exports for **Python, Python array, C, C string, escaped string, JavaScript, NASM `db`, Base64,
  PowerShell, C#, Java, Ruby, Rust, YARA** — one click each 🆕

### editor & misc

- syntax-highlighted editor with line numbers, auto-assembly as you type
- **labels & directives** — GNU-as-style sources just work: `_start:`, `loop:`, `.global`,
  `.type`, `.section`, `.cfi_*` … all accepted; `.byte`/`.word`/`.quad`/`.asciz` emit real data
- lenient hex input: `b8736b6964`, `b8 73 6b …`, `\xb8\x73…`, `0xb8, 0x73` all parse
- **cross-arch hint** — paste bytes that belong to another architecture and the disassembler
  tells you which one decodes them cleanly
- `↑ from assembler` — pipe assembled bytes straight into the disassembler
- shareable URLs (`share ↗` encodes source + arch in the hash), state restored from localStorage
- `ctrl/cmd + ⏎` to assemble (or disassemble, from the hex box)
- **installable PWA** 🆕 — manifest + service worker: the whole workbench (shell, engines,
  emulation chunks) caches on first visit and then works **fully offline**; "install" it from
  your browser and it opens as its own app with zero network
- responsive down to phone widths — every panel stacks, nothing scrolls sideways

## run it

```sh
npm install     # also copies engine wasm into public/wasm/ (postinstall)
npm run dev     # http://localhost:5173
npm test        # vitest suite (82 tests) — assembles/disassembles through the real wasm engines
npm run check   # typescript, no emit
npm run build   # static site in dist/ — host it anywhere
npm run preview # serve the production build locally
```

`dist/` is fully static: any static host works (GitHub Pages, Netlify, Railway static, nginx, `python -m http.server`).

## testing

`src/tests/` holds a [vitest](https://vitest.dev/) suite that runs the *real* keystone/capstone
wasm engines in Node (a tiny shim points their wasm loader at `public/wasm/` via `file://`):

- **ground-truth tables** — syscall numbers are asserted against known kernel values
  (x86-64 `read`=0 … `openat`=257, arm64 `mmap`=222, …)
- **every preset** is assembled, disassembled back, and — for the ones claiming *null-free* —
  byte-scanned for `00` (this test has caught a lying preset in the wild)
- **the encoder** is proven on all four arches: payload = input ^ key, and the *entire generated
  stub+payload program* must assemble
- hex parsing, comment stripping, directive handling, export formats, gadget finding and
  cross-arch hints are all covered

```sh
npm test                  # one-shot
npx vitest                # watch mode while developing
```

CI (`.github/workflows/ci.yml`) runs install → typecheck → test → build on every push/PR and
uploads `dist/` as an artifact.

## deploying

The build is a plain static bundle with **relative paths** (`base: './'`), so it drops onto any
host, including subpaths like `user.github.io/clovshell/`:

```sh
npm run build   # → dist/
```

- **GitHub Pages** — this repo ships a deploy workflow (`.github/workflows/deploy.yml`):
  every push to `main` builds, tests and publishes to `https://atulhacks.github.io/clovshell/`.
  The relative base means no 404s under the repo subpath.
- **Netlify / Vercel / Cloudflare Pages** — build command `npm run build`, publish directory
  `dist`. No framework preset needed.
- **nginx / any static file server** — serve `dist/`; add `application/wasm` for `.wasm` if your
  server doesn't set it (most do).
- **Railway** — static site service, root directory `/`, output `dist`.

The service worker registers only in production builds, so `vite dev` never fights your cache —
when testing the PWA locally use `npm run build && npm run preview` and hard-reload between
changes. To ship a new version, bump the `CACHE` name in `public/sw.js` so clients refresh.

## architecture

```
src/
  engines.ts        keystone + capstone loading, arch registry, assemble()/disassemble()
  directives.ts     strips non-emitting assembler directives (some crash keystone's wasm)
  emu.ts            unicorn engine loading (lazy, per-arch chunks), memory layout, syscall hooks
  syscalls-data.ts  generated: 1 634 syscall entries from the Linux kernel tables
  syscalls.ts       searchable syscall panel + per-arch scaffold generator
  presets.ts        classic shellcode presets
  encoder.ts        xor encoder + self-decoding stub generation (all four arches)
  gadgets.ts        ROP gadget finder (sliding-window disassembly)
  hex.ts            lenient hex parsing, formatting, bad-char & null counting
  formats.ts        the export formatters (python/c/js/powershell/yara…)
  highlight.ts      tiny per-arch asm syntax highlighter
  editor.ts         textarea + backdrop-highlight + gutter, scroll-synced
  ui.ts             small DOM helpers (copy, toast, file download)
  main.ts           app wiring, state, URL sharing
  tests/            vitest suite (runs the real wasm engines in Node)
scripts/
  gen-syscalls.mjs  regenerates syscalls-data.ts from torvalds/linux (via gh api, cached)
  copy-wasm.mjs     copies keystone/capstone wasm from node_modules into public/wasm/
public/
  sw.js             service worker — precaches the shell + engines for full offline use
  manifest.webmanifest, favicon.svg
  wasm/             keystone.wasm (4.3 MB) + capstone.wasm (1.8 MB), copied from node_modules
.github/workflows/ci.yml   typecheck + test + build on every push/PR
```

No framework, no runtime dependencies beyond the engines.

**Loading strategy** — first paint ships ~40 kB of JS (gzipped). Keystone + capstone wasm load on
boot; each unicorn engine (x86 273 kB, ARM 271 kB, ARM64 409 kB gzipped) is a separate lazy chunk
that only downloads the first time you press ▶ run for that arch.

## quirks worth knowing

- **comments** — `;` (NASM-style), `#`, `//` and — on ARM — `@` all work. Comments are stripped
  (quote-aware) before the source reaches keystone, so anything inside a comment (unicode, parens,
  dashes) is safe. Consequence: keystone's native `;` *statement separator* is not available —
  one instruction per line.
- **labels** — keystone resolves them itself (branch immediates are absolute addresses from the
  start of the blob), and capstone prints resolved targets the same way, so `loop:` round-trips
  through bytes and back. GNU *numeric* local labels (`1:` / `1b`) are not supported by keystone.
- **directives** — non-emitting assembler directives (`.global`, `.type`, `.section`, `.cfi_*`…)
  are stripped before assembly: keystone rejects some (`.type` on ARM32) and its wasm build
  **crashes outright on bare `.text`/`.data`** (section switching touches wasm memory it doesn't
  own). Data-emitting directives (`.byte`, `.short`, `.word`, `.long`, `.quad`, `.xword`, `.octa`,
  `.ascii`, `.asciz`, `.string`, `.skip`, `.zero`, `.space`, `.fill`) are kept and emit real
  bytes. Unrecognized dot-directives are dropped silently — use `.short` where gas would take
  `.hword`. keystone's own failures are additionally caught in a try/catch so a wasm crash can
  never take the UI down.
- **error messages** carry the offending line: `✗ Invalid operand — near line 3: \`mov ebs, …\``.
  keystone itself reports no position; clovshell re-assembles progressively longer prefixes to find
  the failing line. It's a hint — a forward reference (`jmp label` before `label:`) can occasionally
  point one line off.
- **instruction counts** are derived by disassembling the emitted bytes; keystone's own count is
  unreliable around comments.
- keystone's x86 parser is the gas-flavoured one (`mov eax, 1`, intel syntax).
- MIPS/PPC assemble fine in keystone but the capstone build used here only disassembles x86/ARM
  families — those arches are deliberately not exposed.
- **emulation caveats** — unicorn's timeout parameter spawns a QEMU timer thread that aborts under
  WASM, so clovshell always runs with timeout 0 and enforces its own instruction limit. The syscall
  emulation is deliberately shallow: file/socket I/O is stubbed (no real bytes are read or sent),
  which is exactly what you want for a public tool.
- ARM's `ldr rX, =imm` literal-pool placement is unreliable in keystone; prefer `movw`/`movt` in
  shellcode you plan to assemble here.

## regenerating the syscall tables

```sh
node scripts/gen-syscalls.mjs   # needs `gh` authenticated; kernel sources cached in scripts/kernel-src/
```

## license notes

- this project is licensed under the **GPL-2.0** (see [LICENSE](LICENSE)).
- keystone and its JS binding are **GPL-2.0**; unicorn and its JS binding are **GPL-2.0** — the
  combined work you build and distribute from this repo inherits that.
- capstone is BSD-3.
- intended for security research, CTFs and education.
