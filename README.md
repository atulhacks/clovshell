<div align="center">

<img src="public/favicon.svg" width="96" alt="clovshell logo" />

# clovshell

**A shellcode workbench in your browser.** Assemble, disassemble, emulate, inspect, and export x86 and ARM shellcode.

[Live demo](https://atulhacks.github.io/clovshell/) · [Run locally](#run-locally)

[![CI](https://github.com/atulhacks/clovshell/actions/workflows/ci.yml/badge.svg)](https://github.com/atulhacks/clovshell/actions/workflows/ci.yml)
[![License: GPL-2.0](https://img.shields.io/badge/license-GPL--2.0-blue.svg)](LICENSE)

<img src="docs/shot-hero.png" width="800" alt="clovshell editor, shellcode bytes, and disassembly" />

</div>

clovshell runs [Keystone](https://www.keystone-engine.org/), [Capstone](https://www.capstone-engine.org/),
and [Unicorn](https://www.unicorn-engine.org/) as WebAssembly. Assembly and emulation happen locally;
your source and shellcode are not sent to a backend.

| Target | Mode | Emulated syscall entry |
| --- | --- | --- |
| x86-64 | 64-bit | `syscall` |
| x86-32 | 32-bit | `int 0x80` |
| ARM | A32 | `svc` |
| ARM64 | AArch64 | `svc` |

## Run locally

```sh
npm install
npm run dev
```

Open the URL printed by Vite (normally `http://localhost:5173`). `npm install` copies the Keystone
and Capstone WASM files into `public/wasm/` through `postinstall`.

## What you can do

### Assemble and inspect

- Write x86-64, x86-32, ARM A32, or ARM64 assembly and see the emitted bytes and instruction listing.
- Paste hex as contiguous bytes, spaced bytes, `\xNN`, or `0xNN`; drop a raw `.bin` file into the page.
  Assembly files (`.asm`/`.s`) can be dropped into the editor.
- Highlight bad bytes such as `00 0a 0d`, count null bytes, and download the result as `.bin`.
- Use labels, common data-emitting directives, and an approximate source-line hint for assembly errors.

### Emulate and trace

- Run shellcode in Unicorn's mapped code and stack memory. Syscalls are intercepted, not issued by
  the host; the UI shows calls, arguments, return values, faults, and final registers.
- Step through the first **400 executed instructions**, including the bytes fetched from emulated
  memory (useful for self-modifying code) and registers captured before each instruction. Navigate
  with buttons or arrow keys, or save the trace as JSON.
- Set an initial first-argument register (`rdi`, `r0`, or `x0`) for function-style shellcode.
- Keep the UI responsive with worker-based emulation, a 30-second outer timeout, and a
  100,000-instruction limit.

### Transform and extract

- Generate self-decoding XOR wrappers for all four targets. Auto-pick a key that avoids configured
  bad bytes in the **complete stub and payload**, then load the result into the editor and run it.
- Find short ROP gadgets by scanning each byte offset, with a 400-result cap and text filtering.
- Export Python, C, C#, Java, JavaScript, Rust, Ruby, PowerShell, NASM, Base64, escaped strings,
  and YARA snippets. Each format has copy and download controls.

### Work faster

- Browse per-architecture Linux syscall numbers and insert an assembly scaffold at the cursor.
- Load tested `execve` and exit presets with one click. Share source and architecture through a
  URL fragment; the editor also restores local state.
- Choose among five themes. The layout works at phone widths and respects reduced-motion settings.
- Install the production build as a PWA. Once its assets have been precached, it works offline,
  including the lazy-loaded emulator engines.

[Emulation screenshot](docs/shot-emulation.png) · [XOR encoder screenshot](docs/shot-encoder.png)

## Scope and limits

clovshell is a CPU-and-syscall workbench, **not a full Linux VM**. File and socket operations are
simulated; unmodeled syscalls return `-ENOSYS`. It currently exposes ARM **A32**, not Thumb, and
supports only the four targets in the table above.

The emulator stops on unmapped memory faults. Returning shellcode lands on a sentinel instead of
continuing into unrelated memory. Its instruction trace is capped at 400 entries even when the
program executes longer. Gadget searches are likewise bounded to keep large inputs responsive.

## Build, test, and deploy

```sh
npm run check    # TypeScript typecheck
npm test         # Vitest, including real WASM engines and cross-architecture emulation
npm run build    # production site in dist/
npm run preview  # serve the production build locally
```

`dist/` is static and uses relative asset paths, so it can be served from a domain root or a
subpath. The build generates a content-derived service-worker cache name and precaches the app,
WASM files, and lazy worker/engine chunks. Use `npm run build && npm run preview` to test offline
behavior; the service worker does not register in Vite's development mode.

GitHub Actions runs typecheck, tests, and build for pushes and pull requests. The Pages workflow
publishes `main` to the [live demo](https://atulhacks.github.io/clovshell/). For another static
host, publish the contents of `dist/`.

## Assembly notes

- Write one instruction per line. `;`, `#`, `//`, and ARM `@` comments are stripped before assembly;
  Keystone's semicolon statement separator is therefore unavailable.
- Labels resolve through Keystone. GNU numeric local labels (`1:` / `1b`) are not supported.
- Non-emitting directives such as `.global`, `.type`, `.section`, and `.cfi_*` are ignored.
  Data-emitting directives such as `.byte`, `.word`, `.quad`, `.ascii`, and `.asciz` are retained.
  Unrecognized dot-directives are dropped; use `.short` in place of `.hword`.
- Error-line hints are approximate for forward references. The x86 parser uses Intel-style
  operands (`mov eax, 1`). On ARM, prefer `movw`/`movt` over Keystone's unreliable
  `ldr rX, =imm` literal-pool placement.

## Project map

| Path | Purpose |
| --- | --- |
| `src/engines.ts`, `src/directives.ts` | WASM assembly/disassembly and source preprocessing |
| `src/emu.ts`, `src/emu-worker.ts` | Emulation, syscall models, and execution capture |
| `src/encoder.ts`, `src/gadgets.ts`, `src/gadget-worker.ts` | XOR wrappers and bounded gadget scans |
| `src/syscalls*.ts`, `src/presets.ts` | Syscall reference, scaffolds, and examples |
| `src/main.ts`, `src/editor.ts`, `src/ui.ts` | Workbench interface and state |
| `src/tests/` | Engine and UI-logic regression tests |
| `scripts/` | WASM copy, syscall-table generation, service-worker finalization |
| `public/sw.js` | Production offline cache |

The syscall data can be regenerated with `node scripts/gen-syscalls.mjs` using an authenticated
`gh` CLI. The script caches the kernel sources under `scripts/kernel-src/`.

## License

clovshell is [GPL-2.0](LICENSE). Keystone and Unicorn are GPL-2.0; Capstone is BSD-3-Clause.
