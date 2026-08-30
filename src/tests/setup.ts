// Node-test shim: engines.ts builds its wasm URLs from document.baseURI.
// Point a minimal fake document at public/ so keystone/capstone resolve the
// same files the browser serves (emscripten handles file:// in node).

const base = new URL('../../public/', import.meta.url).href;
(globalThis as Record<string, unknown>).document = { baseURI: base };
