// Copies the engine .wasm files from node_modules into public/wasm/
// so they are served as static assets next to the app (and land in dist/ on build).
import { cpSync, mkdirSync, rmSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const dest = join(root, 'public', 'wasm');

rmSync(dest, { recursive: true, force: true });
mkdirSync(dest, { recursive: true });

const engines = [
  ['@alexaltea/keystone-js/dist/keystone.wasm', 'keystone.wasm'],
  ['capstone-wasm/dist/capstone.wasm', 'capstone.wasm'],
];

for (const [src, name] of engines) {
  cpSync(join(root, 'node_modules', src), join(dest, name));
  console.log(`wasm: ${name} -> public/wasm/`);
}
