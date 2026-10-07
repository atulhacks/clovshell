import { createHash } from 'node:crypto';
import { readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { dirname, join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const dist = join(root, 'dist');
const swPath = join(dist, 'sw.js');

function listFiles(dir) {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const path = join(dir, entry.name);
    return entry.isDirectory() ? listFiles(path) : [path];
  });
}

const files = listFiles(dist).filter((path) => path !== swPath).sort();
const digest = createHash('sha256');
for (const path of files) {
  digest.update(relative(dist, path));
  digest.update(readFileSync(path));
}
const cache = `clovshell-${digest.digest('hex').slice(0, 12)}`;
const assets = ['./', ...files.map((path) => './' + relative(dist, path).replaceAll('\\', '/'))];
let sw = readFileSync(swPath, 'utf8');
if (!sw.includes("const CACHE = '__BUILD_CACHE__';") || !sw.includes('const PRECACHE_ASSETS = [];')) {
  throw new Error('service worker template markers are missing');
}
sw = sw.replace("const CACHE = '__BUILD_CACHE__';", `const CACHE = '${cache}';`);
sw = sw.replace('const PRECACHE_ASSETS = [];', `const PRECACHE_ASSETS = ${JSON.stringify(assets)};`);
writeFileSync(swPath, sw);
console.log(`service worker: ${cache}, ${assets.length} precached URLs`);
