import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    // engines.ts resolves wasm paths against document.baseURI (browser idiom);
    // setup.ts points a fake document at public/ before any engine loads
    setupFiles: ['./src/tests/setup.ts'],
    include: ['src/tests/**/*.test.ts'],
    testTimeout: 30_000,
    hookTimeout: 60_000,
    // the engine wasm modules are large — silence the chunk warnings
    pool: 'forks',
  },
});
