import { defineConfig } from 'vite';

export default defineConfig({
  // relative base so the build works from any subpath (static host, Railway, file-ish serves)
  base: './',
  build: {
    target: 'es2022',
    // keep wasm/asset urls intact rather than inlining anything
    assetsInlineLimit: 0,
  },
});
