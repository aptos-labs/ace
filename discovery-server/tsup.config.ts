import { defineConfig } from 'tsup';

export default defineConfig({
  entry: ['src/index.ts'],
  format: ['esm'],
  target: 'node22',
  // Shebang, plus a real `require` for the ESM bundle: some bundled transitive deps (e.g.
  // http2-wrapper via the SDK's HTTP client) do a dynamic `require('http2')`, which esbuild's
  // ESM output otherwise turns into a throwing stub ("Dynamic require of X is not supported").
  // `createRequire(import.meta.url)` makes those resolve to the real Node built-ins at runtime.
  banner: {
    js: [
      '#!/usr/bin/env node',
      "import { createRequire as __ace_createRequire } from 'module';",
      'const require = __ace_createRequire(import.meta.url);',
    ].join('\n'),
  },
  clean: true,
  splitting: false,
  // Bundle every dependency (incl. the workspace @aptos-labs/ace-sdk and ts-sdk) into one file,
  // so the container image is just node + dist/index.js — no node_modules to ship or resolve.
  noExternal: [/.*/],
});
