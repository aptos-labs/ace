import { defineConfig } from 'tsup';

export default defineConfig({
  entry: ['src/index.ts'],
  format: ['esm'],
  target: 'node22',
  banner: { js: '#!/usr/bin/env node' },
  clean: true,
  splitting: false,
  // Bundle every dependency (incl. the workspace @aptos-labs/ace-sdk and ts-sdk) into one file,
  // so the container image is just node + dist/index.js — no node_modules to ship or resolve.
  noExternal: [/.*/],
});
