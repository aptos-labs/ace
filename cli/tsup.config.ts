import { defineConfig } from 'tsup';

export default defineConfig({
  entry: ['src/index.ts'],
  format: ['esm'],
  target: 'node22',
  banner: { js: '#!/usr/bin/env node' },
  clean: true,
  splitting: false,
  skipNodeModulesBundle: true,
  external: ['@aptos-labs/ts-sdk', '@aptos-labs/gas-station-client'],
});
