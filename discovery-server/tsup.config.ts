import { defineConfig } from 'tsup';

export default defineConfig({
  entry: ['src/index.ts'],
  format: ['cjs'],
  target: 'node18',
  banner: { js: '#!/usr/bin/env node' },
  clean: true,
  splitting: false,
});
