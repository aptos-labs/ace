import { defineConfig } from "tsup";

export default defineConfig({
  entry: {
    index: "src/index.ts",
    aptos: "src/aptos.ts",
    solana: "src/solana.ts",
  },
  format: "esm",
  outDir: "dist/esm",
  bundle: true,
  clean: true,
  dts: true,
  minify: false,
  skipNodeModulesBundle: true,
  sourcemap: true,
  target: "es2022",
  platform: "node",
  splitting: false,
});
