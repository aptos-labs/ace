import { defineConfig } from "tsup";

export default defineConfig({
  entry: ["src/index.ts"],
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
});
