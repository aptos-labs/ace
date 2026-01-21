import { defineConfig } from "tsup";
import type { Options, Format } from "tsup";

type MandatoryOptions = Options & {
  outDir: string;
  format: Format | Format[];
};

const DEFAULT_CONFIG: Options = {
  bundle: true,
  clean: true,
  dts: true,
  minify: false,
  skipNodeModulesBundle: true,
  sourcemap: true,
  target: "es2022",
  platform: "node",
};

// CommonJS config
const COMMON_CONFIG: MandatoryOptions = {
  ...DEFAULT_CONFIG,
  entry: ["src/index.ts"],
  format: "cjs",
  outDir: "dist/common",
};

// ESM config
const ESM_CONFIG: MandatoryOptions = {
  ...DEFAULT_CONFIG,
  entry: ["src/index.ts"],
  format: "esm",
  outDir: "dist/esm",
};

export default defineConfig([COMMON_CONFIG, ESM_CONFIG]);
