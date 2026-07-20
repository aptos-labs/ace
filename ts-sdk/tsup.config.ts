import { defineConfig } from "tsup";
import type { Options, Format } from "tsup";

type MandatoryOptions = Options & {
  outDir: string;
  format: Format | Format[];
};

const DEFAULT_CONFIG: Options = {
  bundle: true,
  clean: false,
  dts: true,
  minify: false,
  skipNodeModulesBundle: true,
  sourcemap: true,
  target: "es2022",
  platform: "node",
  splitting: false,
};

const ENTRY_POINTS = {
  index: "src/index.ts",
  aptos: "src/aptos.ts",
  solana: "src/solana.ts",
};

function makeConfig(
  entryName: keyof typeof ENTRY_POINTS,
  format: Format,
  outDir: string,
): MandatoryOptions {
  return {
    ...DEFAULT_CONFIG,
    entry: { [entryName]: ENTRY_POINTS[entryName] },
    format,
    outDir,
  };
}

export default defineConfig([
  makeConfig("index", "cjs", "dist/common"),
  makeConfig("aptos", "cjs", "dist/common"),
  makeConfig("solana", "cjs", "dist/common"),
  makeConfig("index", "esm", "dist/esm"),
  makeConfig("aptos", "esm", "dist/esm"),
  makeConfig("solana", "esm", "dist/esm"),
]);
