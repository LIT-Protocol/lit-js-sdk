const { build } = require("esbuild");
const { nodeBuiltIns } = require("esbuild-node-builtins");
const { nodeExternalsPlugin } = require("esbuild-node-externals");

build({
  entryPoints: ["src/index.js"],
  bundle: true,
  minify: true,
  format: "cjs",
  sourcemap: true,
  outfile: "build/index.esbuild.js",
  sourceRoot: "./",
  plugins: [nodeBuiltIns(), nodeExternalsPlugin()],
  platform: "browser",
  treeShaking: true,
});
