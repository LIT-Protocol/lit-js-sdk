const { build } = require("esbuild");
const { nodeBuiltIns } = require("esbuild-node-builtins");

build({
  entryPoints: ["src/index.js"],
  bundle: true,
  minify: true,
  sourcemap: true,
  outfile: "build/index.web.js",
  sourceRoot: "./",
  globalName: "LitJsSdk",
  plugins: [nodeBuiltIns()],
  define: { global: "window" },
  inject: ["./polyfills.js"],
});
