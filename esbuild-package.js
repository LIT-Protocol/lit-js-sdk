const { build } = require("esbuild");
build({
  entryPoints: ["src/index.js"],
  bundle: true,
  minify: true,
  sourcemap: true,
  outfile: "build/index.js",
  sourceRoot: "./",
  platform: "node",
  inject: ["./esbuild-nodejs-shims.js"],
});
