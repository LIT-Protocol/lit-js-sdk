const { build } = require("esbuild");
build({
  entryPoints: ["src/index.js"],
  bundle: true,
  minify: false,
  sourcemap: true,
  outfile: "build/index.node.js",
  sourceRoot: "./",
  platform: "node",
  inject: ["./esbuild-nodejs-shims.js"],
});
