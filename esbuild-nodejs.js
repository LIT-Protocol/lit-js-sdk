const { build } = require("esbuild");
build({
  entryPoints: ["src/index.js"],
  bundle: true,
  minify: true,
  sourcemap: true,
  outfile: "build/index.node.js",
  loader: {
    ".svg": "dataurl",
    ".css": "text",
  },
  sourceRoot: "./",
  platform: "node",
  inject: ["./esbuild-nodejs-shims.js"],
});
