const { build, analyzeMetafile } = require("esbuild");

const go = async () => {
  let result = await build({
    entryPoints: ["src/index.js"],
    bundle: true,
    minify: true,
    sourcemap: true,
    outfile: "build/index.universal.js",
    loader: {
      ".svg": "dataurl",
      ".css": "text",
    },
    sourceRoot: "./",
    format: "esm",
    mainFields: ["main"],
    platform: "neutral",
    inject: ["./esbuild-universal-shims.js"],
    define: { window: "globalThis", global: "globalThis" },
    metafile: true,
  });
  let text = await analyzeMetafile(result.metafile);
  console.log(text);
};

go();
