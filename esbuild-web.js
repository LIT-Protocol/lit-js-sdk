const { build, analyzeMetafile } = require("esbuild");
const { nodeBuiltIns } = require("esbuild-node-builtins");
const { dedupBn } = require("./esbuild-plugins.js");

const go = async () => {
  let result = await build({
    entryPoints: ["src/index.ts"],
    bundle: true,
    minify: true,
    sourcemap: true,
    outfile: "dist/index.web.js",
    loader: {
      ".svg": "dataurl",
      ".css": "text",
    },
    sourceRoot: "./",
    globalName: "LitJsSdk",
    plugins: [nodeBuiltIns(), dedupBn],
    define: { global: "window" },
    inject: ["./esbuild-web-shims.js"],
    metafile: true,
  });

  // let text = await analyzeMetafile(result.metafile);
  // console.log(text);
};

go();
