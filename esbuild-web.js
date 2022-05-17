const { build, analyzeMetafile } = require("esbuild");
const { nodeBuiltIns } = require("esbuild-node-builtins");
const { dedupBn } = require("./esbuild-plugins.js");

const go = async () => {
  let result = await build({
    entryPoints: ["src/index.js"],
    bundle: true,
    minify: true,
    sourcemap: true,
    outfile: "build/index.web.js",
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
