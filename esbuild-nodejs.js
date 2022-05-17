const { build, analyzeMetafile } = require("esbuild");
const { dedupBn } = require("./esbuild-plugins.js");

const go = async () => {
  let result = await build({
    entryPoints: ["src/index.js"],
    bundle: true,
    minify: true,
    sourcemap: true,
    outfile: "build/index.node.js",
    loader: {
      ".svg": "dataurl",
      ".css": "text",
    },
    plugins: [dedupBn],
    sourceRoot: "./",
    platform: "node",
    inject: ["./esbuild-nodejs-shims.js"],
    metafile: true,
  });
  // let text = await analyzeMetafile(result.metafile);
  // console.log(text);
};

go();
