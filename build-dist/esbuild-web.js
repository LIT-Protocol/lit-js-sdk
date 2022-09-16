"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
const { build, analyzeMetafile } = require("esbuild");
const { nodeBuiltIns } = require("esbuild-node-builtins");
const { dedupBn } = require("./esbuild-plugins.js");
const go = () => __awaiter(void 0, void 0, void 0, function* () {
    let result = yield build({
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
});
go();
