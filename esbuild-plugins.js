const fs = require("fs");

const dedupBn = {
  name: "dedupe-bn",
  setup({ onResolve }) {
    const bn = require.resolve("bn.js/lib/bn.js");
    onResolve({ filter: /^bn\.js$/ }, () => {
      return { path: bn };
    });
  },
};

// this is now done in the lit-ecdsa-wasm-combine repo in convert_wasm_to_js.py
// const fixImportOfRandom = {
//   name: "import-random-fixer",
//   setup({ onEnd }) {
//     onEnd((result) => {
//       console.log("running onEnd");
//       // console.log("onEnd, result", result);
//       // this is a hack to fix require that is bundled by esbuild and comes from rust -> WASM

//       //     // this is what it would look unminified
//       //     const find = `
//       // imports.wbg.__wbg_require_edfaedd93e302925 = function() {
//       //   return handleError(function(arg0, arg1, arg2) {
//       //     var ret = getObject(arg0).require(getStringFromWasm02(arg1, arg2));
//       //     return addHeapObject(ret);
//       //   }, arguments);
//       // };
//       //     `.trim();

//       //     // we're essentially just telling it to use the native require
//       //     const replace = `
//       // imports.wbg.__wbg_require_edfaedd93e302925 = function() {
//       //   return handleError(function(arg0, arg1, arg2) {
//       //     var ret = require(getStringFromWasm02(arg1, arg2));
//       //     return addHeapObject(ret);
//       //   }, arguments);
//       // };
//       //     `.trim();

//       // this is probably fragile... and might break.
//       const find = `t.wbg.__wbg_require_edfaedd93e302925=function(){return u2(function(a,i,c){var u=Mi(a).require(a9(i,c));return co(u)},arguments)}`;
//       const replace = `t.wbg.__wbg_require_edfaedd93e302925=function(){return u2(function(a,i,c){var u=require(a9(i,c));return co(u)},arguments)}`;

//       const code = fs.readFileSync("./build/index.node.js", "utf8");
//       const newCode = code.replace(find, replace);
//       fs.writeFileSync("./build/index.node.js", newCode);
//     });
//   },
// };

module.exports = { dedupBn };
