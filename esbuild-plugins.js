const dedupBn = {
  name: "dedupe-bn",
  setup({ onResolve }) {
    const bn = require.resolve("bn.js/lib/bn.js");
    onResolve({ filter: /^bn\.js$/ }, () => {
      return { path: bn };
    });
  },
};

module.exports = { dedupBn };
