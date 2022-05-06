module.exports = function (fileInfo, api, options) {
  return api
    .jscodeshift(fileInfo.source)
    .findVariableDeclarators("window")
    .renameTo("globalThis")
    .toSource();
};
