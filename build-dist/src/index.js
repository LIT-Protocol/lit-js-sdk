"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
require("regenerator-runtime/runtime");
// add window global on nodejs
const frameComms_1 = require("./utils/frameComms");
if (typeof window !== "undefined") {
    // only run this in browser
    if ((0, frameComms_1.inIframe)()) {
        (0, frameComms_1.listenForFrameParentMessages)();
    }
    else {
        (0, frameComms_1.listenForChildFrameMessages)();
    }
}
const lit_1 = require("./utils/lit");
const eth_1 = require("./utils/eth");
const crypto_1 = require("./utils/crypto");
const browser_1 = require("./utils/browser");
const constants_1 = require("./lib/constants");
const utils_1 = require("./lib/utils");
const bls_sdk_js_1 = require("./lib/bls-sdk.js");
const litNodeClient_1 = __importDefault(require("./utils/litNodeClient"));
const init_1 = require("./utils/init");
const version_1 = require("./version");
(0, bls_sdk_js_1.initWasmBlsSdk)().then((exports) => {
    globalThis.wasmExports = exports;
    // console.log("wasmExports loaded");
});
const functions = {
    encryptString: lit_1.encryptString,
    decryptString: lit_1.decryptString,
    zipAndEncryptString: lit_1.zipAndEncryptString,
    zipAndEncryptFiles: lit_1.zipAndEncryptFiles,
    encryptZip: lit_1.encryptZip,
    decryptZip: lit_1.decryptZip,
    encryptFile: lit_1.encryptFile,
    decryptFile: lit_1.decryptFile,
    connectWeb3: eth_1.connectWeb3,
    disconnectWeb3: eth_1.disconnectWeb3,
    checkAndSignAuthMessage: lit_1.checkAndSignAuthMessage,
    signAndSaveAuthMessage: eth_1.signAndSaveAuthMessage,
    createHtmlLIT: lit_1.createHtmlLIT,
    mintLIT: eth_1.mintLIT,
    toggleLock: lit_1.toggleLock,
    encryptWithSymmetricKey: crypto_1.encryptWithSymmetricKey,
    decryptWithSymmetricKey: crypto_1.decryptWithSymmetricKey,
    LIT_CHAINS: constants_1.LIT_CHAINS,
    LIT_SVM_CHAINS: constants_1.LIT_SVM_CHAINS,
    ALL_LIT_CHAINS: constants_1.ALL_LIT_CHAINS,
    LitNodeClient: litNodeClient_1.default,
    encryptWithPubKey: crypto_1.encryptWithPubKey,
    decryptWithPrivKey: crypto_1.decryptWithPrivKey,
    fileToDataUrl: browser_1.fileToDataUrl,
    findLITs: eth_1.findLITs,
    sendLIT: eth_1.sendLIT,
    litJsSdkLoadedInALIT: init_1.litJsSdkLoadedInALIT,
    unlockLitWithKey: lit_1.unlockLitWithKey,
    injectViewerIFrame: browser_1.injectViewerIFrame,
    printError: utils_1.printError,
    canonicalAccessControlConditionFormatter: crypto_1.canonicalAccessControlConditionFormatter,
    canonicalEVMContractConditionFormatter: crypto_1.canonicalEVMContractConditionFormatter,
    canonicalUnifiedAccessControlConditionFormatter: crypto_1.canonicalUnifiedAccessControlConditionFormatter,
    verifyJwt: lit_1.verifyJwt,
    encryptFileAndZipWithMetadata: lit_1.encryptFileAndZipWithMetadata,
    hashAccessControlConditions: crypto_1.hashAccessControlConditions,
    hashEVMContractConditions: crypto_1.hashEVMContractConditions,
    hashUnifiedAccessControlConditions: crypto_1.hashUnifiedAccessControlConditions,
    decryptZipFileWithMetadata: lit_1.decryptZipFileWithMetadata,
    downloadFile: browser_1.downloadFile,
    decimalPlaces: eth_1.decimalPlaces,
    humanizeAccessControlConditions: lit_1.humanizeAccessControlConditions,
    lookupNameServiceAddress: eth_1.lookupNameServiceAddress,
    getTokenList: lit_1.getTokenList,
    version: version_1.version,
    encodeCallData: eth_1.encodeCallData,
    decodeCallResult: eth_1.decodeCallResult,
    uint8arrayFromString: browser_1.uint8arrayFromString,
    uint8arrayToString: browser_1.uint8arrayToString,
    signMessageAsync: eth_1.signMessageAsync,
    wasmBlsSdkHelpers: bls_sdk_js_1.wasmBlsSdkHelpers,
    initWasmBlsSdk: bls_sdk_js_1.initWasmBlsSdk,
    generateSymmetricKey: crypto_1.generateSymmetricKey,
    importSymmetricKey: crypto_1.importSymmetricKey,
    blobToBase64String: browser_1.blobToBase64String,
    base64StringToBlob: browser_1.base64StringToBlob,
};
module.exports = functions;
