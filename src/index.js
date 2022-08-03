import "regenerator-runtime/runtime";

// add window global on nodejs
import {
  listenForChildFrameMessages,
  listenForFrameParentMessages,
  inIframe,
} from "./utils/frameComms";

if (typeof window !== "undefined") {
  // only run this in browser
  if (inIframe()) {
    listenForFrameParentMessages();
  } else {
    listenForChildFrameMessages();
  }
}

import {
  fromString as uint8arrayFromString,
  toString as uint8arrayToString,
} from "uint8arrays";

import {
  encryptString,
  decryptString,
  zipAndEncryptString,
  zipAndEncryptFiles,
  encryptZip,
  decryptZip,
  encryptFile,
  decryptFile,
  createHtmlLIT,
  toggleLock,
  unlockLitWithKey,
  verifyJwt,
  encryptFileAndZipWithMetadata,
  decryptZipFileWithMetadata,
  humanizeAccessControlConditions,
  getTokenList,
  checkAndSignAuthMessage,
} from "./utils/lit";

import {
  connectWeb3,
  disconnectWeb3,
  mintLIT,
  signAndSaveAuthMessage,
  findLITs,
  sendLIT,
  decimalPlaces,
  lookupNameServiceAddress,
  encodeCallData,
  decodeCallResult,
  signMessageAsync,
} from "./utils/eth";

import {
  decryptWithPrivKey,
  encryptWithPubKey,
  canonicalAccessControlConditionFormatter,
  canonicalEVMContractConditionFormatter,
  canonicalUnifiedAccessControlConditionFormatter,
  hashAccessControlConditions,
  hashEVMContractConditions,
  hashUnifiedAccessControlConditions,
  encryptWithSymmetricKey,
  decryptWithSymmetricKey,
  generateSymmetricKey,
  importSymmetricKey,
} from "./utils/crypto";

import {
  fileToDataUrl,
  injectViewerIFrame,
  downloadFile,
} from "./utils/browser";

import { LIT_CHAINS, LIT_SVM_CHAINS, ALL_LIT_CHAINS } from "./lib/constants";
import { printError } from "./lib/utils";
import { initWasmBlsSdk, wasmBlsSdkHelpers } from "./lib/bls-sdk.js";

import LitNodeClient from "./utils/litNodeClient";

import { litJsSdkLoadedInALIT } from "./utils/init";

import { version } from "./version";

initWasmBlsSdk().then((exports) => {
  globalThis.wasmExports = exports;
  // console.log("wasmExports loaded");
});

const functions = {
  encryptString,
  decryptString,
  zipAndEncryptString,
  zipAndEncryptFiles,
  encryptZip,
  decryptZip,
  encryptFile,
  decryptFile,
  connectWeb3,
  disconnectWeb3,
  checkAndSignAuthMessage,
  signAndSaveAuthMessage,
  createHtmlLIT,
  mintLIT,
  toggleLock,
  encryptWithSymmetricKey,
  decryptWithSymmetricKey,
  LIT_CHAINS,
  LIT_SVM_CHAINS,
  ALL_LIT_CHAINS,
  LitNodeClient,
  encryptWithPubKey,
  decryptWithPrivKey,
  fileToDataUrl,
  findLITs,
  sendLIT,
  litJsSdkLoadedInALIT,
  unlockLitWithKey,
  injectViewerIFrame,
  printError,
  canonicalAccessControlConditionFormatter,
  canonicalEVMContractConditionFormatter,
  canonicalUnifiedAccessControlConditionFormatter,
  verifyJwt,
  encryptFileAndZipWithMetadata,
  hashAccessControlConditions,
  hashEVMContractConditions,
  hashUnifiedAccessControlConditions,
  decryptZipFileWithMetadata,
  downloadFile,
  decimalPlaces,
  humanizeAccessControlConditions,
  lookupNameServiceAddress,
  getTokenList,
  version,
  encodeCallData,
  decodeCallResult,
  uint8arrayFromString,
  uint8arrayToString,
  signMessageAsync,
  wasmBlsSdkHelpers,
  initWasmBlsSdk,
  generateSymmetricKey,
  importSymmetricKey,
};

module.exports = functions;
