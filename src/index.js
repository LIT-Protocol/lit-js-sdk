import "regenerator-runtime/runtime";

import {
  zipAndEncryptString,
  zipAndEncryptFiles,
  encryptZip,
  decryptZip,
  createHtmlLIT,
  toggleLock,
  unlockLitWithKey,
  verifyJwt,
  encryptFileAndZipWithMetadata,
  decryptZipFileWithMetadata,
  humanizeAccessControlConditions,
  getTokenList,
} from "./utils/lit";

import {
  connectWeb3,
  disconnectWeb3,
  mintLIT,
  checkAndSignAuthMessage,
  findLITs,
  sendLIT,
  decimalPlaces,
  lookupNameServiceAddress,
  encodeCallData,
  decodeCallResult,
} from "./utils/eth";

import {
  decryptWithPrivKey,
  encryptWithPubKey,
  canonicalAccessControlConditionFormatter,
  hashAccessControlConditions,
} from "./utils/crypto";

import {
  fileToDataUrl,
  injectViewerIFrame,
  downloadFile,
} from "./utils/browser";

import { LIT_CHAINS } from "./lib/constants";
import { printError } from "./lib/utils";
import { initWasmBlsSdk } from "./lib/bls-sdk.js";

import LitNodeClient from "./utils/litNodeClient";

import { litJsSdkLoadedInALIT } from "./utils/init";

import {
  listenForChildFrameMessages,
  listenForFrameParentMessages,
  inIframe,
} from "./utils/frameComms";

import { version } from "./version";

if (typeof window !== "undefined") {
  // only run this in browser
  if (inIframe()) {
    listenForFrameParentMessages();
  } else {
    listenForChildFrameMessages();
  }
} else {
  global.window = {};
}

initWasmBlsSdk().then((exports) => {
  // console.log('wtf, window? ', typeof window !== 'undefined')
  window.wasmExports = exports;
});

const functions = {
  zipAndEncryptString,
  zipAndEncryptFiles,
  encryptZip,
  decryptZip,
  connectWeb3,
  disconnectWeb3,
  checkAndSignAuthMessage,
  createHtmlLIT,
  mintLIT,
  toggleLock,
  LIT_CHAINS,
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
  verifyJwt,
  encryptFileAndZipWithMetadata,
  hashAccessControlConditions,
  decryptZipFileWithMetadata,
  downloadFile,
  decimalPlaces,
  humanizeAccessControlConditions,
  lookupNameServiceAddress,
  getTokenList,
  version,
  encodeCallData,
  decodeCallResult,
};

module.exports = functions;
