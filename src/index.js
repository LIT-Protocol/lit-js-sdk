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

import uint8arrayFromString from "uint8arrays/from-string";
import uint8arrayToString from "uint8arrays/to-string";

import {
  encryptString,
  decryptString,
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
  signAndSaveAuthMessage,
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

import { version } from "./version";

initWasmBlsSdk().then((exports) => {
  globalThis.wasmExports = exports;
  console.log("wasmExports loaded");
});

const functions = {
  encryptString,
  decryptString,
  zipAndEncryptString,
  zipAndEncryptFiles,
  encryptZip,
  decryptZip,
  connectWeb3,
  disconnectWeb3,
  checkAndSignAuthMessage,
  signAndSaveAuthMessage,
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
  uint8arrayFromString,
  uint8arrayToString,
};

module.exports = functions;
