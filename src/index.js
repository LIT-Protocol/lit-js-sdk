import 'regenerator-runtime/runtime'

import {
  zipAndEncryptString,
  zipAndEncryptFiles,
  encryptZip,
  decryptZip,
  createHtmlLIT,
  toggleLock,
  unlockLitWithKey
} from './utils/lit'

import {
  connectWeb3,
  mintLIT,
  checkAndSignAuthMessage,
  getMerkleProof,
  findLITs,
  sendLIT
} from './utils/eth'

import {
  decryptWithPrivKey,
  encryptWithPubKey
} from './utils/crypto'

import {
  fileToDataUrl,
  injectViewerIFrame
} from './utils/browser'

import { LIT_CHAINS, protobufs } from './lib/constants'
import { kFragKey, printError } from './lib/utils'
import { init } from './lib/bls-sdk.js'

import LitNodeClient from './utils/litNodeClient'

import { litJsSdkLoadedInALIT } from './utils/init'

import {
  listenForChildFrameMessages,
  listenForFrameParentMessages,
  inIframe
} from './utils/frameComms'

if (typeof window !== 'undefined') {
  // only run this in browser
  if (inIframe()) {
    listenForFrameParentMessages()
  } else {
    listenForChildFrameMessages()
  }
}

init().then((exports) => {
  window.wasmExports = exports
})

const functions = {
  zipAndEncryptString,
  zipAndEncryptFiles,
  encryptZip,
  decryptZip,
  connectWeb3,
  checkAndSignAuthMessage,
  createHtmlLIT,
  mintLIT,
  toggleLock,
  LIT_CHAINS,
  LitNodeClient,
  protobufs,
  kFragKey,
  encryptWithPubKey,
  decryptWithPrivKey,
  fileToDataUrl,
  getMerkleProof,
  findLITs,
  sendLIT,
  litJsSdkLoadedInALIT,
  unlockLitWithKey,
  injectViewerIFrame,
  printError
}

export default functions
