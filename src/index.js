import 'regenerator-runtime/runtime'

import {
  zipAndEncryptString,
  zipAndEncryptFiles,
  encryptZip,
  decryptZip,
  createHtmlLIT,
  toggleLock
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

import { fileToDataUrl } from './utils/browser'

import { LIT_CHAINS, protobufs } from './lib/constants'
import { kFragKey } from './lib/utils'

import LitNodeClient from './utils/lit-node-client'

import {
  listenForChildFrameMessages,
  listenForFrameParentMessages,
  sendMessageToFrameParent,
  inIframe
} from './utils/frameComms'

if (inIframe()) {
  listenForFrameParentMessages()
} else {
  listenForChildFrameMessages()
}

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
  sendMessageToFrameParent
}

export default functions
