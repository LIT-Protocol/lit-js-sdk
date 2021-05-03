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
  checkAndSignAuthMessage
} from './utils/eth'

import { LIT_CHAINS, protobufs } from './lib/constants'
import { kFragKey } from './lib/utils'

import LitNodeClient from './utils/lit-node-client'

import {
  getUploadUrl,
  createTokenMetadata
} from './utils/cloudFunctions'

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
  getUploadUrl,
  createTokenMetadata,
  protobufs,
  kFragKey
}

export default functions
