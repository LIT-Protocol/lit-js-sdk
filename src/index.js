import {
  zipAndEncryptString,
  zipAndEncryptFiles,
  encryptZip,
  decryptZip,
  createHtmlLIT,
  toggleLock
} from './utils/lit'

import {
  checkAndDeriveKeypair,
  connectWeb3,
  mintLIT,
  LIT_CHAINS
} from './utils/eth'

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
  checkAndDeriveKeypair,
  connectWeb3,
  createHtmlLIT,
  mintLIT,
  toggleLock,
  LIT_CHAINS,
  LitNodeClient,
  getUploadUrl,
  createTokenMetadata
}

export default functions
