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
  checkAndSignAuthMessage
} from './utils/eth'

import { LIT_CHAINS, protobufs } from './lib/constants'
import { kFragKey } from './lib/utils'

import LitNodeClient from './utils/lit-node-client'

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
  kFragKey
}

export default functions
