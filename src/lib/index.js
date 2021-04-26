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
  LIT_CHAINS
}

export default functions
