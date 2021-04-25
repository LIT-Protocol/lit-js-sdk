import {
  zipAndEncryptString,
  zipAndEncryptFiles,
  encryptZip,
  decryptZip
} from './utils/lit'

import {
  checkAndDeriveKeypair,
  connectWeb3
} from './utils/eth'

const functions = {
  zipAndEncryptString,
  zipAndEncryptFiles,
  encryptZip,
  decryptZip,
  checkAndDeriveKeypair,
  connectWeb3
}

export default functions
