
import nacl from 'tweetnacl'
import naclUtil from 'tweetnacl-util'

const SYMM_KEY_ALGO_PARAMS = {
  name: 'AES-CBC',
  length: 256
}

export function compareArrayBuffers (buf1, buf2) {
  if (buf1.byteLength !== buf2.byteLength) return false
  const dv1 = new Uint8Array(buf1)
  const dv2 = new Uint8Array(buf2)
  for (let i = 0; i !== buf1.byteLength; i++) {
    if (dv1[i] !== dv2[i]) return false
  }
  return true
}

export async function importSymmetricKey (jwkSymmKey) {
  const importedSymmKey = await crypto.subtle.importKey(
    'jwk',
    JSON.parse(jwkSymmKey),
    SYMM_KEY_ALGO_PARAMS,
    true,
    ['encrypt', 'decrypt']
  )
  return importedSymmKey
}
export async function generateSymmetricKey () {
  const symmKey = await crypto.subtle.generateKey(
    SYMM_KEY_ALGO_PARAMS,
    true,
    ['encrypt', 'decrypt']
  )
  return symmKey
}

export async function decryptWithSymmetricKey (
  encryptedBlob,
  symmKey
) {
  const recoveredIv = await encryptedBlob.slice(0, 16).arrayBuffer()
  const encryptedZipArrayBuffer = await encryptedBlob.slice(16).arrayBuffer()
  const decryptedZip = await crypto.subtle.decrypt(
    {
      name: 'AES-CBC',
      iv: recoveredIv
    },
    symmKey,
    encryptedZipArrayBuffer
  )
  return decryptedZip
}

// used this as an example
// https://github.com/infotechinc/symmetric-encryption-in-browser/blob/master/crypto.js
export async function encryptWithSymmetricKey (
  symmKey,
  data
) {
  // encrypt the zip with symmetric key
  const iv = window.crypto.getRandomValues(new Uint8Array(16))

  const encryptedZipData = await crypto.subtle.encrypt(
    {
      name: 'AES-CBC',
      iv
    },
    symmKey,
    data
  )
  const encryptedZipBlob = new Blob([iv, new Uint8Array(encryptedZipData)], { type: 'application/octet-stream' })
  return encryptedZipBlob
}

// borrowed from eth-sig-util from meatmask.
export function encryptWithPubkey (
  receiverPublicKey,
  data,
  version
) {
  switch (version) {
    case 'x25519-xsalsa20-poly1305': {
      // generate ephemeral keypair
      const ephemeralKeyPair = nacl.box.keyPair()

      // assemble encryption parameters - from string to UInt8
      let pubKeyUInt8Array
      try {
        pubKeyUInt8Array = naclUtil.decodeBase64(receiverPublicKey)
      } catch (err) {
        throw new Error('Bad public key')
      }

      const msgParamsUInt8Array = naclUtil.decodeUTF8(data)
      const nonce = nacl.randomBytes(nacl.box.nonceLength)

      // encrypt
      const encryptedMessage = nacl.box(
        msgParamsUInt8Array,
        nonce,
        pubKeyUInt8Array,
        ephemeralKeyPair.secretKey
      )

      // handle encrypted data
      const output = {
        version: 'x25519-xsalsa20-poly1305',
        nonce: naclUtil.encodeBase64(nonce),
        ephemPublicKey: naclUtil.encodeBase64(ephemeralKeyPair.publicKey),
        ciphertext: naclUtil.encodeBase64(encryptedMessage)
      }
      // return encrypted msg data
      return output
    }

    default:
      throw new Error('Encryption type/version not supported')
  }
}

// borrowed from eth-sig-util from meatmask.
export function decryptWithPrivkey (
  encryptedData,
  receiverPrivateKey
) {
  switch (encryptedData.version) {
    case 'x25519-xsalsa20-poly1305': {
      const recieverEncryptionPrivateKey = naclUtil.decodeBase64(receiverPrivateKey)

      // assemble decryption parameters
      const nonce = naclUtil.decodeBase64(encryptedData.nonce)
      const ciphertext = naclUtil.decodeBase64(encryptedData.ciphertext)
      const ephemPublicKey = naclUtil.decodeBase64(
        encryptedData.ephemPublicKey
      )

      // decrypt
      const decryptedMessage = nacl.box.open(
        ciphertext,
        nonce,
        ephemPublicKey,
        recieverEncryptionPrivateKey
      )

      // return decrypted msg data
      let output
      try {
        output = naclUtil.encodeUTF8(decryptedMessage)
      } catch (err) {
        throw new Error('Decryption failed.')
      }

      if (output) {
        return output
      }
      throw new Error('Decryption failed.')
    }

    default:
      throw new Error('Encryption type/version not supported.')
  }
}
