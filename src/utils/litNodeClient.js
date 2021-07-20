
import uint8arrayFromString from 'uint8arrays/from-string'
import uint8arrayToString from 'uint8arrays/to-string'
import naclUtil from 'tweetnacl-util'

import { mostCommonString } from '../lib/utils'
import { wasmBlsSdkHelpers } from '../lib/bls-sdk'
import { hashAccessControlConditions, hashResourceId } from './crypto'

/**
 * A LIT node client.  Connects directly to the LIT nodes to store and retrieve encryption keys.  Only holders of an NFT that corresponds with a LIT may store and retrieve the keys.
 * @param {Object} config
 * @param {boolean} [config.alertWhenUnauthorized=true] Whether or not to show a JS alert() when a user tries to unlock a LIT but is unauthorized.  If you turn this off, you should create an event listener for the "lit-authFailure" event on the document, and show your own error to the user.
 * @param {number} [config.minNodeCount=8] The minimum number of nodes that must be connected for the LitNodeClient to be ready to use.
 */
export default class LitNodeClient {
  constructor(
    config = {
      alertWhenUnauthorized: true,
      minNodeCount: 2,
      bootstrapUrls: ['http://127.0.0.1:7470', 'http://127.0.0.1:7471', 'http://127.0.0.1:7472']
    }
  ) {
    this.config = config
    this.connectedNodes = new Set()
    this.serverKeys = {}
    this.ready = false
    this.subnetPubKey = null
    this.networkPubKey = null
    this.networkPubKeySet = null

    if (typeof window !== 'undefined' && window && window.localStorage) {
      let configOverride = window.localStorage.getItem('LitNodeClientConfig')
      if (configOverride) {
        configOverride = JSON.parse(configOverride)
      }
      this.config = { ...config, ...configOverride }
    }
  }

  /**
 * Retrieve the symmetric encryption key from the LIT nodes.  Note that this will only work if the current user meets the access control conditions specified when the data was encrypted.  That access control condition is typically that the user is a holder of the NFT that corresponds to this encrypted data.  This NFT token address and ID was specified when this LIT was created.
 * @param {Object} params
 * @param {string} params.tokenAddress The token address of the NFT that corresponds to this LIT.  This should be an ERC721 or ERC1155 token.
 * @param {string} params.tokenId The token ID of the NFT that corresponds to this LIT
* @param {string} params.chain The chain that the corresponding NFT lives on.  Currently "polygon" and "ethereum" are supported.
 * @param {AuthSig} params.authSig The authentication signature that proves that the user owns the crypto wallet address that should be an owner of the NFT that corresponds to this LIT.
 * @returns {Object} The symmetric encryption key that can be used to decrypt the locked content inside the LIT.  You should pass this key to the decryptZip function.
*/
  async getSignedToken({ accessControlConditions, chain, authSig, resourceId }) {
    // ask each node to decrypt the content
    const nodePromises = []
    for (const url of this.connectedNodes) {
      nodePromises.push(this.getSigningShare({ url, accessControlConditions, resourceId, authSig, chain }))
    }
    const signatureShares = await Promise.all(nodePromises)
    console.log('signatureShares', signatureShares)

    // sort the decryption shares by share index.  this is important when combining the shares.
    signatureShares.sort((a, b) => a.shareIndex - b.shareIndex)

    // combine the signature shares

    // // set signature shares bytes in wasm
    // signatureShares.forEach((s, idx) => {
    //   wasmExports.set_share_indexes(idx, s.shareIndex)
    //   const shareAsBytes = uint8arrayFromString(s.decryptionShare, 'base16')
    //   for (let i = 0; i < shareAsBytes.length; i++) {
    //     wasmExports.set_decryption_shares_byte(i, idx, shareAsBytes[i])
    //   }
    // })

    // // set the public key set bytes in wasm
    const pkSetAsBytes = uint8arrayFromString(this.networkPubKeySet, 'base16')
    // wasmBlsSdkHelpers.set_mc_bytes(pkSetAsBytes)

    // // set the ciphertext bytes
    // const ciphertextAsBytes = uint8arrayFromString(toDecrypt, 'base16')
    // for (let i = 0; i < ciphertextAsBytes.length; i++) {
    //   wasmExports.set_ct_byte(i, ciphertextAsBytes[i])
    // }

    const justSigShares = signatureShares.map(s => ({
      shareHex: s.signatureShare,
      shareIndex: s.shareIndex
    }))
    const signature = wasmBlsSdkHelpers.combine_signatures(pkSetAsBytes, justSigShares)
    console.log('signature is ', uint8arrayToString(signature, 'base16'))

    return signature
  }

  /**
   *
   *
  * Securely save the symmetric encryption key to the LIT nodes.
  * @param {Object} params
  * @param {Array} params.accessControlConditions The access control conditions under which this key will be able to be decrypted
  * @param {string} params.chain The chain that the corresponding NFT lives on.  Currently "polygon" and "ethereum" are supported.
  * @param {AuthSig} params.authSig The authentication signature that proves that the user owns the crypto wallet address that should be an owner of the NFT that corresponds to this LIT.
  * @param {string} params.symmetricKey The symmetric encryption key that was used to encrypt the locked content inside the LIT.  You should use zipAndEncryptString or zipAndEncryptFiles to get this encryption key.  This key will be split up using threshold encryption so that the LIT nodes cannot decrypt a given LIT.
  * @returns {Object} An object that gives the status of the operation, denoted via a boolean with the key "success"
  */
  async saveSigningCondition({ accessControlConditions, chain, authSig, resourceId }) {
    console.log('saveSigningCondition')

    // hash the resource id
    const hashOfResourceId = await hashResourceId(resourceId)
    const hashOfResourceIdStr = uint8arrayToString(new Uint8Array(hashOfResourceId), 'base16')

    // hash the access control conditions
    const hashOfConditions = await hashAccessControlConditions(accessControlConditions)
    const hashOfConditionsStr = uint8arrayToString(new Uint8Array(hashOfConditions), 'base16')
    // create access control conditions on lit nodes
    const nodePromises = []
    for (const url of this.connectedNodes) {
      nodePromises.push(this.storeSigningConditionWithNode({ url, key: hashOfResourceIdStr, val: hashOfConditionsStr, authSig, chain }))
    }
    await Promise.all(nodePromises)
  }

  /**
   * Retrieve the symmetric encryption key from the LIT nodes.  Note that this will only work if the current user meets the access control conditions specified when the data was encrypted.  That access control condition is typically that the user is a holder of the NFT that corresponds to this encrypted data.  This NFT token address and ID was specified when this LIT was created.
   * @param {Object} params
   * @param {string} params.tokenAddress The token address of the NFT that corresponds to this LIT.  This should be an ERC721 or ERC1155 token.
   * @param {string} params.tokenId The token ID of the NFT that corresponds to this LIT
  * @param {string} params.chain The chain that the corresponding NFT lives on.  Currently "polygon" and "ethereum" are supported.
   * @param {AuthSig} params.authSig The authentication signature that proves that the user owns the crypto wallet address that should be an owner of the NFT that corresponds to this LIT.
   * @returns {Object} The symmetric encryption key that can be used to decrypt the locked content inside the LIT.  You should pass this key to the decryptZip function.
  */
  async getEncryptionKey({ accessControlConditions, toDecrypt, chain, authSig }) {
    // ask each node to decrypt the content
    const nodePromises = []
    for (const url of this.connectedNodes) {
      nodePromises.push(this.getDecryptionShare({ url, accessControlConditions, toDecrypt, authSig, chain }))
    }
    const decryptionShares = await Promise.all(nodePromises)
    console.log('decryptionShares', decryptionShares)

    // sort the decryption shares by share index.  this is important when combining the shares.
    decryptionShares.sort((a, b) => a.shareIndex - b.shareIndex)

    // combine the decryption shares

    // set decryption shares bytes in wasm
    decryptionShares.forEach((s, idx) => {
      wasmExports.set_share_indexes(idx, s.shareIndex)
      const shareAsBytes = uint8arrayFromString(s.decryptionShare, 'base16')
      for (let i = 0; i < shareAsBytes.length; i++) {
        wasmExports.set_decryption_shares_byte(i, idx, shareAsBytes[i])
      }
    })

    // set the public key set bytes in wasm
    const pkSetAsBytes = uint8arrayFromString(this.networkPubKeySet, 'base16')
    wasmBlsSdkHelpers.set_mc_bytes(pkSetAsBytes)

    // set the ciphertext bytes
    const ciphertextAsBytes = uint8arrayFromString(toDecrypt, 'base16')
    for (let i = 0; i < ciphertextAsBytes.length; i++) {
      wasmExports.set_ct_byte(i, ciphertextAsBytes[i])
    }

    const decrypted = wasmBlsSdkHelpers.combine_decryption_shares(decryptionShares.length, pkSetAsBytes.length, ciphertextAsBytes.length)
    // console.log('decrypted is ', uint8arrayToString(decrypted, 'base16'))

    return decrypted
  }

  /**
  * Securely save the symmetric encryption key to the LIT nodes.
  * @param {Object} params
  * @param {Array} params.accessControlConditions The access control conditions under which this key will be able to be decrypted
  * @param {string} params.chain The chain that the corresponding NFT lives on.  Currently "polygon" and "ethereum" are supported.
  * @param {AuthSig} params.authSig The authentication signature that proves that the user owns the crypto wallet address that should be an owner of the NFT that corresponds to this LIT.
  * @param {string} params.symmetricKey The symmetric encryption key that was used to encrypt the locked content inside the LIT.  You should use zipAndEncryptString or zipAndEncryptFiles to get this encryption key.  This key will be split up using threshold encryption so that the LIT nodes cannot decrypt a given LIT.
  * @returns {Object} An object that gives the status of the operation, denoted via a boolean with the key "success"
  */
  async saveEncryptionKey({ accessControlConditions, chain, authSig, symmetricKey }) {
    console.log('saveEncryptionKey')

    // encrypt with network pubkey
    const encryptedKey = wasmBlsSdkHelpers.encrypt(uint8arrayFromString(this.subnetPubKey, 'base16'), symmetricKey)
    console.log('symmetric key encrypted with LIT network key: ', uint8arrayToString(encryptedKey, 'base16'))
    // hash the encrypted pubkey
    const hashOfKey = await crypto.subtle.digest('SHA-256', encryptedKey)
    const hashOfKeyStr = uint8arrayToString(new Uint8Array(hashOfKey), 'base16')

    // hash the access control conditions
    const hashOfConditions = await hashAccessControlConditions(accessControlConditions)
    const hashOfConditionsStr = uint8arrayToString(new Uint8Array(hashOfConditions), 'base16')
    // create access control conditions on lit nodes
    const nodePromises = []
    for (const url of this.connectedNodes) {
      nodePromises.push(this.storeEncryptionConditionWithNode({ url, key: hashOfKeyStr, val: hashOfConditionsStr, authSig, chain }))
    }
    await Promise.all(nodePromises)

    return encryptedKey
  }

  async storeSigningConditionWithNode({ url, key, val, authSig, chain }) {
    console.log('storeSigningConditionWithNode')
    const urlWithPath = `${url}/web/signing/store`
    const data = {
      key,
      val,
      authSig,
      chain
    }
    return await this.sendCommandToNode({ url: urlWithPath, data })
  }

  async storeEncryptionConditionWithNode({ url, key, val, authSig, chain }) {
    console.log('storeEncryptionConditionWithNode')
    const urlWithPath = `${url}/web/encryption/store`
    const data = {
      key,
      val,
      authSig,
      chain
    }
    return await this.sendCommandToNode({ url: urlWithPath, data })
  }

  async getSigningShare({ url, accessControlConditions, resourceId, authSig, chain }) {
    console.log('getSigningShare')
    const urlWithPath = `${url}/web/signing/retrieve`
    const data = {
      accessControlConditions,
      resourceId,
      authSig,
      chain
    }
    return await this.sendCommandToNode({ url: urlWithPath, data })
  }

  async getDecryptionShare({ url, accessControlConditions, toDecrypt, authSig, chain }) {
    console.log('getDecryptionShare')
    const urlWithPath = `${url}/web/encryption/retrieve`
    const data = {
      accessControlConditions,
      toDecrypt,
      authSig,
      chain
    }
    return await this.sendCommandToNode({ url: urlWithPath, data })
  }

  async handshakeWithSgx({ url }) {
    const urlWithPath = `${url}/web/handshake`
    console.debug(`handshakeWithSgx ${urlWithPath}`)
    const data = {
      clientPublicKey: 'test'
    }
    return await this.sendCommandToNode({ url: urlWithPath, data })
  }

  async sendCommandToNode({ url, data }) {
    console.log(`sendCommandToNode with url ${url} and data`, data)
    return await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(data)
    })
      .then(response => response.json())
      .then(data => {
        console.log('Success:', data)
        return data
      })
  }

  async connect() {
    // handshake with each node
    for (const url of this.config.bootstrapUrls) {
      this.handshakeWithSgx({ url })
        .then(resp => {
          this.connectedNodes.add(url)
          this.serverKeys[url] = {
            serverPubKey: resp.serverPublicKey,
            subnetPubKey: resp.subnetPublicKey,
            networkPubKey: resp.networkPublicKey,
            networkPubKeySet: resp.networkPublicKeySet
          }
        })
    }

    const interval = window.setInterval(() => {
      if (Object.keys(this.serverKeys).length >= this.config.minNodeCount) {
        clearInterval(interval)
        // pick the most common public keys for the subnet and network from the bunch, in case some evil node returned a bad key
        this.subnetPubKey = mostCommonString(Object.values(this.serverKeys).map(keysFromSingleNode => keysFromSingleNode.subnetPubKey))
        this.networkPubKey = mostCommonString(Object.values(this.serverKeys).map(keysFromSingleNode => keysFromSingleNode.networkPubKey))
        this.networkPubKeySet = mostCommonString(Object.values(this.serverKeys).map(keysFromSingleNode => keysFromSingleNode.networkPubKeySet))
        this.ready = true
        console.debug('lit is ready')
        document.dispatchEvent(new Event('lit-ready'))
      }
    }, 500)

    window.wasmBlsSdkHelpers = wasmBlsSdkHelpers // for debug
  }
}
