// import 'babel-polyfill'
import Libp2p from 'libp2p'
import Websockets from 'libp2p-websockets'
import WebRTCDirect from '@lit-protocol/libp2p-webrtc-direct'
import { NOISE } from 'libp2p-noise'
import { FaultTolerance } from 'libp2p/src/transport-manager'
import Mplex from 'libp2p-mplex'
import KadDHT from 'libp2p-kad-dht'
import PeerId from 'peer-id'
import Bootstrap from 'libp2p-bootstrap'
import pipe from 'it-pipe'
import CID from 'cids'
import secrets from 'secrets.js-lit'
import uint8arrayFromString from 'uint8arrays/from-string'
import uint8arrayToString from 'uint8arrays/to-string'
import all from 'it-all'
import naclUtil from 'tweetnacl-util'

import { mostCommonString } from '../lib/utils'
import { encryptWithPubKey, decryptWithPrivKey } from './crypto'

/**
 * A LIT node client.  Connects directly to the LIT nodes to store and retrieve encryption keys.  Only holders of an NFT that corresponds with a LIT may store and retrieve the keys.
 * @param {Object} config
 * @param {boolean} [config.alertWhenUnauthorized=true] Whether or not to show a JS alert() when a user tries to unlock a LIT but is unauthorized.  If you turn this off, you should create an event listener for the "lit-authFailure" event on the document, and show your own error to the user.
 * @param {number} [config.minNodeCount=8] The minimum number of nodes that must be connected for the LitNodeClient to be ready to use.
 */
export default class LitNodeClient {
  constructor (
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

    if (typeof window !== 'undefined' && window && window.localStorage) {
      let configOverride = window.localStorage.getItem('LitNodeClientConfig')
      if (configOverride) {
        configOverride = JSON.parse(configOverride)
      }
      this.config = { ...config, ...configOverride }
    }
  }

  /**
   * Retrieve the symmetric encryption key from the LIT nodes.  Note that this will only work if the current user is a holder of the NFT that corresponds to this LIT.  This NFT token address and ID was specified when this LIT was created.
   * @param {Object} params
   * @param {string} params.tokenAddress The token address of the NFT that corresponds to this LIT.  This should be an ERC721 or ERC1155 token.
   * @param {string} params.tokenId The token ID of the NFT that corresponds to this LIT
  * @param {string} params.chain The chain that the corresponding NFT lives on.  Currently "polygon" and "ethereum" are supported.
   * @param {AuthSig} params.authSig The authentication signature that proves that the user owns the crypto wallet address that should be an owner of the NFT that corresponds to this LIT.
   * @returns {Object} The symmetric encryption key that can be used to decrypt the locked content inside the LIT.  You should pass this key to the decryptZip function.
  */
  async getEncryptionKey ({ accessControlConditions, chain, authSig }) {
    // ask each node to decrypt the content

    // combine the decryption shares

  }

  /**
 * Securely save the symmetric encryption key to the LIT nodes.
 * @param {Object} params
 * @param {string} params.tokenAddress The token address of the NFT that corresponds to this LIT.  This should be an ERC721 or ERC1155 token.
 * @param {string} params.tokenId The token ID of the NFT that corresponds to this LIT
 * @param {string} params.chain The chain that the corresponding NFT lives on.  Currently "polygon" and "ethereum" are supported.
 * @param {AuthSig} params.authSig The authentication signature that proves that the user owns the crypto wallet address that should be an owner of the NFT that corresponds to this LIT.
 * @param {string} params.symmetricKey The symmetric encryption key that was used to encrypt the locked content inside the LIT.  You should use zipAndEncryptString or zipAndEncryptFiles to get this encryption key.  This key will be split up using threshold encryption so that the LIT nodes cannot decrypt a given LIT.
 * @returns {Object} An object that gives the status of the operation, denoted via a boolean with the key "success"
 */
  async saveEncryptionKey ({ accessControlConditions, chain, authSig, symmetricKey }) {
    // encrypt with network pubkey

    // hash the encrypted pubkey

    // create access control conditions on lit nodes
  }

  async getEncryptionKeyDecryptionShares ({ accessControlConditions, authSig, chain }) {

  }

  async storeDataWithNode ({ peerId, accessControlConditions, fragmentNumber, val, authSig, chain }) {

  }

  async getDataFromNode ({ peerId, accessControlConditions, authSig, chain }) {

  }

  async handshakeWithSgx ({ url }) {
    console.debug(`handshakeWithSgx ${url}`)
    const data = {
      client_public_key: 'test'
    }
    return await this.sendCommandToNode({ url, data })
  }

  async sendCommandToNode ({ url, data }) {

  }

  async connect () {
    // handshake with each node
    for (const url of this.bootstrapUrls) {
      this.handshakeWithSgx(url)
        .then(resp => {
          this.connectedNodes.add(url)
          this.serverKeys[url] = {
            serverPubKey: resp.server_public_key,
            subnetPubKey: resp.subnet_public_key,
            networkPubKey: resp.network_public_key
          }
        })
    }

    const interval = window.setInterval(() => {
      if (Object.keys(this.serverKeys).length >= this.config.minNodeCount) {
        clearInterval(interval)
        // pick the most common public keys for the subnet and network from the bunch, in case some evil node returned a bad key
        this.subnetPubKey = mostCommonString(Object.values(this.serverKeys).map(keysFromSingleNode => keysFromSingleNode.subnetPubKey))
        this.networkPubKey = mostCommonString(Object.values(this.serverKeys).map(keysFromSingleNode => keysFromSingleNode.networkPubKey))
        this.ready = true
        console.debug('lit is ready')
        document.dispatchEvent(new Event('lit-ready'))
      }
    }, 500)
  }
}
