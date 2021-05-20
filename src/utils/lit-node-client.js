// import 'babel-polyfill'
import Libp2p from 'libp2p'
import Websockets from 'libp2p-websockets'
import WebRTCDirect from '@lit-protocol/libp2p-webrtc-direct'
import { NOISE } from 'libp2p-noise'
import Mplex from 'libp2p-mplex'
import KadDHT from 'libp2p-kad-dht'
import PeerId from 'peer-id'
import { multiaddr } from 'multiaddr'
import Bootstrap from 'libp2p-bootstrap'
import pipe from 'it-pipe'
import lp from 'it-length-prefixed'
import multihashing from 'multihashing'
import CID from 'cids'
import pushable from 'it-pushable'
import secrets from 'secrets.js-lit'
import uint8arrayFromString from 'uint8arrays/from-string'
import uint8arrayToString from 'uint8arrays/to-string'
import all from 'it-all'
import naclUtil from 'tweetnacl-util'

import { protobufs } from '../lib/constants'
import { kFragKey } from '../lib/utils'
import { encryptWithPubKey, decryptWithPrivKey } from './crypto'

const { Request, Response, StoreKeyFragmentResponse, GetKeyFragmentResponse } = protobufs

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
      minNodeCount: 8
    }
  ) {
    this.config = config
    this.libp2p = null
    this.connectedNodes = new Set()
    this.serverPubKeys = {}
    this.ready = false
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
  async getEncryptionKey ({ tokenAddress, tokenId, chain, authSig }) {
    const encryptedKFrags = await this.getEncryptionKeyFragments({ tokenAddress, tokenId, authSig, chain })
    if (encryptedKFrags.some(k => k === 'AUTH_FAILURE')) {
      if (this.config.alertWhenUnauthorized) {
        alert('You are not authorized to unlock to this LIT')
      }
      document.dispatchEvent(new Event('lit-authFailure'))
      return null
    }
    const commsKeypair = JSON.parse(localStorage.getItem('lit-comms-keypair'))
    // decrypt kfrags
    const kFrags = []
    for (let i = 0; i < encryptedKFrags.length; i++) {
      const decrypted = decryptWithPrivKey(JSON.parse(encryptedKFrags[i]), commsKeypair.secretKey)
      kFrags.push(decrypted)
    }
    const secret = secrets.combine(kFrags)
    const symmetricKey = Buffer.from(secret, 'hex').toString()
    return symmetricKey
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
  async saveEncryptionKey ({ tokenAddress, tokenId, chain, authSig, symmetricKey }) {
    // console.log(`saveEncryptionKey with tokenAddress ${tokenAddress} and tokenId ${tokenId} and symmetricKey ${symmetricKey} and authSig ${authSig} and chain ${chain}`)
    const nodes = Array.from(this.connectedNodes)
    // split up into nodes.length fragments
    const numShares = nodes.length
    const threshold = Math.floor(numShares / 2)
    // convert from base64 to hex
    const secret = Buffer.from(symmetricKey).toString('hex')
    console.debug(`splitting up into ${numShares} shares with a threshold of ${threshold}`)
    const kFrags = secrets.share(secret, numShares, threshold)
    if (kFrags.length !== nodes.length) {
      throw new Error(`kFrags.length (${kFrags.length}) !== nodes.length (${nodes.length})`)
    }
    const storagePromises = []
    const normalizedTokenAddress = tokenAddress.toLowerCase()
    for (let i = 0; i < nodes.length; i++) {
      const peerId = nodes[i]
      console.debug(`storing kFrag in node ${i + 1} of ${nodes.length}`)
      // encrypt kfrag with sgx key
      const serverPubKey = naclUtil.encodeBase64(this.serverPubKeys[peerId])
      const encryptedKFrag = JSON.stringify(encryptWithPubKey(serverPubKey, kFrags[i], 'x25519-xsalsa20-poly1305'))
      storagePromises.push(
        this.storeDataWithNode({
          peerId,
          tokenAddress: normalizedTokenAddress,
          tokenId,
          fragmentNumber: i,
          val: encryptedKFrag,
          authSig,
          chain
        })
      )
    }
    const resps = await Promise.all(storagePromises)
    if (resps.some(k => k === 'AUTH_FAILURE')) {
      if (this.config.alertWhenUnauthorized) {
        alert('You are not authorized to publish to this LIT')
      }
      document.dispatchEvent(new Event('lit-authFailure'))
      return { success: false }
    }
    console.log('all stored')
    return { success: true }
  }

  async getEncryptionKeyFragments ({ tokenAddress, tokenId, authSig, chain }) {
    // find providers
    const normalizedTokenAddress = tokenAddress.toLowerCase()
    const keyId = kFragKey({ tokenAddress, tokenId, chain })
    const cid = new CID(keyId)
    const providers = await all(this.libp2p.contentRouting.findProviders(cid, { timeout: 3000 }))
    console.log(`Found ${providers.length} providers`)
    const kFragPromises = []
    for (let i = 0; i < providers.length; i++) {
      const peerId = providers[i].id.toB58String()
      console.debug(`Getting ${keyId} from ${peerId}`)
      kFragPromises.push(this.getDataFromNode({
        peerId,
        tokenAddress: normalizedTokenAddress,
        tokenId,
        authSig,
        keyId,
        chain
      }))
    }
    const kFrags = await Promise.all(kFragPromises)
    return kFrags
  }

  async storeDataWithNode ({ peerId, tokenAddress, tokenId, fragmentNumber, val, authSig, chain }) {
    console.debug(`storing data with node ${peerId} with tokenAddress ${tokenAddress} and tokenId ${tokenId}`)
    const data = Request.encode({
      type: Request.Type.STORE_KEY_FRAGMENT,
      storeKeyFragment: {
        fragmentValue: uint8arrayFromString(val),
        fragmentNumber: uint8arrayFromString(fragmentNumber)
      },
      authSig: uint8arrayFromString(JSON.stringify(authSig)),
      tokenParams: {
        tokenAddress: uint8arrayFromString(tokenAddress),
        tokenId: uint8arrayFromString(tokenId.toString()),
        chain: uint8arrayFromString(chain)
      }
    })
    return await this.sendCommandToPeer({ peerId, data })
  }

  async getDataFromNode ({ peerId, tokenAddress, tokenId, keyId, authSig, chain }) {
    console.debug(`getDataFromNode ${peerId} with keyId ${keyId}`)
    const commsKeypair = JSON.parse(localStorage.getItem('lit-comms-keypair'))
    const data = Request.encode({
      type: Request.Type.GET_KEY_FRAGMENT,
      getKeyFragment: {
        keyId: uint8arrayFromString(keyId)
      },
      authSig: uint8arrayFromString(JSON.stringify(authSig)),
      tokenParams: {
        tokenAddress: uint8arrayFromString(tokenAddress),
        tokenId: uint8arrayFromString(tokenId.toString()),
        chain: uint8arrayFromString(chain)
      },
      clientPubKey: naclUtil.decodeBase64(commsKeypair.publicKey)
    })
    return await this.sendCommandToPeer({ peerId, data })
  }

  async handshakeWithSgx ({ peerId }) {
    console.debug(`handshakeWithSgx ${peerId}`)
    const data = Request.encode({
      type: Request.Type.HANDSHAKE
      // TODO clientPubKey:
    })
    return await this.sendCommandToPeer({ peerId, data })
  }

  async sendCommandToPeer ({ peerId, data }) {
    const connection = this.libp2p.connectionManager.get(PeerId.createFromB58String(peerId))
    const { stream } = await connection.newStream(['/lit/1.0.0'])
    console.debug(`sendCommandToPeer ${peerId}`)
    let retVal = null
    await pipe(
      [data],
      stream,
      async (source) => {
        console.debug('in sendCommandToPeer callback')
        // seems like for await generators are broken in chrome for now, so pulling out the data manually.
        const { value, done } = await source.next()
        // console.debug('got value from source.next()', value)
        const resp = Response.decode(value.slice())
        if (resp.type === Response.Type.HANDSHAKE_RESPONSE) {
          // save pubkey
          this.serverPubKeys[peerId] = resp.serverPubKey
          console.log('handshake success for ' + peerId + ' - got server pub key ' + naclUtil.encodeBase64(resp.serverPubKey))
          retVal = true
        } else if (resp.type === Response.Type.STORE_KEY_FRAGMENT_RESPONSE) {
          if (resp.storeKeyFragmentResponse.result === StoreKeyFragmentResponse.Result.SUCCESS) {
            console.log('success storing key fragment')
            retVal = true
          } else if (resp.storeKeyFragmentResponse.result === StoreKeyFragmentResponse.Result.AUTH_FAILURE) {
            console.log('auth failure.  user doesnt own token')
            retVal = 'AUTH_FAILURE'
          } else {
            console.log('error storing key fragment: ')
            console.log(uint8arrayToString(resp.storeKeyFragmentResponse.errorMessage))
            retVal = false
          }
        } else if (resp.type === Response.Type.GET_KEY_FRAGMENT_RESPONSE) {
          if (resp.getKeyFragmentResponse.result === GetKeyFragmentResponse.Result.SUCCESS) {
            console.log('success getting key fragment')
            retVal = uint8arrayToString(resp.getKeyFragmentResponse.fragmentValue)
          } else if (resp.getKeyFragmentResponse.result === GetKeyFragmentResponse.Result.NOT_FOUND) {
            console.log('key fragment not found')
            retVal = false
          } else if (resp.getKeyFragmentResponse.result === GetKeyFragmentResponse.Result.AUTH_FAILURE) {
            console.log('auth failure.  user doesnt own token')
            retVal = 'AUTH_FAILURE'
          } else {
            console.log('unknown error getting key fragment')
            retVal = false
          }
        } else {
          console.log('unknown response type')
        }
      }
    )
    return retVal
  }

  async connect () {
    const hardcodedPeerId = '12D3KooWK1KtaAV5rWjbAmZcd62VYSmEz1k81jzr87JAcSS7rKdQ'
    // Create our libp2p node
    this.libp2p = await Libp2p.create({
      modules: {
        transport: [Websockets, WebRTCDirect],
        connEncryption: [NOISE],
        streamMuxer: [Mplex],
        dht: KadDHT,
        peerDiscovery: [Bootstrap]
      },
      config: {
        dht: {
          enabled: true
        },
        peerDiscovery: {
          [Bootstrap.tag]: {
            enabled: true,
            list: [`/dns4/node1.litgateway.com/tcp/9090/https/p2p-webrtc-direct/p2p/${hardcodedPeerId}`]
          }
        }
      }
    })

    // Listen for new peers
    this.libp2p.on('peer:discovery', (peerId) => {
      console.debug(`Found peer ${peerId.toB58String()}`)
    })

    // Listen for new connections to peers
    this.libp2p.connectionManager.on('peer:connect', async (connection) => {
      const peerId = connection.remotePeer.toB58String()
      console.debug(`Connected to ${peerId}`)
      if (this.connectedNodes.has(peerId)) {
        return
      }
      this.connectedNodes.add(peerId)
      // handshake.  wait a second for the connection to settle.
      setTimeout(async () => {
        await this.handshakeWithSgx({ peerId })
      }, 1000)
    })

    // Listen for peers disconnecting
    this.libp2p.connectionManager.on('peer:disconnect', (connection) => {
      const peerId = connection.remotePeer.toB58String()
      console.debug(`Disconnected from ${peerId}`)
      this.connectedNodes.delete(peerId)
    })

    await this.libp2p.start()
    console.debug(`libp2p id is ${this.libp2p.peerId.toB58String()}`)
    this.libp2p.multiaddrs.forEach((ma) => console.debug(`${ma.toString()}/p2p/${this.libp2p.peerId.toB58String()}`))

    const interval = window.setInterval(() => {
      if (Array.from(this.connectedNodes).length >= this.config.minNodeCount) {
        clearInterval(interval)
        this.ready = true
        console.debug('lit is ready')
        document.dispatchEvent(new Event('lit-ready'))
      }
    }, 1000)

    // Export libp2p to the window so you can play with the API
    window.libp2p = this.libp2p
    window.PeerId = PeerId
    // const hashed = multihashing(Buffer.from('1'), 'sha2-256')
    // window.cid = new CID(hashed)

    // const node1PeerId = PeerId.createFromB58String('QmXQtURimWjx8ihhWp1jjMv3rnv8xzq1qwY6KSzMr8dSGL')
    // const ma = multiaddr('/ip4/127.0.0.1/tcp/9092/ws/p2p')
    // libp2p.peerStore.addressBook.set(node1PeerId, [ma])
  }
}
