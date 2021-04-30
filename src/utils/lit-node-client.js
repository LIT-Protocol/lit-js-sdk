// import 'babel-polyfill'
import Libp2p from 'libp2p'
import Websockets from 'libp2p-websockets'
import WebRTCDirect from 'libp2p-webrtc-direct'
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
import secrets from 'secrets.js-grempe'
import protons from 'protons'
import uint8arrayFromString from 'uint8arrays/from-string'
import uint8arrayToString from 'uint8arrays/to-string'

const { Request, Response, StoreKeyFragmentResponse } = protons(`
message Request {
  enum Type {
    GET_KEY_FRAGMENT = 0;
    STORE_KEY_FRAGMENT = 1;
  }
  required Type type = 1;
  optional GetKeyFragment getKeyFragment = 2;
  optional StoreKeyFragment storeKeyFragment = 3;
}
message Response {
  enum Type {
    GET_KEY_FRAGMENT_RESPONSE = 0;
    STORE_KEY_FRAGMENT_RESPONSE = 1;
  }
  required Type type = 1;
  optional GetKeyFragmentResponse getKeyFragmentResponse = 2;
  optional StoreKeyFragmentResponse storeKeyFragmentResponse = 3;
}
message GetKeyFragment {
  required bytes keyId = 1;
}
message GetKeyFragmentResponse {
  required bytes keyId = 1;
  required bytes fragmentValue = 2;
}
message StoreKeyFragment {
  required bytes keyId = 1;
  required bytes fragmentValue = 2;
}
message StoreKeyFragmentResponse {
  enum Result {
    SUCCESS = 0;
    ERROR = 1;
  }
  required Result result = 1;
  optional string errorMessage = 2;
}
`)

export default class LitNodeClient {
  constructor (config) {
    this.libp2p = null
    this.connectedNodes = new Set()
  }

  async saveEncryptionKey ({ contractAddress, tokenId, symmetricKey }) {
    const nodeKeys = Object.keys(this.connectedNodes)
    // split up into nodeKeys.length fragments
    const numShares = nodeKeys.length
    const threshold = Math.floor(numShares / 2)
    // convert from base64 to hex
    const secret = Buffer.from(symmetricKey, 'base64').toString('hex')
    const kFrags = secrets.share(secret, numShares, threshold)
    if (kFrags.length !== nodeKeys.length) {
      throw new Error(`kFrags.length (${kFrags.length}) !== nodeKeys.length (${nodeKeys.length})`)
    }
    const storagePromises = []
    const normalizedContractAddress = contractAddress.toLowerCase()
    const normalizedTokenid = tokenId.toString(16).padStart(64, '0') // to hex and padded for consistent length
    for (let i = 0; i < nodeKeys.length; i++) {
      const key = `${normalizedContractAddress}|${normalizedTokenid}|${i}`
      console.debug(`storing kFrag with key ${key} in node ${i + 1} of ${nodeKeys.length}`)
      storagePromises.push(
        this.storeDataWithNode({
          peerId: nodeKeys[i],
          key,
          val: kFrags[i]
        })
      )
    }
    await Promise.all(storagePromises)
    console.log('all stored')
    return { success: true }
  }

  async storeDataWithNode ({ peerId, key, val }) {
    const hashed = multihashing(Buffer.from(key), 'sha2-256')
    const cid = new CID(hashed)
    const msg = Request.encode({
      type: Request.Type.STORE_KEY_FRAGMENT,
      storeKeyFragment: {
        keyId: uint8arrayFromString(cid.toString()),
        fragmentValue: uint8arrayFromString(val)
      }
    })
    return await this.sendCommandToPeer(peerId, msg)
  }

  async getData ({ peerId, key }) {
    const hashed = multihashing(Buffer.from(key), 'sha2-256')
    const cid = new CID(hashed)
    const msg = JSON.stringify({ cmd: 'get', key: cid.toString() })
    return await this.sendCommandToPeer(peerId, msg)
  }

  async sendCommandToPeer (peerId, data) {
    const connection = this.libp2p.connectionManager.get(PeerId.createFromB58String(peerId))
    const { stream } = await connection.newStream(['/lit/1.0.0'])
    const response = []
    await pipe(
      [data],
      stream,
      async function (source) {
        const { value, done } = await source.next()
        const resp = Response.decode(value.slice())
        if (resp.type === Response.Type.STORE_KEY_FRAGMENT_RESPONSE) {
          if (resp.storeKeyFragmentResponse.result === StoreKeyFragmentResponse.Result.SUCCESS) {
            console.log('success storing key fragment')
          } else {
            console.log('error storing key fragment')
          }
        } else {
          console.log('unknown response type')
        }
      }
    )
    return response
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
            list: [`/ip4/127.0.0.1/tcp/9090/http/p2p-webrtc-direct/p2p/${hardcodedPeerId}`]
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
