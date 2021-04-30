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

export default class LitNodeClient {
  constructor (config) {
    this.libp2p = null
    this.connectedNodes = {}
  }

  async saveEncryptionKey ({ contractAddress, tokenId, symmetricKey }) {
    const nodeKeys = Object.keys(this.connectedNodes)
    // split up into nodeKeys.length fragments
  }

  async storeData ({ peerId, key, val }) {
    // const stream = await this.getStream(peerId)
    const hashed = multihashing(Buffer.from('1'), 'sha2-256')
    const cid = new CID(hashed)
    const msg = JSON.stringify({ cmd: 'set', key: cid.toString(), val })
    const node = this.connectedNodes[peerId]
    node.send(msg)
  }

  // async getStream (peerId) {
  //   const conn = this.libp2p.connectionManager.get(peerId)
  //   if (!conn) {
  //     console.error('trying to store data but no connection to ' + peerId.toB58String())
  //     return
  //   }
  //   console.log('streams: ')
  // }

  dataReceived ({ peerId, msg }) {
    console.log(`dataReceived from ${peerId.toB58String()}: ${msg}`)
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
      console.debug(`Connected to ${connection.remotePeer.toB58String()}`)
      const { stream } = await connection.newStream(['/lit/1.0.0'])
      // write data
      const p = pushable()
      pipe(
        p,
        lp.encode(),
        stream.sink
      )
      this.connectedNodes[connection.remotePeer.toB58String()] = {
        send: p.push
      }

      // pipe(
      //   stream.source,
      //   lp.decode(),
      //   async (source) => {
      //     for await (const msg of source) {
      //       // console.log(`Peer ${connection.remotePeer.toB58String()} responded with ${msg}`)
      //       this.dataReceived({ peerId: connection.remotePeer, msg })
      //     }
      //   }
      // )

      // send some data
      // const dialed = await libp2p.dialProtocol(connection.remotePeer, '/lit/1.0.0')
      // // Write operation. Data sent as a buffer
      // pipe(
      //   p,
      //   lp.encode(),
      //   dialed.stream.sink
      // )
      // pipe(
      //   dialed.stream.source,
      //   lp.decode(),
      //   async (source) => {
      //     for await (const msg of source) {
      //       console.log(`Peer ${connection.remotePeer.toB58String()} responded with ${msg}`)
      //     }
      //   }
      // )
      // const hashed = multihashing(Buffer.from('1'), 'sha2-256')
      // const cid = new CID(hashed)
      // const msg = JSON.stringify({ cmd: 'set', key: cid.toString(), val: 'woof' })
      // p.push(msg)
      // setTimeout(() => {
      //   const msg = JSON.stringify({ cmd: 'get', key: cid.toString() })
      //   p.push(msg)
      // }, 3000)
    })

    // Listen for peers disconnecting
    this.libp2p.connectionManager.on('peer:disconnect', (connection) => {
      console.debug(`Disconnected from ${connection.remotePeer.toB58String()}`)
    })

    await this.libp2p.start()
    console.debug(`libp2p id is ${this.libp2p.peerId.toB58String()}`)
    this.libp2p.multiaddrs.forEach((ma) => console.debug(`${ma.toString()}/p2p/${this.libp2p.peerId.toB58String()}`))

    // Export libp2p to the window so you can play with the API
    window.libp2p = this.libp2p
    // const hashed = multihashing(Buffer.from('1'), 'sha2-256')
    // window.cid = new CID(hashed)

    // const node1PeerId = PeerId.createFromB58String('QmXQtURimWjx8ihhWp1jjMv3rnv8xzq1qwY6KSzMr8dSGL')
    // const ma = multiaddr('/ip4/127.0.0.1/tcp/9092/ws/p2p')
    // libp2p.peerStore.addressBook.set(node1PeerId, [ma])
  }
}
