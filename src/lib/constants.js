
/**
 * @typedef {Object} LITChain
 * @property {string} contractAddress - The address of the token contract
 * @property {string} chainId - The chain ID of the chain that this token contract is deployed on.  Used for EVM chains.
 * @property {string} name - The human readable name of the chain
 */

/**
 * Pre-deployed token contracts that you may use for minting LITs.  These are ERC1155 contracts that let you mint any quantity of a given token.  Use the chain name as a key in this object.  Currently "polygon" and "ethereum" are supported.
 * @constant
 * @type {LITChain}
 * @default
*/
export const LIT_CHAINS = {
  polygon: {
    contractAddress: '0xb9A323711528D0c5a70df790929f4739f1cDd7fD',
    chainId: 137,
    name: 'Polygon',
    symbol: 'MATIC',
    decimals: 18,
    rpcUrls: ['https://floral-rough-flower.matic.quiknode.pro/a17b25f97cc396bb2b6aaf85a005f579bf93dc73/'],
    blockExplorerUrls: ['https://explorer.matic.network'],
    type: 'ERC1155',
    websocketUrl: 'wss://floral-rough-flower.matic.quiknode.pro/a17b25f97cc396bb2b6aaf85a005f579bf93dc73/'
  },
  fantom: {
    contractAddress: '0x3110c39b428221012934A7F617913b095BC1078C',
    chainId: 250,
    name: 'Fantom',
    symbol: 'FTM',
    decimals: 18,
    rpcUrls: ['https://rpcapi.fantom.network'],
    blockExplorerUrls: ['https://ftmscan.com'],
    type: 'ERC1155',
    websocketUrl: 'wss://wsapi.fantom.network'
  },
  xdai: {
    contractAddress: '0x3110c39b428221012934A7F617913b095BC1078C',
    chainId: 100,
    name: 'xDai',
    symbol: 'xDai',
    decimals: 18,
    rpcUrls: ['https://rpc.xdaichain.com'],
    blockExplorerUrls: [' https://blockscout.com/xdai/mainnet'],
    type: 'ERC1155',
    websocketUrl: 'wss://wsapi.fantom.network'
  },
  ethereum: {
    contractAddress: '0x55485885e82E25446DEC314Ccb810Bda06B9e01B',
    chainId: 1,
    name: 'Ethereum',
    symbol: 'ETH',
    decimals: 18,
    type: 'ERC1155',
    websocketUrl: 'wss://mainnet.infura.io/ws/v3/ddf1ca3700f34497bca2bf03607fde38'
  },
  kovan: {
    contractAddress: '0xA9b2180C2A479Ba9b263878C4d81AE4e0E717846',
    chainId: 42,
    name: 'Ethereum',
    symbol: 'ETH',
    decimals: 18,
    rpcUrls: ['https://kovan.infura.io/v3/ddf1ca3700f34497bca2bf03607fde38'],
    blockExplorerUrls: ['https://kovan.etherscan.io'],
    type: 'ERC20'
  }
}
