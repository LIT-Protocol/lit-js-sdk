
/**
 * @typedef {Object} LITChain
 * @property {string} contractAddress - The address of the token contract
 * @property {string} chainId - The chain ID of the chain that this token contract is deployed on.  Used for EVM chains.
 * @property {string} name - The human readable name of the chain
 */

/**
 * Pre-deployed token contracts that you may use for minting LITs.  These are ERC1155 contracts that let you mint any quantity of a given token.  Use the chain name as a key in this object.  Currently "ethereum", "polygon", "fantom", and "xdai" are supported.
 * @constant
 * @type {LITChain}
 * @default
*/
export const LIT_CHAINS = {
  polygon: {
    contractAddress: '0x7C7757a9675f06F3BE4618bB68732c4aB25D2e88',
    chainId: 137,
    name: 'Polygon',
    symbol: 'MATIC',
    decimals: 18,
    rpcUrls: ['https://rpc-mainnet.maticvigil.com/v1/96bf5fa6e03d272fbd09de48d03927b95633726c'],
    blockExplorerUrls: ['https://explorer.matic.network'],
    type: 'ERC1155'
  },
  fantom: {
    contractAddress: '0x5bD3Fe8Ab542f0AaBF7552FAAf376Fd8Aa9b3869',
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
    contractAddress: '0xDFc2Fd83dFfD0Dafb216F412aB3B18f2777406aF',
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
    contractAddress: '0xA54F7579fFb3F98bd8649fF02813F575f9b3d353',
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


export const NETWORK_PUB_KEY = "9971e835a1fe1a4d78e381eebbe0ddc84fde5119169db816900de796d10187f3c53d65c1202ac083d099a517f34a9b62"
