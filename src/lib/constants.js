/**
 * @typedef {Object} LITChain
 * @property {string} contractAddress - The address of the token contract for the optional predeployed ERC1155 contract
 * @property {string} chainId - The chain ID of the chain that this token contract is deployed on.  Used for EVM chains.
 * @property {string} name - The human readable name of the chain
 */

/**
 * Chains supported by the LIT protocol.  Each chain includes an optional pre-deployed token contract that you may use for minting LITs.  These are ERC1155 contracts that let you mint any quantity of a given token.  Use the chain name as a key in this object.
 * @constant
 * @type {LITChain}
 * @default
 */
export const LIT_CHAINS = {
  ethereum: {
    contractAddress: "0xA54F7579fFb3F98bd8649fF02813F575f9b3d353",
    chainId: 1,
    name: "Ethereum",
    symbol: "ETH",
    decimals: 18,
    type: "ERC1155",
    rpcUrls: ["https://api.mycryptoapi.com/eth"],
    blockExplorerUrls: ["https://etherscan.io"],
  },
  polygon: {
    contractAddress: "0x7C7757a9675f06F3BE4618bB68732c4aB25D2e88",
    chainId: 137,
    name: "Polygon",
    symbol: "MATIC",
    decimals: 18,
    rpcUrls: ["https://polygon-rpc.com"],
    blockExplorerUrls: ["https://explorer.matic.network"],
    type: "ERC1155",
  },
  fantom: {
    contractAddress: "0x5bD3Fe8Ab542f0AaBF7552FAAf376Fd8Aa9b3869",
    chainId: 250,
    name: "Fantom",
    symbol: "FTM",
    decimals: 18,
    rpcUrls: ["https://rpcapi.fantom.network"],
    blockExplorerUrls: ["https://ftmscan.com"],
    type: "ERC1155",
  },
  xdai: {
    contractAddress: "0xDFc2Fd83dFfD0Dafb216F412aB3B18f2777406aF",
    chainId: 100,
    name: "xDai",
    symbol: "xDai",
    decimals: 18,
    rpcUrls: ["https://rpc.xdaichain.com"],
    blockExplorerUrls: [" https://blockscout.com/xdai/mainnet"],
    type: "ERC1155",
  },
  bsc: {
    contractAddress: "0xc716950e5DEae248160109F562e1C9bF8E0CA25B",
    chainId: 56,
    name: "Binance Smart Chain",
    symbol: "BNB",
    decimals: 18,
    rpcUrls: ["https://bsc-dataseed.binance.org/"],
    blockExplorerUrls: [" https://bscscan.com/"],
    type: "ERC1155",
  },
  arbitrum: {
    contractAddress: "0xc716950e5DEae248160109F562e1C9bF8E0CA25B",
    chainId: 42161,
    name: "Arbitrum",
    symbol: "AETH",
    decimals: 18,
    type: "ERC1155",
    rpcUrls: ["https://arb1.arbitrum.io/rpc"],
    blockExplorerUrls: ["https://arbiscan.io/"],
  },
  harmony: {
    contractAddress: "0xBB118507E802D17ECDD4343797066dDc13Cde7C6",
    chainId: 1666600000,
    name: "Harmony",
    symbol: "ONE",
    decimals: 18,
    type: "ERC1155",
    rpcUrls: ["https://api.harmony.one"],
    blockExplorerUrls: ["https://explorer.harmony.one/"],
  },
  kovan: {
    contractAddress: "0x9dB60Db3Dd9311861D87D33B0463AaD9fB4bb0E6",
    chainId: 42,
    name: "Kovan",
    symbol: "ETH",
    decimals: 18,
    rpcUrls: ["https://kovan.infura.io/v3/ddf1ca3700f34497bca2bf03607fde38"],
    blockExplorerUrls: ["https://kovan.etherscan.io"],
    type: "ERC1155",
  },
  mumbai: {
    contractAddress: "0xc716950e5DEae248160109F562e1C9bF8E0CA25B",
    chainId: 80001,
    name: "Mumbai",
    symbol: "MATIC",
    decimals: 18,
    rpcUrls: [
      "https://rpc-mumbai.maticvigil.com/v1/96bf5fa6e03d272fbd09de48d03927b95633726c",
    ],
    blockExplorerUrls: ["https://mumbai.polygonscan.com"],
    type: "ERC1155",
  },
  goerli: {
    contractAddress: "0xc716950e5DEae248160109F562e1C9bF8E0CA25B",
    chainId: 5,
    name: "Goerli",
    symbol: "ETH",
    decimals: 18,
    rpcUrls: ["https://goerli.infura.io/v3/96dffb3d8c084dec952c61bd6230af34"],
    blockExplorerUrls: ["https://goerli.etherscan.io"],
    type: "ERC1155",
  },
  ropsten: {
    contractAddress: "0x61544f0AE85f8fed6Eb315c406644eb58e15A1E7",
    chainId: 3,
    name: "Ropsten",
    symbol: "ETH",
    decimals: 18,
    rpcUrls: ["https://ropsten.infura.io/v3/96dffb3d8c084dec952c61bd6230af34"],
    blockExplorerUrls: ["https://ropsten.etherscan.io"],
    type: "ERC1155",
  },
  rinkeby: {
    contractAddress: "0xc716950e5deae248160109f562e1c9bf8e0ca25b",
    chainId: 4,
    name: "Rinkeby",
    symbol: "ETH",
    decimals: 18,
    rpcUrls: ["https://rinkeby.infura.io/v3/96dffb3d8c084dec952c61bd6230af34"],
    blockExplorerUrls: ["https://rinkeby.etherscan.io"],
    type: "ERC1155",
  },
};

export const NETWORK_PUB_KEY =
  "9971e835a1fe1a4d78e381eebbe0ddc84fde5119169db816900de796d10187f3c53d65c1202ac083d099a517f34a9b62";
