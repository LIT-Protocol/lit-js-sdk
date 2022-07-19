/**
 * @typedef {Object} LITChain
 * @property {string} vmType - Either EVM for an Ethereum compatible chain or SVM for a Solana compatible chain
 * @property {string} name - The human readable name of the chain
 */

/**
 * @typedef {Object} LITEVMChain
 * @property {string} contractAddress - The address of the token contract for the optional predeployed ERC1155 contract.  Only present on EVM chains.
 * @property {string} chainId - The chain ID of the chain that this token contract is deployed on.  Used for EVM chains.
 * @property {string} name - The human readable name of the chain
 */

/**
 * @typedef {Object} LITSVMChain
 * @property {string} name - The human readable name of the chain
 */

/**
 * @typedef {Object} LITCosmosChain
 * @property {string} name - The human readable name of the chain
 */

/**
 * EVM Chains supported by the LIT protocol.  Each chain includes an optional pre-deployed token contract that you may use for minting LITs.  These are ERC1155 contracts that let you mint any quantity of a given token.  Use the chain name as a key in this object.
 * @constant
 * @type {LITEVMChain}
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
    rpcUrls: [
      "https://eth-mainnet.alchemyapi.io/v2/EuGnkVlzVoEkzdg0lpCarhm8YHOxWVxE",
    ],
    blockExplorerUrls: ["https://etherscan.io"],
    vmType: "EVM",
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
    vmType: "EVM",
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
    vmType: "EVM",
  },
  xdai: {
    contractAddress: "0xDFc2Fd83dFfD0Dafb216F412aB3B18f2777406aF",
    chainId: 100,
    name: "xDai",
    symbol: "xDai",
    decimals: 18,
    rpcUrls: ["https://rpc.gnosischain.com"],
    blockExplorerUrls: [" https://blockscout.com/xdai/mainnet"],
    type: "ERC1155",
    vmType: "EVM",
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
    vmType: "EVM",
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
    vmType: "EVM",
  },
  avalanche: {
    contractAddress: "0xBB118507E802D17ECDD4343797066dDc13Cde7C6",
    chainId: 43114,
    name: "Avalanche",
    symbol: "AVAX",
    decimals: 18,
    type: "ERC1155",
    rpcUrls: ["https://api.avax.network/ext/bc/C/rpc"],
    blockExplorerUrls: ["https://snowtrace.io/"],
    vmType: "EVM",
  },
  fuji: {
    contractAddress: "0xc716950e5DEae248160109F562e1C9bF8E0CA25B",
    chainId: 43113,
    name: "Avalanche FUJI Testnet",
    symbol: "AVAX",
    decimals: 18,
    type: "ERC1155",
    rpcUrls: ["https://api.avax-test.network/ext/bc/C/rpc"],
    blockExplorerUrls: ["https://testnet.snowtrace.io/"],
    vmType: "EVM",
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
    vmType: "EVM",
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
    vmType: "EVM",
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
    vmType: "EVM",
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
    vmType: "EVM",
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
    vmType: "EVM",
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
    vmType: "EVM",
  },
  cronos: {
    contractAddress: "0xc716950e5DEae248160109F562e1C9bF8E0CA25B",
    chainId: 25,
    name: "Cronos",
    symbol: "CRO",
    decimals: 18,
    rpcUrls: ["https://evm-cronos.org"],
    blockExplorerUrls: ["https://cronos.org/explorer/"],
    type: "ERC1155",
    vmType: "EVM",
  },
  optimism: {
    contractAddress: "0xbF68B4c9aCbed79278465007f20a08Fa045281E0",
    chainId: 10,
    name: "Optimism",
    symbol: "ETH",
    decimals: 18,
    rpcUrls: ["https://mainnet.optimism.io"],
    blockExplorerUrls: ["https://optimistic.etherscan.io"],
    type: "ERC1155",
    vmType: "EVM",
  },
  celo: {
    contractAddress: "0xBB118507E802D17ECDD4343797066dDc13Cde7C6",
    chainId: 42220,
    name: "Celo",
    symbol: "CELO",
    decimals: 18,
    rpcUrls: ["https://forno.celo.org"],
    blockExplorerUrls: ["https://explorer.celo.org"],
    type: "ERC1155",
    vmType: "EVM",
  },
  aurora: {
    contractAddress: null,
    chainId: 1313161554,
    name: "Aurora",
    symbol: "ETH",
    decimals: 18,
    rpcUrls: ["https://mainnet.aurora.dev"],
    blockExplorerUrls: ["https://aurorascan.dev"],
    type: null,
    vmType: "EVM",
  },
  eluvio: {
    contractAddress: null,
    chainId: 955305,
    name: "Eluvio",
    symbol: "ELV",
    decimals: 18,
    rpcUrls: ["https://host-76-74-28-226.contentfabric.io/eth"],
    blockExplorerUrls: ["https://explorer.eluv.io"],
    type: null,
    vmType: "EVM",
  },
  alfajores: {
    contractAddress: null,
    chainId: 44787,
    name: "Alfajores",
    symbol: "CELO",
    decimals: 18,
    rpcUrls: ["https://alfajores-forno.celo-testnet.org"],
    blockExplorerUrls: ["https://alfajores-blockscout.celo-testnet.org"],
    type: null,
    vmType: "EVM",
  },
  xdc: {
    contractAddress: null,
    chainId: 50,
    name: "XDC Blockchain",
    symbol: "XDC",
    decimals: 18,
    rpcUrls: ["https://rpc.xinfin.network"],
    blockExplorerUrls: ["https://explorer.xinfin.network"],
    type: null,
    vmType: "EVM",
  },
  evmos: {
    contractAddress: null,
    chainId: 9001,
    name: "EVMOS",
    symbol: "EVMOS",
    decimals: 18,
    rpcUrls: ["https://eth.bd.evmos.org:8545"],
    blockExplorerUrls: ["https://evm.evmos.org"],
    type: null,
    vmType: "EVM",
  },
  evmosTestnet: {
    contractAddress: null,
    chainId: 9000,
    name: "EVMOS Testnet",
    symbol: "EVMOS",
    decimals: 18,
    rpcUrls: ["https://eth.bd.evmos.dev:8545"],
    blockExplorerUrls: ["https://evm.evmos.dev"],
    type: null,
    vmType: "EVM",
  },
};

/**
 * Solana Chains supported by the LIT protocol.  Use the chain name as a key in this object.
 * @constant
 * @type {LITSVMChain}
 * @default
 */
export const LIT_SVM_CHAINS = {
  solana: {
    name: "Solana",
    symbol: "SOL",
    decimals: 9,
    rpcUrls: ["https://api.mainnet-beta.solana.com"],
    blockExplorerUrls: ["https://explorer.solana.com/"],
    vmType: "SVM",
  },
  solanaDevnet: {
    name: "Solana Devnet",
    symbol: "SOL",
    decimals: 9,
    rpcUrls: ["https://api.devnet.solana.com"],
    blockExplorerUrls: ["https://explorer.solana.com/"],
    vmType: "SVM",
  },
  solanaTestnet: {
    name: "Solana Testnet",
    symbol: "SOL",
    decimals: 9,
    rpcUrls: ["https://api.testnet.solana.com"],
    blockExplorerUrls: ["https://explorer.solana.com/"],
    vmType: "SVM",
  },
};

/**
 * Cosmos Chains supported by the LIT protocol.  Use the chain name as a key in this object.
 * @constant
 * @type {LITCosmosChain}
 * @default
 */
export const LIT_COSMOS_CHAINS = {
  cosmos: {
    name: "Cosmos",
    symbol: "ATOM",
    decimals: 6,
    chainId: "cosmoshub-4",
    rpcUrls: ["https://lcd-cosmoshub.keplr.app"],
    blockExplorerUrls: ["https://atomscan.com/"],
    vmType: "CVM",
  },
  kyve: {
    name: "Kyve",
    symbol: "KYVE",
    decimals: 6,
    chainId: "korellia",
    rpcUrls: ["https://api.korellia.kyve.network"],
    blockExplorerUrls: ["https://explorer.kyve.network/"],
    vmType: "CVM",
  },
  evmosCosmos: {
    name: "EVMOS Cosmos",
    symbol: "EVMOS",
    decimals: 18,
    chainId: "evmos_9001-2",
    rpcUrls: ["https://rest.bd.evmos.org:1317"],
    blockExplorerUrls: ["https://evmos.bigdipper.live"],
    vmType: "CVM",
  },
  evmosCosmosTestnet: {
    name: "Evmos Cosmos Testnet",
    symbol: "EVMOS",
    decimals: 18,
    chainId: "evmos_9000-4",
    rpcUrls: ["https://rest.bd.evmos.dev:1317"],
    blockExplorerUrls: ["https://testnet.bigdipper.live"],
    vmType: "CVM",
  },
};

/**
 * All Chains supported by the LIT protocol.  Use the chain name as a key in this object.
 * @constant
 * @type {LITChain}
 * @default
 */
export const ALL_LIT_CHAINS = {
  ...LIT_CHAINS,
  ...LIT_SVM_CHAINS,
  ...LIT_COSMOS_CHAINS,
};

export const NETWORK_PUB_KEY =
  "9971e835a1fe1a4d78e381eebbe0ddc84fde5119169db816900de796d10187f3c53d65c1202ac083d099a517f34a9b62";

export const LIT_NETWORKS = {
  jalapeno: [
    "https://node2.litgateway.com:7370",
    "https://node2.litgateway.com:7371",
    "https://node2.litgateway.com:7372",
    "https://node2.litgateway.com:7373",
    "https://node2.litgateway.com:7374",
    "https://node2.litgateway.com:7375",
    "https://node2.litgateway.com:7376",
    "https://node2.litgateway.com:7377",
    "https://node2.litgateway.com:7378",
    "https://node2.litgateway.com:7379",
  ],
  serrano: [
    "https://serrano.litgateway.com:7370",
    "https://serrano.litgateway.com:7371",
    "https://serrano.litgateway.com:7372",
    "https://serrano.litgateway.com:7373",
    "https://serrano.litgateway.com:7374",
    "https://serrano.litgateway.com:7375",
    "https://serrano.litgateway.com:7376",
    "https://serrano.litgateway.com:7377",
    "https://serrano.litgateway.com:7378",
    "https://serrano.litgateway.com:7379",
  ],
  localhost: [
    "http://localhost:7470",
    "http://localhost:7471",
    "http://localhost:7472",
    "http://localhost:7473",
    "http://localhost:7474",
    "http://localhost:7475",
    "http://localhost:7476",
    "http://localhost:7477",
    "http://localhost:7478",
    "http://localhost:7479",
  ],
};

// you can either pass a "chain" param to lit functions, which it uses to tell which network your sig came from.
// or, you can pass a authSig that has and of these keys in it to tell which network your sig came from.
export const LIT_AUTH_SIG_CHAIN_KEYS = ["ethereum", "solana", "cosmos", "kyve"];
