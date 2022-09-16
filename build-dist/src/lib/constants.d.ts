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
export const LIT_CHAINS: LITEVMChain;
/**
 * Solana Chains supported by the LIT protocol.  Use the chain name as a key in this object.
 * @constant
 * @type {LITSVMChain}
 * @default
 */
export const LIT_SVM_CHAINS: LITSVMChain;
/**
 * Cosmos Chains supported by the LIT protocol.  Use the chain name as a key in this object.
 * @constant
 * @type {LITCosmosChain}
 * @default
 */
export const LIT_COSMOS_CHAINS: LITCosmosChain;
/**
 * All Chains supported by the LIT protocol.  Use the chain name as a key in this object.
 * @constant
 * @type {LITChain}
 * @default
 */
export const ALL_LIT_CHAINS: LITChain;
export const NETWORK_PUB_KEY: "9971e835a1fe1a4d78e381eebbe0ddc84fde5119169db816900de796d10187f3c53d65c1202ac083d099a517f34a9b62";
export const LIT_AUTH_SIG_CHAIN_KEYS: string[];
export type LITChain = {
    /**
     * - Either EVM for an Ethereum compatible chain or SVM for a Solana compatible chain
     */
    vmType: string;
    /**
     * - The human readable name of the chain
     */
    name: string;
};
export type LITEVMChain = {
    /**
     * - The address of the token contract for the optional predeployed ERC1155 contract.  Only present on EVM chains.
     */
    contractAddress: string;
    /**
     * - The chain ID of the chain that this token contract is deployed on.  Used for EVM chains.
     */
    chainId: string;
    /**
     * - The human readable name of the chain
     */
    name: string;
};
export type LITSVMChain = {
    /**
     * - The human readable name of the chain
     */
    name: string;
};
export type LITCosmosChain = {
    /**
     * - The human readable name of the chain
     */
    name: string;
};
