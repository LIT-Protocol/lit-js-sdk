import { Web3Provider } from "@ethersproject/providers";
export declare function encodeCallData({ abi, functionName, functionParams }: any): any;
export declare function decodeCallResult({ abi, functionName, data }: any): any;
export declare function connectWeb3({ chainId }?: {
    chainId?: number | undefined;
}): Promise<{
    web3: Web3Provider;
    account: string;
}>;
/**
 * Delete any saved AuthSigs from local storage.  Takes no params and returns nothing.  This will also clear out the WalletConnect cache in local storage.  We often run this function as a result of the user pressing a "Logout" button.
 */
export declare function disconnectWeb3(): Promise<void>;
export declare function checkAndSignEVMAuthMessage({ chain, resources, switchChain }: any): Promise<string | null | undefined>;
/**
 * Sign the auth message with the user's wallet, and store it in localStorage.  Called by checkAndSignAuthMessage if the user does not have a signature stored.
 * @param {Object} params
 * @param {Web3Provider} params.web3 An ethers.js Web3Provider instance
 * @param {string} params.account The account to sign the message with
 * @returns {AuthSig} The AuthSig created or retrieved
 */
export declare function signAndSaveAuthMessage({ web3, account, chainId, resources }: any): Promise<{
    sig: any;
    derivedVia: string;
    signedMessage: string;
    address: string;
}>;
/**
 * @typedef {Object} AuthSig
 * @property {string} sig - The actual hex-encoded signature
 * @property {string} derivedVia - The method used to derive the signature. Typically "web3.eth.personal.sign"
 * @property {string} signedMessage - The message that was signed
 * @property {string} address - The crypto wallet address that signed the message
 */
export declare function signMessage({ body, web3, account }: any): Promise<{
    signature: any;
    address: string;
}>;
export declare const signMessageAsync: (signer: any, address: any, message: any) => Promise<any>;
/**
 * This function mints a LIT using our pre-deployed token contracts.  You may use our contracts, or you may supply your own.  Our contracts are ERC1155 tokens on Polygon and Ethereum.  Using these contracts is the easiest way to get started.
 * @param {Object} params
 * @param {string} params.chain The chain to mint on.  "ethereum" and "polygon" are currently supported.
 * @param {number} params.quantity The number of tokens to mint.  Note that these will be fungible, so they will not have serial numbers.
 * @returns {Object} The txHash, tokenId, tokenAddress, mintingAddress, and authSig.
 */
export declare function mintLIT({ chain, quantity }: any): Promise<string | {
    txHash: any;
    tokenId: any;
    tokenAddress: any;
    mintingAddress: string;
    authSig: string | null | undefined;
    errorCode?: undefined;
} | {
    errorCode: string;
    txHash?: undefined;
    tokenId?: undefined;
    tokenAddress?: undefined;
    mintingAddress?: undefined;
    authSig?: undefined;
} | null | undefined>;
/**
 * Finds the tokens that the current user owns from the predeployed LIT contracts
 * @param {Object} params
 * @param {string} params.chain The chain that was minted on. "ethereum" and "polygon" are currently supported.
 * @param {number} params.accountAddress The account address to check
 * @returns {array} The token ids owned by the accountAddress
 */
export declare function findLITs(): Promise<{
    tokenIds: any;
    chain: string | undefined;
    errorCode?: undefined;
} | {
    errorCode: string;
    tokenIds?: undefined;
    chain?: undefined;
}>;
/**
 * Send a token to another account
 * @param {Object} params
 * @param {string} params.tokenMetadata The token metadata of the token to be transferred.  Should include tokenId, tokenAddress, and chain
 * @param {number} params.to The account address to send the token to
 * @returns {Object} Success or error
 */
export declare function sendLIT({ tokenMetadata, to }: any): Promise<{
    success: boolean;
    errorCode?: undefined;
} | {
    errorCode: string;
    success?: undefined;
}>;
/**
 * Get the number of decimal places in a token
 * @param {Object} params
 * @param {string} params.contractAddress The token contract address
 * @param {string} params.chain The chain on which the token is deployed
 * @returns {number} The number of decimal places in the token
 */
export declare function decimalPlaces({ contractAddress, chain }: any): Promise<any>;
/**
 * Lookup an eth address from a given ENS name
 * @param {Object} params
 * @param {string} params.chain The chain on which to resolve the name
 * @param {string} params.name The name to resolve
 * @returns {string} The resolved eth address
 */
export declare function lookupNameServiceAddress({ chain, name }: any): Promise<string | null>;
