/**
 * @typedef {Object} AccessControlCondition
 * @property {string} contractAddress - The address of the contract that will be queried
 * @property {string} chain - The chain name of the chain that this contract is deployed on.  See LIT_CHAINS for currently supported chains.
 * @property {string} standardContractType - If the contract is an ERC20, ERC721, or ERC1155, please put that here
 * @property {string} method - The smart contract function to call
 * @property {Array} parameters - The parameters to use when calling the smart contract.  You can use the special ":userAddress" parameter which will be replaced with the requesting user's wallet address, verified via message signature
 * @property {Object} returnValueTest - An object containing two keys: "comparator" and "value".  The return value of the smart contract function will be compared against these.  For example, to check if someone holds an NFT, you could use "comparator: >" and "value: 0" which would check that a user has a token balance greater than zero.
 */
/**
 * @typedef {Object} EVMContractCondition
 * @property {string} contractAddress - The address of the contract that will be queried
 * @property {string} chain - The chain name of the chain that this contract is deployed on.  See LIT_CHAINS for currently supported chains.
 * @property {string} functionName - The smart contract function to call
 * @property {Array} functionParams - The parameters to use when calling the smart contract.  You can use the special ":userAddress" parameter which will be replaced with the requesting user's wallet address, verified via message signature
 * @property {Object} functionAbi - The ABI of the smart contract function to call.  This is used to encode the function parameters and decode the return value of the function.  Do not pass the entire contract ABI here.  Instead, find the function you want to call in the contract ABI and pass that function's ABI here.
 * @property {Object} returnValueTest - An object containing three keys: "key", "comparator" and "value".  The return value of the smart contract function will be compared against these.  For example, to check if someone holds an NFT, you could use "key": "", "comparator: >" and "value: 0" which would check that a user has a token balance greater than zero.  The "key" is used when the return value is a struct which contains multiple values and should be the name of the returned value from the function abi.  You must always pass "key" when using "returnValueTest", even if you pass an empty string for it, because the function only returns a single value.
 */
/**
 * @typedef {Object} SolRpcCondition
 * @property {string} method - The Solana RPC method to be called.  You can find a list here: https://docs.solana.com/developing/clients/jsonrpc-api
 * @property {Array} params - The parameters to use when making the RPC call.  You can use the special ":userAddress" parameter which will be replaced with the requesting user's wallet address, verified via message signature
 * @property {string} chain - The chain name of the chain that this contract is deployed on.  See ALL_LIT_CHAINS for currently supported chains.  On Solana, we support "solana" for mainnet, "solanaDevnet" for devnet and "solanaTestnet" for testnet.
 * @property {Object} returnValueTest - An object containing three keys: "key", "comparator" and "value".  The return value of the rpc call will be compared against these.  The "key" selector supports JSONPath syntax, so you can filter and iterate over the results.  For example, to check if someone holds an NFT with address 29G6GSKNGP8K6ATy65QrNZk4rNgsZX1sttvb5iLXWDcE, you could use "method": "GetTokenAccountsByOwner", "params": [":userAddress",{"programId":"TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"},{"encoding":"jsonParsed"}], "key": "$[?(@.account.data.parsed.info.mint == "29G6GSKNGP8K6ATy65QrNZk4rNgsZX1sttvb5iLXWDcE")].account.data.parsed.info.tokenAmount.amount", "comparator: >" and "value: 0" which would check that a user has a token balance greater than zero.  The "key" is used when the return value is an array or object which contains multiple values and should be the name of the returned value or a JSONPath item.  You must always pass "key" when using "returnValueTest", even if you pass an empty string for it, because the rpc call only returns a single value.
 */
/**
 * @typedef {Object} CosmosCondition
 * @property {string} path - The RPC URL path that will be called.  This will typically contain any parameters you need for the call.  Note that you can use the special ":userAddress" parameter which will be replaced with the requesting user's wallet address, verified via message signature.  For example, this path would be used to get the requesting user's balance: "/cosmos/bank/v1beta1/balances/:userAddress"
 * @property {string} chain - The chain name of the chain that this contract is deployed on.  See ALL_LIT_CHAINS for currently supported chains.  On Cosmos we currently support "cosmos" and "kyve"
 * @property {Object} returnValueTest - An object containing three keys: "key", "comparator" and "value".  The return value of the rpc call will be compared against these.  The "key" selector supports JSONPath syntax, so you can filter and iterate over the results.  For example, to check the balance of someone's account, you can use the key "$.balances[0].amount" which will pull out balances[0].amount from the JSON response and compare it against the "value" field according to the "comparator".  The "key" is used when the return value is an array or object which contains multiple values and should be the name of the returned value or a JSONPath item.  You must always pass "key" when using "returnValueTest", even if you pass an empty string for it, because the rpc call only returns a single value.
 */
/**
 * @typedef {Object} ResourceId
 * @property {string} baseUrl - The base url of the resource that will be authorized
 * @property {string} path - The path of the url of the resource that will be authorized
 * @property {string} orgId - The org id that the user would be authorized to belong to.  The orgId key must be present but it may contain an empty string if you don't need to store anything in it.
 * @property {string} role - The role that the user would be authorized to have.  The role key must be present but it may contain an empty string if you don't need to store anything in it.
 * @property {string} extraData - Any extra data you may want to store.  You may store stringified JSON in here, for example.  The extraData key must be present but it may contain an empty string if you don't need to store anything in it.
 */
/**
 * @typedef {Object} CallRequest
 * @property {string} to - The address of the contract that will be queried
 * @property {string} from - Optional.  The address calling the function.
 * @property {string} data - Hex encoded data to send to the contract.
 */
/**
 * A LIT node client.  Connects directly to the LIT nodes to store and retrieve encryption keys and signing requests.  Only holders of an NFT that corresponds with a LIT may store and retrieve the keys.
 * @param {Object} config
 * @param {boolean} [config.alertWhenUnauthorized=true] Whether or not to show a JS alert() when a user tries to unlock a LIT but is unauthorized.  An exception will also be thrown regardless of this option.
 * @param {number} [config.minNodeCount=6] The minimum number of nodes that must be connected for the LitNodeClient to be ready to use.
 * @param {boolean} [config.debug=true] Whether or not to show debug messages.
 */
export default class LitNodeClient {
    config: any;
    connectedNodes: any;
    networkPubKey: any;
    networkPubKeySet: any;
    ready: any;
    serverKeys: any;
    subnetPubKey: any;
    constructor(config: any);
    /**
     * Request a signed JWT of any solidity function call from the LIT network.  There are no prerequisites for this function.  You should use this function if you need to transmit information across chains, or from a blockchain to a centralized DB or server.  The signature of the returned JWT verifies that the response is genuine.
     * @param {Object} params
     * @param {Array.<CallRequest>} params.callRequests The call requests to make.  The responses will be signed and returned.
     * @param {string} params.chain The chain name of the chain that this contract is deployed on.  See LIT_CHAINS for currently supported chains.
     * @returns {Object} A signed JWT that proves the response to the function call is genuine. You may present this to a smart contract, or a server for authorization, and it can be verified using the verifyJwt function.
     */
    getSignedChainDataToken({ callRequests, chain }: any): Promise<string>;
    /**
     * Request a signed JWT from the LIT network.  Before calling this function, you must either create or know of a resource id and access control conditions for the item you wish to gain authorization for.  You can create an access control condition using the saveSigningCondition function.
     * @param {Object} params
     * @param {Array.<AccessControlCondition>} params.accessControlConditions The access control conditions that the user must meet to obtain this signed token.  This could be posession of an NFT, for example.  You must pass either accessControlConditions or evmContractConditions or solRpcConditions or unifiedAccessControlConditions.
     * @param {Array.<EVMContractCondition>} params.evmContractConditions  EVM Smart Contract access control conditions that the user must meet to obtain this signed token.  This could be posession of an NFT, for example.  This is different than accessControlConditions because accessControlConditions only supports a limited number of contract calls.  evmContractConditions supports any contract call.  You must pass either accessControlConditions or evmContractConditions solRpcConditions or unifiedAccessControlConditions.
     * @param {Array.<SolRpcCondition>} params.solRpcConditions  Solana RPC call conditions that the user must meet to obtain this signed token.  This could be posession of an NFT, for example.
     * @param {Array.<AccessControlCondition|EVMContractCondition|SolRpcCondition>} params.unifiedAccessControlConditions  An array of unified access control conditions.  You may use AccessControlCondition, EVMContractCondition, or SolRpcCondition objects in this array, but make sure you add a conditionType for each one.  You must pass either accessControlConditions or evmContractConditions or solRpcConditions or unifiedAccessControlConditions.
     * @param {string} params.chain The chain name of the chain that you are querying.  See ALL_LIT_CHAINS for currently supported chains.
     * @param {AuthSig} params.authSig The authentication signature that proves that the user owns the crypto wallet address that meets the access control conditions.
     * @param {ResourceId} params.resourceId The resourceId representing something on the web via a URL
     * @returns {Object} A signed JWT that proves you meet the access control conditions for the given resource id.  You may present this to a server for authorization, and the server can verify it using the verifyJwt function.
     */
    getSignedToken({ accessControlConditions, evmContractConditions, solRpcConditions, unifiedAccessControlConditions, chain, authSig, resourceId }: any): Promise<string | undefined>;
    /**
     * Associated access control conditions with a resource on the web.  After calling this function, users may use the getSignedToken function to request a signed JWT from the LIT network.  This JWT proves that the user meets the access control conditions, and is authorized to access the resource you specified in the resourceId parameter of the saveSigningCondition function.
     * @param {Object} params
     * @param {Array.<AccessControlCondition>} params.accessControlConditions The access control conditions that the user must meet to obtain this signed token.  This could be posession of an NFT, for example.  You must pass either accessControlConditions or evmContractConditions or solRpcConditions or unifiedAccessControlConditions.
     * @param {Array.<EVMContractCondition>} params.evmContractConditions  EVM Smart Contract access control conditions that the user must meet to obtain this signed token.  This could be posession of an NFT, for example.  This is different than accessControlConditions because accessControlConditions only supports a limited number of contract calls.  evmContractConditions supports any contract call.  You must pass either accessControlConditions or evmContractConditions or solRpcConditions or unifiedAccessControlConditions.
     * @param {Array.<SolRpcCondition>} params.solRpcConditions  Solana RPC call conditions that the user must meet to obtain this signed token.  This could be posession of an NFT, for example.
     * @param {Array.<AccessControlCondition|EVMContractCondition|SolRpcCondition>} params.unifiedAccessControlConditions  An array of unified access control conditions.  You may use AccessControlCondition, EVMContractCondition, or SolRpcCondition objects in this array, but make sure you add a conditionType for each one.  You must pass either accessControlConditions or evmContractConditions or solRpcConditions or unifiedAccessControlConditions.
     * @param {string} params.chain The chain name of the chain that you are querying.  See ALL_LIT_CHAINS for currently supported chains.
     * @param {AuthSig} params.authSig The authentication signature that proves that the user owns the crypto wallet address that meets the access control conditions
     * @param {ResourceId} params.resourceId The resourceId representing something on the web via a URL
     * @param {boolean} params.permanent Whether or not the access control condition should be saved permanently.  If false, the access control conditions will be updateable by the creator.  If you don't pass this param, it's set to true by default.
     * @returns {boolean} Success
     */
    saveSigningCondition({ accessControlConditions, evmContractConditions, solRpcConditions, unifiedAccessControlConditions, chain, authSig, resourceId, permanant, permanent }: any): Promise<true | undefined>;
    /**
     * Retrieve the symmetric encryption key from the LIT nodes.  Note that this will only work if the current user meets the access control conditions specified when the data was encrypted.  That access control condition is typically that the user is a holder of the NFT that corresponds to this encrypted data.  This NFT token address and ID was specified when this LIT was created.
     * @param {Object} params
     * @param {Array.<AccessControlCondition>} params.accessControlConditions The access control conditions that the user must meet to obtain this signed token.  This could be posession of an NFT, for example.  You must pass either accessControlConditions or evmContractConditions or solRpcConditions or unifiedAccessControlConditions.
     * @param {Array.<EVMContractCondition>} params.evmContractConditions  EVM Smart Contract access control conditions that the user must meet to obtain this signed token.  This could be posession of an NFT, for example.  This is different than accessControlConditions because accessControlConditions only supports a limited number of contract calls.  evmContractConditions supports any contract call.  You must pass either accessControlConditions or evmContractConditions or solRpcConditions or unifiedAccessControlConditions.
     * @param {Array.<SolRpcCondition>} params.solRpcConditions  Solana RPC call conditions that the user must meet to obtain this signed token.  This could be posession of an NFT, for example.
     * @param {Array.<AccessControlCondition|EVMContractCondition|SolRpcCondition>} params.unifiedAccessControlConditions  An array of unified access control conditions.  You may use AccessControlCondition, EVMContractCondition, or SolRpcCondition objects in this array, but make sure you add a conditionType for each one.  You must pass either accessControlConditions or evmContractConditions or solRpcConditions or unifiedAccessControlConditions.
     * @param {string} params.toDecrypt The ciphertext that you wish to decrypt encoded as a hex string
     * @param {string} params.chain The chain name of the chain that you are querying.  See ALL_LIT_CHAINS for currently supported chains.
     * @param {AuthSig} params.authSig The authentication signature that proves that the user owns the crypto wallet address meets the access control conditions.
     * @returns {Uint8Array} The symmetric encryption key that can be used to decrypt the locked content inside the LIT.  You should pass this key to the decryptZip function.
     */
    getEncryptionKey({ accessControlConditions, evmContractConditions, solRpcConditions, unifiedAccessControlConditions, toDecrypt, chain, authSig }: any): Promise<Uint8Array | undefined>;
    /**
     * Securely save the association between access control conditions and something that you wish to decrypt
     * @param {Object} params
     * @param {Array.<AccessControlCondition>} params.accessControlConditions The access control conditions that the user must meet to obtain this signed token.  This could be posession of an NFT, for example.  You must pass either accessControlConditions or evmContractConditions or solRpcConditions or unifiedAccessControlConditions.
     * @param {Array.<EVMContractCondition>} params.evmContractConditions  EVM Smart Contract access control conditions that the user must meet to obtain this signed token.  This could be posession of an NFT, for example.  This is different than accessControlConditions because accessControlConditions only supports a limited number of contract calls.  evmContractConditions supports any contract call.  You must pass either accessControlConditions or evmContractConditions or solRpcConditions or unifiedAccessControlConditions.
     * @param {Array.<SolRpcCondition>} params.solRpcConditions  Solana RPC call conditions that the user must meet to obtain this signed token.  This could be posession of an NFT, for example.
     * @param {Array.<AccessControlCondition|EVMContractCondition|SolRpcCondition>} params.unifiedAccessControlConditions  An array of unified access control conditions.  You may use AccessControlCondition, EVMContractCondition, or SolRpcCondition objects in this array, but make sure you add a conditionType for each one.  You must pass either accessControlConditions or evmContractConditions or solRpcConditions or unifiedAccessControlConditions.
     * @param {string} params.chain The chain name of the chain that you are querying.  See ALL_LIT_CHAINS for currently supported chains.
     * @param {AuthSig} params.authSig The authentication signature that proves that the user owns the crypto wallet address meets the access control conditions
     * @param {string} params.symmetricKey The symmetric encryption key that was used to encrypt the locked content inside the LIT as a Uint8Array.  You should use zipAndEncryptString or zipAndEncryptFiles to get this encryption key.  This key will be hashed and the hash will be sent to the LIT nodes.  You must pass either symmetricKey or encryptedSymmetricKey.
     * @param {Uint8Array} params.encryptedSymmetricKey The encrypted symmetric key of the item you with to update.  You must pass either symmetricKey or encryptedSymmetricKey.
     * @param {boolean} params.permanent Whether or not the access control condition should be saved permanently.  If false, the access control conditions will be updateable by the creator.  If you don't pass this param, it's set to true by default.
     * @returns {Uint8Array} The symmetricKey parameter that has been encrypted with the network public key.  Save this - you will need it to decrypt the content in the future.
     */
    saveEncryptionKey({ accessControlConditions, evmContractConditions, solRpcConditions, unifiedAccessControlConditions, chain, authSig, symmetricKey, encryptedSymmetricKey, permanant, permanent }: any): Promise<any>;
    storeSigningConditionWithNode({ url, key, val, authSig, chain, permanent }: any): Promise<any>;
    storeEncryptionConditionWithNode({ url, key, val, authSig, chain, permanent }: any): Promise<any>;
    getChainDataSigningShare({ url, callRequests, chain, iat, exp }: any): Promise<any>;
    getSigningShare({ url, accessControlConditions, evmContractConditions, solRpcConditions, unifiedAccessControlConditions, resourceId, authSig, chain, iat, exp }: any): Promise<any>;
    getDecryptionShare({ url, accessControlConditions, evmContractConditions, solRpcConditions, unifiedAccessControlConditions, toDecrypt, authSig, chain }: any): Promise<any>;
    handshakeWithSgx({ url }: any): Promise<any>;
    sendCommandToNode({ url, data }: any): Promise<any>;
    handleNodePromises(promises: any): Promise<{
        success: boolean;
        values: any[];
        error?: undefined;
    } | {
        success: boolean;
        error: any;
        values?: undefined;
    }>;
    throwNodeError(res: any): void;
    /**
     * Connect to the LIT nodes.
     * @returns {Promise} A promise that resolves when the nodes are connected.
     */
    connect(): Promise<unknown>;
}
