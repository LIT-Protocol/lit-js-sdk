import protons from 'protons'

export const protobufs = protons(`
message Request {
  enum Type {
    HANDSHAKE = 0;
    GET_KEY_FRAGMENT = 1;
    STORE_KEY_FRAGMENT = 2;
  }
  required Type type = 1;
  optional GetKeyFragment getKeyFragment = 2;
  optional StoreKeyFragment storeKeyFragment = 3;
  optional bytes authSig = 4;
  optional TokenParams tokenParams = 5;
  optional bytes clientPubKey = 6;
  optional bytes merkleProof = 7;
}
message Response {
  enum Type {
    HANDSHAKE_RESPONSE = 0;
    GET_KEY_FRAGMENT_RESPONSE = 1;
    STORE_KEY_FRAGMENT_RESPONSE = 2;
  }
  required Type type = 1;
  optional GetKeyFragmentResponse getKeyFragmentResponse = 2;
  optional StoreKeyFragmentResponse storeKeyFragmentResponse = 3;
  optional bytes serverPubKey = 4;
}
message GetKeyFragment {
  required bytes keyId = 1;
}
message GetKeyFragmentResponse {
  enum Result {
    SUCCESS = 0;
    NOT_FOUND = 1;
    AUTH_FAILURE = 2;
    ERROR = 3;
  }
  required Result result = 1;
  optional bytes keyId = 2;
  optional bytes fragmentValue = 3;
}
message StoreKeyFragment {
  required bytes fragmentValue = 1;
  required bytes fragmentNumber = 2;
}
message StoreKeyFragmentResponse {
  enum Result {
    SUCCESS = 0;
    AUTH_FAILURE = 1;
    ERROR = 2;
  }
  required Result result = 1;
  optional bytes errorMessage = 2;
}
message TokenParams {
  required bytes tokenAddress = 1;
  required bytes tokenId = 2;
  required bytes chain = 3;
}
`)

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
    rpcUrls: ['https://rpc-mainnet.maticvigil.com'],
    blockExplorerUrls: ['https://explorer.matic.network'],
    balanceStorageSlot: 1,
    type: 'ERC1155'
  },
  ethereum: {
    contractAddress: '0x55485885e82E25446DEC314Ccb810Bda06B9e01B',
    chainId: 1,
    name: 'Ethereum',
    symbol: 'ETH',
    decimals: 18,
    balanceStorageSlot: 1,
    type: 'ERC1155'
  },
  kovan: {
    contractAddress: '0xA9b2180C2A479Ba9b263878C4d81AE4e0E717846',
    chainId: 42,
    name: 'Ethereum',
    symbol: 'ETH',
    decimals: 18,
    balanceStorageSlot: 1,
    type: 'ERC20'
  }
}
