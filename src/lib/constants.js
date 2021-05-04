const protons = require('protons')

export const protobufs = protons(`
message Request {
  enum Type {
    GET_KEY_FRAGMENT = 0;
    STORE_KEY_FRAGMENT = 1;
  }
  required Type type = 1;
  optional GetKeyFragment getKeyFragment = 2;
  optional StoreKeyFragment storeKeyFragment = 3;
  optional bytes authSig = 4;
  optional TokenParams tokenParams = 5;
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
  required bytes keyId = 4;
}
message GetKeyFragmentResponse {
  enum Result {
    SUCCESS = 0;
    NOT_FOUND = 1;
    ERROR = 2;
  }
  required Result result = 1;
  optional bytes keyId = 2;
  optional bytes fragmentValue = 3;
}
message StoreKeyFragment {
  required bytes fragmentValue = 4;
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

export const LIT_CHAINS = {
  polygon: {
    contractAddress: '0xb9A323711528D0c5a70df790929f4739f1cDd7fD',
    chainId: 137
  },
  ethereum: {
    contractAddress: '0x55485885e82E25446DEC314Ccb810Bda06B9e01B',
    chainId: 1
  }
}
