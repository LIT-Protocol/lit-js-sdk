export declare namespace Lit {
  export namespace Actions {
    /**
     * Check if a given IPFS ID is permitted to sign using a given PKP tokenId
     * @param params.tokenId - The tokenId to check
     * @param params.ipfsId - The IPFS ID of some JS code (a lit action)
     * @returns A boolean indicating whether the IPFS ID is permitted to sign using the PKP tokenId
     */
    declare function isPermittedAction(params: {
      tokenId: string;
      ipfsId: string;
    }): boolean;

    /**
     * Check if a given wallet address is permitted to sign using a given PKP tokenId
     * @param params.tokenId - The tokenId to check
     * @param params.address - The wallet address to check
     * @returns A boolean indicating whether the wallet address is permitted to sign using the PKP tokenId
     */
    declare function isPermittedAddress(params: {
      tokenId: string;
      address: string;
    }): boolean;

    /**
     * Check if a given auth method is permitted to sign using a given PKP tokenId
     * @param params.tokenId - The tokenId to check
     * @param params.authMethodType - The auth method type.  This is an integer.  This mapping shows the initial set but this set may be expanded over time without updating this contract: https://github.com/LIT-Protocol/LitNodeContracts/blob/main/contracts/PKPPermissions.sol#L25
     * @param params.userId - The id of the auth method to check expressed as an array of unsigned 8-bit integers (a Uint8Array)
     * @returns A boolean indicating whether the auth method is permitted to sign using the PKP tokenId
     */
    declare function isPermittedAuthMethod(params: {
      tokenId: string;
      authMethodType: number;
      userId: Uint8Array;
    }): boolean;

    /**
     * Get the full list of actions that are permitted to sign using a given PKP tokenId
     * @param params.tokenId - The tokenId to check
     * @returns An array of IPFS IDs of lit actions that are permitted to sign using the PKP tokenId
     */
    declare function getPermittedActions(params: { tokenId: string }): string[];

    /**
     * Get the full list of addresses that are permitted to sign using a given PKP tokenId
     * @param params.tokenId - The tokenId to check
     * @returns An array of addresses that are permitted to sign using the PKP tokenId
     */
    declare function getPermittedAddresses(params: {
      tokenId: string;
    }): string[];

    /**
     * Get the full list of auth methods that are permitted to sign using a given PKP tokenId
     * @param params.tokenId - The tokenId to check
     * @returns An array of auth methods that are permitted to sign using the PKP tokenId.  Each auth method is an object with the following properties: auth_method_type, id, and user_pubkey (used for web authn, this is the pubkey of the user's authentication keypair)
     */
    declare function getPermittedAuthMethods(params: {
      tokenId: string;
    }): object[];

    /**
     * Get the permitted auth method scopes for a given PKP tokenId and auth method type + id
     * @param params.tokenId - The tokenId to check
     * @param params.authMethodType - The auth method type to look up
     * @param params.userId - The id of the auth method to check expressed as an array of unsigned 8-bit integers (a Uint8Array)
     * @param params.maxScopeId - The maximum scope id to check.  This is an integer.
     * @returns An array of booleans that define if a given scope id is turned on.  The index of the array is the scope id.  For example, if the array is [true, false, true], then scope ids 0 and 2 are turned on, but scope id 1 is turned off.
     */
    declare function getPermittedAuthMethodScopes(params: {
      tokenId: string;
      authMethodType: string;
      userId: Uint8Array;
      maxScopeId: number;
    }): boolean[];

    /**
     * Converts a PKP public key to a PKP token ID by hashing it with keccak256
     * @param params.publicKey - The public key to convert
     * @returns The token ID as a string
     */
    declare function pubkeyToTokenId(params: { publicKey: string }): string;

    /**
     * Gets latest nonce for the given address on a supported chain
     * @param params.address - The wallet address for getting the nonce
     * @param params.chain - The chain of which the nonce is fetched
     * @returns The token ID as a string
     */
    declare function getLatestNonce(params: {
      address: string;
      chain: string;
    }): string;

    /**
     * Ask the Lit Node to sign any data using the ECDSA Algorithm with it's private key share.  The resulting signature share will be returned to the Lit JS SDK which will automatically combine the shares and give you the full signature to use.
     * @param params.toSign - The data to sign.  Should be an array of 8-bit integers.
     * @param params.publicKey - The public key of the PKP you wish to sign with
     * @param params.sigName - You can put any string here.  This is used to identify the signature in the response by the Lit JS SDK.  This is useful if you are signing multiple messages at once.  When you get the final signature out, it will be in an object with this signature name as the key.
     * @returns This function will return the string "success" if it works.  The signature share is returned behind the scenes to the Lit JS SDK which will automatically combine the shares and give you the full signature to use.
     */
    declare function signEcdsa(params: {
      toSign: Uint8Array;
      publicKey: string;
      sigName: string;
    }): string;

    /**
     * Ask the Lit Node to sign a message using the eth_personalSign algorithm.  The resulting signature share will be returned to the Lit JS SDK which will automatically combine the shares and give you the full signature to use.
     * @param params.message - The message to sign.  Should be a string.
     * @param params.publicKey - The public key of the PKP you wish to sign with
     * @param params.sigName - You can put any string here.  This is used to identify the signature in the response by the Lit JS SDK.  This is useful if you are signing multiple messages at once.  When you get the final signature out, it will be in an object with this signature name as the key.
     * @returns This function will return the string "success" if it works.  The signature share is returned behind the scenes to the Lit JS SDK which will automatically combine the shares and give you the full signature to use.
     */
    declare function ethPersonalSignMessageEcdsa(params: {
      message: string;
      publicKey: string;
      sigName: string;
    }): string;

    /**
     * Checks a condition using the Lit condition checking engine.  This is the same engine that powers our Access Control product.  You can use this to check any condition that you can express in our condition language.  This is a powerful tool that allows you to build complex conditions that can be checked in a decentralized way.  Visit https://developer.litprotocol.com and click on the "Access Control" section to learn more.
     * @param params.conditions - An array of access control condition objects
     * @param params.authSig - The AuthSig to use for the condition check.  For example, if you were checking for NFT ownership, this AuthSig would be the signature from the NFT owner's wallet.
     * @param params.chain - The chain this AuthSig comes from
     * @returns A boolean indicating whether the condition check passed or failed
     */
    declare function checkConditions(params: {
      conditions: object[];
      authSig: any;
      chain: string;
    }): boolean;

    /**
     * Set the response returned to the client
     * @param params.response - The response to send to the client.  You can put any string here, like you could use JSON.stringify on a JS object and send it here.
     */
    declare function setResponse(params: { response: string }): void;

    /**
     * Call a child Lit Action
     * @param params.ipfsId - The IPFS ID of the Lit Action to call
     * @param params.params - The parameters to pass to the child Lit Action
     * @returns The response from the child Lit Action.  Note that any signatures performed by the child Lit Action will be automatically combined and returned with the parent Lit Action to the Lit JS SDK client.
     */
    declare function call(params: { ipfsId: string; params: any }): string;

    /**
     * Convert a Uint8Array to a string.  This is a re-export of this function: https://www.npmjs.com/package/uint8arrays#tostringarray-encoding--utf8
     * @param array - The Uint8Array to convert
     * @param encoding - The encoding to use.  Defaults to "utf8"
     * @returns The string representation of the Uint8Array
     */
    declare function uint8arrayToString(
      array: Uint8Array,
      encoding: string
    ): string;

    /**
     * Convert a string to a Uint8Array.  This is a re-export of this function: https://www.npmjs.com/package/uint8arrays#fromstringstring-encoding--utf8
     * @param string - The string to convert
     * @param encoding - The encoding to use.  Defaults to "utf8"
     * @returns The Uint8Array representation of the string
     */
    declare function uint8arrayFromString(
      string: string,
      encoding: string
    ): Uint8Array;
  }
}
