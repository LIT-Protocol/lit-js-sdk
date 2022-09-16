import Blob from "cross-blob";
/**
 * Hash the unified access control conditions using SHA-256 in a deterministic way.
 * @param {Object} unifiedAccessControlConditions - The unified access control conditions to hash.
 * @returns {Promise<ArrayBuffer>} A promise that resolves to an ArrayBuffer that contains the hash
 */
export declare function hashUnifiedAccessControlConditions(unifiedAccessControlConditions: any): Promise<ArrayBuffer>;
export declare function canonicalUnifiedAccessControlConditionFormatter(cond: any): any;
export declare function hashCosmosConditions(cosmosConditions: any): Promise<ArrayBuffer>;
export declare function canonicalCosmosConditionFormatter(cond: any): any;
export declare function hashSolRpcConditions(solRpcConditions: any): Promise<ArrayBuffer>;
export declare function canonicalSolRpcConditionFormatter(cond: any, requireV2Conditions?: boolean): any;
export declare function canonicalResourceIdFormatter(resId: any): {
    baseUrl: any;
    path: any;
    orgId: any;
    role: any;
    extraData: any;
};
export declare function hashResourceId(resourceId: any): Promise<ArrayBuffer>;
export declare function canonicalEVMContractConditionFormatter(cond: any): any;
export declare function hashEVMContractConditions(accessControlConditions: any): Promise<ArrayBuffer>;
export declare function canonicalAccessControlConditionFormatter(cond: any): any;
export declare function hashAccessControlConditions(accessControlConditions: any): Promise<ArrayBuffer>;
export declare function compareArrayBuffers(buf1: any, buf2: any): boolean;
/**
 * Import a symmetric key from a Uint8Array to a webcrypto key.  You should only use this if you're handling your own key generation and management with Lit.  Typically, Lit handles this internally for you.
 * @param {Uint8Array} symmKey The symmetric key to import
 * @returns {Promise<CryptoKey>} A promise that resolves to the imported key
 */
export declare function importSymmetricKey(symmKey: any): Promise<CryptoKey>;
/**
 * Generate a new random symmetric key using WebCrypto subtle API.  You should only use this if you're handling your own key generation and management with Lit.  Typically, Lit handles this internally for you.
 * @returns {Promise<CryptoKey>} A promise that resolves to the generated key
 */
export declare function generateSymmetricKey(): Promise<CryptoKey>;
/**
 * Decrypt an encrypted blob with a symmetric key.  Uses AES-CBC via SubtleCrypto
 * @param {Blob} encryptedBlob The encrypted blob that should be decrypted
 * @param {Object} symmKey The symmetric key
 * @returns {Blob} The decrypted blob
 */
export declare function decryptWithSymmetricKey(encryptedBlob: any, symmKey: any): Blob;
/**
 * Encrypt a blob with a symmetric key
 * @param {Object} symmKey The symmetric key
 * @param {Blob} data The blob to encrypt
 * @returns {Blob} The encrypted blob
 */
export declare function encryptWithSymmetricKey(symmKey: any, data: any): Blob;
/**
 * Encrypt a blob with the public key of a receiver
 * @param {string} receiverPublicKey The base64 encoded 32 byte public key.  The corresponding private key will be able to decrypt this blob
 * @param {Blob} data The blob to encrypt
 * @param {string} version The encryption algorithm to use.  This should be set to "x25519-xsalsa20-poly1305" as no other algorithms are implemented right now.
 * @returns {Blob} The encrypted blob
 */
export declare function encryptWithPubKey(receiverPublicKey: any, data: any, version: any): Blob;
/**
 * Decrypt a blob with a private key
 * @param {Blob} encryptedData The blob to decrypt
 * @param {string} receiverPrivateKey The base64 encoded 32 byte private key.  The corresponding public key was used to encrypt this blob
 * @param {string} version The encryption algorithm to use.  This should be set to "x25519-xsalsa20-poly1305" as no other algorithms are implemented right now.
 * @returns {Blob} The decrypted blob
 */
export declare function decryptWithPrivKey(encryptedData: any, receiverPrivateKey: any): Blob;
