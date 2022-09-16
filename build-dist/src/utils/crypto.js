"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.decryptWithPrivKey = exports.encryptWithPubKey = exports.encryptWithSymmetricKey = exports.decryptWithSymmetricKey = exports.generateSymmetricKey = exports.importSymmetricKey = exports.compareArrayBuffers = exports.hashAccessControlConditions = exports.canonicalAccessControlConditionFormatter = exports.hashEVMContractConditions = exports.canonicalEVMContractConditionFormatter = exports.hashResourceId = exports.canonicalResourceIdFormatter = exports.canonicalSolRpcConditionFormatter = exports.hashSolRpcConditions = exports.canonicalCosmosConditionFormatter = exports.hashCosmosConditions = exports.canonicalUnifiedAccessControlConditionFormatter = exports.hashUnifiedAccessControlConditions = void 0;
const tweetnacl_1 = __importDefault(require("tweetnacl"));
const tweetnacl_util_1 = __importDefault(require("tweetnacl-util"));
const cross_blob_1 = __importDefault(require("cross-blob"));
const utils_1 = require("../lib/utils");
const SYMM_KEY_ALGO_PARAMS = {
    name: "AES-CBC",
    length: 256,
};
/**
 * Hash the unified access control conditions using SHA-256 in a deterministic way.
 * @param {Object} unifiedAccessControlConditions - The unified access control conditions to hash.
 * @returns {Promise<ArrayBuffer>} A promise that resolves to an ArrayBuffer that contains the hash
 */
function hashUnifiedAccessControlConditions(unifiedAccessControlConditions) {
    const conds = unifiedAccessControlConditions.map((c) => canonicalUnifiedAccessControlConditionFormatter(c));
    const toHash = JSON.stringify(conds);
    (0, utils_1.log)("Hashing unified access control conditions: ", toHash);
    const encoder = new TextEncoder();
    const data = encoder.encode(toHash);
    return crypto.subtle.digest("SHA-256", data);
}
exports.hashUnifiedAccessControlConditions = hashUnifiedAccessControlConditions;
// @ts-expect-error TS(7023): 'canonicalUnifiedAccessControlConditionFormatter' ... Remove this comment to see the full error message
function canonicalUnifiedAccessControlConditionFormatter(cond) {
    if (Array.isArray(cond)) {
        return cond.map((c) => canonicalUnifiedAccessControlConditionFormatter(c));
    }
    if ("operator" in cond) {
        return {
            operator: cond.operator,
        };
    }
    if ("returnValueTest" in cond) {
        if (cond.conditionType === "solRpc") {
            return canonicalSolRpcConditionFormatter(cond, true);
        }
        else if (cond.conditionType === "evmBasic") {
            return canonicalAccessControlConditionFormatter(cond);
        }
        else if (cond.conditionType === "evmContract") {
            return canonicalEVMContractConditionFormatter(cond);
        }
        else if (cond.conditionType === "cosmos") {
            return canonicalCosmosConditionFormatter(cond);
        }
        else {
            (0, utils_1.throwError)({
                message: `You passed an invalid access control condition that is missing or has a wrong "conditionType": ${JSON.stringify(cond)}`,
                name: "InvalidAccessControlCondition",
                errorCode: "invalid_access_control_condition",
            });
        }
    }
    (0, utils_1.throwError)({
        message: `You passed an invalid access control condition: ${cond}`,
        name: "InvalidAccessControlCondition",
        errorCode: "invalid_access_control_condition",
    });
}
exports.canonicalUnifiedAccessControlConditionFormatter = canonicalUnifiedAccessControlConditionFormatter;
function hashCosmosConditions(cosmosConditions) {
    const conds = cosmosConditions.map((c) => canonicalCosmosConditionFormatter(c));
    const toHash = JSON.stringify(conds);
    (0, utils_1.log)("Hashing cosmos conditions: ", toHash);
    const encoder = new TextEncoder();
    const data = encoder.encode(toHash);
    return crypto.subtle.digest("SHA-256", data);
}
exports.hashCosmosConditions = hashCosmosConditions;
// @ts-expect-error TS(7023): 'canonicalCosmosConditionFormatter' implicitly has... Remove this comment to see the full error message
function canonicalCosmosConditionFormatter(cond) {
    // need to return in the exact format below:
    /*
    pub struct CosmosCondition {
        pub path: String,
        pub chain: String,
        pub return_value_test: JsonReturnValueTestV2,
  }
    */
    if (Array.isArray(cond)) {
        return cond.map((c) => canonicalCosmosConditionFormatter(c));
    }
    if ("operator" in cond) {
        return {
            operator: cond.operator,
        };
    }
    if ("returnValueTest" in cond) {
        const { returnValueTest } = cond;
        const canonicalReturnValueTest = {
            key: returnValueTest.key,
            comparator: returnValueTest.comparator,
            value: returnValueTest.value,
        };
        return {
            path: cond.path,
            chain: cond.chain,
            returnValueTest: canonicalReturnValueTest,
        };
    }
    (0, utils_1.throwError)({
        message: `You passed an invalid access control condition: ${cond}`,
        name: "InvalidAccessControlCondition",
        errorCode: "invalid_access_control_condition",
    });
}
exports.canonicalCosmosConditionFormatter = canonicalCosmosConditionFormatter;
function hashSolRpcConditions(solRpcConditions) {
    const conds = solRpcConditions.map((c) => canonicalSolRpcConditionFormatter(c));
    const toHash = JSON.stringify(conds);
    (0, utils_1.log)("Hashing sol rpc conditions: ", toHash);
    const encoder = new TextEncoder();
    const data = encoder.encode(toHash);
    return crypto.subtle.digest("SHA-256", data);
}
exports.hashSolRpcConditions = hashSolRpcConditions;
// @ts-expect-error TS(7023): 'canonicalSolRpcConditionFormatter' implicitly has... Remove this comment to see the full error message
function canonicalSolRpcConditionFormatter(cond, requireV2Conditions = false) {
    // need to return in the exact format below
    // but make sure we don't include the optional fields:
    /*
  #[derive(Debug, Serialize, Deserialize, Clone)]
  #[serde(rename_all = "camelCase")]
  pub struct SolRpcCondition {
      pub method: String,
      pub params: Vec<serde_json::Value>,
      pub pda_params: Option<Vec<serde_json::Value>>,
      pub pda_interface: Option<SolPdaInterface>,
      pub chain: String,
      pub return_value_test: JsonReturnValueTestV2,
  }
  
  #[derive(Debug, Serialize, Deserialize, Clone)]
  #[serde(rename_all = "camelCase")]
  pub struct SolPdaInterface {
      pub offset: u64,
      pub fields: serde_json::Value,
  }
    */
    if (Array.isArray(cond)) {
        return cond.map((c) => canonicalSolRpcConditionFormatter(c, requireV2Conditions));
    }
    if ("operator" in cond) {
        return {
            operator: cond.operator,
        };
    }
    if ("returnValueTest" in cond) {
        const { returnValueTest } = cond;
        const canonicalReturnValueTest = {
            key: returnValueTest.key,
            comparator: returnValueTest.comparator,
            value: returnValueTest.value,
        };
        // check if this is a sol v1 or v2 condition
        // v1 conditions didn't have any pda params or pda interface or pda key
        if ("pdaParams" in cond || requireV2Conditions) {
            if (!("pdaInterface" in cond) ||
                !("offset" in cond.pdaInterface) ||
                !("fields" in cond.pdaInterface) ||
                !("pdaKey" in cond)) {
                (0, utils_1.throwError)({
                    message: `Solana RPC Conditions have changed and there are some new fields you must include in your condition.  Check the docs here: https://developer.litprotocol.com/AccessControlConditions/solRpcConditions`,
                    name: "InvalidAccessControlCondition",
                    errorCode: "invalid_access_control_condition",
                });
            }
            const canonicalPdaInterface = {
                offset: cond.pdaInterface.offset,
                fields: cond.pdaInterface.fields,
            };
            return {
                method: cond.method,
                params: cond.params,
                pdaParams: cond.pdaParams,
                pdaInterface: canonicalPdaInterface,
                pdaKey: cond.pdaKey,
                chain: cond.chain,
                returnValueTest: canonicalReturnValueTest,
            };
        }
        else {
            return {
                method: cond.method,
                params: cond.params,
                chain: cond.chain,
                returnValueTest: canonicalReturnValueTest,
            };
        }
    }
    (0, utils_1.throwError)({
        message: `You passed an invalid access control condition: ${cond}`,
        name: "InvalidAccessControlCondition",
        errorCode: "invalid_access_control_condition",
    });
}
exports.canonicalSolRpcConditionFormatter = canonicalSolRpcConditionFormatter;
function canonicalResourceIdFormatter(resId) {
    // need to return in the exact format below:
    return {
        baseUrl: resId.baseUrl,
        path: resId.path,
        orgId: resId.orgId,
        role: resId.role,
        extraData: resId.extraData,
    };
}
exports.canonicalResourceIdFormatter = canonicalResourceIdFormatter;
function hashResourceId(resourceId) {
    const resId = canonicalResourceIdFormatter(resourceId);
    const toHash = JSON.stringify(resId);
    const encoder = new TextEncoder();
    const data = encoder.encode(toHash);
    return crypto.subtle.digest("SHA-256", data);
}
exports.hashResourceId = hashResourceId;
function canonicalAbiParams(params) {
    return params.map((param) => ({
        name: param.name,
        type: param.type
    }));
}
// @ts-expect-error TS(7023): 'canonicalEVMContractConditionFormatter' implicitl... Remove this comment to see the full error message
function canonicalEVMContractConditionFormatter(cond) {
    // need to return in the exact format below:
    /*
    pub struct JsonAccessControlCondition {
      pub contract_address: String,
      pub chain: String,
      pub standard_contract_type: String,
      pub method: String,
      pub parameters: Vec<String>,
      pub return_value_test: JsonReturnValueTest,
    }
    */
    if (Array.isArray(cond)) {
        return cond.map((c) => canonicalEVMContractConditionFormatter(c));
    }
    if ("operator" in cond) {
        return {
            operator: cond.operator,
        };
    }
    if ("returnValueTest" in cond) {
        /* abi needs to match:
          pub name: String,
        /// Function input.
        pub inputs: Vec<Param>,
        /// Function output.
        pub outputs: Vec<Param>,
        #[deprecated(note = "The constant attribute was removed in Solidity 0.5.0 and has been \
              replaced with stateMutability. If parsing a JSON AST created with \
              this version or later this value will always be false, which may be wrong.")]
        /// Constant function.
        #[cfg_attr(feature = "full-serde", serde(default))]
        pub constant: bool,
        /// Whether the function reads or modifies blockchain state
        #[cfg_attr(feature = "full-serde", serde(rename = "stateMutability", default))]
        pub state_mutability: StateMutability,
        */
        const { functionAbi, returnValueTest } = cond;
        const canonicalAbi = {
            name: functionAbi.name,
            inputs: canonicalAbiParams(functionAbi.inputs),
            outputs: canonicalAbiParams(functionAbi.outputs),
            constant: typeof functionAbi.constant === "undefined"
                ? false
                : functionAbi.constant,
            stateMutability: functionAbi.stateMutability,
        };
        const canonicalReturnValueTest = {
            key: returnValueTest.key,
            comparator: returnValueTest.comparator,
            value: returnValueTest.value,
        };
        return {
            contractAddress: cond.contractAddress,
            functionName: cond.functionName,
            functionParams: cond.functionParams,
            functionAbi: canonicalAbi,
            chain: cond.chain,
            returnValueTest: canonicalReturnValueTest,
        };
    }
    (0, utils_1.throwError)({
        message: `You passed an invalid access control condition: ${cond}`,
        name: "InvalidAccessControlCondition",
        errorCode: "invalid_access_control_condition",
    });
}
exports.canonicalEVMContractConditionFormatter = canonicalEVMContractConditionFormatter;
function hashEVMContractConditions(accessControlConditions) {
    const conds = accessControlConditions.map((c) => canonicalEVMContractConditionFormatter(c));
    const toHash = JSON.stringify(conds);
    (0, utils_1.log)("Hashing evm contract conditions: ", toHash);
    const encoder = new TextEncoder();
    const data = encoder.encode(toHash);
    return crypto.subtle.digest("SHA-256", data);
}
exports.hashEVMContractConditions = hashEVMContractConditions;
// @ts-expect-error TS(7023): 'canonicalAccessControlConditionFormatter' implici... Remove this comment to see the full error message
function canonicalAccessControlConditionFormatter(cond) {
    // need to return in the exact format below:
    /*
    pub struct JsonAccessControlCondition {
      pub contract_address: String,
      pub chain: String,
      pub standard_contract_type: String,
      pub method: String,
      pub parameters: Vec<String>,
      pub return_value_test: JsonReturnValueTest,
    }
    */
    if (Array.isArray(cond)) {
        return cond.map((c) => canonicalAccessControlConditionFormatter(c));
    }
    if ("operator" in cond) {
        return {
            operator: cond.operator,
        };
    }
    if ("returnValueTest" in cond) {
        return {
            contractAddress: cond.contractAddress,
            chain: cond.chain,
            standardContractType: cond.standardContractType,
            method: cond.method,
            parameters: cond.parameters,
            returnValueTest: {
                comparator: cond.returnValueTest.comparator,
                value: cond.returnValueTest.value,
            },
        };
    }
    (0, utils_1.throwError)({
        message: `You passed an invalid access control condition: ${cond}`,
        name: "InvalidAccessControlCondition",
        errorCode: "invalid_access_control_condition",
    });
}
exports.canonicalAccessControlConditionFormatter = canonicalAccessControlConditionFormatter;
function hashAccessControlConditions(accessControlConditions) {
    const conds = accessControlConditions.map((c) => canonicalAccessControlConditionFormatter(c));
    const toHash = JSON.stringify(conds);
    (0, utils_1.log)("Hashing access control conditions: ", toHash);
    const encoder = new TextEncoder();
    const data = encoder.encode(toHash);
    return crypto.subtle.digest("SHA-256", data);
}
exports.hashAccessControlConditions = hashAccessControlConditions;
function compareArrayBuffers(buf1, buf2) {
    if (buf1.byteLength !== buf2.byteLength)
        return false;
    const dv1 = new Uint8Array(buf1);
    const dv2 = new Uint8Array(buf2);
    for (let i = 0; i !== buf1.byteLength; i++) {
        if (dv1[i] !== dv2[i])
            return false;
    }
    return true;
}
exports.compareArrayBuffers = compareArrayBuffers;
/**
 * Import a symmetric key from a Uint8Array to a webcrypto key.  You should only use this if you're handling your own key generation and management with Lit.  Typically, Lit handles this internally for you.
 * @param {Uint8Array} symmKey The symmetric key to import
 * @returns {Promise<CryptoKey>} A promise that resolves to the imported key
 */
function importSymmetricKey(symmKey) {
    return __awaiter(this, void 0, void 0, function* () {
        const importedSymmKey = yield crypto.subtle.importKey("raw", symmKey, SYMM_KEY_ALGO_PARAMS, true, ["encrypt", "decrypt"]);
        return importedSymmKey;
    });
}
exports.importSymmetricKey = importSymmetricKey;
/**
 * Generate a new random symmetric key using WebCrypto subtle API.  You should only use this if you're handling your own key generation and management with Lit.  Typically, Lit handles this internally for you.
 * @returns {Promise<CryptoKey>} A promise that resolves to the generated key
 */
function generateSymmetricKey() {
    return __awaiter(this, void 0, void 0, function* () {
        const symmKey = yield crypto.subtle.generateKey(SYMM_KEY_ALGO_PARAMS, true, [
            "encrypt",
            "decrypt",
        ]);
        return symmKey;
    });
}
exports.generateSymmetricKey = generateSymmetricKey;
/**
 * Decrypt an encrypted blob with a symmetric key.  Uses AES-CBC via SubtleCrypto
 * @param {Blob} encryptedBlob The encrypted blob that should be decrypted
 * @param {Object} symmKey The symmetric key
 * @returns {Blob} The decrypted blob
 */
function decryptWithSymmetricKey(encryptedBlob, symmKey) {
    return __awaiter(this, void 0, void 0, function* () {
        const recoveredIv = yield encryptedBlob.slice(0, 16).arrayBuffer();
        const encryptedZipArrayBuffer = yield encryptedBlob.slice(16).arrayBuffer();
        const decryptedZip = yield crypto.subtle.decrypt({
            name: "AES-CBC",
            iv: recoveredIv,
        }, symmKey, encryptedZipArrayBuffer);
        return decryptedZip;
    });
}
exports.decryptWithSymmetricKey = decryptWithSymmetricKey;
// used this as an example
// https://github.com/infotechinc/symmetric-encryption-in-browser/blob/master/crypto.js
/**
 * Encrypt a blob with a symmetric key
 * @param {Object} symmKey The symmetric key
 * @param {Blob} data The blob to encrypt
 * @returns {Blob} The encrypted blob
 */
function encryptWithSymmetricKey(symmKey, data) {
    return __awaiter(this, void 0, void 0, function* () {
        // encrypt the zip with symmetric key
        const iv = crypto.getRandomValues(new Uint8Array(16));
        const encryptedZipData = yield crypto.subtle.encrypt({
            name: "AES-CBC",
            iv,
        }, symmKey, data);
        const encryptedZipBlob = new cross_blob_1.default([iv, new Uint8Array(encryptedZipData)], {
            type: "application/octet-stream",
        });
        return encryptedZipBlob;
    });
}
exports.encryptWithSymmetricKey = encryptWithSymmetricKey;
// borrowed from eth-sig-util from meatmask.
/**
 * Encrypt a blob with the public key of a receiver
 * @param {string} receiverPublicKey The base64 encoded 32 byte public key.  The corresponding private key will be able to decrypt this blob
 * @param {Blob} data The blob to encrypt
 * @param {string} version The encryption algorithm to use.  This should be set to "x25519-xsalsa20-poly1305" as no other algorithms are implemented right now.
 * @returns {Blob} The encrypted blob
 */
function encryptWithPubKey(receiverPublicKey, data, version) {
    switch (version) {
        case "x25519-xsalsa20-poly1305": {
            // generate ephemeral keypair
            const ephemeralKeyPair = tweetnacl_1.default.box.keyPair();
            // assemble encryption parameters - from string to UInt8
            let pubKeyUInt8Array;
            try {
                pubKeyUInt8Array = tweetnacl_util_1.default.decodeBase64(receiverPublicKey);
            }
            catch (err) {
                throw new Error("Bad public key");
            }
            // padding?  not needed for c decryption?
            // const paddingBytes = new Uint8Array(32)
            // paddingBytes.fill(0)
            // const msgParamsUInt8Array = new Uint8Array([...paddingBytes, ...naclUtil.decodeUTF8(data)])
            const msgParamsUInt8Array = tweetnacl_util_1.default.decodeUTF8(data);
            const nonce = tweetnacl_1.default.randomBytes(tweetnacl_1.default.box.nonceLength);
            // encrypt
            const encryptedMessage = tweetnacl_1.default.box(msgParamsUInt8Array, nonce, pubKeyUInt8Array, ephemeralKeyPair.secretKey);
            // handle encrypted data
            const output = {
                version: "x25519-xsalsa20-poly1305",
                nonce: tweetnacl_util_1.default.encodeBase64(nonce),
                ephemPublicKey: tweetnacl_util_1.default.encodeBase64(ephemeralKeyPair.publicKey),
                ciphertext: tweetnacl_util_1.default.encodeBase64(encryptedMessage),
            };
            // return encrypted msg data
            return output;
        }
        default:
            throw new Error("Encryption type/version not supported");
    }
}
exports.encryptWithPubKey = encryptWithPubKey;
// borrowed from eth-sig-util from meatmask.
/**
 * Decrypt a blob with a private key
 * @param {Blob} encryptedData The blob to decrypt
 * @param {string} receiverPrivateKey The base64 encoded 32 byte private key.  The corresponding public key was used to encrypt this blob
 * @param {string} version The encryption algorithm to use.  This should be set to "x25519-xsalsa20-poly1305" as no other algorithms are implemented right now.
 * @returns {Blob} The decrypted blob
 */
function decryptWithPrivKey(encryptedData, receiverPrivateKey) {
    switch (encryptedData.version) {
        case "x25519-xsalsa20-poly1305": {
            const recieverEncryptionPrivateKey = tweetnacl_util_1.default.decodeBase64(receiverPrivateKey);
            // assemble decryption parameters
            const nonce = tweetnacl_util_1.default.decodeBase64(encryptedData.nonce);
            const ciphertext = tweetnacl_util_1.default.decodeBase64(encryptedData.ciphertext);
            const ephemPublicKey = tweetnacl_util_1.default.decodeBase64(encryptedData.ephemPublicKey);
            // decrypt
            const decryptedMessage = tweetnacl_1.default.box.open(ciphertext, nonce, ephemPublicKey, recieverEncryptionPrivateKey);
            // return decrypted msg data
            let output;
            try {
                // @ts-expect-error TS(2345): Argument of type 'Uint8Array | null' is not assign... Remove this comment to see the full error message
                output = tweetnacl_util_1.default.encodeUTF8(decryptedMessage);
            }
            catch (err) {
                throw new Error("Decryption failed.  Could not encode result as utf8");
            }
            if (output) {
                return output;
            }
            throw new Error("Decryption failed.  Output is falsy");
        }
        default:
            throw new Error("Encryption type/version not supported.");
    }
}
exports.decryptWithPrivKey = decryptWithPrivKey;
