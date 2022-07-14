import nacl from "tweetnacl";
import naclUtil from "tweetnacl-util";
import {
  fromString as uint8arrayFromString,
  toString as uint8arrayToString,
} from "uint8arrays";
import { throwError, log } from "../lib/utils";
import * as wasmECDSA from "../lib/ecdsa-sdk";
import { wasmBlsSdkHelpers } from "../lib/bls-sdk";

const SYMM_KEY_ALGO_PARAMS = {
  name: "AES-CBC",
  length: 256,
};

/**
 * Hash the unified access control conditions using SHA-256 in a deterministic way.
 * @param {Object} unifiedAccessControlConditions - The unified access control conditions to hash.
 * @returns {Promise<ArrayBuffer>} A promise that resolves to an ArrayBuffer that contains the hash
 */
export function hashUnifiedAccessControlConditions(
  unifiedAccessControlConditions
) {
  const conds = unifiedAccessControlConditions.map((c) =>
    canonicalUnifiedAccessControlConditionFormatter(c)
  );
  const toHash = JSON.stringify(conds);
  log("Hashing unified access control conditions: ", toHash);
  const encoder = new TextEncoder();
  const data = encoder.encode(toHash);
  return crypto.subtle.digest("SHA-256", data);
}

export function canonicalUnifiedAccessControlConditionFormatter(cond) {
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
      return canonicalSolRpcConditionFormatter(cond);
    } else if (cond.conditionType === "evmBasic") {
      return canonicalAccessControlConditionFormatter(cond);
    } else if (cond.conditionType === "evmContract") {
      return canonicalEVMContractConditionFormatter(cond);
    } else if (cond.conditionType === "cosmos") {
      return canonicalCosmosConditionFormatter(cond);
    } else {
      throwError({
        message: `You passed an invalid access control condition that is missing or has a wrong "conditionType": ${JSON.stringify(
          cond
        )}`,
        name: "InvalidAccessControlCondition",
        errorCode: "invalid_access_control_condition",
      });
    }
  }

  throwError({
    message: `You passed an invalid access control condition: ${cond}`,
    name: "InvalidAccessControlCondition",
    errorCode: "invalid_access_control_condition",
  });
}

export function hashCosmosConditions(cosmosConditions) {
  const conds = cosmosConditions.map((c) =>
    canonicalCosmosConditionFormatter(c)
  );
  const toHash = JSON.stringify(conds);
  log("Hashing cosmos conditions: ", toHash);
  const encoder = new TextEncoder();
  const data = encoder.encode(toHash);
  return crypto.subtle.digest("SHA-256", data);
}

export function canonicalCosmosConditionFormatter(cond) {
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

  throwError({
    message: `You passed an invalid access control condition: ${cond}`,
    name: "InvalidAccessControlCondition",
    errorCode: "invalid_access_control_condition",
  });
}

export function hashSolRpcConditions(solRpcConditions) {
  const conds = solRpcConditions.map((c) =>
    canonicalSolRpcConditionFormatter(c)
  );
  const toHash = JSON.stringify(conds);
  log("Hashing sol rpc conditions: ", toHash);
  const encoder = new TextEncoder();
  const data = encoder.encode(toHash);
  return crypto.subtle.digest("SHA-256", data);
}

export function canonicalSolRpcConditionFormatter(cond) {
  // need to return in the exact format below:
  /*
  pub struct SolRpcCondition {
      pub method: String,
      pub params: Vec<String>,
      pub return_value_test: JsonReturnValueTestV2,
  }
  */

  if (Array.isArray(cond)) {
    return cond.map((c) => canonicalSolRpcConditionFormatter(c));
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
      method: cond.method,
      params: cond.params,
      chain: cond.chain,
      returnValueTest: canonicalReturnValueTest,
    };
  }

  throwError({
    message: `You passed an invalid access control condition: ${cond}`,
    name: "InvalidAccessControlCondition",
    errorCode: "invalid_access_control_condition",
  });
}

export function canonicalResourceIdFormatter(resId) {
  // need to return in the exact format below:

  return {
    baseUrl: resId.baseUrl,
    path: resId.path,
    orgId: resId.orgId,
    role: resId.role,
    extraData: resId.extraData,
  };
}

export function hashResourceId(resourceId) {
  const resId = canonicalResourceIdFormatter(resourceId);
  const toHash = JSON.stringify(resId);
  const encoder = new TextEncoder();
  const data = encoder.encode(toHash);
  return crypto.subtle.digest("SHA-256", data);
}

function canonicalAbiParams(params) {
  return params.map((param) => ({
    name: param.name,
    type: param.type,
  }));
}

export function canonicalEVMContractConditionFormatter(cond) {
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
      constant:
        typeof functionAbi.constant === "undefined"
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

  throwError({
    message: `You passed an invalid access control condition: ${cond}`,
    name: "InvalidAccessControlCondition",
    errorCode: "invalid_access_control_condition",
  });
}

export function hashEVMContractConditions(accessControlConditions) {
  const conds = accessControlConditions.map((c) =>
    canonicalEVMContractConditionFormatter(c)
  );
  const toHash = JSON.stringify(conds);
  log("Hashing evm contract conditions: ", toHash);
  const encoder = new TextEncoder();
  const data = encoder.encode(toHash);
  return crypto.subtle.digest("SHA-256", data);
}

export function canonicalAccessControlConditionFormatter(cond) {
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

  throwError({
    message: `You passed an invalid access control condition: ${cond}`,
    name: "InvalidAccessControlCondition",
    errorCode: "invalid_access_control_condition",
  });
}

export function hashAccessControlConditions(accessControlConditions) {
  const conds = accessControlConditions.map((c) =>
    canonicalAccessControlConditionFormatter(c)
  );
  const toHash = JSON.stringify(conds);
  log("Hashing access control conditions: ", toHash);
  const encoder = new TextEncoder();
  const data = encoder.encode(toHash);
  return crypto.subtle.digest("SHA-256", data);
}

export function compareArrayBuffers(buf1, buf2) {
  if (buf1.byteLength !== buf2.byteLength) return false;
  const dv1 = new Uint8Array(buf1);
  const dv2 = new Uint8Array(buf2);
  for (let i = 0; i !== buf1.byteLength; i++) {
    if (dv1[i] !== dv2[i]) return false;
  }
  return true;
}

export function encryptWithBlsPubkey({ pubkey, data }) {
  return wasmBlsSdkHelpers.encrypt(
    uint8arrayFromString(pubkey, "base16"),
    data
  );
}

export async function importSymmetricKey(symmKey) {
  const importedSymmKey = await crypto.subtle.importKey(
    "raw",
    symmKey,
    SYMM_KEY_ALGO_PARAMS,
    true,
    ["encrypt", "decrypt"]
  );
  return importedSymmKey;
}
export async function generateSymmetricKey() {
  const symmKey = await crypto.subtle.generateKey(SYMM_KEY_ALGO_PARAMS, true, [
    "encrypt",
    "decrypt",
  ]);
  return symmKey;
}

/**
 * Decrypt an encrypted blob with a symmetric key.  Uses AES-CBC via SubtleCrypto
 * @param {Blob} encryptedBlob The encrypted blob that should be decrypted
 * @param {Object} symmKey The symmetric key
 * @returns {Blob} The decrypted blob
 */
export async function decryptWithSymmetricKey(encryptedBlob, symmKey) {
  const recoveredIv = await encryptedBlob.slice(0, 16).arrayBuffer();
  const encryptedZipArrayBuffer = await encryptedBlob.slice(16).arrayBuffer();
  const decryptedZip = await crypto.subtle.decrypt(
    {
      name: "AES-CBC",
      iv: recoveredIv,
    },
    symmKey,
    encryptedZipArrayBuffer
  );
  return decryptedZip;
}

// used this as an example
// https://github.com/infotechinc/symmetric-encryption-in-browser/blob/master/crypto.js
/**
 * Encrypt a blob with a symmetric key
 * @param {Object} symmKey The symmetric key
 * @param {Blob} data The blob to encrypt
 * @returns {Blob} The encrypted blob
 */
export async function encryptWithSymmetricKey(symmKey, data) {
  // encrypt the zip with symmetric key
  const iv = crypto.getRandomValues(new Uint8Array(16));

  const encryptedZipData = await crypto.subtle.encrypt(
    {
      name: "AES-CBC",
      iv,
    },
    symmKey,
    data
  );
  const encryptedZipBlob = new Blob([iv, new Uint8Array(encryptedZipData)], {
    type: "application/octet-stream",
  });
  return encryptedZipBlob;
}

// borrowed from eth-sig-util from meatmask.
/**
 * Encrypt a blob with the public key of a receiver
 * @param {string} receiverPublicKey The base64 encoded 32 byte public key.  The corresponding private key will be able to decrypt this blob
 * @param {Blob} data The blob to encrypt
 * @param {string} version The encryption algorithm to use.  This should be set to "x25519-xsalsa20-poly1305" as no other algorithms are implemented right now.
 * @returns {Blob} The encrypted blob
 */
export function encryptWithPubKey(receiverPublicKey, data, version) {
  switch (version) {
    case "x25519-xsalsa20-poly1305": {
      // generate ephemeral keypair
      const ephemeralKeyPair = nacl.box.keyPair();

      // assemble encryption parameters - from string to UInt8
      let pubKeyUInt8Array;
      try {
        pubKeyUInt8Array = naclUtil.decodeBase64(receiverPublicKey);
      } catch (err) {
        throw new Error("Bad public key");
      }

      // padding?  not needed for c decryption?
      // const paddingBytes = new Uint8Array(32)
      // paddingBytes.fill(0)
      // const msgParamsUInt8Array = new Uint8Array([...paddingBytes, ...naclUtil.decodeUTF8(data)])
      const msgParamsUInt8Array = naclUtil.decodeUTF8(data);
      const nonce = nacl.randomBytes(nacl.box.nonceLength);

      // encrypt
      const encryptedMessage = nacl.box(
        msgParamsUInt8Array,
        nonce,
        pubKeyUInt8Array,
        ephemeralKeyPair.secretKey
      );

      // handle encrypted data
      const output = {
        version: "x25519-xsalsa20-poly1305",
        nonce: naclUtil.encodeBase64(nonce),
        ephemPublicKey: naclUtil.encodeBase64(ephemeralKeyPair.publicKey),
        ciphertext: naclUtil.encodeBase64(encryptedMessage),
      };
      // return encrypted msg data
      return output;
    }

    default:
      throw new Error("Encryption type/version not supported");
  }
}

// borrowed from eth-sig-util from meatmask.
/**
 * Decrypt a blob with a private key
 * @param {Blob} encryptedData The blob to decrypt
 * @param {string} receiverPrivateKey The base64 encoded 32 byte private key.  The corresponding public key was used to encrypt this blob
 * @param {string} version The encryption algorithm to use.  This should be set to "x25519-xsalsa20-poly1305" as no other algorithms are implemented right now.
 * @returns {Blob} The decrypted blob
 */
export function decryptWithPrivKey(encryptedData, receiverPrivateKey) {
  switch (encryptedData.version) {
    case "x25519-xsalsa20-poly1305": {
      const recieverEncryptionPrivateKey =
        naclUtil.decodeBase64(receiverPrivateKey);

      // assemble decryption parameters
      const nonce = naclUtil.decodeBase64(encryptedData.nonce);
      const ciphertext = naclUtil.decodeBase64(encryptedData.ciphertext);
      const ephemPublicKey = naclUtil.decodeBase64(
        encryptedData.ephemPublicKey
      );

      // decrypt
      const decryptedMessage = nacl.box.open(
        ciphertext,
        nonce,
        ephemPublicKey,
        recieverEncryptionPrivateKey
      );

      // return decrypted msg data
      let output;
      try {
        output = naclUtil.encodeUTF8(decryptedMessage);
      } catch (err) {
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

export function combineEcdsaShares(sigShares) {
  // R_x & R_y values can come from any node (they will be different per node), and will generate a valid signature
  const R_x = sigShares[0].localX;
  const R_y = sigShares[0].localY;
  // the public key can come from any node - it obviously will be identical from each node
  const publicKey = sigShares[0].publicKey;
  const dataSigned = "0x" + sigShares[0].dataSigned;
  const validShares = sigShares.map((s) => s.shareHex);
  const shares = JSON.stringify(validShares);
  log("shares is", shares);
  const sig = JSON.parse(wasmECDSA.combine_signature(R_x, R_y, shares));

  log("signature", sig);

  return sig;
}

export function combineBlsShares(sigSharesWithEverything, networkPubKeySet) {
  const pkSetAsBytes = uint8arrayFromString(networkPubKeySet, "base16");
  log("pkSetAsBytes", pkSetAsBytes);

  const sigShares = sigSharesWithEverything.map((s) => ({
    shareHex: s.shareHex,
    shareIndex: s.shareIndex,
  }));
  const signature = wasmBlsSdkHelpers.combine_signatures(
    pkSetAsBytes,
    sigShares
  );
  // log("raw sig", signature);
  log("signature is ", uint8arrayToString(signature, "base16"));

  return { signature: uint8arrayToString(signature, "base16") };
}

export function combineBlsDecryptionShares(
  decryptionShares,
  networkPubKeySet,
  toDecrypt
) {
  // sort the decryption shares by share index.  this is important when combining the shares.
  decryptionShares.sort((a, b) => a.shareIndex - b.shareIndex);

  // combine the decryption shares
  // log("combineBlsDecryptionShares");
  // log("decryptionShares", decryptionShares);
  // log("networkPubKeySet", networkPubKeySet);
  // log("toDecrypt", toDecrypt);

  // set decryption shares bytes in wasm
  decryptionShares.forEach((s, idx) => {
    wasmExports.set_share_indexes(idx, s.shareIndex);
    const shareAsBytes = uint8arrayFromString(s.decryptionShare, "base16");
    for (let i = 0; i < shareAsBytes.length; i++) {
      wasmExports.set_decryption_shares_byte(i, idx, shareAsBytes[i]);
    }
  });

  // set the public key set bytes in wasm
  const pkSetAsBytes = uint8arrayFromString(networkPubKeySet, "base16");
  wasmBlsSdkHelpers.set_mc_bytes(pkSetAsBytes);

  // set the ciphertext bytes
  const ciphertextAsBytes = uint8arrayFromString(toDecrypt, "base16");
  for (let i = 0; i < ciphertextAsBytes.length; i++) {
    wasmExports.set_ct_byte(i, ciphertextAsBytes[i]);
  }

  const decrypted = wasmBlsSdkHelpers.combine_decryption_shares(
    decryptionShares.length,
    pkSetAsBytes.length,
    ciphertextAsBytes.length
  );
  // log("decrypted is ", uint8arrayToString(decrypted, "base16"));
  return decrypted;
}
