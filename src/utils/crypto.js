import nacl from "tweetnacl";
import naclUtil from "tweetnacl-util";
import uint8arrayFromString from "uint8arrays/from-string";
import { throwError } from "../lib/utils";

const SYMM_KEY_ALGO_PARAMS = {
  name: "AES-CBC",
  length: 256,
};

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
      returnValueTest: cond.returnValueTest,
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
