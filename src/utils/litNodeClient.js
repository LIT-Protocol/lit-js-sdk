import uint8arrayFromString from "uint8arrays/from-string";
import uint8arrayToString from "uint8arrays/to-string";
import naclUtil from "tweetnacl-util";

import { mostCommonString, throwError } from "../lib/utils";
import { wasmBlsSdkHelpers } from "../lib/bls-sdk";
import {
  hashAccessControlConditions,
  hashResourceId,
  canonicalAccessControlConditionFormatter,
  canonicalResourceIdFormatter,
} from "./crypto";

/**
 * @typedef {Object} AccessControlCondition
 * @property {string} contractAddress - The address of the contract that will be queried
 * @property {string} chain - The chain name of the chain that this contract is deployed on.  See LIT_CHAINS for currently supported chains.
 * @property {string} standardContractType - If the contract is an ERC20, ERC721, or ERC1155, please put that here
 * @property {string} method - The smart contract function to call
 * @property {Array} parameters - The parameters to use when calling the smart contract.  You can use the special ":userAddress" parameter which will be replaced with the requesting user's wallet address, verified via message signature
 * @property {Object} returnValueTest - An object containing two keys: "comparator" and "value".  The return value of the smart contract function will be compared against these.  For example, to check if someone holds an NFT, you could use "comparator: >" and "value: 0" which would check that a user has a token balance greater than zero.
 */

//  pub base_url: String,
//  pub path: String,
//  pub org_id: String,

/**
 * @typedef {Object} ResourceId
 * @property {string} baseUrl - The base url of the resource that will be authorized
 * @property {string} path - The path of the url of the resource that will be authorized
 * @property {string} orgId - Optional.  The org id that the user would be authorized to belong to.
 * @property {string} role - Optional.  The role that the user would be authorized to have.
 * @property {string} extraData - Optional.  Any extra data you may want to store.  You may store stringified JSON in here, for example.
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
 */
export default class LitNodeClient {
  constructor(config) {
    console.log("config passed in is ", config);
    this.config = {
      alertWhenUnauthorized: true,
      minNodeCount: 6,
      bootstrapUrls: [
        "https://node2.litgateway.com:7370",
        "https://node2.litgateway.com:7371",
        "https://node2.litgateway.com:7372",
        "https://node2.litgateway.com:7373",
        "https://node2.litgateway.com:7374",
        "https://node2.litgateway.com:7375",
        "https://node2.litgateway.com:7376",
        "https://node2.litgateway.com:7377",
        "https://node2.litgateway.com:7378",
        "https://node2.litgateway.com:7379",
      ],
    };
    if (config) {
      this.config = { ...this.config, ...config };
    }

    this.connectedNodes = new Set();
    this.serverKeys = {};
    this.ready = false;
    this.subnetPubKey = null;
    this.networkPubKey = null;
    this.networkPubKeySet = null;

    if (typeof window !== "undefined" && window && window.localStorage) {
      let configOverride = window.localStorage.getItem("LitNodeClientConfig");
      if (configOverride) {
        configOverride = JSON.parse(configOverride);
        this.config = { ...configOverride };
      }
    }
  }

  /**
   * Request a signed JWT of any solidity function call from the LIT network.  There are no prerequisites for this function.  You should use this function if you need to transmit information across chains, or from a blockchain to a centralized DB or server.  The signature of the returned JWT verifies that the response is genuine.
   * @param {Object} params
   * @param {Array.<CallRequest>} params.callRequests The call requests to make.  The responses will be signed and returned.
   * @param {string} params.chain The chain name of the chain that this contract is deployed on.  See LIT_CHAINS for currently supported chains.
   * @returns {Object} A signed JWT that proves the response to the function call is genuine. You may present this to a smart contract, or a server for authorization, and it can be verified using the verifyJwt function.
   */
  async getSignedChainDataToken({ callRequests, chain }) {
    // we need to send jwt params iat (issued at) and exp (expiration)
    // because the nodes may have different wall clock times
    // the nodes will verify that these params are withing a grace period
    const now = Date.now();
    const iat = Math.floor(now / 1000);
    const exp = iat + 12 * 60 * 60; // 12 hours in seconds

    // ask each node to sign the content
    const nodePromises = [];
    for (const url of this.connectedNodes) {
      nodePromises.push(
        this.getChainDataSigningShare({
          url,
          callRequests,
          chain,
          iat,
          exp,
        })
      );
    }
    const signatureShares = await Promise.all(nodePromises);
    console.log("signatureShares", signatureShares);
    const goodShares = signatureShares.filter((d) => d.signatureShare !== "");
    if (goodShares.length < this.config.minNodeCount) {
      console.log(
        `majority of shares are bad. goodShares is ${JSON.stringify(
          goodShares
        )}`
      );
      if (this.config.alertWhenUnauthorized) {
        alert(
          "You are not authorized to receive a signature to grant access to this content"
        );
      }

      throwError({
        message: `You are not authorized to recieve a signature on this item`,
        name: "UnauthorizedException",
        errorCode: "not_authorized",
      });
    }

    // sanity check
    if (
      !signatureShares.every(
        (val, i, arr) => val.unsignedJwt === arr[0].unsignedJwt
      )
    ) {
      const msg =
        "Unsigned JWT is not the same from all the nodes.  This means the combined signature will be bad because the nodes signed the wrong things";
      console.log(msg);
      alert(msg);
    }

    // sort the sig shares by share index.  this is important when combining the shares.
    signatureShares.sort((a, b) => a.shareIndex - b.shareIndex);

    // combine the signature shares

    const pkSetAsBytes = uint8arrayFromString(this.networkPubKeySet, "base16");
    console.log("pkSetAsBytes", pkSetAsBytes);

    const sigShares = signatureShares.map((s) => ({
      shareHex: s.signatureShare,
      shareIndex: s.shareIndex,
    }));
    const signature = wasmBlsSdkHelpers.combine_signatures(
      pkSetAsBytes,
      sigShares
    );
    console.log("raw sig", signature);
    console.log("signature is ", uint8arrayToString(signature, "base16"));

    const unsignedJwt = mostCommonString(
      signatureShares.map((s) => s.unsignedJwt)
    );

    // convert the sig to base64 and append to the jwt
    const finalJwt = `${unsignedJwt}.${uint8arrayToString(
      signature,
      "base64url"
    )}`;

    return finalJwt;
  }

  /**
   * Request a signed JWT from the LIT network.  Before calling this function, you must either create or know of a resource id and access control conditions for the item you wish to gain authorization for.  You can create an access control condition using the saveSigningCondition function.
   * @param {Object} params
   * @param {Array.<AccessControlCondition>} params.accessControlConditions The access control conditions that the user must meet to obtain this signed token.  This could be posession of an NFT, for example.
   * @param {string} params.chain The chain name of the chain that this contract is deployed on.  See LIT_CHAINS for currently supported chains.
   * @param {AuthSig} params.authSig The authentication signature that proves that the user owns the crypto wallet address that meets the access control conditions.
   * @param {ResourceId} params.resourceId The resourceId representing something on the web via a URL
   * @returns {Object} A signed JWT that proves you meet the access control conditions for the given resource id.  You may present this to a server for authorization, and the server can verify it using the verifyJwt function.
   */
  async getSignedToken({
    accessControlConditions,
    chain,
    authSig,
    resourceId,
  }) {
    // we need to send jwt params iat (issued at) and exp (expiration)
    // because the nodes may have different wall clock times
    // the nodes will verify that these params are withing a grace period
    const now = Date.now();
    const iat = Math.floor(now / 1000);
    const exp = iat + 12 * 60 * 60; // 12 hours in seconds

    const formattedAccessControlConditions = accessControlConditions.map((c) =>
      canonicalAccessControlConditionFormatter(c)
    );
    const formattedResourceId = canonicalResourceIdFormatter(resourceId);

    // ask each node to sign the content
    const nodePromises = [];
    for (const url of this.connectedNodes) {
      nodePromises.push(
        this.getSigningShare({
          url,
          accessControlConditions: formattedAccessControlConditions,
          resourceId: formattedResourceId,
          authSig,
          chain,
          iat,
          exp,
        })
      );
    }
    const signatureShares = await Promise.all(nodePromises);
    console.log("signatureShares", signatureShares);
    const goodShares = signatureShares.filter((d) => d.signatureShare !== "");
    if (goodShares.length < this.config.minNodeCount) {
      console.log(
        `majority of shares are bad. goodShares is ${JSON.stringify(
          goodShares
        )}`
      );
      if (this.config.alertWhenUnauthorized) {
        alert(
          "You are not authorized to receive a signature to grant access to this content"
        );
      }

      throwError({
        message: `You are not authorized to recieve a signature on this item`,
        name: "UnauthorizedException",
        errorCode: "not_authorized",
      });
    }

    // sanity check
    if (
      !signatureShares.every(
        (val, i, arr) => val.unsignedJwt === arr[0].unsignedJwt
      )
    ) {
      const msg =
        "Unsigned JWT is not the same from all the nodes.  This means the combined signature will be bad because the nodes signed the wrong things";
      console.log(msg);
      alert(msg);
    }

    // sort the sig shares by share index.  this is important when combining the shares.
    signatureShares.sort((a, b) => a.shareIndex - b.shareIndex);

    // combine the signature shares

    const pkSetAsBytes = uint8arrayFromString(this.networkPubKeySet, "base16");
    console.log("pkSetAsBytes", pkSetAsBytes);

    const sigShares = signatureShares.map((s) => ({
      shareHex: s.signatureShare,
      shareIndex: s.shareIndex,
    }));
    const signature = wasmBlsSdkHelpers.combine_signatures(
      pkSetAsBytes,
      sigShares
    );
    console.log("raw sig", signature);
    console.log("signature is ", uint8arrayToString(signature, "base16"));

    const unsignedJwt = mostCommonString(
      signatureShares.map((s) => s.unsignedJwt)
    );

    // convert the sig to base64 and append to the jwt
    const finalJwt = `${unsignedJwt}.${uint8arrayToString(
      signature,
      "base64url"
    )}`;

    return finalJwt;
  }

  /**
   * Associated access control conditions with a resource on the web.  After calling this function, users may use the getSignedToken function to request a signed JWT from the LIT network.  This JWT proves that the user meets the access control conditions, and is authorized to access the resource you specified in the resourceId parameter of the saveSigningCondition function.
   * @param {Object} params
   * @param {Array.<AccessControlCondition>} params.accessControlConditions The access control conditions that the user must meet to obtain a signed token.  This could be posession of an NFT, for example.
   * @param {string} params.chain The chain name of the chain that this contract is deployed on.  See LIT_CHAINS for currently supported chains.
   * @param {AuthSig} params.authSig The authentication signature that proves that the user owns the crypto wallet address that meets the access control conditions
   * @param {ResourceId} params.resourceId The resourceId representing something on the web via a URL
   * @returns {boolean} Success
   */
  async saveSigningCondition({
    accessControlConditions,
    chain,
    authSig,
    resourceId,
  }) {
    console.log("saveSigningCondition");

    // hash the resource id
    const hashOfResourceId = await hashResourceId(resourceId);
    const hashOfResourceIdStr = uint8arrayToString(
      new Uint8Array(hashOfResourceId),
      "base16"
    );

    // hash the access control conditions
    const hashOfConditions = await hashAccessControlConditions(
      accessControlConditions
    );
    const hashOfConditionsStr = uint8arrayToString(
      new Uint8Array(hashOfConditions),
      "base16"
    );
    // create access control conditions on lit nodes
    const nodePromises = [];
    for (const url of this.connectedNodes) {
      nodePromises.push(
        this.storeSigningConditionWithNode({
          url,
          key: hashOfResourceIdStr,
          val: hashOfConditionsStr,
          authSig,
          chain,
        })
      );
    }
    await Promise.all(nodePromises);

    return true;
  }

  /**
   * Retrieve the symmetric encryption key from the LIT nodes.  Note that this will only work if the current user meets the access control conditions specified when the data was encrypted.  That access control condition is typically that the user is a holder of the NFT that corresponds to this encrypted data.  This NFT token address and ID was specified when this LIT was created.
   * @param {Object} params
   * @param {Array.<AccessControlCondition>} params.accessControlConditions The access control conditions that the user must meet to obtain the encryption key, used to decrypt the data.  This could be posession of an NFT, for example.
   * @param {string} params.toDecrypt The ciphertext that you wish to decrypt
   * @param {string} params.chain The chain name of the chain that this contract is deployed on.  See LIT_CHAINS for currently supported chains.
   * @param {AuthSig} params.authSig The authentication signature that proves that the user owns the crypto wallet address meets the access control conditions.
   * @returns {Object} The symmetric encryption key that can be used to decrypt the locked content inside the LIT.  You should pass this key to the decryptZip function.
   */
  async getEncryptionKey({
    accessControlConditions,
    toDecrypt,
    chain,
    authSig,
  }) {
    // ask each node to decrypt the content
    const nodePromises = [];
    for (const url of this.connectedNodes) {
      nodePromises.push(
        this.getDecryptionShare({
          url,
          accessControlConditions,
          toDecrypt,
          authSig,
          chain,
        })
      );
    }
    const decryptionShares = await Promise.all(nodePromises);
    console.log("decryptionShares", decryptionShares);
    const goodShares = decryptionShares.filter((d) => d.decryptionShare !== "");
    if (goodShares.length < this.config.minNodeCount) {
      console.log(
        `majority of shares are bad. goodShares is ${JSON.stringify(
          goodShares
        )}`
      );
      if (this.config.alertWhenUnauthorized) {
        alert("You are not authorized to unlock this content");
      }

      throwError({
        message: `You are not authorized to unlock this item`,
        name: "UnauthorizedException",
        errorCode: "not_authorized",
      });
    }

    // sort the decryption shares by share index.  this is important when combining the shares.
    decryptionShares.sort((a, b) => a.shareIndex - b.shareIndex);

    // combine the decryption shares

    // set decryption shares bytes in wasm
    decryptionShares.forEach((s, idx) => {
      wasmExports.set_share_indexes(idx, s.shareIndex);
      const shareAsBytes = uint8arrayFromString(s.decryptionShare, "base16");
      for (let i = 0; i < shareAsBytes.length; i++) {
        wasmExports.set_decryption_shares_byte(i, idx, shareAsBytes[i]);
      }
    });

    // set the public key set bytes in wasm
    const pkSetAsBytes = uint8arrayFromString(this.networkPubKeySet, "base16");
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
    // console.log('decrypted is ', uint8arrayToString(decrypted, 'base16'))

    return decrypted;
  }

  /**
   * Securely save the association between access control conditions and something that you wish to decrypt
   * @param {Object} params
   * @param {Array.<AccessControlCondition>} params.accessControlConditions The access control conditions that the user must meet to obtain a signed token.  This could be posession of an NFT, for example.  Save this - you will neeed it to decrypt the content in the future.
   * @param {string} params.chain The chain name of the chain that this contract is deployed on.  See LIT_CHAINS for currently supported chains.
   * @param {AuthSig} params.authSig The authentication signature that proves that the user owns the crypto wallet address meets the access control conditions
   * @param {string} params.symmetricKey The symmetric encryption key that was used to encrypt the locked content inside the LIT.  You should use zipAndEncryptString or zipAndEncryptFiles to get this encryption key.  This key will be hashed and the hash will be sent to the LIT nodes.
   * @returns {Uint8Array} The symmetricKey parameter that has been encrypted with the network public key.  Save this - you will neeed it to decrypt the content in the future.
   */
  async saveEncryptionKey({
    accessControlConditions,
    chain,
    authSig,
    symmetricKey,
  }) {
    console.log("LitNodeClient.saveEncryptionKey");
    if (!symmetricKey || symmetricKey == "") {
      throw new Error("symmetricKey is blank");
    }
    if (!chain) {
      throw new Error("chain is blank");
    }
    if (!accessControlConditions || accessControlConditions.length == 0) {
      throw new Error("accessControlConditions is blank");
    }
    if (!authSig) {
      throw new Error("authSig is blank");
    }

    // encrypt with network pubkey
    const encryptedKey = wasmBlsSdkHelpers.encrypt(
      uint8arrayFromString(this.subnetPubKey, "base16"),
      symmetricKey
    );
    console.log(
      "symmetric key encrypted with LIT network key: ",
      uint8arrayToString(encryptedKey, "base16")
    );
    // hash the encrypted pubkey
    const hashOfKey = await crypto.subtle.digest("SHA-256", encryptedKey);
    const hashOfKeyStr = uint8arrayToString(
      new Uint8Array(hashOfKey),
      "base16"
    );

    // hash the access control conditions
    const hashOfConditions = await hashAccessControlConditions(
      accessControlConditions
    );
    const hashOfConditionsStr = uint8arrayToString(
      new Uint8Array(hashOfConditions),
      "base16"
    );
    // create access control conditions on lit nodes
    const nodePromises = [];
    for (const url of this.connectedNodes) {
      nodePromises.push(
        this.storeEncryptionConditionWithNode({
          url,
          key: hashOfKeyStr,
          val: hashOfConditionsStr,
          authSig,
          chain,
        })
      );
    }
    await Promise.all(nodePromises);

    return encryptedKey;
  }

  async storeSigningConditionWithNode({ url, key, val, authSig, chain }) {
    console.log("storeSigningConditionWithNode");
    const urlWithPath = `${url}/web/signing/store`;
    const data = {
      key,
      val,
      authSig,
      chain,
    };
    return await this.sendCommandToNode({ url: urlWithPath, data });
  }

  async storeEncryptionConditionWithNode({ url, key, val, authSig, chain }) {
    console.log("storeEncryptionConditionWithNode");
    const urlWithPath = `${url}/web/encryption/store`;
    const data = {
      key,
      val,
      authSig,
      chain,
    };
    return await this.sendCommandToNode({ url: urlWithPath, data });
  }

  async getChainDataSigningShare({ url, callRequests, chain, iat, exp }) {
    console.log("getChainDataSigningShare");
    const urlWithPath = `${url}/web/signing/sign_chain_data`;
    const data = {
      callRequests,
      chain,
      iat,
      exp,
    };
    return await this.sendCommandToNode({ url: urlWithPath, data });
  }

  async getSigningShare({
    url,
    accessControlConditions,
    resourceId,
    authSig,
    chain,
    iat,
    exp,
  }) {
    console.log("getSigningShare");
    const urlWithPath = `${url}/web/signing/retrieve`;
    const data = {
      accessControlConditions,
      resourceId,
      authSig,
      chain,
      iat,
      exp,
    };
    return await this.sendCommandToNode({ url: urlWithPath, data });
  }

  async getDecryptionShare({
    url,
    accessControlConditions,
    toDecrypt,
    authSig,
    chain,
  }) {
    console.log("getDecryptionShare");
    const urlWithPath = `${url}/web/encryption/retrieve`;
    const data = {
      accessControlConditions,
      toDecrypt,
      authSig,
      chain,
    };
    return await this.sendCommandToNode({ url: urlWithPath, data });
  }

  async handshakeWithSgx({ url }) {
    const urlWithPath = `${url}/web/handshake`;
    console.debug(`handshakeWithSgx ${urlWithPath}`);
    const data = {
      clientPublicKey: "test",
    };
    return await this.sendCommandToNode({ url: urlWithPath, data });
  }

  async sendCommandToNode({ url, data }) {
    console.log(`sendCommandToNode with url ${url} and data`, data);
    return await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(data),
    })
      .then((response) => response.json())
      .then((data) => {
        console.log("Success:", data);
        return data;
      });
  }

  async connect() {
    // handshake with each node
    for (const url of this.config.bootstrapUrls) {
      this.handshakeWithSgx({ url }).then((resp) => {
        this.connectedNodes.add(url);
        this.serverKeys[url] = {
          serverPubKey: resp.serverPublicKey,
          subnetPubKey: resp.subnetPublicKey,
          networkPubKey: resp.networkPublicKey,
          networkPubKeySet: resp.networkPublicKeySet,
        };
      });
    }

    const interval = window.setInterval(() => {
      if (Object.keys(this.serverKeys).length >= this.config.minNodeCount) {
        clearInterval(interval);
        // pick the most common public keys for the subnet and network from the bunch, in case some evil node returned a bad key
        this.subnetPubKey = mostCommonString(
          Object.values(this.serverKeys).map(
            (keysFromSingleNode) => keysFromSingleNode.subnetPubKey
          )
        );
        this.networkPubKey = mostCommonString(
          Object.values(this.serverKeys).map(
            (keysFromSingleNode) => keysFromSingleNode.networkPubKey
          )
        );
        this.networkPubKeySet = mostCommonString(
          Object.values(this.serverKeys).map(
            (keysFromSingleNode) => keysFromSingleNode.networkPubKeySet
          )
        );
        this.ready = true;
        console.debug("lit is ready");
        document.dispatchEvent(new Event("lit-ready"));
      }
    }, 500);

    window.wasmBlsSdkHelpers = wasmBlsSdkHelpers; // for debug
  }
}
