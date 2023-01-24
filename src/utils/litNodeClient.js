import Uint8arrays from "../lib/uint8arrays";
const uint8arrayFromString = Uint8arrays.fromString;
const uint8arrayToString = Uint8arrays.toString;
import naclUtil from "tweetnacl-util";
import nacl from "tweetnacl";
import { LIT_CHAINS } from "../lib/constants";
import { version } from "../version";
import { serialize } from "@ethersproject/transactions";

import {
  mostCommonString,
  throwError,
  log,
  checkType,
  checkIfAuthSigRequiresChainParam,
  convertLitActionsParams,
} from "../lib/utils";
import { wasmBlsSdkHelpers } from "../lib/bls-sdk";
import * as wasmECDSA from "../lib/ecdsa-sdk";
import { joinSignature } from "@ethersproject/bytes";
import { computeAddress } from "@ethersproject/transactions";
import { SiweMessage } from "lit-siwe";
import { generateSessionKeyPair } from "./crypto";

import {
  getSessionKeyUri,
  parseResource,
  checkAndSignAuthMessage,
  configure,
} from "./lit";

import {
  hashAccessControlConditions,
  hashEVMContractConditions,
  hashSolRpcConditions,
  hashResourceId,
  hashUnifiedAccessControlConditions,
  canonicalAccessControlConditionFormatter,
  canonicalEVMContractConditionFormatter,
  canonicalSolRpcConditionFormatter,
  canonicalResourceIdFormatter,
  canonicalUnifiedAccessControlConditionFormatter,
  combineEcdsaShares,
  combineBlsShares,
  combineBlsDecryptionShares,
} from "./crypto";
import { Base64 } from "js-base64";

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
  constructor(config) {
    // configure() also stores config to `globalThis.litConfig`, see function def
    this.config = configure(config);

    this.connectedNodes = new Set();
    this.serverKeys = {};
    this.ready = false;
    this.subnetPubKey = null;
    this.networkPubKey = null;
    this.networkPubKeySet = null;
  }

  /**
   * Crafts & signs the transaction using LitActions.signEcdsa() on the given chain
   * @param {Object} params
   * @param {string} params.to The "to" parameter in the transaction
   * @param {string} params.value The "value" parameter in the transaction
   * @param {string} params.data The "data" parameter in the transaction
   * @param {string} params.chain Used to get the "chainId" parameter in the transaction
   * @param {string} params.publicKey The publicKey used in the LitActions.signEcdsa() function
   * @param {string} params.gasPrice [Optional] The "gasPrice" parameter in the transaction
   * @param {string} params.gasLimit [Optional] The "gasLimit" parameter in the transaction
   * @returns {Object} An object containing the resulting signature.
   */
  async signPKPTransaction({
    to,
    value,
    data,
    chain,
    publicKey,
    gasPrice,
    gasLimit,
  }) {
    if (!this.ready) {
      throwError({
        message:
          "LitNodeClient is not ready.  Please call await litNodeClient.connect() first.",
        name: "LitNodeClientNotReadyError",
        errorCode: "lit_node_client_not_ready",
      });
    }

    const chainId = LIT_CHAINS[chain].chainId;
    if (!chainId) {
      throwError({
        message: "Invalid chain.  Please pass a valid chain.",
        name: "InvalidChain",
        errorCode: "invalid_input_chain",
      });
    }

    if (!publicKey) {
      throwError({
        message: "Pubic Key not provided.  Please pass a valid Public Key.",
        name: "MissingPublicKey",
        errorCode: "missing_public_key",
      });
    }

    const authSig = await checkAndSignAuthMessage({ chain });

    const signLitTransaction = `
      (async () => {
        const fromAddress = ethers.utils.computeAddress(publicKey);
        const latestNonce = await LitActions.getLatestNonce({ address: fromAddress, chain });
        const txParams = {
          nonce: latestNonce,
          gasPrice,
          gasLimit,
          to,
          value,
          chainId,
          data,
        };

        LitActions.setResponse({ response: JSON.stringify(txParams) });
        
        const serializedTx = ethers.utils.serializeTransaction(txParams);
        const rlpEncodedTxn = ethers.utils.arrayify(serializedTx);
        const unsignedTxn =  ethers.utils.arrayify(ethers.utils.keccak256(rlpEncodedTxn));

        const sigShare = await LitActions.signEcdsa({ toSign: unsignedTxn, publicKey, sigName });
      })();
    `;

    return await this.executeJs({
      code: signLitTransaction,
      authSig,
      jsParams: {
        publicKey,
        chain,
        sigName: "sig1",
        chainId,
        to,
        value,
        data,
        gasPrice: gasPrice || "0x2e90edd000",
        gasLimit: gasLimit || "0x" + (30000).toString(16),
      },
    });
  }

  /**
   * Signs & sends the transaction using the Provider on the given chain
   * @param {Object} params
   * @param {Object} params.provider The provider used to send the signed transaction to the appropriate network
   * @param {string} params.to The "to" parameter in the transaction
   * @param {string} params.value The "value" parameter in the transaction
   * @param {string} params.data The "data" parameter in the transaction
   * @param {string} params.chain Used to get the "chainId" parameter in the transaction
   * @param {string} params.publicKey The publicKey used in the LitActions.signEcdsa() function
   * @param {string} params.gasPrice [Optional] The "gasPrice" parameter in the transaction
   * @param {string} params.gasLimit [Optional] The "gasLimit" parameter in the transaction
   * @returns {Object} A promise of the corresponding TransactionResponse.
   */
  async sendPKPTransaction({
    provider,
    to,
    value,
    data,
    chain,
    publicKey,
    gasPrice,
    gasLimit,
  }) {
    const signResult = await this.signPKPTransaction({
      to,
      value,
      data,
      gasPrice,
      gasLimit,
      chain,
      publicKey,
    });

    const tx = signResult.response;
    const signature = signResult.signatures["sig1"].signature;
    const serializedTx = serialize(tx, signature);
    return provider.sendTransaction(serializedTx);
  }

  /**
   * Execute JS on the nodes and combine and return any resulting signatures
   * @param {Object} params
   * @param {string} params.code JS code to run on the nodes
   * @param {string} params.ipfsId The IPFS ID of some JS code to run on the nodes
   * @param {AuthSig} params.authSig the authSig to use to authorize the user with the nodes
   * @param {Object} params.jsParams An object that contains params to expose to the Lit Action.  These will be injected to the JS runtime before your code runs, so you can use any of these as normal variables in your Lit Action.
   * @param {Boolean} params.debug A boolean that defines if debug info will be returned or not.
   * @returns {Object} An object containing the resulting signatures.  Each signature comes with the public key and the data signed.
   */
  async executeJs({
    code,
    ipfsId,
    authSig,
    sessionSigs,
    authMethods = [],
    jsParams = {},
    debug,
  }) {
    if (!this.ready) {
      throwError({
        message:
          "LitNodeClient is not ready.  Please call await litNodeClient.connect() first.",
        name: "LitNodeClientNotReadyError",
        errorCode: "lit_node_client_not_ready",
      });
    }

    // -- validate
    if (
      authSig &&
      !checkType({
        value: authSig,
        allowedTypes: ["Object"],
        paramName: "authSig",
        functionName: "executeJs",
      })
    )
      return;

    if (
      sessionSigs &&
      !checkType({
        value: sessionSigs,
        allowedTypes: ["Object"],
        paramName: "sessionSigs",
        functionName: "executeJs",
      })
    )
      return;

    if (!sessionSigs && !authSig) {
      throwError({
        message: "You must pass either authSig or sessionSigs",
        name: "InvalidArgumentException",
        errorCode: "invalid_argument",
      });
      return;
    }

    // some JS types don't serialize well, so we will convert them before sending to the nodes
    jsParams = convertLitActionsParams(jsParams);

    // generate a unique id for this request
    const requestId = Math.random().toString(16).slice(2);

    const reqBody = { authSig, jsParams, authMethods, requestId };
    if (code) {
      // base64 encode before sending over the wire
      const encodedJs = uint8arrayToString(
        uint8arrayFromString(code, "utf8"),
        "base64"
      );
      reqBody.code = encodedJs;
    } else if (ipfsId) {
      reqBody.ipfsId = ipfsId;
    } else {
      throwError({
        message: "You must pass either code or ipfsId",
        name: "MissingParameterError",
        errorCode: "missing_parameter",
      });
    }

    // log("sending request to all nodes for executeJs: ", reqBody);

    // ask each node to run the js
    const nodePromises = [];
    for (const url of this.connectedNodes) {
      let sigToPassToNode = authSig;
      if (sessionSigs) {
        // find the sessionSig for this node
        sigToPassToNode = sessionSigs[url];
        if (!sigToPassToNode) {
          throwError({
            message: `You passed sessionSigs but we could not find session sig for node ${url}`,
            name: "InvalidArgumentException",
            errorCode: "invalid_argument",
          });
        }
      }
      reqBody.authSig = sigToPassToNode;
      nodePromises.push(
        this.getJsExecutionShares({
          url,
          ...reqBody,
        })
      );
    }
    const res = await this.handleNodePromises(nodePromises);
    if (res.success === false) {
      this.throwNodeError(res);
      return;
    }
    const responseData = res.values;

    log("responseData", JSON.stringify(responseData, null, 2));

    // combine the signatures
    const signedData = responseData.map((r) => r.signedData);

    const signatures = {};
    Object.keys(signedData[0]).forEach((key) => {
      const shares = signedData.map((r) => r[key]);
      shares.sort((a, b) => a.shareIndex - b.shareIndex);
      const sigShares = shares.map((s) => ({
        sigType: s.sigType,
        shareHex: s.signatureShare,
        shareIndex: s.shareIndex,
        localX: s.localX,
        localY: s.localY,
        publicKey: s.publicKey,
        dataSigned: s.dataSigned,
      }));
      log("sigShares", sigShares);
      const sigType = mostCommonString(sigShares.map((s) => s.sigType));
      let signature;
      if (sigType === "BLS") {
        signature = combineBlsShares(sigShares, this.networkPubKeySet);
      } else if (sigType === "ECDSA") {
        const goodShares = sigShares.filter((d) => d.shareHex !== "");
        if (goodShares.length < this.config.minNodeCount) {
          log(
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
        signature = combineEcdsaShares(goodShares);
      } else {
        throwError({
          message: "Unknown signature type",
          name: "UnknownSignatureTypeError",
          errorCode: "unknown_signature_type",
        });
      }

      const encodedSig = joinSignature({
        r: "0x" + signature.r,
        s: "0x" + signature.s,
        v: signature.recid,
      });

      signatures[key] = {
        ...signature,
        signature: encodedSig,
        publicKey: "0x" + mostCommonString(sigShares.map((s) => s.publicKey)),
        dataSigned: "0x" + mostCommonString(sigShares.map((s) => s.dataSigned)),
      };
    });

    // combine the decryptions
    const decryptedData = responseData.map((r) => r.decryptedData);

    const decryptions = {};
    Object.keys(decryptedData[0]).forEach((key) => {
      const shares = decryptedData.map((r) => r[key]);
      const decShares = shares.map((s) => ({
        algorithmType: s.algorithmType,
        decryptionShare: s.decryptionShare,
        shareIndex: s.shareIndex,
        publicKey: s.publicKey,
        ciphertext: s.ciphertext,
      }));
      const algorithmType = mostCommonString(
        decShares.map((s) => s.algorithmType)
      );
      const ciphertext = mostCommonString(decShares.map((s) => s.ciphertext));
      let decrypted;
      if (algorithmType === "BLS") {
        decrypted = combineBlsDecryptionShares(
          decShares,
          this.networkPubKeySet,
          ciphertext
        );
      } else {
        throwError({
          message: "Unknown decryption algorithm type",
          name: "UnknownDecryptionAlgorithmTypeError",
          errorCode: "unknown_decryption_algorithm_type",
        });
      }

      decryptions[key] = {
        decrypted: uint8arrayToString(decrypted, "base16"),
        publicKey: mostCommonString(decShares.map((s) => s.publicKey)),
        ciphertext: mostCommonString(decShares.map((s) => s.ciphertext)),
      };
    });

    let response = mostCommonString(responseData.map((r) => r.response));
    try {
      response = JSON.parse(response);
    } catch (e) {
      log(
        "Error parsing response as json.  Swallowing and returning as string.",
        response
      );
    }

    const mostCommonLogs = mostCommonString(responseData.map((r) => r.logs));

    let returnVal = {
      signatures,
      decryptions,
      response,
      logs: mostCommonLogs,
    };

    if (debug) {
      const allNodeResponses = responseData.map((r) => r.response);
      const allNodeLogs = responseData.map((r) => r.logs);
      returnVal.debug = {
        allNodeResponses,
        allNodeLogs,
        rawNodeHTTPResponses: responseData,
      };
    }

    return returnVal;
  }

  /**
   * Sign a session key using a PKP
   * @param {Object} params
   * @param {string} params.sessionKey The session key to sign
   * @param {Array<Object>} params.authMethods The auth methods to try for authenticating with the PKP.  You must pass either at least 1 AuthMethod or an authSig
   * @param {AuthSig} params.authSig The authSig to use try for authenticating with the PKP.  You must pass either at least 1 AuthMethod or an authSig
   * @param {Object} params.pkpPublicKey The PKP public key to use for signing
   * @param {String} params.expiration When this session signature will expire.  The user will have to reauthenticate after this time using whatever auth method you set up.  This means you will have to call this signSessionKey function again to get a new session signature.  This is a RFC3339 timestamp.  The default is 24 hours from now.
   * @returns {Object} An object containing the resulting signature.
   */
  async signSessionKey({
    sessionKey,
    authMethods,
    pkpPublicKey,
    authSig,
    expiration,
    resources = [],
    chain,
  }) {
    if (!this.ready) {
      throwError({
        message:
          "LitNodeClient is not ready.  Please call await litNodeClient.connect() first.",
        name: "LitNodeClientNotReadyError",
        errorCode: "lit_node_client_not_ready",
      });
    }

    const pkpEthAddress = computeAddress(pkpPublicKey);

    let siweMessage = new SiweMessage({
      domain: globalThis.location.host,
      address: pkpEthAddress,
      statement: "Lit Protocol PKP session signature",
      uri: sessionKey,
      version: "1",
      chainId: "1",
      expirationTime:
        expiration || new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
      resources,
    });
    siweMessage = siweMessage.prepareMessage();

    // generate a unique id for this request
    const requestId = Math.random().toString(16).slice(2);

    /* body must include:
    pub session_key: String,
    pub auth_methods: Vec<AuthMethod>,
    pub pkp_public_key: String,
    pub auth_sig: Option<AuthSigItem>,
    pub siwe_message: String,
    */
    const reqBody = {
      sessionKey,
      authMethods,
      pkpPublicKey,
      authSig,
      siweMessage,
      requestId,
    };

    // log("sending request to all nodes for signSessionKey: ", reqBody);

    // ask each node to run the js
    const nodePromises = [];
    for (const url of this.connectedNodes) {
      nodePromises.push(
        this.getSignSessionKeyShares({
          url,
          body: reqBody,
        })
      );
    }
    const res = await this.handleNodePromises(nodePromises);
    if (res.success === false) {
      this.throwNodeError(res);
      return;
    }
    const responseData = res.values;

    log("responseData", JSON.stringify(responseData, null, 2));

    // combine the signatures
    const signedData = responseData.map((r) => r.signedData);

    const signatures = {};
    Object.keys(signedData[0]).forEach((key) => {
      const shares = signedData.map((r) => r[key]);
      shares.sort((a, b) => a.shareIndex - b.shareIndex);
      const sigShares = shares.map((s) => ({
        sigType: s.sigType,
        shareHex: s.signatureShare,
        shareIndex: s.shareIndex,
        localX: s.localX,
        localY: s.localY,
        publicKey: s.publicKey,
        dataSigned: s.dataSigned,
        siweMessage: s.siweMessage,
      }));
      log("sigShares", sigShares);
      const sigType = mostCommonString(sigShares.map((s) => s.sigType));
      let signature;
      if (sigType === "BLS") {
        signature = combineBlsShares(sigShares, this.networkPubKeySet);
      } else if (sigType === "ECDSA") {
        signature = combineEcdsaShares(sigShares);
      } else {
        throwError({
          message: "Unknown signature type",
          name: "UnknownSignatureTypeError",
          errorCode: "unknown_signature_type",
        });
      }

      const encodedSig = joinSignature({
        r: "0x" + signature.r,
        s: "0x" + signature.s,
        v: signature.recid,
      });

      signatures[key] = {
        ...signature,
        signature: encodedSig,
        publicKey: "0x" + mostCommonString(sigShares.map((s) => s.publicKey)),
        dataSigned: "0x" + mostCommonString(sigShares.map((s) => s.dataSigned)),
        siweMessage: mostCommonString(sigShares.map((s) => s.siweMessage)),
      };
    });

    const { sessionSig } = signatures;

    return {
      sig: sessionSig.signature,
      derivedVia: "web3.eth.personal.sign via Lit PKP",
      signedMessage: sessionSig.siweMessage,
      address: computeAddress(sessionSig.publicKey),
    };
  }

  /**
   * Request a signed JWT of any solidity function call from the LIT network.  There are no prerequisites for this function.  You should use this function if you need to transmit information across chains, or from a blockchain to a centralized DB or server.  The signature of the returned JWT verifies that the response is genuine.
   * @param {Object} params
   * @param {Array.<CallRequest>} params.callRequests The call requests to make.  The responses will be signed and returned.
   * @param {string} params.chain The chain name of the chain that this contract is deployed on.  See LIT_CHAINS for currently supported chains.
   * @returns {Object} A signed JWT that proves the response to the function call is genuine. You may present this to a smart contract, or a server for authorization, and it can be verified using the verifyJwt function.
   */
  async getSignedChainDataToken({ callRequests, chain }) {
    if (!this.ready) {
      throwError({
        message:
          "LitNodeClient is not ready.  Please call await litNodeClient.connect() first.",
        name: "LitNodeClientNotReadyError",
        errorCode: "lit_node_client_not_ready",
      });
    }

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
    log("signatureShares", signatureShares);
    const goodShares = signatureShares.filter((d) => d.signatureShare !== "");
    if (goodShares.length < this.config.minNodeCount) {
      log(
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
      log(msg);
      alert(msg);
    }

    // sort the sig shares by share index.  this is important when combining the shares.
    signatureShares.sort((a, b) => a.shareIndex - b.shareIndex);

    // combine the signature shares

    const pkSetAsBytes = uint8arrayFromString(this.networkPubKeySet, "base16");
    log("pkSetAsBytes", pkSetAsBytes);

    const sigShares = signatureShares.map((s) => ({
      shareHex: s.signatureShare,
      shareIndex: s.shareIndex,
    }));
    const signature = wasmBlsSdkHelpers.combine_signatures(
      pkSetAsBytes,
      sigShares
    );
    log("raw sig", signature);
    log("signature is ", uint8arrayToString(signature, "base16"));

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
   * @param {Array.<AccessControlCondition>} params.accessControlConditions The access control conditions that the user must meet to obtain this signed token.  This could be posession of an NFT, for example.  You must pass either accessControlConditions or evmContractConditions or solRpcConditions or unifiedAccessControlConditions.
   * @param {Array.<EVMContractCondition>} params.evmContractConditions  EVM Smart Contract access control conditions that the user must meet to obtain this signed token.  This could be posession of an NFT, for example.  This is different than accessControlConditions because accessControlConditions only supports a limited number of contract calls.  evmContractConditions supports any contract call.  You must pass either accessControlConditions or evmContractConditions solRpcConditions or unifiedAccessControlConditions.
   * @param {Array.<SolRpcCondition>} params.solRpcConditions  Solana RPC call conditions that the user must meet to obtain this signed token.  This could be posession of an NFT, for example.
   * @param {Array.<AccessControlCondition|EVMContractCondition|SolRpcCondition>} params.unifiedAccessControlConditions  An array of unified access control conditions.  You may use AccessControlCondition, EVMContractCondition, or SolRpcCondition objects in this array, but make sure you add a conditionType for each one.  You must pass either accessControlConditions or evmContractConditions or solRpcConditions or unifiedAccessControlConditions.
   * @param {string} params.chain The chain name of the chain that you are querying.  See ALL_LIT_CHAINS for currently supported chains.
   * @param {AuthSig} params.authSig The authentication signature that proves that the user owns the crypto wallet address that meets the access control conditions.
   * @param {ResourceId} params.resourceId The resourceId representing something on the web via a URL
   * @returns {Object} A signed JWT that proves you meet the access control conditions for the given resource id.  You may present this to a server for authorization, and the server can verify it using the verifyJwt function.
   */
  async getSignedToken({
    accessControlConditions,
    evmContractConditions,
    solRpcConditions,
    unifiedAccessControlConditions,
    chain,
    authSig,
    resourceId,
    sessionSigs,
  }) {
    if (!this.ready) {
      throwError({
        message:
          "LitNodeClient is not ready.  Please call await litNodeClient.connect() first.",
        name: "LitNodeClientNotReadyError",
        errorCode: "lit_node_client_not_ready",
      });
    }

    // -- validate
    if (
      accessControlConditions &&
      !checkType({
        value: accessControlConditions,
        allowedTypes: ["Array"],
        paramName: "accessControlConditions",
        functionName: "getSignedToken",
      })
    )
      return;
    if (
      evmContractConditions &&
      !checkType({
        value: evmContractConditions,
        allowedTypes: ["Array"],
        paramName: "evmContractConditions",
        functionName: "getSignedToken",
      })
    )
      return;
    if (
      solRpcConditions &&
      !checkType({
        value: solRpcConditions,
        allowedTypes: ["Array"],
        paramName: "solRpcConditions",
        functionName: "getSignedToken",
      })
    )
      return;
    if (
      unifiedAccessControlConditions &&
      !checkType({
        value: unifiedAccessControlConditions,
        allowedTypes: ["Array"],
        paramName: "unifiedAccessControlConditions",
        functionName: "getSignedToken",
      })
    )
      return;
    if (
      !checkType({
        value: resourceId,
        allowedTypes: ["Object"],
        paramName: "resourceId",
        functionName: "getSignedToken",
      })
    )
      return;
    if (
      authSig &&
      !checkType({
        value: authSig,
        allowedTypes: ["Object"],
        paramName: "authSig",
        functionName: "getSignedToken",
      })
    )
      return;

    // log("sessionSigs", sessionSigs);

    if (
      sessionSigs &&
      !checkType({
        value: sessionSigs,
        allowedTypes: ["Object"],
        paramName: "sessionSigs",
        functionName: "getSignedToken",
      })
    )
      return;

    if (!sessionSigs && !authSig) {
      throwError({
        message: "You must pass either authSig or sessionSigs",
        name: "InvalidArgumentException",
        errorCode: "invalid_argument",
      });
      return;
    }

    if (
      authSig &&
      !checkIfAuthSigRequiresChainParam(authSig, chain, "getSignedToken")
    )
      return;

    // we need to send jwt params iat (issued at) and exp (expiration)
    // because the nodes may have different wall clock times
    // the nodes will verify that these params are withing a grace period
    const now = Date.now();
    const iat = Math.floor(now / 1000);
    const exp = iat + 12 * 60 * 60; // 12 hours in seconds

    let formattedAccessControlConditions;
    let formattedEVMContractConditions;
    let formattedSolRpcConditions;
    let formattedUnifiedAccessControlConditions;
    if (accessControlConditions) {
      formattedAccessControlConditions = accessControlConditions.map((c) =>
        canonicalAccessControlConditionFormatter(c)
      );
      log(
        "formattedAccessControlConditions",
        JSON.stringify(formattedAccessControlConditions)
      );
    } else if (evmContractConditions) {
      formattedEVMContractConditions = evmContractConditions.map((c) =>
        canonicalEVMContractConditionFormatter(c)
      );
      log(
        "formattedEVMContractConditions",
        JSON.stringify(formattedEVMContractConditions)
      );
    } else if (solRpcConditions) {
      formattedSolRpcConditions = solRpcConditions.map((c) =>
        canonicalSolRpcConditionFormatter(c)
      );
      log(
        "formattedSolRpcConditions",
        JSON.stringify(formattedSolRpcConditions)
      );
    } else if (unifiedAccessControlConditions) {
      formattedUnifiedAccessControlConditions =
        unifiedAccessControlConditions.map((c) =>
          canonicalUnifiedAccessControlConditionFormatter(c)
        );
      log(
        "formattedUnifiedAccessControlConditions",
        JSON.stringify(formattedUnifiedAccessControlConditions)
      );
    } else {
      throwError({
        message: `You must provide either accessControlConditions or evmContractConditions or solRpcConditions or unifiedAccessControlConditions`,
        name: "InvalidArgumentException",
        errorCode: "invalid_argument",
      });
    }

    const formattedResourceId = canonicalResourceIdFormatter(resourceId);

    // ask each node to sign the content
    const nodePromises = [];
    for (const url of this.connectedNodes) {
      let sigToPassToNode = authSig;
      if (sessionSigs) {
        // find the sessionSig for this node
        sigToPassToNode = sessionSigs[url];
        if (!sigToPassToNode) {
          throwError({
            message: `You passed sessionSigs but we could not find session sig for node ${url}`,
            name: "InvalidArgumentException",
            errorCode: "invalid_argument",
          });
        }
      }
      nodePromises.push(
        this.getSigningShare({
          url,
          accessControlConditions: formattedAccessControlConditions,
          evmContractConditions: formattedEVMContractConditions,
          solRpcConditions: formattedSolRpcConditions,
          unifiedAccessControlConditions:
            formattedUnifiedAccessControlConditions,
          resourceId: formattedResourceId,
          authSig: sigToPassToNode,
          chain,
          iat,
          exp,
        })
      );
    }

    const res = await this.handleNodePromises(nodePromises);
    if (res.success === false) {
      this.throwNodeError(res);
      return;
    }
    const signatureShares = res.values;
    log("signatureShares", signatureShares);

    // sanity check
    if (
      !signatureShares.every(
        (val, i, arr) => val.unsignedJwt === arr[0].unsignedJwt
      )
    ) {
      const msg =
        "Unsigned JWT is not the same from all the nodes.  This means the combined signature will be bad because the nodes signed the wrong things";
      log(msg);
      alert(msg);
    }

    // sort the sig shares by share index.  this is important when combining the shares.
    signatureShares.sort((a, b) => a.shareIndex - b.shareIndex);

    // combine the signature shares

    const pkSetAsBytes = uint8arrayFromString(this.networkPubKeySet, "base16");
    log("pkSetAsBytes", pkSetAsBytes);

    const sigShares = signatureShares.map((s) => ({
      shareHex: s.signatureShare,
      shareIndex: s.shareIndex,
    }));
    const signature = wasmBlsSdkHelpers.combine_signatures(
      pkSetAsBytes,
      sigShares
    );
    log("raw sig", signature);
    log("signature is ", uint8arrayToString(signature, "base16"));

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
  async saveSigningCondition({
    accessControlConditions,
    evmContractConditions,
    solRpcConditions,
    unifiedAccessControlConditions,
    chain,
    authSig,
    resourceId,
    permanant,
    permanent = true,
    sessionSigs,
  }) {
    log("saveSigningCondition");

    if (!this.ready) {
      throwError({
        message:
          "LitNodeClient is not ready.  Please call await litNodeClient.connect() first.",
        name: "LitNodeClientNotReadyError",
        errorCode: "lit_node_client_not_ready",
      });
    }

    // -- validate
    if (
      accessControlConditions &&
      !checkType({
        value: accessControlConditions,
        allowedTypes: ["Array"],
        paramName: "accessControlConditions",
        functionName: "getSignedToken",
      })
    )
      return;
    if (
      evmContractConditions &&
      !checkType({
        value: evmContractConditions,
        allowedTypes: ["Array"],
        paramName: "evmContractConditions",
        functionName: "getSignedToken",
      })
    )
      return;
    if (
      solRpcConditions &&
      !checkType({
        value: solRpcConditions,
        allowedTypes: ["Array"],
        paramName: "solRpcConditions",
        functionName: "getSignedToken",
      })
    )
      return;
    if (
      unifiedAccessControlConditions &&
      !checkType({
        value: unifiedAccessControlConditions,
        allowedTypes: ["Array"],
        paramName: "unifiedAccessControlConditions",
        functionName: "getSignedToken",
      })
    )
      return;
    if (
      !checkType({
        value: resourceId,
        allowedTypes: ["Object"],
        paramName: "resourceId",
        functionName: "getSignedToken",
      })
    )
      return;
    if (
      authSig &&
      !checkType({
        value: authSig,
        allowedTypes: ["Object"],
        paramName: "authSig",
        functionName: "getSignedToken",
      })
    )
      return;

    log("sessionSigs", sessionSigs);

    if (
      sessionSigs &&
      !checkType({
        value: sessionSigs,
        allowedTypes: ["Object"],
        paramName: "sessionSigs",
        functionName: "getSignedToken",
      })
    )
      return;

    if (!sessionSigs && !authSig) {
      throwError({
        message: "You must pass either authSig or sessionSigs",
        name: "InvalidArgumentException",
        errorCode: "invalid_argument",
      });
      return;
    }

    if (
      authSig &&
      !checkIfAuthSigRequiresChainParam(authSig, chain, "getSignedToken")
    )
      return;

    // this is to fix my spelling mistake that we must now maintain forever lol
    if (typeof permanant !== "undefined") {
      permanent = permanant;
    }

    // hash the resource id
    const hashOfResourceId = await hashResourceId(resourceId);
    const hashOfResourceIdStr = uint8arrayToString(
      new Uint8Array(hashOfResourceId),
      "base16"
    );

    let hashOfConditions;
    // hash the access control conditions
    if (accessControlConditions) {
      hashOfConditions = await hashAccessControlConditions(
        accessControlConditions
      );
    } else if (evmContractConditions) {
      hashOfConditions = await hashEVMContractConditions(evmContractConditions);
    } else if (solRpcConditions) {
      hashOfConditions = await hashSolRpcConditions(solRpcConditions);
    } else if (unifiedAccessControlConditions) {
      hashOfConditions = await hashUnifiedAccessControlConditions(
        unifiedAccessControlConditions
      );
    } else {
      throwError({
        message: `You must provide either accessControlConditions or evmContractConditions or solRpcConditions or unifiedAccessControlConditions`,
        name: "InvalidArgumentException",
        errorCode: "invalid_argument",
      });
    }

    const hashOfConditionsStr = uint8arrayToString(
      new Uint8Array(hashOfConditions),
      "base16"
    );
    // create access control conditions on lit nodes
    const nodePromises = [];
    for (const url of this.connectedNodes) {
      let authSigToSend = authSig;
      if (sessionSigs) {
        // use a separate authSig for each node
        authSigToSend = sessionSigs[url];
      }
      nodePromises.push(
        this.storeSigningConditionWithNode({
          url,
          key: hashOfResourceIdStr,
          val: hashOfConditionsStr,
          authSig: authSigToSend,
          chain,
          permanent: permanent ? 1 : 0,
        })
      );
    }

    const res = await this.handleNodePromises(nodePromises);
    if (res.success === false) {
      this.throwNodeError(res);
      return;
    }

    return true;
  }

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
  async getEncryptionKey({
    accessControlConditions,
    evmContractConditions,
    solRpcConditions,
    unifiedAccessControlConditions,
    toDecrypt,
    chain,
    authSig,
    sessionSigs,
  }) {
    if (!this.ready) {
      throwError({
        message:
          "LitNodeClient is not ready.  Please call await litNodeClient.connect() first.",
        name: "LitNodeClientNotReadyError",
        errorCode: "lit_node_client_not_ready",
      });
    }

    // -- validate
    if (
      accessControlConditions &&
      !checkType({
        value: accessControlConditions,
        allowedTypes: ["Array"],
        paramName: "accessControlConditions",
        functionName: "getEncryptionKey",
      })
    )
      return;
    if (
      evmContractConditions &&
      !checkType({
        value: evmContractConditions,
        allowedTypes: ["Array"],
        paramName: "evmContractConditions",
        functionName: "getEncryptionKey",
      })
    )
      return;
    if (
      solRpcConditions &&
      !checkType({
        value: solRpcConditions,
        allowedTypes: ["Array"],
        paramName: "solRpcConditions",
        functionName: "getEncryptionKey",
      })
    )
      return;
    if (
      unifiedAccessControlConditions &&
      !checkType({
        value: unifiedAccessControlConditions,
        allowedTypes: ["Array"],
        paramName: "unifiedAccessControlConditions",
        functionName: "getEncryptionKey",
      })
    )
      return;
    if (
      !checkType({
        value: toDecrypt,
        allowedTypes: ["String"],
        paramName: "toDecrypt",
        functionName: "getEncryptionKey",
      })
    )
      return;
    if (
      authSig &&
      !checkType({
        value: authSig,
        allowedTypes: ["Object"],
        paramName: "authSig",
        functionName: "getEncryptionKey",
      })
    )
      return;
    if (
      sessionSigs &&
      !checkType({
        value: sessionSigs,
        allowedTypes: ["Object"],
        paramName: "sessionSigs",
        functionName: "getEncryptionKey",
      })
    )
      return;

    if (!sessionSigs && !authSig) {
      throwError({
        message: "You must pass either authSig or sessionSigs",
        name: "InvalidArgumentException",
        errorCode: "invalid_argument",
      });
      return;
    }

    if (
      authSig &&
      !checkIfAuthSigRequiresChainParam(authSig, chain, "getEncryptionKey")
    )
      return;

    let formattedAccessControlConditions;
    let formattedEVMContractConditions;
    let formattedSolRpcConditions;
    let formattedUnifiedAccessControlConditions;
    if (accessControlConditions) {
      formattedAccessControlConditions = accessControlConditions.map((c) =>
        canonicalAccessControlConditionFormatter(c)
      );
      log(
        "formattedAccessControlConditions: ",
        JSON.stringify(formattedAccessControlConditions)
      );
    } else if (evmContractConditions) {
      formattedEVMContractConditions = evmContractConditions.map((c) =>
        canonicalEVMContractConditionFormatter(c)
      );
      log(
        "formattedEVMContractConditions",
        JSON.stringify(formattedEVMContractConditions)
      );
    } else if (solRpcConditions) {
      formattedSolRpcConditions = solRpcConditions.map((c) =>
        canonicalSolRpcConditionFormatter(c)
      );
      log(
        "formattedSolRpcConditions",
        JSON.stringify(formattedSolRpcConditions)
      );
    } else if (unifiedAccessControlConditions) {
      formattedUnifiedAccessControlConditions =
        unifiedAccessControlConditions.map((c) =>
          canonicalUnifiedAccessControlConditionFormatter(c)
        );
      log(
        "formattedUnifiedAccessControlConditions",
        JSON.stringify(formattedUnifiedAccessControlConditions)
      );
    } else {
      throwError({
        message: `You must provide either accessControlConditions or evmContractConditions or solRpcConditions or unifiedAccessControlConditions`,
        name: "InvalidArgumentException",
        errorCode: "invalid_argument",
      });
    }

    // ask each node to decrypt the content
    const nodePromises = [];
    for (const url of this.connectedNodes) {
      let sigToPassToNode = authSig;
      if (sessionSigs) {
        // find the sessionSig for this node
        sigToPassToNode = sessionSigs[url];
        if (!sigToPassToNode) {
          throwError({
            message: `You passed sessionSigs but we could not find session sig for node ${url}`,
            name: "InvalidArgumentException",
            errorCode: "invalid_argument",
          });
        }
      }
      nodePromises.push(
        this.getDecryptionShare({
          url,
          accessControlConditions: formattedAccessControlConditions,
          evmContractConditions: formattedEVMContractConditions,
          solRpcConditions: formattedSolRpcConditions,
          unifiedAccessControlConditions:
            formattedUnifiedAccessControlConditions,
          toDecrypt,
          authSig: sigToPassToNode,
          chain,
        })
      );
    }
    const res = await this.handleNodePromises(nodePromises);
    if (res.success === false) {
      this.throwNodeError(res);
      return;
    }
    const decryptionShares = res.values;
    log("decryptionShares", decryptionShares);

    // // sort the decryption shares by share index.  this is important when combining the shares.
    // decryptionShares.sort((a, b) => a.shareIndex - b.shareIndex);

    // // combine the decryption shares

    // // set decryption shares bytes in wasm
    // decryptionShares.forEach((s, idx) => {
    //   wasmExports.set_share_indexes(idx, s.shareIndex);
    //   const shareAsBytes = uint8arrayFromString(s.decryptionShare, "base16");
    //   for (let i = 0; i < shareAsBytes.length; i++) {
    //     wasmExports.set_decryption_shares_byte(i, idx, shareAsBytes[i]);
    //   }
    // });

    // // set the public key set bytes in wasm
    // const pkSetAsBytes = uint8arrayFromString(this.networkPubKeySet, "base16");
    // wasmBlsSdkHelpers.set_mc_bytes(pkSetAsBytes);

    // // set the ciphertext bytes
    // const ciphertextAsBytes = uint8arrayFromString(toDecrypt, "base16");
    // for (let i = 0; i < ciphertextAsBytes.length; i++) {
    //   wasmExports.set_ct_byte(i, ciphertextAsBytes[i]);
    // }

    // const decrypted = wasmBlsSdkHelpers.combine_decryption_shares(
    //   decryptionShares.length,
    //   pkSetAsBytes.length,
    //   ciphertextAsBytes.length
    // );
    // log('decrypted is ', uint8arrayToString(decrypted, 'base16'))

    const decrypted = combineBlsDecryptionShares(
      decryptionShares,
      this.networkPubKeySet,
      toDecrypt
    );

    return decrypted;
  }

  /**
   * Securely save the association between access control conditions and something that you wish to decrypt
   * @param {Object} params
   * @param {Array.<AccessControlCondition>} params.accessControlConditions The access control conditions that the user must meet to obtain this signed token.  This could be posession of an NFT, for example.  You must pass either accessControlConditions or evmContractConditions or solRpcConditions or unifiedAccessControlConditions.
   * @param {Array.<EVMContractCondition>} params.evmContractConditions  EVM Smart Contract access control conditions that the user must meet to obtain this signed token.  This could be posession of an NFT, for example.  This is different than accessControlConditions because accessControlConditions only supports a limited number of contract calls.  evmContractConditions supports any contract call.  You must pass either accessControlConditions or evmContractConditions or solRpcConditions or unifiedAccessControlConditions.
   * @param {Array.<SolRpcCondition>} params.solRpcConditions  Solana RPC call conditions that the user must meet to obtain this signed token.  This could be posession of an NFT, for example.
   * @param {Array.<AccessControlCondition|EVMContractCondition|SolRpcCondition>} params.unifiedAccessControlConditions  An array of unified access control conditions.  You may use AccessControlCondition, EVMContractCondition, or SolRpcCondition objects in this array, but make sure you add a conditionType for each one.  You must pass either accessControlConditions or evmContractConditions or solRpcConditions or unifiedAccessControlConditions.
   * @param {string} params.chain The chain name of the chain that you are querying.  See ALL_LIT_CHAINS for currently supported chains.
   * @param {AuthSig} params.authSig The authentication signature that proves that the user owns the crypto wallet address meets the access control conditions
   * @param {Uint8Array} params.symmetricKey The symmetric encryption key that was used to encrypt the locked content inside the LIT as a Uint8Array.  You should use zipAndEncryptString or zipAndEncryptFiles to get this encryption key.  This key will be hashed and the hash will be sent to the LIT nodes.  You must pass either symmetricKey or encryptedSymmetricKey.
   * @param {Uint8Array} params.encryptedSymmetricKey The encrypted symmetric key of the item you with to update.  You must pass either symmetricKey or encryptedSymmetricKey.
   * @param {boolean} params.permanent Whether or not the access control condition should be saved permanently.  If false, the access control conditions will be updateable by the creator.  If you don't pass this param, it's set to true by default.
   * @returns {Uint8Array} The symmetricKey parameter that has been encrypted with the network public key.  Save this - you will need it to decrypt the content in the future.
   */

  async saveEncryptionKey({
    accessControlConditions,
    evmContractConditions,
    solRpcConditions,
    unifiedAccessControlConditions,
    chain,
    authSig,
    symmetricKey,
    encryptedSymmetricKey,
    permanant,
    permanent = true,
    sessionSigs,
  }) {
    log("LitNodeClient.saveEncryptionKey");

    if (!this.ready) {
      throwError({
        message:
          "LitNodeClient is not ready.  Please call await litNodeClient.connect() first.",
        name: "LitNodeClientNotReadyError",
        errorCode: "lit_node_client_not_ready",
      });
    }

    // -- validate
    if (
      accessControlConditions &&
      !checkType({
        value: accessControlConditions,
        allowedTypes: ["Array"],
        paramName: "accessControlConditions",
        functionName: "saveEncryptionKey",
      })
    )
      return;
    if (
      evmContractConditions &&
      !checkType({
        value: evmContractConditions,
        allowedTypes: ["Array"],
        paramName: "evmContractConditions",
        functionName: "saveEncryptionKey",
      })
    )
      return;
    if (
      solRpcConditions &&
      !checkType({
        value: solRpcConditions,
        allowedTypes: ["Array"],
        paramName: "solRpcConditions",
        functionName: "saveEncryptionKey",
      })
    )
      return;
    if (
      unifiedAccessControlConditions &&
      !checkType({
        value: unifiedAccessControlConditions,
        allowedTypes: ["Array"],
        paramName: "unifiedAccessControlConditions",
        functionName: "saveEncryptionKey",
      })
    )
      return;

    if (
      authSig &&
      !checkType({
        value: authSig,
        allowedTypes: ["Object"],
        paramName: "authSig",
        functionName: "saveEncryptionKey",
      })
    )
      return;

    if (
      sessionSigs &&
      !checkType({
        value: sessionSigs,
        allowedTypes: ["Object"],
        paramName: "sessionSigs",
        functionName: "saveEncryptionKey",
      })
    )
      return;
    if (!sessionSigs && !authSig) {
      throwError({
        message: "You must pass either authSig or sessionSigs",
        name: "InvalidArgumentException",
        errorCode: "invalid_argument",
      });
      return;
    }
    if (
      authSig &&
      !checkIfAuthSigRequiresChainParam(authSig, chain, "saveEncryptionKey")
    )
      return;
    if (
      symmetricKey &&
      !checkType({
        value: symmetricKey,
        allowedTypes: ["Uint8Array"],
        paramName: "symmetricKey",
        functionName: "saveEncryptionKey",
      })
    )
      return;
    if (
      encryptedSymmetricKey &&
      !checkType({
        value: encryptedSymmetricKey,
        allowedTypes: ["Uint8Array"],
        paramName: "encryptedSymmetricKey",
        functionName: "saveEncryptionKey",
      })
    )
      return;

    // to fix spelling mistake
    if (typeof permanant !== "undefined") {
      permanent = permanant;
    }

    if (
      (!symmetricKey || symmetricKey == "") &&
      (!encryptedSymmetricKey || encryptedSymmetricKey == "")
    ) {
      throw new Error(
        "symmetricKey and encryptedSymmetricKey are blank.  You must pass one or the other"
      );
    }

    if (
      (!accessControlConditions || accessControlConditions.length == 0) &&
      (!evmContractConditions || evmContractConditions.length == 0) &&
      (!solRpcConditions || solRpcConditions.length == 0) &&
      (!unifiedAccessControlConditions ||
        unifiedAccessControlConditions.length == 0)
    ) {
      throw new Error(
        "accessControlConditions and evmContractConditions and solRpcConditions and unifiedAccessControlConditions are blank"
      );
    }

    // encrypt with network pubkey
    let encryptedKey;
    if (encryptedSymmetricKey) {
      encryptedKey = encryptedSymmetricKey;
    } else {
      encryptedKey = wasmBlsSdkHelpers.encrypt(
        uint8arrayFromString(this.subnetPubKey, "base16"),
        symmetricKey
      );
      log(
        "symmetric key encrypted with LIT network key: ",
        uint8arrayToString(encryptedKey, "base16")
      );
    }
    // hash the encrypted pubkey
    const hashOfKey = await crypto.subtle.digest("SHA-256", encryptedKey);
    const hashOfKeyStr = uint8arrayToString(
      new Uint8Array(hashOfKey),
      "base16"
    );

    // hash the access control conditions
    let hashOfConditions;
    // hash the access control conditions
    if (accessControlConditions) {
      hashOfConditions = await hashAccessControlConditions(
        accessControlConditions
      );
    } else if (evmContractConditions) {
      hashOfConditions = await hashEVMContractConditions(evmContractConditions);
    } else if (solRpcConditions) {
      hashOfConditions = await hashSolRpcConditions(solRpcConditions);
    } else if (unifiedAccessControlConditions) {
      hashOfConditions = await hashUnifiedAccessControlConditions(
        unifiedAccessControlConditions
      );
    } else {
      throwError({
        message: `You must provide either accessControlConditions or evmContractConditions or solRpcConditions or unifiedAccessControlConditions`,
        name: "InvalidArgumentException",
        errorCode: "invalid_argument",
      });
    }

    const hashOfConditionsStr = uint8arrayToString(
      new Uint8Array(hashOfConditions),
      "base16"
    );

    // create access control conditions on lit nodes
    const nodePromises = [];
    for (const url of this.connectedNodes) {
      let sigToPassToNode = authSig;
      if (sessionSigs) {
        // find the sessionSig for this node
        sigToPassToNode = sessionSigs[url];
        if (!sigToPassToNode) {
          throwError({
            message: `You passed sessionSigs but we could not find session sig for node ${url}`,
            name: "InvalidArgumentException",
            errorCode: "invalid_argument",
          });
        }
      }
      nodePromises.push(
        this.storeEncryptionConditionWithNode({
          url,
          key: hashOfKeyStr,
          val: hashOfConditionsStr,
          authSig: sigToPassToNode,
          chain,
          permanent: permanent ? 1 : 0,
        })
      );
    }

    const res = await this.handleNodePromises(nodePromises);
    if (res.success === false) {
      this.throwNodeError(res);
      return;
    }

    return encryptedKey;
  }

  /**
   * Signs a message with Lit threshold ECDSA algorithms.
   * @param {Object} params
   * @param {string} params.message The message to be signed - note this message is not currently converted to a digest!!!!!
   * @param {string} params.chain The chain name of the chain that this contract is deployed on.  See LIT_CHAINS for currently supported chains.
   * @returns {Object} JSON structure with signed message, signature & public key.
   */
  async signWithEcdsa({ message, chain }) {
    // ask each node to decrypt the content
    const nodePromises = [];
    for (const url of this.connectedNodes) {
      nodePromises.push(
        this.signECDSA({
          url,
          message,
          chain,
          iat: 0,
          exp: 0,
        })
      );
    }

    try {
      const share_data = await Promise.all(nodePromises);
      // R_x & R_y values can come from any node (they will be different per node), and will generate a valid signature
      const R_x = share_data[0].local_x;
      const R_y = share_data[0].local_y;
      // the public key can come from any node - it obviously will be identical from each node
      const public_key = share_data[0].public_key;
      const valid_shares = share_data.map((s) => s.signature_share);
      const shares = JSON.stringify(valid_shares);
      await wasmECDSA.initWasmEcdsaSdk(); // init WASM
      const signature = wasmECDSA.combine_signature(R_x, R_y, shares);
      log("raw ecdsav sig", signature);
      return signature;
    } catch (e) {
      log("Error - signed_ecdsa_messages ");
      const signed_ecdsa_message = nodePromises[0];
      return signed_ecdsa_message;
    }
    return throwError("some other error?");
  }

  /**
   * Validates a condition, and then signs the condition if the validation returns true.   Before calling this function, you must know the on chain conditions that you wish to validate.
   * @param {Object} params
   * @param {Array.<AccessControlCondition>} params.accessControlConditions The on chain control conditions that are to be evaluated and - if valid -  signed.
   * @param {string} params.chain The chain name of the chain that you are querying.  See ALL_LIT_CHAINS for currently supported chains.
   * @param {AuthSig} params.authSig The authentication signature that proves that the user owns the crypto wallet address that seeks to evaluate conditions.
   * @returns {Object} JSON structure with signed message, signature & public key..
   */
  async validate_and_sign_ecdsa({ accessControlConditions, chain, auth_sig }) {
    if (!this.ready) {
      throwError({
        message:
          "LitNodeClient is not ready.  Please call await litNodeClient.connect() first.",
        name: "LitNodeClientNotReadyError",
        errorCode: "lit_node_client_not_ready",
      });
    }

    // we need to send jwt params iat (issued at) and exp (expiration)
    // because the nodes may have different wall clock times
    // the nodes will verify that these params are withing a grace period
    const now = Date.now();
    const iat = Math.floor(now / 1000);
    const exp = iat + 12 * 60 * 60; // 12 hours in seconds

    let formattedAccessControlConditions;
    let formattedEVMContractConditions;
    let formattedSolRpcConditions;
    if (accessControlConditions) {
      formattedAccessControlConditions = accessControlConditions.map((c) =>
        canonicalAccessControlConditionFormatter(c)
      );
      log(
        "formattedAccessControlConditions",
        JSON.stringify(formattedAccessControlConditions)
      );
    }
    // else if (evmContractConditions) {
    //   formattedEVMContractConditions = evmContractConditions.map((c) =>
    //     canonicalEVMContractConditionFormatter(c)
    //   );
    //   log(
    //     "formattedEVMContractConditions",
    //     JSON.stringify(formattedEVMContractConditions)
    //   );
    // } else if (solRpcConditions) {
    //   formattedSolRpcConditions = solRpcConditions.map((c) =>
    //     canonicalSolRpcConditionFormatter(c)
    //   );
    //   log(
    //     "formattedSolRpcConditions",
    //     JSON.stringify(formattedSolRpcConditions)
    //   );
    // }
    else {
      throwError({
        message: `You must provide either accessControlConditions or evmContractConditions or solRpcConditions`,
        name: "InvalidArgumentException",
        errorCode: "invalid_argument",
      });
    }

    // ask each node to sign the content
    const nodePromises = [];
    for (const url of this.connectedNodes) {
      nodePromises.push(
        this.sign_condition_ecdsa({
          url,
          accessControlConditions: formattedAccessControlConditions,
          evmContractConditions: formattedEVMContractConditions,
          solRpcConditions: formattedSolRpcConditions,
          auth_sig,
          chain,
          iat,
          exp,
        })
      );
    }

    try {
      const share_data = await Promise.all(nodePromises);

      if (share_data[0].result == "failure") return "Condition Failed";

      // R_x & R_y values can come from any node (they will be different per node), and will generate a valid signature
      const R_x = share_data[0].local_x;
      const R_y = share_data[0].local_y;

      // the public key can come from any node - it obviously will be identical from each node
      const public_key = share_data[0].public_key;
      const valid_shares = share_data.map((s) => s.signature_share);
      const shares = JSON.stringify(valid_shares);
      await wasmECDSA.initWasmEcdsaSdk(); // init WASM
      const signature = wasmECDSA.combine_signature(R_x, R_y, shares);
      log("raw ecdsa sig", signature);
      return signature;
    } catch (e) {
      log("Error - signed_ecdsa_messages - ", e);
      const signed_ecdsa_message = nodePromises[0];
      return signed_ecdsa_message;
    }
  }

  async storeSigningConditionWithNode({
    url,
    key,
    val,
    authSig,
    chain,
    permanent,
  }) {
    log("storeSigningConditionWithNode");
    const urlWithPath = `${url}/web/signing/store`;
    const data = {
      key,
      val,
      authSig,
      chain,
      permanant: permanent,
    };
    return await this.sendCommandToNode({ url: urlWithPath, data });
  }

  async storeEncryptionConditionWithNode({
    url,
    key,
    val,
    authSig,
    chain,
    permanent,
  }) {
    log("storeEncryptionConditionWithNode");
    const urlWithPath = `${url}/web/encryption/store`;
    const data = {
      key,
      val,
      authSig,
      chain,
      permanant: permanent,
    };
    return await this.sendCommandToNode({ url: urlWithPath, data });
  }

  async getChainDataSigningShare({ url, callRequests, chain, iat, exp }) {
    log("getChainDataSigningShare");
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
    evmContractConditions,
    solRpcConditions,
    unifiedAccessControlConditions,
    resourceId,
    authSig,
    chain,
    iat,
    exp,
  }) {
    log("getSigningShare");
    const urlWithPath = `${url}/web/signing/retrieve`;
    const data = {
      accessControlConditions,
      evmContractConditions,
      solRpcConditions,
      unifiedAccessControlConditions,
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
    evmContractConditions,
    solRpcConditions,
    unifiedAccessControlConditions,
    toDecrypt,
    authSig,
    chain,
  }) {
    log("getDecryptionShare");
    const urlWithPath = `${url}/web/encryption/retrieve`;
    const data = {
      accessControlConditions,
      evmContractConditions,
      solRpcConditions,
      unifiedAccessControlConditions,
      toDecrypt,
      authSig,
      chain,
    };
    return await this.sendCommandToNode({ url: urlWithPath, data });
  }

  async getJsExecutionShares({
    url,
    code,
    ipfsId,
    authSig,
    jsParams,
    authMethods,
    requestId,
  }) {
    log("getJsExecutionShares");
    const urlWithPath = `${url}/web/execute`;
    const data = {
      code,
      ipfsId,
      authSig,
      jsParams,
      authMethods,
      requestId,
    };
    return await this.sendCommandToNode({ url: urlWithPath, data });
  }

  async getSignSessionKeyShares({ url, body }) {
    log("getSignSessionKeyShares");
    const urlWithPath = `${url}/web/sign_session_key`;
    return await this.sendCommandToNode({ url: urlWithPath, data: body });
  }

  async handshakeWithSgx({ url }) {
    const urlWithPath = `${url}/web/handshake`;
    log(`handshakeWithSgx ${urlWithPath}`);
    const data = {
      clientPublicKey: "test",
    };
    return await this.sendCommandToNode({ url: urlWithPath, data });
  }

  sendCommandToNode({ url, data }) {
    log(`sendCommandToNode with url ${url} and data`, data);
    return fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "lit-js-sdk-version": version,
      },
      body: JSON.stringify(data),
    }).then(async (response) => {
      const isJson = response.headers
        .get("content-type")
        ?.includes("application/json");
      const data = isJson ? await response.json() : null;

      if (!response.ok) {
        // get error message from body or default to response status
        const error = data || response.status;
        return Promise.reject(error);
      }

      return data;
    });
  }

  async handleNodePromises(promises) {
    const responses = await Promise.allSettled(promises);
    log("responses", responses);
    const successes = responses.filter((r) => r.status === "fulfilled");
    if (successes.length >= this.config.minNodeCount) {
      return {
        success: true,
        values: successes.map((r) => r.value),
      };
    }

    // if we're here, then we did not succeed.  time to handle and report errors.
    const rejected = responses.filter((r) => r.status === "rejected");
    const mostCommonError = JSON.parse(
      mostCommonString(rejected.map((r) => JSON.stringify(r.reason)))
    );
    log(`most common error: ${JSON.stringify(mostCommonError)}`);
    return {
      success: false,
      error: mostCommonError,
    };
  }

  throwNodeError(res) {
    if (res.error && res.error.errorCode) {
      if (
        res.error.errorCode === "not_authorized" &&
        this.config.alertWhenUnauthorized
      ) {
        alert("You are not authorized to access to this content");
      }
      throwError({ ...res.error, name: "NodeError" });
    } else {
      throwError({
        message: `There was an error getting the signing shares from the nodes`,
        name: "UnknownError",
        errorCode: "unknown_error",
      });
    }
  }

  async signECDSA({ url, message, chain, iat, exp }) {
    log("sign_message_ecdsa");
    const urlWithPath = `${url}/web/signing/sign_message_ecdsa`;
    const data = {
      message,
      chain,
      iat,
      exp,
    };
    return await this.sendCommandToNode({ url: urlWithPath, data });
  }

  async sign_condition_ecdsa({
    url,
    accessControlConditions,
    evmContractConditions,
    solRpcConditions,
    auth_sig,
    chain,
    iat,
    exp,
  }) {
    log("sign_condition_ecdsa");
    const urlWithPath = `${url}/web/signing/sign_condition_ecdsa`;
    const data = {
      access_control_conditions: accessControlConditions,
      evmContractConditions,
      solRpcConditions,
      auth_sig,
      chain,
      iat,
      exp,
    };
    return await this.sendCommandToNode({ url: urlWithPath, data });
  }

  // high level, how this works:
  // generate or retrieve session key
  // generate or retrieve the wallet signature of the session key
  // sign the specific resources with the session key
  /**
   * Get session signatures for a set of resources
   * @param {Object} params
   * @param {String} params.expiration When this session signature will expire.  The user will have to reauthenticate after this time using whatever auth method you set up.  This means you will have to call this signSessionKey function again to get a new session signature.  This is a RFC3339 timestamp.  The default is 24 hours from now.
   * @param {String} params.chain The chain to use for the session signature.  This is the chain that will be used to sign the session key.  If you're using EVM then this probably doesn't matter at all.
   * @param {Array<String>} params.resources These are the resources that will be signed with the session key.  You may pass a wildcard that allows these session signatures to work with any resource on Lit.  To see a list of resources, check out the docs: https://developer.litprotocol.com/sdk/explanation/walletsigs/sessionsigs/#resources-you-can-request
   * @param {Array<String>} params.sessionCapabilityObject An optional capability object you want to request for this session.  If you pass nothing, then this will default to a wildcard for each type of resource you're accessing.  For example, if you passed ["litEncryptionCondition://123456"] then this would default to ["litEncryptionConditionCapability://*"], which would grant this session signature the ability to decrypt any resource.
   * @param {bool} params.switchChain If you want to ask Metamask to try and switch the user's chain, you may pass true here.  This will only work if the user is using Metamask.  If the user is not using Metamask, then this will be ignored.
   * @param {Function} params.authNeededCallback This is a callback that will be called if the user needs to authenticate using a PKP.  For example, if the user has no wallet, but owns a Lit PKP though something like Google Oauth, then you can use this callback to prompt the user to authenticate with their PKP.  This callback should use the LitNodeClient.signSessionKey function to get a session signature for the user from their PKP.  If you don't pass this callback, then the user will be prompted to authenticate with their wallet, like metamask.
   * @returns {Object} An object containing the resulting signature.
   */
  async getSessionSigs({
    expiration,
    chain,
    resources = [],
    sessionCapabilityObject,
    switchChain,
    authNeededCallback,
    sessionKey,
  }) {
    if (!sessionKey) {
      // check if we already have a session key + signature for this chain
      let storedSessionKey;
      try {
        storedSessionKey = localStorage.getItem(`lit-session-key`);
      } catch (e) {
        log("Localstorage not available.  Not a problem.  Continuing...");
      }
      if (!storedSessionKey || storedSessionKey === "") {
        // if not, generate one
        sessionKey = generateSessionKeyPair();
        try {
          localStorage.setItem(`lit-session-key`, JSON.stringify(sessionKey));
        } catch (e) {
          log("Localstorage not available.  Not a problem.  Continuing...");
        }
      } else {
        sessionKey = JSON.parse(storedSessionKey);
      }
    }

    let sessionKeyUri = getSessionKeyUri({ publicKey: sessionKey.publicKey });

    // if the user passed no sessionCapabilityObject, let's create them for them
    // with wildcards so the user doesn't have to sign every time
    if (
      !sessionCapabilityObject ||
      Object.keys(sessionCapabilityObject).length === 0
    ) {
      let capabilityObject = {
        def: [],
      };
      let defaultActionsToAdd = new Set();

      resources.forEach((resource) => {
        const { protocol, resourceId } = parseResource({ resource });

        if (!defaultActionsToAdd.has(protocol)) {
          defaultActionsToAdd.add(protocol);
        }
      });
      capabilityObject.def = Array.from(defaultActionsToAdd);
      sessionCapabilityObject = capabilityObject;
    }

    if (!expiration) {
      // set default of 24 hours
      expiration = new Date(Date.now() + 1000 * 60 * 60 * 24).toISOString();
    }

    // check if we already have a wallet sig from the user
    // and then check a few things, including that:
    // 1. the sig isn't expired
    // 2. the sig is for the correct session key
    // 3. the sig has the sessionCapabilityObject requires to fulfill the resources requested

    let walletSig;
    try {
      walletSig = localStorage.getItem(`lit-wallet-sig`);
    } catch (e) {
      log("Localstorage not available.  Not a problem.  Continuing...");
    }
    if (!walletSig || walletSig == "") {
      if (authNeededCallback) {
        walletSig = await authNeededCallback({
          chain,
          // convert into SIWE ReCap compliant session capability.
          resources: [
            `urn:recap:lit:session:${Base64.encode(
              JSON.stringify(sessionCapabilityObject)
            )}`,
          ],
          expiration,
          uri: sessionKeyUri,
          litNodeClient: this,
        });
      } else {
        walletSig = await checkAndSignAuthMessage({
          chain,
          // convert into SIWE ReCap compliant session capability.
          resources: [
            `urn:recap:lit:session:${Base64.encode(
              JSON.stringify(sessionCapabilityObject)
            )}`,
          ],
          switchChain,
          expiration,
          uri: sessionKeyUri,
        });
      }
    } else {
      walletSig = JSON.parse(walletSig);
    }

    const siweMessage = new SiweMessage(walletSig.signedMessage);
    let needToReSignSessionKey = false;
    try {
      // make sure it's legit
      await siweMessage.verify({ signature: walletSig.sig });
    } catch (e) {
      needToReSignSessionKey = true;
    }

    // make sure the sig is for the correct session key
    if (siweMessage.uri !== sessionKeyUri) {
      needToReSignSessionKey = true;
    }

    // make sure the sig has the session capabilities required to fulfill the resources requested
    for (let i = 0; i < resources.length; i++) {
      const resource = resources[i];

      // check if we have blanket permissions or if we authed the specific resource for the protocol
      const permissionsFound = findPermissionsForResource(
        resource,
        sessionCapabilityObject
      );
      if (!permissionsFound) {
        needToReSignSessionKey = true;
      }
    }

    if (needToReSignSessionKey) {
      log("need to re-sign session key.  Signing...");
      if (authNeededCallback) {
        walletSig = await authNeededCallback({
          chain,
          // convert into SIWE ReCap compliant session capability.
          resources: [
            `urn:recap:lit:session:${Base64.encode(
              JSON.stringify(sessionCapabilityObject)
            )}`,
          ],
          expiration,
          uri: sessionKeyUri,
          litNodeClient: this,
        });
      } else {
        walletSig = await checkAndSignAuthMessage({
          chain,
          // convert into SIWE ReCap compliant session capability.
          resources: [
            `urn:recap:lit:session:${Base64.encode(
              JSON.stringify(sessionCapabilityObject)
            )}`,
          ],
          switchChain,
          expiration,
          uri: sessionKeyUri,
        });
      }
    }

    // okay great, now we have a valid signed session key
    // let's sign the resources with the session key
    // 5 minutes is the default expiration for a session signature
    // because we can generate a new session sig every time the user wants to access a resource
    // without prompting them to sign with their wallet
    let sessionExpiration = new Date(Date.now() + 1000 * 60 * 5);
    const signingTemplate = {
      sessionKey: sessionKey.publicKey,
      resources,
      capabilities: [walletSig],
      issuedAt: new Date().toISOString(),
      expiration: sessionExpiration.toISOString(),
    };
    const signatures = {};

    this.connectedNodes.forEach((nodeAddress) => {
      const toSign = {
        ...signingTemplate,
        nodeAddress,
      };
      let signedMessage = JSON.stringify(toSign);
      const uint8arrayKey = uint8arrayFromString(
        sessionKey.secretKey,
        "base16"
      );
      const uint8arrayMessage = uint8arrayFromString(signedMessage, "utf8");
      let signature = nacl.sign.detached(uint8arrayMessage, uint8arrayKey);
      // console.log("signature", signature);
      signatures[nodeAddress] = {
        sig: uint8arrayToString(signature, "base16"),
        derivedVia: "litSessionSignViaNacl",
        signedMessage,
        address: sessionKey.publicKey,
        algo: "ed25519",
      };
    });

    return signatures;
  }

  /**
   * Connect to the LIT nodes.
   * @returns {Promise} A promise that resolves when the nodes are connected.
   */
  connect() {
    // handshake with each node
    for (const url of this.config.bootstrapUrls) {
      this.handshakeWithSgx({ url })
        .then((resp) => {
          this.connectedNodes.add(url);
          this.serverKeys[url] = {
            serverPubKey: resp.serverPublicKey,
            subnetPubKey: resp.subnetPublicKey,
            networkPubKey: resp.networkPublicKey,
            networkPubKeySet: resp.networkPublicKeySet,
          };
        })
        .catch((e) => {
          throw e;
        });
    }

    return new Promise((resolve) => {
      const interval = setInterval(() => {
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
          log("lit is ready");
          if (typeof document !== "undefined") {
            document.dispatchEvent(new Event("lit-ready"));
          }

          resolve();
        }
      }, 500);
    });
  }
}

// check if we have blanket permissions or if we authed the specific resource for the protocol
function findPermissionsForResource(resource, capabilityObject) {
  const { protocol, resourceId } = parseResource({ resource });

  // first check default permitted actions
  for (const defaultAction of capabilityObject.def) {
    if (defaultAction === "*" || defaultAction === protocol) {
      return true;
    }
  }

  // then check specific targets
  if (Object.keys(capabilityObject.tar).indexOf(resourceId) === -1) {
    return false;
  }

  for (const permittedAction of capabilityObject.tar[resourceId]) {
    if (permittedAction === "*" || permittedAction === protocol) {
      return true;
    }
  }

  return false;
}
