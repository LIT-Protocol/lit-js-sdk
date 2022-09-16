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
exports.lookupNameServiceAddress = exports.decimalPlaces = exports.sendLIT = exports.findLITs = exports.mintLIT = exports.signMessageAsync = exports.signMessage = exports.signAndSaveAuthMessage = exports.checkAndSignEVMAuthMessage = exports.disconnectWeb3 = exports.connectWeb3 = exports.decodeCallResult = exports.encodeCallData = void 0;
const contracts_1 = require("@ethersproject/contracts");
const wallet_1 = require("@ethersproject/wallet");
const providers_1 = require("@ethersproject/providers");
const strings_1 = require("@ethersproject/strings");
const bytes_1 = require("@ethersproject/bytes");
const address_1 = require("@ethersproject/address");
const ethereum_provider_1 = __importDefault(require("@walletconnect/ethereum-provider"));
const lit_connect_modal_1 = __importDefault(require("lit-connect-modal"));
const lit_siwe_1 = require("lit-siwe");
const tweetnacl_util_1 = __importDefault(require("tweetnacl-util"));
const tweetnacl_1 = __importDefault(require("tweetnacl"));
const LIT_json_1 = __importDefault(require("../abis/LIT.json"));
// @ts-expect-error TS(2732): Cannot find module '../abis/ERC20.json'. Consider ... Remove this comment to see the full error message
const ERC20_json_1 = __importDefault(require("../abis/ERC20.json"));
const constants_1 = require("../lib/constants");
const utils_1 = require("../lib/utils");
function chainHexIdToChainName(chainHexId) {
    for (let i = 0; i < Object.keys(constants_1.LIT_CHAINS).length; i++) {
        const chainName = Object.keys(constants_1.LIT_CHAINS)[i];
        // @ts-expect-error TS(7053): Element implicitly has an 'any' type because expre... Remove this comment to see the full error message
        const litChainHexId = "0x" + constants_1.LIT_CHAINS[chainName].chainId.toString("16");
        if (litChainHexId === chainHexId) {
            return chainName;
        }
    }
}
function encodeCallData({ abi, functionName, functionParams }) {
    // @ts-expect-error TS(2304): Cannot find name 'ethers'.
    const iface = new ethers.utils.Interface(abi);
    const callData = iface.encodeFunctionData(functionName, functionParams);
    return callData;
}
exports.encodeCallData = encodeCallData;
function decodeCallResult({ abi, functionName, data }) {
    // @ts-expect-error TS(2304): Cannot find name 'ethers'.
    const iface = new ethers.utils.Interface(abi);
    const decoded = iface.decodeFunctionResult(functionName, data);
    return decoded;
}
exports.decodeCallResult = decodeCallResult;
function connectWeb3({ chainId = 1 } = {}) {
    return __awaiter(this, void 0, void 0, function* () {
        const rpcUrls = {};
        // need to make it look like this:
        // rpc: {
        //   1: "https://mainnet.mycustomnode.com",
        //   3: "https://ropsten.mycustomnode.com",
        //   100: "https://dai.poa.network",
        //   // ...
        // },
        for (let i = 0; i < Object.keys(constants_1.LIT_CHAINS).length; i++) {
            const chainName = Object.keys(constants_1.LIT_CHAINS)[i];
            // @ts-expect-error TS(7053): Element implicitly has an 'any' type because expre... Remove this comment to see the full error message
            const chainId = constants_1.LIT_CHAINS[chainName].chainId;
            // @ts-expect-error TS(7053): Element implicitly has an 'any' type because expre... Remove this comment to see the full error message
            const rpcUrl = constants_1.LIT_CHAINS[chainName].rpcUrls[0];
            // @ts-expect-error TS(7053): Element implicitly has an 'any' type because expre... Remove this comment to see the full error message
            rpcUrls[chainId] = rpcUrl;
        }
        const providerOptions = {
            walletconnect: {
                package: ethereum_provider_1.default,
                options: {
                    infuraId: "cd614bfa5c2f4703b7ab0ec0547d9f81",
                    rpc: rpcUrls,
                    chainId,
                },
            },
        };
        (0, utils_1.log)("getting provider via lit connect modal");
        const dialog = new lit_connect_modal_1.default({
            providerOptions,
        });
        const provider = yield dialog.getWalletProvider();
        (0, utils_1.log)("got provider", provider);
        const web3 = new providers_1.Web3Provider(provider);
        // const provider = await detectEthereumProvider();
        // const web3 = new Web3Provider(provider);
        // trigger metamask popup
        yield provider.enable();
        (0, utils_1.log)("listing accounts");
        const accounts = yield web3.listAccounts();
        // const accounts = await provider.request({
        //   method: "eth_requestAccounts",
        //   params: [],
        // });
        (0, utils_1.log)("accounts", accounts);
        const account = accounts[0].toLowerCase();
        return { web3, account };
    });
}
exports.connectWeb3 = connectWeb3;
/**
 * Delete any saved AuthSigs from local storage.  Takes no params and returns nothing.  This will also clear out the WalletConnect cache in local storage.  We often run this function as a result of the user pressing a "Logout" button.
 */
function disconnectWeb3() {
    return __awaiter(this, void 0, void 0, function* () {
        localStorage.removeItem("walletconnect");
        localStorage.removeItem("lit-auth-signature");
        localStorage.removeItem("lit-auth-sol-signature");
        localStorage.removeItem("lit-auth-cosmos-signature");
        localStorage.removeItem("lit-web3-provider");
    });
}
exports.disconnectWeb3 = disconnectWeb3;
// taken from the excellent repo https://github.com/zmitton/eth-proof
// export async function getMerkleProof({ tokenAddress, balanceStorageSlot, tokenId }) {
//   log(`getMerkleProof for { tokenAddress, balanceStorageSlot, tokenId } ${tokenAddress}, ${balanceStorageSlot}, ${tokenId}`)
//   const { web3, account } = await connectWeb3()
//   log(`getting mappingAt(${balanceStorageSlot}, ${tokenId}, ${account})`)
//   const storageAddress = mappingAt(balanceStorageSlot, parseInt(tokenId), account)
//   log('storageAddress: ', storageAddress)
//   // you may need to try the below twicce because sometimes the proof isn't available for the latest block on polygon because the node just isn't fast enough
//   let tries = 0
//   let rpcProof = null
//   let rpcBlock = null
//   while (!rpcProof && tries < 6) {
//     try {
//       if (!rpcBlock) {
//         // only set the rpc block once
//         rpcBlock = await web3.request({ method: 'eth_getBlockByNumber', params: ['latest', false] })
//         log('rpcBlock: ', rpcBlock)
//       }
//       rpcProof = await web3.request({ method: 'eth_getProof', params: [tokenAddress, [storageAddress], rpcBlock.number] })
//       log('rpcProof: ', rpcProof)
//     } catch (e) {
//       log(e)
//       log(`error getting rpc proof, have made ${tries} attempts`)
//       tries++
//     }
//   }
//   return {
//     header: rpcBlock,
//     accountProof: rpcProof.accountProof,
//     storageProof: rpcProof.storageProof[0].proof,
//     blockHash: rpcBlock.hash
//   }
// }
// export async function checkAndDeriveKeypair () {
//   let keypair = localStorage.getItem('lit-keypair')
//   if (!keypair) {
//     await deriveEncryptionKeys()
//     keypair = localStorage.getItem('lit-keypair')
//   }
//   keypair = JSON.parse(keypair)
//   const { web3, account } = await connectWeb3()
//   // make sure we are on the right account
//   if (account !== keypair.address) {
//     await deriveEncryptionKeys()
//     keypair = localStorage.getItem('lit-keypair')
//     keypair = JSON.parse(keypair)
//   }
//   return keypair
// }
function checkAndSignEVMAuthMessage({ chain, resources, switchChain }) {
    return __awaiter(this, void 0, void 0, function* () {
        // @ts-expect-error TS(7053): Element implicitly has an 'any' type because expre... Remove this comment to see the full error message
        const selectedChain = constants_1.LIT_CHAINS[chain];
        const { web3, account } = yield connectWeb3({
            chainId: selectedChain.chainId,
        });
        (0, utils_1.log)(`got web3 and account: ${account}`);
        let chainId;
        try {
            const resp = yield web3.getNetwork();
            chainId = resp.chainId;
        }
        catch (e) {
            // couldn't get chainId.  throw the incorrect network error
            (0, utils_1.log)("getNetwork threw an exception", e);
            (0, utils_1.throwError)({
                message: `Incorrect network selected.  Please switch to the ${chain} network in your wallet and try again.`,
                name: "WrongNetworkException",
                errorCode: "wrong_network",
            });
        }
        let selectedChainId = "0x" + selectedChain.chainId.toString("16");
        (0, utils_1.log)("chainId from web3", chainId);
        (0, utils_1.log)(`checkAndSignAuthMessage with chainId ${chainId} and chain set to ${chain} and selectedChain is `, selectedChain);
        if (chainId !== selectedChain.chainId && switchChain) {
            if (web3.provider instanceof ethereum_provider_1.default) {
                // this chain switching won't work.  alert the user that they need to switch chains manually
                (0, utils_1.throwError)({
                    message: `Incorrect network selected.  Please switch to the ${chain} network in your wallet and try again.`,
                    name: "WrongNetworkException",
                    errorCode: "wrong_network",
                });
                return;
            }
            try {
                (0, utils_1.log)("trying to switch to chainId", selectedChainId);
                // @ts-expect-error TS(2722): Cannot invoke an object which is possibly 'undefin... Remove this comment to see the full error message
                yield web3.provider.request({
                    method: "wallet_switchEthereumChain",
                    params: [{ chainId: selectedChainId }],
                });
            }
            catch (switchError) {
                (0, utils_1.log)("error switching to chainId", switchError);
                // This error code indicates that the chain has not been added to MetaMask.
                if (switchError.code === 4902) {
                    try {
                        const data = [
                            {
                                chainId: selectedChainId,
                                chainName: selectedChain.name,
                                nativeCurrency: {
                                    name: selectedChain.name,
                                    symbol: selectedChain.symbol,
                                    decimals: selectedChain.decimals,
                                },
                                rpcUrls: selectedChain.rpcUrls,
                                blockExplorerUrls: selectedChain.blockExplorerUrls,
                            },
                        ];
                        // @ts-expect-error TS(2722): Cannot invoke an object which is possibly 'undefin... Remove this comment to see the full error message
                        yield web3.provider.request({
                            method: "wallet_addEthereumChain",
                            params: data,
                        });
                    }
                    catch (addError) {
                        // handle "add" error
                        if (addError.code === -32601) {
                            // metamask code indicating "no such method"
                            (0, utils_1.throwError)({
                                message: `Incorrect network selected.  Please switch to the ${chain} network in your wallet and try again.`,
                                name: "WrongNetworkException",
                                errorCode: "wrong_network",
                            });
                        }
                        else {
                            throw addError;
                        }
                    }
                }
                else {
                    if (switchError.code === -32601) {
                        // metamask code indicating "no such method"
                        (0, utils_1.throwError)({
                            message: `Incorrect network selected.  Please switch to the ${chain} network in your wallet and try again.`,
                            name: "WrongNetworkException",
                            errorCode: "wrong_network",
                        });
                    }
                    else {
                        throw switchError;
                    }
                }
            }
            // we may have switched the chain to the selected chain.  set the chainId accordingly
            chainId = selectedChain.chainId;
        }
        (0, utils_1.log)("checking if sig is in local storage");
        let authSig = localStorage.getItem("lit-auth-signature");
        if (!authSig) {
            (0, utils_1.log)("signing auth message because sig is not in local storage");
            yield signAndSaveAuthMessage({
                web3,
                account,
                chainId,
                resources,
            });
            authSig = localStorage.getItem("lit-auth-signature");
        }
        // @ts-expect-error TS(2345): Argument of type 'string | null' is not assignable... Remove this comment to see the full error message
        authSig = JSON.parse(authSig);
        // make sure we are on the right account
        if (account !== authSig.address) {
            (0, utils_1.log)("signing auth message because account is not the same as the address in the auth sig");
            yield signAndSaveAuthMessage({
                web3,
                account,
                chainId: selectedChain.chainId,
                resources,
            });
            authSig = localStorage.getItem("lit-auth-signature");
            // @ts-expect-error TS(2345): Argument of type 'string | null' is not assignable... Remove this comment to see the full error message
            authSig = JSON.parse(authSig);
        }
        else {
            // check the resources of the sig and re-sign if they don't match
            let mustResign = false;
            try {
                const parsedSiwe = new lit_siwe_1.SiweMessage(authSig.signedMessage);
                (0, utils_1.log)("parsedSiwe.resources", parsedSiwe.resources);
                if (JSON.stringify(parsedSiwe.resources) !== JSON.stringify(resources)) {
                    (0, utils_1.log)("signing auth message because resources differ from the resources in the auth sig");
                    mustResign = true;
                }
                else if (parsedSiwe.address !== (0, address_1.getAddress)(parsedSiwe.address)) {
                    (0, utils_1.log)("signing auth message because parsedSig.address is not equal to the same address but checksummed.  This usually means the user had a non-checksummed address saved and so they need to re-sign.");
                    mustResign = true;
                }
            }
            catch (e) {
                (0, utils_1.log)("error parsing siwe sig.  making the user sign again: ", e);
                mustResign = true;
            }
            if (mustResign) {
                yield signAndSaveAuthMessage({
                    web3,
                    account,
                    chainId: selectedChain.chainId,
                    resources,
                });
                authSig = localStorage.getItem("lit-auth-signature");
                // @ts-expect-error TS(2345): Argument of type 'string | null' is not assignable... Remove this comment to see the full error message
                authSig = JSON.parse(authSig);
            }
        }
        (0, utils_1.log)("got auth sig", authSig);
        return authSig;
    });
}
exports.checkAndSignEVMAuthMessage = checkAndSignEVMAuthMessage;
/**
 * Sign the auth message with the user's wallet, and store it in localStorage.  Called by checkAndSignAuthMessage if the user does not have a signature stored.
 * @param {Object} params
 * @param {Web3Provider} params.web3 An ethers.js Web3Provider instance
 * @param {string} params.account The account to sign the message with
 * @returns {AuthSig} The AuthSig created or retrieved
 */
function signAndSaveAuthMessage({ web3, account, chainId, resources }) {
    return __awaiter(this, void 0, void 0, function* () {
        // const { chainId } = await web3.getNetwork();
        const preparedMessage = {
            domain: globalThis.location.host,
            address: (0, address_1.getAddress)(account),
            uri: globalThis.location.origin,
            version: "1",
            chainId,
        };
        if (resources && resources.length > 0) {
            preparedMessage.resources = resources;
        }
        const message = new lit_siwe_1.SiweMessage(preparedMessage);
        const body = message.prepareMessage();
        const signedResult = yield signMessage({
            body,
            web3,
            account,
        });
        const authSig = {
            sig: signedResult.signature,
            derivedVia: "web3.eth.personal.sign",
            signedMessage: body,
            address: signedResult.address,
        };
        localStorage.setItem("lit-auth-signature", JSON.stringify(authSig));
        // store a keypair in localstorage for communication with sgx
        const commsKeyPair = tweetnacl_1.default.box.keyPair();
        localStorage.setItem("lit-comms-keypair", JSON.stringify({
            publicKey: tweetnacl_util_1.default.encodeBase64(commsKeyPair.publicKey),
            secretKey: tweetnacl_util_1.default.encodeBase64(commsKeyPair.secretKey),
        }));
        (0, utils_1.log)("generated and saved lit-comms-keypair");
        return authSig;
    });
}
exports.signAndSaveAuthMessage = signAndSaveAuthMessage;
/**
 * @typedef {Object} AuthSig
 * @property {string} sig - The actual hex-encoded signature
 * @property {string} derivedVia - The method used to derive the signature. Typically "web3.eth.personal.sign"
 * @property {string} signedMessage - The message that was signed
 * @property {string} address - The crypto wallet address that signed the message
 */
function signMessage({ body, web3, account }) {
    return __awaiter(this, void 0, void 0, function* () {
        if (!web3 || !account) {
            let resp = yield connectWeb3();
            web3 = resp.web3;
            account = resp.account;
        }
        (0, utils_1.log)("pausing...");
        yield new Promise((resolve) => setTimeout(resolve, 500));
        (0, utils_1.log)("signing with ", account);
        // const signature = await web3.getSigner().signMessage(body);
        const signature = yield (0, exports.signMessageAsync)(web3.getSigner(), account, body);
        //.request({ method: 'personal_sign', params: [account, body] })
        const address = (0, wallet_1.verifyMessage)(body, signature).toLowerCase();
        (0, utils_1.log)("Signature: ", signature);
        (0, utils_1.log)("recovered address: ", address);
        if (address !== account) {
            const msg = `ruh roh, the user signed with a different address (${address}) then they\'re using with web3 (${account}).  this will lead to confusion.`;
            console.error(msg);
            alert("something seems to be wrong with your wallets message signing.  maybe restart your browser or your wallet.  your recovered sig address does not match your web3 account address");
            throw new Error(msg);
        }
        return { signature, address };
    });
}
exports.signMessage = signMessage;
// wrapper around signMessage that tries personal_sign first.  this is to fix a
// bug with walletconnect where just using signMessage was failing
const signMessageAsync = (signer, address, message) => __awaiter(void 0, void 0, void 0, function* () {
    const messageBytes = (0, strings_1.toUtf8Bytes)(message);
    if (signer instanceof providers_1.JsonRpcSigner) {
        try {
            (0, utils_1.log)("Signing with personal_sign");
            const signature = yield signer.provider.send("personal_sign", [
                (0, bytes_1.hexlify)(messageBytes),
                address.toLowerCase(),
            ]);
            return signature;
        }
        catch (e) {
            (0, utils_1.log)("Signing with personal_sign failed, trying signMessage as a fallback");
            if (e.message.includes("personal_sign")) {
                return yield signer.signMessage(messageBytes);
            }
            throw e;
        }
    }
    else {
        (0, utils_1.log)("signing with signMessage");
        return yield signer.signMessage(messageBytes);
    }
});
exports.signMessageAsync = signMessageAsync;
// export async function decryptWithWeb3PrivateKey (encryptedData) {
//   const { web3, account } = await connectWeb3()
//   try {
//     const decryptedMessage = ethereum
//       .request({
//         method: 'eth_decrypt',
//         params: [encryptedData, account]
//       })
//     return decryptedMessage
//   } catch (error) {
//     log(error)
//     return false
//   }
// }
//
// async function deriveKeysViaSignature () {
//   const { signature, address } = await signMessage({ body: KEY_DERIVATION_SIGNATURE_BODY })
//   log('Signed message: ' + signature)
//
//   // derive keypair
//   const data = Buffer.from(signature.substring(2), 'hex')
//   const hash = await crypto.subtle.digest('SHA-256', data)
//   const uint8Hash = new Uint8Array(hash)
//   const { publicKey, secretKey } = nacl.box.keyPair.fromSecretKey(uint8Hash)
//   return {
//     publicKey: naclUtil.encodeBase64(publicKey),
//     secretKey: naclUtil.encodeBase64(secretKey)
//   }
// }
//
// // this only works on metamask :(
// async function deriveKeysViaPrivateKey () {
//   try {
//     const { web3, account } = await connectWeb3()
//     /* global ethereum */
//     /* eslint no-undef: "error" */
//     const publicKey = await ethereum
//       .request({
//         method: 'eth_getEncryptionPublicKey',
//         params: [account] // you must have access to the specified account
//       })
//     return { publicKey }
//   } catch (error) {
//     log(error)
//     if (error.code === 4001) {
//       // EIP-1193 userRejectedRequest error
//       log("We can't encrypt anything without the key.")
//       error('You must accept the metamask request to derive your public encryption key')
//     } else {
//       console.error(error)
//     }
//     return { error }
//   }
// }
//
// export async function deriveEncryptionKeys () {
//   let keypair = {}
//   // key derivation via metamask is more desirable because then even this SDK can't see the secret key :-D
//   const { error, publicKey } = await deriveKeysViaPrivateKey()
//   if (!error) {
//     keypair = {
//       publicKey,
//       derivedVia: 'eth_getEncryptionPublicKey'
//     }
//   } else {
//     const { publicKey, secretKey } = await deriveKeysViaSignature()
//     keypair = {
//       publicKey,
//       secretKey,
//       derivedVia: 'web3.eth.personal.sign',
//       signedMessage: KEY_DERIVATION_SIGNATURE_BODY
//     }
//   }
//
//   const { web3, account } = await connectWeb3()
//   keypair.address = account
//
//   log('public key: ' + keypair.publicKey)
//   const asString = JSON.stringify(keypair)
//   localStorage.setItem('lit-keypair', asString)
//
//   // is it already saved on the server?
//   const { pubkey, errorCode } = await getPublicKey({
//     address: account
//   })
//   if (errorCode === 'not_found' || pubkey !== keypair.publicKey) {
//     // add it
//     const msg = `I am saving my public key so that others can send me LITs.  It is ${pubkey}`
//     const res = await signMessage({ body: msg })
//     await savePublicKey({
//       sig: res.signature,
//       msg,
//       pubkey: keypair.publicKey
//     })
//   }
// }
/**
 * This function mints a LIT using our pre-deployed token contracts.  You may use our contracts, or you may supply your own.  Our contracts are ERC1155 tokens on Polygon and Ethereum.  Using these contracts is the easiest way to get started.
 * @param {Object} params
 * @param {string} params.chain The chain to mint on.  "ethereum" and "polygon" are currently supported.
 * @param {number} params.quantity The number of tokens to mint.  Note that these will be fungible, so they will not have serial numbers.
 * @returns {Object} The txHash, tokenId, tokenAddress, mintingAddress, and authSig.
 */
function mintLIT({ chain, quantity }) {
    return __awaiter(this, void 0, void 0, function* () {
        (0, utils_1.log)(`minting ${quantity} tokens on ${chain}`);
        try {
            const authSig = yield checkAndSignEVMAuthMessage({
                chain,
                switchChain: true,
            });
            if (authSig.errorCode) {
                return authSig;
            }
            const { web3, account } = yield connectWeb3();
            // @ts-expect-error TS(7053): Element implicitly has an 'any' type because expre... Remove this comment to see the full error message
            const tokenAddress = constants_1.LIT_CHAINS[chain].contractAddress;
            if (!tokenAddress) {
                (0, utils_1.log)("No token address for this chain.  It's not supported via MintLIT.");
                (0, utils_1.throwError)({
                    message: `This chain is not supported for minting with the Lit token contract because it hasn't been deployed to this chain.  You can use Lit with your own token contract on this chain, though.`,
                    name: "MintingNotSupported",
                    errorCode: "minting_not_supported",
                });
                return;
            }
            const contract = new contracts_1.Contract(tokenAddress, LIT_json_1.default.abi, web3.getSigner());
            (0, utils_1.log)("sending to chain...");
            const tx = yield contract.mint(quantity);
            (0, utils_1.log)("sent to chain.  waiting to be mined...");
            const txReceipt = yield tx.wait();
            (0, utils_1.log)("txReceipt: ", txReceipt);
            const tokenId = txReceipt.events[0].args[3].toNumber();
            return {
                txHash: txReceipt.transactionHash,
                tokenId,
                tokenAddress,
                mintingAddress: account,
                authSig,
            };
        }
        catch (error) {
            (0, utils_1.log)(error);
            if (error.code === 4001) {
                // EIP-1193 userRejectedRequest error
                (0, utils_1.log)("User rejected request");
                return { errorCode: "user_rejected_request" };
            }
            else {
                console.error(error);
            }
            return { errorCode: "unknown_error" };
        }
    });
}
exports.mintLIT = mintLIT;
/**
 * Finds the tokens that the current user owns from the predeployed LIT contracts
 * @param {Object} params
 * @param {string} params.chain The chain that was minted on. "ethereum" and "polygon" are currently supported.
 * @param {number} params.accountAddress The account address to check
 * @returns {array} The token ids owned by the accountAddress
 */
function findLITs() {
    return __awaiter(this, void 0, void 0, function* () {
        (0, utils_1.log)("findLITs");
        try {
            const { web3, account } = yield connectWeb3();
            const { chainId } = yield web3.getNetwork();
            // @ts-expect-error TS(2345): Argument of type 'string' is not assignable to par... Remove this comment to see the full error message
            const chainHexId = "0x" + chainId.toString("16");
            // const chainHexId = await web3.request({ method: 'eth_chainId', params: [] })
            const chain = chainHexIdToChainName(chainHexId);
            // @ts-expect-error TS(2538): Type 'undefined' cannot be used as an index type.
            const tokenAddress = constants_1.LIT_CHAINS[chain].contractAddress;
            const contract = new contracts_1.Contract(tokenAddress, LIT_json_1.default.abi, web3.getSigner());
            (0, utils_1.log)("getting maxTokenid");
            const maxTokenId = yield contract.tokenIds();
            const accounts = [];
            const tokenIds = [];
            for (let i = 0; i <= maxTokenId; i++) {
                accounts.push(account);
                tokenIds.push(i);
            }
            (0, utils_1.log)("getting balanceOfBatch");
            const balances = yield contract.balanceOfBatch(accounts, tokenIds);
            // log('balances', balances)
            const tokenIdsWithNonzeroBalances = balances
                .map((b, i) => (b.toNumber() === 0 ? null : i))
                .filter((b) => b !== null);
            return { tokenIds: tokenIdsWithNonzeroBalances, chain };
        }
        catch (error) {
            (0, utils_1.log)(error);
            if (error.code === 4001) {
                // EIP-1193 userRejectedRequest error
                (0, utils_1.log)("User rejected request");
                return { errorCode: "user_rejected_request" };
            }
            else {
                console.error(error);
            }
            return { errorCode: "unknown_error" };
        }
    });
}
exports.findLITs = findLITs;
/**
 * Send a token to another account
 * @param {Object} params
 * @param {string} params.tokenMetadata The token metadata of the token to be transferred.  Should include tokenId, tokenAddress, and chain
 * @param {number} params.to The account address to send the token to
 * @returns {Object} Success or error
 */
function sendLIT({ tokenMetadata, to }) {
    return __awaiter(this, void 0, void 0, function* () {
        (0, utils_1.log)("sendLIT for ", tokenMetadata);
        try {
            const { web3, account } = yield connectWeb3();
            const { tokenAddress, tokenId, chain } = tokenMetadata;
            const contract = new contracts_1.Contract(tokenAddress, LIT_json_1.default.abi, web3.getSigner());
            (0, utils_1.log)("transferring");
            const maxTokenId = yield contract.safeTransferFrom(account, to, tokenId, 1, []);
            (0, utils_1.log)("sent to chain");
            return { success: true };
        }
        catch (error) {
            (0, utils_1.log)(error);
            if (error.code === 4001) {
                // EIP-1193 userRejectedRequest error
                (0, utils_1.log)("User rejected request");
                return { errorCode: "user_rejected_request" };
            }
            else {
                console.error(error);
            }
            return { errorCode: "unknown_error" };
        }
    });
}
exports.sendLIT = sendLIT;
/**
 * Get the number of decimal places in a token
 * @param {Object} params
 * @param {string} params.contractAddress The token contract address
 * @param {string} params.chain The chain on which the token is deployed
 * @returns {number} The number of decimal places in the token
 */
function decimalPlaces({ contractAddress, chain }) {
    return __awaiter(this, void 0, void 0, function* () {
        // if (chain) {
        //   await checkAndSignEVMAuthMessage({ chain }); // this will switch them to the correct chain
        // }
        // const { web3, account } = await connectWeb3();
        // @ts-expect-error TS(7053): Element implicitly has an 'any' type because expre... Remove this comment to see the full error message
        const rpcUrl = constants_1.LIT_CHAINS[chain].rpcUrls[0];
        const web3 = new providers_1.JsonRpcProvider(rpcUrl);
        const contract = new contracts_1.Contract(contractAddress, ERC20_json_1.default.abi, web3);
        return yield contract.decimals();
    });
}
exports.decimalPlaces = decimalPlaces;
/**
 * Lookup an eth address from a given ENS name
 * @param {Object} params
 * @param {string} params.chain The chain on which to resolve the name
 * @param {string} params.name The name to resolve
 * @returns {string} The resolved eth address
 */
function lookupNameServiceAddress({ chain, name }) {
    return __awaiter(this, void 0, void 0, function* () {
        // await checkAndSignEVMAuthMessage({ chain }); // this will switch them to the correct chain
        // const { web3, account } = await connectWeb3();
        // @ts-expect-error TS(7053): Element implicitly has an 'any' type because expre... Remove this comment to see the full error message
        const rpcUrl = constants_1.LIT_CHAINS[chain].rpcUrls[0];
        const web3 = new providers_1.JsonRpcProvider(rpcUrl);
        var address = yield web3.resolveName(name);
        return address;
        // const parts = name.split(".");
        // const tld = parts[parts.length - 1].toLowerCase();
        // if (tld === "eth") {
        //   var address = await web3.resolveName(name);
        //   return address;
        // } //else {
        // const resolution = Resolution.fromEthersProvider(web3);
        // const address = await resolution.addr(name, "ETH");
        // // TODO: remove unstoppable dependency because it's big.  the below code is
        // // from the ethers ens lib.  can we make the above this small and remove the unstoppable lib?
        // // const addrData = await this.call({
        // //   to: network.ensAddress,
        // //   data: "0x0178b8bf" + namehash(name).substring(2),
        // // });
        // // return this.formatter.callAddress(addrData);
        // return address;
        //}
    });
}
exports.lookupNameServiceAddress = lookupNameServiceAddress;
