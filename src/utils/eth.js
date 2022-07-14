import { Contract } from "@ethersproject/contracts";
import { verifyMessage } from "@ethersproject/wallet";
import {
  Web3Provider,
  JsonRpcSigner,
  JsonRpcProvider,
} from "@ethersproject/providers";
import { toUtf8Bytes } from "@ethersproject/strings";
import { hexlify } from "@ethersproject/bytes";
import { getAddress } from "@ethersproject/address";
import WalletConnectProvider from "@walletconnect/ethereum-provider";
import LitConnectModal from "lit-connect-modal";
import { SiweMessage } from "lit-siwe";

import naclUtil from "tweetnacl-util";
import nacl from "tweetnacl";

import LIT from "../abis/LIT.json";
import ERC20 from "../abis/ERC20.json";
import { LIT_CHAINS } from "../lib/constants";
import { throwError, log } from "../lib/utils";

function chainHexIdToChainName(chainHexId) {
  for (let i = 0; i < Object.keys(LIT_CHAINS).length; i++) {
    const chainName = Object.keys(LIT_CHAINS)[i];
    const litChainHexId = "0x" + LIT_CHAINS[chainName].chainId.toString("16");
    if (litChainHexId === chainHexId) {
      return chainName;
    }
  }
}

export function encodeCallData({ abi, functionName, functionParams }) {
  const iface = new ethers.utils.Interface(abi);
  const callData = iface.encodeFunctionData(functionName, functionParams);
  return callData;
}

export function decodeCallResult({ abi, functionName, data }) {
  const iface = new ethers.utils.Interface(abi);
  const decoded = iface.decodeFunctionResult(functionName, data);
  return decoded;
}

export async function connectWeb3({ chainId = 1 } = {}) {
  const rpcUrls = {};
  // need to make it look like this:
  // rpc: {
  //   1: "https://mainnet.mycustomnode.com",
  //   3: "https://ropsten.mycustomnode.com",
  //   100: "https://dai.poa.network",
  //   // ...
  // },

  for (let i = 0; i < Object.keys(LIT_CHAINS).length; i++) {
    const chainName = Object.keys(LIT_CHAINS)[i];
    const chainId = LIT_CHAINS[chainName].chainId;
    const rpcUrl = LIT_CHAINS[chainName].rpcUrls[0];
    rpcUrls[chainId] = rpcUrl;
  }

  const providerOptions = {
    walletconnect: {
      package: WalletConnectProvider, // required
      options: {
        // infuraId: "cd614bfa5c2f4703b7ab0ec0547d9f81",
        rpc: rpcUrls,
        chainId,
      },
    },
  };

  log("getting provider via lit connect modal");

  const dialog = new LitConnectModal({
    providerOptions,
  });
  const provider = await dialog.getWalletProvider();

  log("got provider", provider);
  const web3 = new Web3Provider(provider);

  // const provider = await detectEthereumProvider();
  // const web3 = new Web3Provider(provider);

  // trigger metamask popup
  await provider.enable();

  log("listing accounts");
  const accounts = await web3.listAccounts();
  // const accounts = await provider.request({
  //   method: "eth_requestAccounts",
  //   params: [],
  // });
  log("accounts", accounts);
  const account = accounts[0].toLowerCase();

  return { web3, account };
}

/**
 * Delete any saved AuthSigs from local storage.  Takes no params and returns nothing.  This will also clear out the WalletConnect cache in local storage.  We often run this function as a result of the user pressing a "Logout" button.
 */
export async function disconnectWeb3() {
  localStorage.removeItem("walletconnect");
  localStorage.removeItem("lit-auth-signature");
  localStorage.removeItem("lit-auth-sol-signature");
  localStorage.removeItem("lit-auth-cosmos-signature");
  localStorage.removeItem("lit-web3-provider");
}

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

export async function checkAndSignEVMAuthMessage({ chain, resources }) {
  const selectedChain = LIT_CHAINS[chain];
  const { web3, account } = await connectWeb3({
    chainId: selectedChain.chainId,
  });
  log(`got web3 and account: ${account}`);

  let chainId;
  try {
    const resp = await web3.getNetwork();
    chainId = resp.chainId;
  } catch (e) {
    // couldn't get chainId.  throw the incorrect network error
    log("getNetwork threw an exception", e);
    throwError({
      message: `Incorrect network selected.  Please switch to the ${chain} network in your wallet and try again.`,
      name: "WrongNetworkException",
      errorCode: "wrong_network",
    });
  }
  let selectedChainId = "0x" + selectedChain.chainId.toString("16");
  log("chainId from web3", chainId);
  log(
    `checkAndSignAuthMessage with chainId ${chainId} and chain set to ${chain} and selectedChain is `,
    selectedChain
  );
  if (chainId !== selectedChain.chainId) {
    if (web3.provider instanceof WalletConnectProvider) {
      // this chain switching won't work.  alert the user that they need to switch chains manually
      throwError({
        message: `Incorrect network selected.  Please switch to the ${chain} network in your wallet and try again.`,
        name: "WrongNetworkException",
        errorCode: "wrong_network",
      });
      return;
    }
    try {
      log("trying to switch to chainId", selectedChainId);
      await web3.provider.request({
        method: "wallet_switchEthereumChain",
        params: [{ chainId: selectedChainId }],
      });
    } catch (switchError) {
      log("error switching to chainId", switchError);
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
          await web3.provider.request({
            method: "wallet_addEthereumChain",
            params: data,
          });
        } catch (addError) {
          // handle "add" error
          if (addError.code === -32601) {
            // metamask code indicating "no such method"
            throwError({
              message: `Incorrect network selected.  Please switch to the ${chain} network in your wallet and try again.`,
              name: "WrongNetworkException",
              errorCode: "wrong_network",
            });
          } else {
            throw addError;
          }
        }
      } else {
        if (switchError.code === -32601) {
          // metamask code indicating "no such method"
          throwError({
            message: `Incorrect network selected.  Please switch to the ${chain} network in your wallet and try again.`,
            name: "WrongNetworkException",
            errorCode: "wrong_network",
          });
        } else {
          throw switchError;
        }
      }
    }
  }
  log("checking if sig is in local storage");
  let authSig = localStorage.getItem("lit-auth-signature");
  if (!authSig) {
    log("signing auth message because sig is not in local storage");
    await signAndSaveAuthMessage({
      web3,
      account,
      chainId: selectedChain.chainId,
      resources,
    });
    authSig = localStorage.getItem("lit-auth-signature");
  }
  authSig = JSON.parse(authSig);
  // make sure we are on the right account
  if (account !== authSig.address) {
    log(
      "signing auth message because account is not the same as the address in the auth sig"
    );
    await signAndSaveAuthMessage({
      web3,
      account,
      chainId: selectedChain.chainId,
      resources,
    });
    authSig = localStorage.getItem("lit-auth-signature");
    authSig = JSON.parse(authSig);
  } else {
    // check the resources of the sig and re-sign if they don't match
    let mustResign = false;
    try {
      const parsedSiwe = new SiweMessage(authSig.signedMessage);
      log("parsedSiwe.resources", parsedSiwe.resources);

      if (JSON.stringify(parsedSiwe.resources) !== JSON.stringify(resources)) {
        log(
          "signing auth message because resources differ from the resources in the auth sig"
        );
        mustResign = true;
      } else if (parsedSiwe.address !== getAddress(parsedSiwe.address)) {
        log(
          "signing auth message because parsedSig.address is not equal to the same address but checksummed.  This usually means the user had a non-checksummed address saved and so they need to re-sign."
        );
        mustResign = true;
      }
    } catch (e) {
      log("error parsing siwe sig.  making the user sign again: ", e);
      mustResign = true;
    }
    if (mustResign) {
      await signAndSaveAuthMessage({
        web3,
        account,
        chainId: selectedChain.chainId,
        resources,
      });
      authSig = localStorage.getItem("lit-auth-signature");
      authSig = JSON.parse(authSig);
    }
  }
  log("got auth sig", authSig);
  return authSig;
}

/**
 * Sign the auth message with the user's wallet, and store it in localStorage.  Called by checkAndSignAuthMessage if the user does not have a signature stored.
 * @param {Object} params
 * @param {Web3Provider} params.web3 An ethers.js Web3Provider instance
 * @param {string} params.account The account to sign the message with
 * @returns {AuthSig} The AuthSig created or retrieved
 */
export async function signAndSaveAuthMessage({
  web3,
  account,
  chainId,
  resources,
}) {
  // const { chainId } = await web3.getNetwork();

  const preparedMessage = {
    domain: globalThis.location.host,
    address: getAddress(account), // convert to EIP-55 format or else SIWE complains
    uri: globalThis.location.origin,
    version: "1",
    // chainId,
  };

  if (resources && resources.length > 0) {
    preparedMessage.resources = resources;
  }

  const message = new SiweMessage(preparedMessage);

  const body = message.prepareMessage();

  const signedResult = await signMessage({
    body,
    web3,
    account,
  });

  localStorage.setItem(
    "lit-auth-signature",
    JSON.stringify({
      sig: signedResult.signature,
      derivedVia: "web3.eth.personal.sign",
      signedMessage: body,
      address: signedResult.address,
    })
  );
  // store a keypair in localstorage for communication with sgx
  const commsKeyPair = nacl.box.keyPair();
  localStorage.setItem(
    "lit-comms-keypair",
    JSON.stringify({
      publicKey: naclUtil.encodeBase64(commsKeyPair.publicKey),
      secretKey: naclUtil.encodeBase64(commsKeyPair.secretKey),
    })
  );
  log("generated and saved lit-comms-keypair");
}

/**
 * @typedef {Object} AuthSig
 * @property {string} sig - The actual hex-encoded signature
 * @property {string} derivedVia - The method used to derive the signature. Typically "web3.eth.personal.sign"
 * @property {string} signedMessage - The message that was signed
 * @property {string} address - The crypto wallet address that signed the message
 */

export async function signMessage({ body, web3, account }) {
  if (!web3 || !account) {
    let resp = await connectWeb3();
    web3 = resp.web3;
    account = resp.account;
  }

  log("pausing...");
  await new Promise((resolve) => setTimeout(resolve, 500));
  log("signing with ", account);
  // const signature = await web3.getSigner().signMessage(body);
  const signature = await signMessageAsync(web3.getSigner(), account, body);
  //.request({ method: 'personal_sign', params: [account, body] })
  const address = verifyMessage(body, signature).toLowerCase();

  log("Signature: ", signature);
  log("recovered address: ", address);

  if (address !== account) {
    const msg = `ruh roh, the user signed with a different address (${address}) then they\'re using with web3 (${account}).  this will lead to confusion.`;
    console.error(msg);
    alert(
      "something seems to be wrong with your wallets message signing.  maybe restart your browser or your wallet.  your recovered sig address does not match your web3 account address"
    );
    throw new Error(msg);
  }

  return { signature, address };
}

// wrapper around signMessage that tries personal_sign first.  this is to fix a
// bug with walletconnect where just using signMessage was failing
export const signMessageAsync = async (signer, address, message) => {
  const messageBytes = toUtf8Bytes(message);
  if (signer instanceof JsonRpcSigner) {
    try {
      log("Signing with personal_sign");
      const signature = await signer.provider.send("personal_sign", [
        hexlify(messageBytes),
        address.toLowerCase(),
      ]);
      return signature;
    } catch (e) {
      log(
        "Signing with personal_sign failed, trying signMessage as a fallback"
      );
      if (e.message.includes("personal_sign")) {
        return await signer.signMessage(messageBytes);
      }
      throw e;
    }
  } else {
    log("signing with signMessage");
    return await signer.signMessage(messageBytes);
  }
};

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
export async function mintLIT({ chain, quantity }) {
  log(`minting ${quantity} tokens on ${chain}`);
  try {
    const authSig = await checkAndSignEVMAuthMessage({ chain });
    if (authSig.errorCode) {
      return authSig;
    }
    const { web3, account } = await connectWeb3();
    const tokenAddress = LIT_CHAINS[chain].contractAddress;
    if (!tokenAddress) {
      log("No token address for this chain.  It's not supported via MintLIT.");
      throwError({
        message: `This chain is not supported for minting with the Lit token contract because it hasn't been deployed to this chain.  You can use Lit with your own token contract on this chain, though.`,
        name: "MintingNotSupported",
        errorCode: "minting_not_supported",
      });
      return;
    }
    const contract = new Contract(tokenAddress, LIT.abi, web3.getSigner());
    log("sending to chain...");
    const tx = await contract.mint(quantity);
    log("sent to chain.  waiting to be mined...");
    const txReceipt = await tx.wait();
    log("txReceipt: ", txReceipt);
    const tokenId = txReceipt.events[0].args[3].toNumber();
    return {
      txHash: txReceipt.transactionHash,
      tokenId,
      tokenAddress,
      mintingAddress: account,
      authSig,
    };
  } catch (error) {
    log(error);
    if (error.code === 4001) {
      // EIP-1193 userRejectedRequest error
      log("User rejected request");
      return { errorCode: "user_rejected_request" };
    } else {
      console.error(error);
    }
    return { errorCode: "unknown_error" };
  }
}

/**
 * Finds the tokens that the current user owns from the predeployed LIT contracts
 * @param {Object} params
 * @param {string} params.chain The chain that was minted on. "ethereum" and "polygon" are currently supported.
 * @param {number} params.accountAddress The account address to check
 * @returns {array} The token ids owned by the accountAddress
 */
export async function findLITs() {
  log("findLITs");

  try {
    const { web3, account } = await connectWeb3();
    const { chainId } = await web3.getNetwork();
    const chainHexId = "0x" + chainId.toString("16");
    // const chainHexId = await web3.request({ method: 'eth_chainId', params: [] })
    const chain = chainHexIdToChainName(chainHexId);
    const tokenAddress = LIT_CHAINS[chain].contractAddress;
    const contract = new Contract(tokenAddress, LIT.abi, web3.getSigner());
    log("getting maxTokenid");
    const maxTokenId = await contract.tokenIds();
    const accounts = [];
    const tokenIds = [];
    for (let i = 0; i <= maxTokenId; i++) {
      accounts.push(account);
      tokenIds.push(i);
    }
    log("getting balanceOfBatch");
    const balances = await contract.balanceOfBatch(accounts, tokenIds);
    // log('balances', balances)
    const tokenIdsWithNonzeroBalances = balances
      .map((b, i) => (b.toNumber() === 0 ? null : i))
      .filter((b) => b !== null);
    return { tokenIds: tokenIdsWithNonzeroBalances, chain };
  } catch (error) {
    log(error);
    if (error.code === 4001) {
      // EIP-1193 userRejectedRequest error
      log("User rejected request");
      return { errorCode: "user_rejected_request" };
    } else {
      console.error(error);
    }
    return { errorCode: "unknown_error" };
  }
}

/**
 * Send a token to another account
 * @param {Object} params
 * @param {string} params.tokenMetadata The token metadata of the token to be transferred.  Should include tokenId, tokenAddress, and chain
 * @param {number} params.to The account address to send the token to
 * @returns {Object} Success or error
 */
export async function sendLIT({ tokenMetadata, to }) {
  log("sendLIT for ", tokenMetadata);

  try {
    const { web3, account } = await connectWeb3();
    const { tokenAddress, tokenId, chain } = tokenMetadata;
    const contract = new Contract(tokenAddress, LIT.abi, web3.getSigner());
    log("transferring");
    const maxTokenId = await contract.safeTransferFrom(
      account,
      to,
      tokenId,
      1,
      []
    );
    log("sent to chain");
    return { success: true };
  } catch (error) {
    log(error);
    if (error.code === 4001) {
      // EIP-1193 userRejectedRequest error
      log("User rejected request");
      return { errorCode: "user_rejected_request" };
    } else {
      console.error(error);
    }
    return { errorCode: "unknown_error" };
  }
}

/**
 * Get the number of decimal places in a token
 * @param {Object} params
 * @param {string} params.contractAddress The token contract address
 * @param {string} params.chain The chain on which the token is deployed
 * @returns {number} The number of decimal places in the token
 */
export async function decimalPlaces({ contractAddress, chain }) {
  // if (chain) {
  //   await checkAndSignEVMAuthMessage({ chain }); // this will switch them to the correct chain
  // }
  // const { web3, account } = await connectWeb3();
  const rpcUrl = LIT_CHAINS[chain].rpcUrls[0];
  const web3 = new JsonRpcProvider(rpcUrl);
  const contract = new Contract(contractAddress, ERC20.abi, web3);
  return await contract.decimals();
}

/**
 * Lookup an eth address from a given ENS name
 * @param {Object} params
 * @param {string} params.chain The chain on which to resolve the name
 * @param {string} params.name The name to resolve
 * @returns {string} The resolved eth address
 */
export async function lookupNameServiceAddress({ chain, name }) {
  // await checkAndSignEVMAuthMessage({ chain }); // this will switch them to the correct chain
  // const { web3, account } = await connectWeb3();
  const rpcUrl = LIT_CHAINS[chain].rpcUrls[0];
  const web3 = new JsonRpcProvider(rpcUrl);

  var address = await web3.resolveName(name);
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
}
