import { Contract } from "@ethersproject/contracts";
import { Interface } from "@ethersproject/abi";
import { verifyMessage } from "@ethersproject/wallet";
import { Web3Provider, JsonRpcSigner } from "@ethersproject/providers";
import { toUtf8Bytes } from "@ethersproject/strings";
import { hexlify } from "@ethersproject/bytes";
import Web3Modal from "lit-web3modal";
import WalletConnectProvider from "@walletconnect/web3-provider";
import Resolution from "@unstoppabledomains/resolution";
import detectEthereumProvider from "@metamask/detect-provider";

import naclUtil from "tweetnacl-util";
import nacl from "tweetnacl";

import LIT from "../abis/LIT.json";
import ERC20 from "../abis/ERC20.json";
import { LIT_CHAINS } from "../lib/constants";
import { throwError } from "../lib/utils";

const AUTH_SIGNATURE_BODY =
  "I am creating an account to use Lit Protocol at {{timestamp}}";

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

export async function connectWeb3() {
  if (typeof window.ethereum === "undefined") {
    throwError({
      message: "No web3 wallet was found",
      name: "NoWalletException",
      errorCode: "no_wallet",
    });
  }

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
      },
    },
  };

  console.log("getting provider via web3modal");
  // disabled because web3modal uses localstorage and breaks when
  // used on opensea
  const web3Modal = new Web3Modal({
    cacheProvider: true, // optional
    providerOptions, // required
  });
  const provider = await web3Modal.connect();
  console.log("got provider", provider);
  const web3 = new Web3Provider(provider);
  console.log("got web3", web3);

  // const provider = await detectEthereumProvider();
  // const web3 = new Web3Provider(provider);

  // trigger metamask popup
  await provider.enable();

  console.log("listing accounts");
  const accounts = await web3.listAccounts();
  // const accounts = await provider.request({
  //   method: "eth_requestAccounts",
  //   params: [],
  // });
  console.log("accounts", accounts);
  const account = accounts[0].toLowerCase();

  return { web3, account };
}

export async function disconnectWeb3() {
  const web3Modal = new Web3Modal({
    cacheProvider: true, // optional
  });
  web3Modal.clearCachedProvider();
  localStorage.removeItem("walletconnect");
  localStorage.removeItem("lit-auth-signature");
}

// taken from the excellent repo https://github.com/zmitton/eth-proof
// export async function getMerkleProof({ tokenAddress, balanceStorageSlot, tokenId }) {
//   console.log(`getMerkleProof for { tokenAddress, balanceStorageSlot, tokenId } ${tokenAddress}, ${balanceStorageSlot}, ${tokenId}`)
//   const { web3, account } = await connectWeb3()
//   console.log(`getting mappingAt(${balanceStorageSlot}, ${tokenId}, ${account})`)
//   const storageAddress = mappingAt(balanceStorageSlot, parseInt(tokenId), account)
//   console.log('storageAddress: ', storageAddress)

//   // you may need to try the below twicce because sometimes the proof isn't available for the latest block on polygon because the node just isn't fast enough
//   let tries = 0
//   let rpcProof = null
//   let rpcBlock = null
//   while (!rpcProof && tries < 6) {
//     try {
//       if (!rpcBlock) {
//         // only set the rpc block once
//         rpcBlock = await web3.request({ method: 'eth_getBlockByNumber', params: ['latest', false] })
//         console.log('rpcBlock: ', rpcBlock)
//       }
//       rpcProof = await web3.request({ method: 'eth_getProof', params: [tokenAddress, [storageAddress], rpcBlock.number] })
//       console.log('rpcProof: ', rpcProof)
//     } catch (e) {
//       console.log(e)
//       console.log(`error getting rpc proof, have made ${tries} attempts`)
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

/**
 * Check for an existing cryptographic authentication signature and create one of it does not exist.  This is used to prove ownership of a given crypto wallet address to the LIT nodes.  The result is stored in LocalStorage so the user doesn't have to sign every time they perform an operation.
 * @param {Object} params
 * @param {string} params.chain The chain you want to use.  "polygon" and "ethereum" are currently supported.
 * @returns {AuthSig} The AuthSig created or retrieved
 */
export async function checkAndSignAuthMessage({ chain }) {
  const { web3, account } = await connectWeb3();
  const { chainId } = await web3.getNetwork();
  const selectedChain = LIT_CHAINS[chain];
  let selectedChainId = "0x" + selectedChain.chainId.toString("16");
  console.log("chainId from web3", chainId);
  console.debug(
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
      console.log("trying to switch to chainId", selectedChainId);
      await web3.provider.request({
        method: "wallet_switchEthereumChain",
        params: [{ chainId: selectedChainId }],
      });
    } catch (switchError) {
      console.log("error switching to chainId", switchError);
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
  console.log("checking if sig is in local storage");
  let authSig = localStorage.getItem("lit-auth-signature");
  if (!authSig) {
    console.log("signing auth message because sig is not in local storage");
    await signAndSaveAuthMessage({ web3, account });
    authSig = localStorage.getItem("lit-auth-signature");
  }
  authSig = JSON.parse(authSig);
  // make sure we are on the right account
  if (account !== authSig.address) {
    console.log(
      "signing auth message because account is not the same as the address in the auth sig"
    );
    await signAndSaveAuthMessage({ web3, account });
    authSig = localStorage.getItem("lit-auth-signature");
    authSig = JSON.parse(authSig);
  }
  console.log("got auth sig", authSig);
  return authSig;
}

/**
 * Sign the auth message with the user's wallet, and store it in localStorage.  Called by checkAndSignAuthMessage if the user does not have a signature stored.
 * @param {Object} params
 * @param {Web3Provider} params.web3 An ethers.js Web3Provider instance
 * @param {string} params.account The account to sign the message with
 * @returns {AuthSig} The AuthSig created or retrieved
 */
export async function signAndSaveAuthMessage({ web3, account }) {
  const now = new Date().toISOString();
  const body = AUTH_SIGNATURE_BODY.replace("{{timestamp}}", now);
  const signedResult = await signMessage({ body, web3, account });
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
  console.log("generated and saved lit-comms-keypair");
}

/**
 * @typedef {Object} AuthSig
 * @property {string} sig - The actual hex-encoded signature
 * @property {string} derivedVia - The method used to derive the signature
 * @property {string} signedMessage - The message that was signed
 * @property {string} address - The crypto wallet address that signed the message
 */
export async function signMessage({ body, web3, account }) {
  if (!web3 || !account) {
    let resp = await connectWeb3();
    web3 = resp.web3;
    account = resp.account;
  }

  console.log("pausing...");
  await new Promise((resolve) => setTimeout(resolve, 500));
  console.log("signing with ", account);
  // const signature = await web3.getSigner().signMessage(body);
  const signature = await signMessageAsync(web3.getSigner(), account, body);
  //.request({ method: 'personal_sign', params: [account, body] })
  const address = verifyMessage(body, signature).toLowerCase();

  console.log("Signature: ", signature);
  console.log("recovered address: ", address);

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
const signMessageAsync = async (signer, address, message) => {
  const messageBytes = toUtf8Bytes(message);
  if (signer instanceof JsonRpcSigner) {
    try {
      const signature = await signer.provider.send("personal_sign", [
        hexlify(messageBytes),
        address.toLowerCase(),
      ]);
      return signature;
    } catch (e) {
      if (e.message.includes("personal_sign")) {
        return await signer.signMessage(messageBytes);
      }
      throw e;
    }
  } else {
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
//     console.log(error)
//     return false
//   }
// }
//
// async function deriveKeysViaSignature () {
//   const { signature, address } = await signMessage({ body: KEY_DERIVATION_SIGNATURE_BODY })
//   console.log('Signed message: ' + signature)
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
//     console.log(error)
//     if (error.code === 4001) {
//       // EIP-1193 userRejectedRequest error
//       console.log("We can't encrypt anything without the key.")
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
//   console.log('public key: ' + keypair.publicKey)
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
  console.log(`minting ${quantity} tokens on ${chain}`);
  try {
    const authSig = await checkAndSignAuthMessage({ chain });
    if (authSig.errorCode) {
      return authSig;
    }
    const { web3, account } = await connectWeb3();
    const tokenAddress = LIT_CHAINS[chain].contractAddress;
    const contract = new Contract(tokenAddress, LIT.abi, web3.getSigner());
    console.log("sending to chain...");
    const tx = await contract.mint(quantity);
    console.log("sent to chain.  waiting to be mined...");
    const txReceipt = await tx.wait();
    console.log("txReceipt: ", txReceipt);
    const tokenId = txReceipt.events[0].args[3].toNumber();
    return {
      txHash: txReceipt.transactionHash,
      tokenId,
      tokenAddress,
      mintingAddress: account,
      authSig,
    };
  } catch (error) {
    console.log(error);
    if (error.code === 4001) {
      // EIP-1193 userRejectedRequest error
      console.log("User rejected request");
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
  console.log("findLITs");

  try {
    const { web3, account } = await connectWeb3();
    const { chainId } = await web3.getNetwork();
    const chainHexId = "0x" + chainId.toString("16");
    // const chainHexId = await web3.request({ method: 'eth_chainId', params: [] })
    const chain = chainHexIdToChainName(chainHexId);
    const tokenAddress = LIT_CHAINS[chain].contractAddress;
    const contract = new Contract(tokenAddress, LIT.abi, new web3.getSigner());
    console.log("getting maxTokenid");
    const maxTokenId = await contract.tokenIds();
    const accounts = [];
    const tokenIds = [];
    for (let i = 0; i <= maxTokenId; i++) {
      accounts.push(account);
      tokenIds.push(i);
    }
    console.log("getting balanceOfBatch");
    const balances = await contract.balanceOfBatch(accounts, tokenIds);
    // console.log('balances', balances)
    const tokenIdsWithNonzeroBalances = balances
      .map((b, i) => (b.toNumber() === 0 ? null : i))
      .filter((b) => b !== null);
    return { tokenIds: tokenIdsWithNonzeroBalances, chain };
  } catch (error) {
    console.log(error);
    if (error.code === 4001) {
      // EIP-1193 userRejectedRequest error
      console.log("User rejected request");
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
  console.log("sendLIT for ", tokenMetadata);

  try {
    const { web3, account } = await connectWeb3();
    const { tokenAddress, tokenId, chain } = tokenMetadata;
    const contract = new Contract(tokenAddress, LIT.abi, web3.getSigner());
    console.log("transferring");
    const maxTokenId = await contract.safeTransferFrom(
      account,
      to,
      tokenId,
      1,
      []
    );
    console.log("sent to chain");
    return { success: true };
  } catch (error) {
    console.log(error);
    if (error.code === 4001) {
      // EIP-1193 userRejectedRequest error
      console.log("User rejected request");
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
  if (chain) {
    await checkAndSignAuthMessage({ chain }); // this will switch them to the correct chain
  }
  const { web3, account } = await connectWeb3();
  const contract = new Contract(contractAddress, ERC20, web3);
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
  await checkAndSignAuthMessage({ chain }); // this will switch them to the correct chain
  const { web3, account } = await connectWeb3();

  const parts = name.split(".");
  const tld = parts[parts.length - 1].toLowerCase();
  if (tld === "eth") {
    var address = await web3.resolveName(name);
    return address;
  } else {
    const resolution = Resolution.fromEthersProvider(web3);
    const address = await resolution.addr(name, "ETH");
    return address;
  }
}
