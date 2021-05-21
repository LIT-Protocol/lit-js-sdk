import Web3 from 'web3'

import detectEthereumProvider from '@metamask/detect-provider'

import naclUtil from 'tweetnacl-util'
import nacl from 'tweetnacl'

import { Header, Proof, Receipt, Transaction } from 'eth-object'
import { mappingAt } from 'eth-util-lite'

import LIT from '../abis/LIT.json'
import { LIT_CHAINS } from '../lib/constants'

const AUTH_SIGNATURE_BODY = 'I am creating an account to use LITs at {{timestamp}}'

// taken from the excellent repo https://github.com/zmitton/eth-proof
export async function getMerkleProof ({ tokenAddress, balanceStorageSlot, tokenId }) {
  const { web3, account } = await connectWeb3()
  const storageAddress = mappingAt(balanceStorageSlot, tokenId, account)
  const rpcBlock = await web3.eth.getBlock('latest')
  const rpcProof = await web3.eth.getProof(tokenAddress, [storageAddress], rpcBlock.number)

  return {
    header: Header.fromRpc(rpcBlock).toJson(),
    accountProof: Proof.fromRpc(rpcProof.accountProof).toJson(),
    storageProof: Proof.fromRpc(rpcProof.storageProof[0].proof).toJson(),
    blockHash: rpcBlock.hash
  }
}

/**
 * @typedef {Object} AuthSig
 * @property {string} sig - The actual hex-encoded signature
 * @property {string} derivedVia - The method used to derive the signature
 * @property {string} signedMessage - The message that was signed
 * @property {string} address - The crypto wallet address that signed the message
 */

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

export async function connectWeb3 () {
  if (typeof window.ethereum === 'undefined') {
    throw new Error({ errorCode: 'no_wallet', message: 'No web3 wallet was found' })
  }

  const provider = await detectEthereumProvider()

  // trigger metamask popup
  const accounts = await provider.request({ method: 'eth_requestAccounts' })
  const account = accounts[0].toLowerCase()

  const web3 = new Web3(provider)
  window.litWeb3 = web3 // for debug
  return { web3, account }
}

/**
 * Check for an existing cryptographic authentication signature and create one of it does not exist.  This is used to prove ownership of a given crypto wallet address to the LIT nodes.  The result is stored in LocalStorage so the user doesn't have to sign every time they perform an operation.
 * @returns {AuthSig} The AuthSig created or retrieved
 */
export async function checkAndSignAuthMessage () {
  let authSig = localStorage.getItem('lit-auth-signature')
  if (!authSig) {
    await signAndSaveAuthMessage()
    authSig = localStorage.getItem('lit-auth-signature')
  }
  authSig = JSON.parse(authSig)
  const { web3, account } = await connectWeb3()
  // make sure we are on the right account
  if (account !== authSig.address) {
    await signAndSaveAuthMessage()
    authSig = localStorage.getItem('lit-auth-signature')
    authSig = JSON.parse(authSig)
  }
  return authSig
}

export async function signAndSaveAuthMessage () {
  const now = (new Date()).toISOString()
  const body = AUTH_SIGNATURE_BODY.replace('{{timestamp}}', now)
  const signedResult = await signMessage({ body })
  localStorage.setItem('lit-auth-signature', JSON.stringify({
    sig: signedResult.signature,
    derivedVia: 'web3.eth.personal.sign',
    signedMessage: body,
    address: signedResult.address
  }))
  // store a keypair in localstorage for communication with sgx
  const commsKeyPair = nacl.box.keyPair()
  localStorage.setItem('lit-comms-keypair', JSON.stringify({
    publicKey: naclUtil.encodeBase64(commsKeyPair.publicKey),
    secretKey: naclUtil.encodeBase64(commsKeyPair.secretKey)
  }))
  console.log('generated and saved lit-comms-keypair')
}

export async function signMessage ({ body }) {
  const { web3, account } = await connectWeb3()

  console.log('signing with ', account)
  const signature = await web3.eth.personal.sign(body, account)
  const address = web3.eth.accounts.recover(body, signature).toLowerCase()

  console.log('Signature: ', signature)
  console.log('recovered address: ', address)

  if (address !== account) {
    const msg = `ruh roh, the user signed with a different address (${address}) then they\'re using with web3 (${account}).  this will lead to confusion.`
    console.error(msg)
    alert('something seems to be wrong with your wallets message signing.  maybe restart your browser or your wallet.  your recovered sig address does not match your web3 account address')
    throw new Error(msg)
  }

  return { signature, address }
}

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
 * This function mints a LIT using our pre-deployed token contracts.  You may our contracts, or you may supply your own.  Our contracts are ERC1155 tokens on Polygon and Ethereum.  Using these contracts is the easiest way to get started.
 * @param {Object} params
 * @param {string} params.chain The chain to mint on.  "ethereum" and "polygon" are currently supported.
 * @param {number} params.quantity The number of tokens to mint.  Note that these will be fungible, so they will not have serial numbers.
 * @returns {Object} The txHash, tokenId, tokenAddress, mintingAddress, and authSig.
 */
export async function mintLIT ({ chain, quantity }) {
  console.log(`minting ${quantity} tokens on ${chain}`)
  const authSig = await checkAndSignAuthMessage()
  const { web3, account } = await connectWeb3()
  const chainId = await web3.eth.getChainId()
  const selectedChain = LIT_CHAINS[chain]
  if (chainId !== selectedChain.chainId) {
    // the metamask chain switching thing does not work on mainnet
    if (selectedChain.chainId !== 1) {
      const data = [{
        chainId: '0x' + selectedChain.chainId.toString('16'),
        chainName: selectedChain.name,
        nativeCurrency:
                {
                  name: selectedChain.name,
                  symbol: selectedChain.symbol,
                  decimals: selectedChain.decimals
                },
        rpcUrls: selectedChain.rpcUrls,
        blockExplorerUrls: selectedChain.blockExplorerUrls
      }]
      const res = await ethereum.request({ method: 'wallet_addEthereumChain', params: data }).catch()
      if (res) {
        console.log(res)
      }
    } else {
      return { errorCode: 'wrong_chain' }
    }
  }
  const tokenAddress = LIT_CHAINS[chain].contractAddress
  const contract = new web3.eth.Contract(LIT.abi, tokenAddress)
  console.log('sending to chain...')
  try {
    const txReceipt = await contract.methods.mint(quantity).send({ from: account })
    console.log('txReceipt: ', txReceipt)
    const tokenId = txReceipt.events.TransferSingle.returnValues.id
    return {
      txHash: txReceipt.transactionHash,
      tokenId,
      tokenAddress,
      mintingAddress: account,
      authSig
    }
  } catch (error) {
    console.log(error)
    if (error.code === 4001) {
      // EIP-1193 userRejectedRequest error
      console.log('User rejected request')
      return { errorCode: 'user_rejected_request' }
    } else {
      console.error(error)
    }
    return { errorCode: 'unknown_error' }
  }
}
