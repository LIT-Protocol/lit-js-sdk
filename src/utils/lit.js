import JSZip from 'jszip'

import {
  importSymmetricKey,
  generateSymmetricKey,
  encryptWithSymmetricKey,
  decryptWithSymmetricKey,
  compareArrayBuffers
} from './crypto'

import {
  checkAndSignAuthMessage,
  getMerkleProof
} from './eth'

import {
  sendMessageToFrameParent
} from './frameComms'

import { fileToDataUrl } from './browser'
import { LIT_CHAINS } from '../lib/constants'

const PACKAGE_CACHE = {}

/**
 * Zip and encrypt a string.  This is used to encrypt any string that is to be locked and included in a LIT.  For example, on MintLIT, we render the HTML/CSS containing the locked files and a grid to view them to a string using ReactDOMServer.renderToString().
 * @param {string} string The string to zip and encrypt
 * @returns {Object} The encryptedZip as a Blob and the symmetricKey used to encrypt it, as a JSON string.  The encrypted zip will contain a single file called "string.txt"
 */
export async function zipAndEncryptString (string) {
  const zip = new JSZip()
  zip.file('string.txt', string)
  return encryptZip(zip)
}

/**
 * Zip and encrypt multiple files.
 * @param {array} files An array of the files you wish to zip and encrypt
 * @returns {Object} The encryptedZip as a Blob and the symmetricKey used to encrypt it, as a JSON string.  The encrypted zip will contain a folder "encryptedAssets" and all of the files will be inside it.
 */
export async function zipAndEncryptFiles (files) {
  // let's zip em
  const zip = new JSZip()
  for (let i = 0; i < files.length; i++) {
    zip.folder('encryptedAssets').file(files[i].name, files[i])
  }
  return encryptZip(zip)
}

/**
 * Decrypt and unzip a zip that was created using encryptZip, zipAndEncryptString, or zipAndEncryptFiles.
 * @param {Blob} encryptedZipBlob The encrypted zip as a Blob
 * @param {Object} symmKey An object containing the symmetric key used that will be used to decrypt this zip.
 * @returns {Array} An array of the decrypted files inside the zip.
 */
export async function decryptZip (encryptedZipBlob, symmKey) {
  // const keypair = await checkAndDeriveKeypair()

  // console.log('Got keypair out of localstorage: ' + keypair)
  // const privkey = keypair.secretKey

  // let decryptedSymmKey = await decryptWithWeb3PrivateKey(symmKey)
  // if (!decryptedSymmKey) {
  //   // fallback to trying the private derived via signature
  //   console.log('probably not metamask')
  //   decryptedSymmKey = decryptWithPrivkey(symmKey, privkey)
  // }
  // console.log('decrypted', decryptedSymmKey)

  // import the decrypted symm key
  const importedSymmKey = await importSymmetricKey(symmKey)

  const decryptedZipArrayBuffer = await decryptWithSymmetricKey(
    encryptedZipBlob,
    importedSymmKey
  )

  // unpack the zip
  const zip = new JSZip()
  const unzipped = await zip.loadAsync(decryptedZipArrayBuffer)

  // load the files into data urls with the metadata attached
  // const files = await Promise.all(unzipped.files.map(async f => {
  //   // const dataUrl = await fileToDataUrl(f)
  //   return {
  //     type: f.type,
  //     name: f.name,
  //     file: f
  //   }
  // }))

  return unzipped.files
}

/**
 * Encrypt a zip file created with JSZip using a new random symmetric key via WebCrypto.
 * @param {JSZip} zip The JSZip instance to encrypt
 * @returns {Object} The encryptedZip as a Blob and the symmetricKey used to encrypt it, as a JSON string.
 */
export async function encryptZip (zip) {
  const zipBlob = await zip.generateAsync({ type: 'blob' })
  const zipBlobArrayBuffer = await zipBlob.arrayBuffer()
  console.log('blob', zipBlob)

  const symmKey = await generateSymmetricKey()
  const encryptedZipBlob = await encryptWithSymmetricKey(
    symmKey,
    zipBlobArrayBuffer
  )

  // to download the encrypted zip file for testing, uncomment this
  // saveAs(encryptedZipBlob, 'encrypted.bin')

  const exportedSymmKey = await crypto.subtle.exportKey('jwk', symmKey)
  console.log('exportedSymmKey', exportedSymmKey)

  // encrypt the symmetric key with the
  // public key derived from the eth wallet
  // const keypair = await checkAndDeriveKeypair()
  // const pubkey = keypair.publicKey
  // const privkey = keypair.secretKey

  // encrypt symm key
  // const encryptedSymmKeyData = encryptWithPubkey(pubkey, JSON.stringify(exportedSymmKey), 'x25519-xsalsa20-poly1305')
  // const packed = JSON.stringify(encryptedSymmKeyData)

  //   console.log('packed symmetric key ', packed)
  //   const unpacked = JSON.parse(packed)
  //   // test decrypt
  //   const decryptedSymmKey = decryptWithPrivkey(unpacked, privkey)
  //   console.log('decrypted', decryptedSymmKey)
  //
  //   // import the decrypted symm key
  //   const importedSymmKey = await importSymmetricKey(decryptedSymmKey)
  //
  //   const decryptedZipArrayBuffer = await decryptWithSymmetricKey(
  //     encryptedZipBlob,
  //     importedSymmKey
  //   )
  //
  //   // compare zip before and after as a sanity check
  //   const isEqual = compareArrayBuffers(
  //     zipBlobArrayBuffer,
  //     decryptedZipArrayBuffer
  //   )
  //   console.log('Zip before and after decryption are equal: ', isEqual)
  //   if (!isEqual) {
  //     throw new Error('Decrypted zip does not match original zip.  Something is wrong.')
  //   }

  // to download the zip, for testing, uncomment this
  //   const decryptedBlob = new Blob(
  //     [decryptedZipArrayBuffer],
  //     { type: 'application/zip' }
  //   )
  //   console.log('decrypted blob', decryptedBlob)
  //
  //   saveAs(decryptedBlob, 'decrypted.zip')
  // console.log('saved')

  return {
    symmetricKey: JSON.stringify(exportedSymmKey),
    encryptedZip: encryptedZipBlob
  }
}

async function getNpmPackage (packageName) {
  // console.log('getting npm package: ' + packageName)
  if (PACKAGE_CACHE[packageName]) {
    // console.log('found in cache')
    return PACKAGE_CACHE[packageName]
  }

  const resp = await fetch('https://unpkg.com/' + packageName)
  if (!resp.ok) {
    console.log('error with response: ', resp)
    throw Error(resp.statusText)
  }
  const blob = await resp.blob()
  // console.log('got blob', blob)
  const dataUrl = await fileToDataUrl(blob)
  // console.log('got dataUrl', dataUrl)
  PACKAGE_CACHE[packageName] = dataUrl
  return dataUrl
}

/**
 * Create a ready-to-go LIT using provided HTML/CSS body and an encrypted zip data url.  You need to design your LIT with HTML and CSS, and provide an unlock button with the id "unlockButton" inside your HTML.  This function will handle the rest.
 * @param {Object} params
 * @param {string} params.title The title that will be used for the title tag in the outputted HTML
 * @param {number} params.htmlBody The HTML body for the locked state of the LIT.  All users will be able to see this HTML.  This HTML must have a button with an id of "unlockButton" which will be automatically set up to decrypt and load the encryptedZipDataUrl
 * @param {string} params.css Any CSS you would like to include in the outputted HTML
 * @param {number} params.encryptedZipDataUrl a data URL of the encrypted zip that contains the locked content that only token holders will be able to view.
 * @param {string} params.tokenAddress The token address of the corresponding NFT for this LIT.  ERC721 and ERC 1155 tokens are currently supported.
 * @param {number} params.tokenId The ID of the token of the corresponding NFT for this LIT.  Only holders of this token ID will be able to unlock and decrypt this LIT.
 * @param {string} params.chain The chain that the corresponding NFT was minted on.  "ethereum" and "polygon" are currently supported.
 * @param {Array} [params.npmPackages=[]] An array of strings of NPM package names that should be embedded into this LIT.  These packages will be pulled down via unpkg, converted to data URLs, and embedded in the LIT HTML.  You can include any packages from npmjs.com.
 * @returns {string} The HTML string that is now a LIT.  You can send this HTML around and only token holders will be able to unlock and decrypt the content inside it.  Included in the HTML is this LIT JS SDK itself, the encrypted locked content, an automatic connection to the LIT nodes network, and a handler for a button with id "unlockButton" which will perform the unlock operation when clicked.
 */
export async function createHtmlLIT ({
  title,
  htmlBody,
  css,
  encryptedZipDataUrl,
  tokenAddress,
  tokenId,
  chain,
  npmPackages = []
}) {
  // uncomment this to embed the LIT JS SDK directly instead of retrieving it from unpkg when a user views the LIT
  // npmPackages.push('lit-js-sdk')
  // console.log('createHtmlLIT with npmPackages', npmPackages)
  let scriptTags = ''
  for (let i = 0; i < npmPackages.length; i++) {
    const scriptDataUrl = await getNpmPackage(npmPackages[i])
    const tag = `<script src="${scriptDataUrl}"></script>\n`
    scriptTags += tag
  }

  // console.log('scriptTags: ', scriptTags)

  return `
<!DOCTYPE html>
<html>
  <head>
    <title>${title}</title>
    <style id="jss-server-side">${css}</style>
    ${scriptTags}
    <script>
      var encryptedZipDataUrl = "${encryptedZipDataUrl}"
      var tokenAddress = "${tokenAddress}"
      var tokenId = "${tokenId}"
      var chain = "${chain}"
      var locked = true
      var useLitPostMessageProxy = false
    </script>
    <script onload='LitJsSdk.default.litJsSdkLoadedInALIT()' src="https://jscdn.litgateway.com/index.web.js"></script>
  </head>
  <body>
    <div id="root">${htmlBody}</div>
    <script>
      const unlockButton = document.getElementById('unlockButton')
      unlockButton.onclick = function() {
        LitJsSdk.default.toggleLock()
      }
    </script>
  </body>
</html>
  `
}

/**
 * Lock and unlock the encrypted content inside a LIT.  This content is only viewable by holders of the NFT that corresponds to this LIT.  Locked content will be decrypted and placed into the HTML element with id "mediaGridHolder".  The HTML element with the id "lockedHeader" will have it's text automatically changed to LOCKED or UNLOCKED to denote the state of the LIT.  Note that if you're creating a LIT using the createHtmlLIT function, you do not need to use this function, because this function is automatically bound to any button in your HTML with the id "unlockButton".
 */
export async function toggleLock () {
  const mediaGridHolder = document.getElementById('mediaGridHolder')
  const lockedHeader = document.getElementById('lockedHeader')

  if (window.locked) {
    // save public content before decryption, so we can toggle back to the
    // locked state in the future
    window.publicContent = mediaGridHolder.innerHTML

    if (!window.useLitPostMessageProxy && !window.litNodeClient.ready) {
      alert('The LIT network is still connecting.  Please try again in about 10 seconds.')
      return
    }

    const authSig = await checkAndSignAuthMessage({ chain: window.chain })
    if (authSig.errorCode && authSig.errorCode === 'wrong_chain') {
      alert('You are connected to the wrong blockchain.  Please switch your metamask to ' + window.chain)
      return
    }

    // get the merkle proof
    const { balanceStorageSlot } = LIT_CHAINS[window.chain]
    let merkleProof = null
    try {
      merkleProof = await getMerkleProof({ tokenAddress: window.tokenAddress, balanceStorageSlot, tokenId: window.tokenId })
    } catch (e) {
      console.log(e)
      alert('Error - could not obtain merkle proof.  Some nodes do not support this operation yet.  Please try another ETH node.')
      return
    }

    if (window.useLitPostMessageProxy) {
      // instead of asking the network for the key part, ask the parent frame
      // the parentframe will then call unlockLit() with the encryption key
      sendMessageToFrameParent({ command: 'getEncryptionKey', target: 'LitNodeClient', params: { tokenAddress: window.tokenAddress, tokenId: window.tokenId, chain: window.chain, authSig, merkleProof } })
      return
    }

    // get the encryption key
    const symmetricKey = await window.litNodeClient.getEncryptionKey({
      tokenAddress: window.tokenAddress,
      tokenId: window.tokenId,
      authSig,
      chain: window.chain,
      merkleProof
    })

    await unlockLitWithKey({ symmetricKey })
  } else {
    mediaGridHolder.innerHTML = window.publicContent
    lockedHeader.innerText = 'LOCKED'
    window.locked = true
  }
}

export async function unlockLitWithKey ({ symmetricKey }) {
  const mediaGridHolder = document.getElementById('mediaGridHolder')
  const lockedHeader = document.getElementById('lockedHeader')

  // convert data url to blob
  const encryptedZipBlob = await (await fetch(window.encryptedZipDataUrl)).blob()
  const decryptedFiles = await decryptZip(encryptedZipBlob, symmetricKey)
  const mediaGridHtmlBody = await decryptedFiles['string.txt'].async('text')
  mediaGridHolder.innerHTML = mediaGridHtmlBody
  lockedHeader.innerText = 'UNLOCKED'
  window.locked = false
}
