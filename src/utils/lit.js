import JSZip from 'jszip'

import {
  importSymmetricKey,
  generateSymmetricKey,
  encryptWithSymmetricKey,
  decryptWithSymmetricKey,
  compareArrayBuffers
} from './crypto'

import {
  checkAndSignAuthMessage
} from './eth'

import { fileToDataUrl } from './browser'

const PACKAGE_CACHE = {}

export async function zipAndEncryptString (string) {
  const zip = new JSZip()
  zip.file('string.txt', string)
  return encryptZip(zip)
}

export async function zipAndEncryptFiles (files) {
  // let's zip em
  const zip = new JSZip()
  for (let i = 0; i < files.length; i++) {
    zip.folder('encryptedAssets').file(files[i].name, files[i])
  }
  return encryptZip(zip)
}

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

      function litJsSdkLoaded(){
         var litNodeClient = new LitJsSdk.default.LitNodeClient()
        litNodeClient.connect()
        window.litNodeClient = litNodeClient
      }
    </script>
    <script onload='litJsSdkLoaded()' src="https://unpkg.com/lit-js-sdk/build/index.web.js"></script>
  </head>
  <body>
    <div id="root">${htmlBody}</div>
    <script>
      const unlockButton = document.getElementById('unlockButton')
      unlockButton.onclick = function() {
        if (!window.litNodeClient.ready){
          alert('The LIT network is still connecting.  Please try again in about 10 seconds.')
          return
        }
        LitJsSdk.default.toggleLock()
      }
    </script>
  </body>
</html>
  `
}

export async function toggleLock () {
  const mediaGridHolder = document.getElementById('mediaGridHolder')
  const lockedHeader = document.getElementById('lockedHeader')

  if (window.locked) {
    // save public content before decryption, so we can toggle back to the
    // locked state in the future
    window.publicContent = mediaGridHolder.innerHTML

    const authSig = await checkAndSignAuthMessage()
    // get the encryption key
    const symmetricKey = await window.litNodeClient.getEncryptionKey({
      tokenAddress: window.tokenAddress,
      tokenId: window.tokenId,
      authSig,
      chain: window.chain
    })

    // convert data url to blob
    const encryptedZipBlob = await (await fetch(window.encryptedZipDataUrl)).blob()
    const decryptedFiles = await decryptZip(encryptedZipBlob, symmetricKey)
    const mediaGridHtmlBody = await decryptedFiles['string.txt'].async('text')
    mediaGridHolder.innerHTML = mediaGridHtmlBody
    lockedHeader.innerText = 'UNLOCKED'
    window.locked = false
  } else {
    mediaGridHolder.innerHTML = window.publicContent
    lockedHeader.innerText = 'LOCKED'
    window.locked = true
  }
}
