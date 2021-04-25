import JSZip from 'jszip'

import {
  encryptWithPubkey,
  decryptWithPrivkey,
  importSymmetricKey,
  generateSymmetricKey,
  encryptWithSymmetricKey,
  decryptWithSymmetricKey,
  compareArrayBuffers
} from './crypto'

import {
  checkAndDeriveKeypair,
  decryptWithWeb3PrivateKey
} from './eth'

import { fileToDataUrl } from './browser'

const PACKAGE_CACHE = {}

export async function zipAndEncryptString (string) {
  const zip = new JSZip()
  zip.file('index.html', string)
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

export async function decryptZip (zip, symmKey) {
  const keypair = await checkAndDeriveKeypair()

  console.log('Got keypair out of localstorage: ' + keypair)
  const privkey = keypair.secretKey

  let decryptedSymmKey = await decryptWithWeb3PrivateKey(symmKey)
  if (!decryptedSymmKey) {
    // fallback to trying the private derived via signature
    console.log('probably not metamask')
    decryptedSymmKey = decryptWithPrivkey(symmKey, privkey)
  }
  console.log('decrypted', decryptedSymmKey)

  // import the decrypted symm key
  const importedSymmKey = await importSymmetricKey(decryptedSymmKey)

  const decryptedZipArrayBuffer = await decryptWithSymmetricKey(
    zip,
    importedSymmKey
  )

  // unpack the zip
  const unzipped = await zip.loadAsync(decryptedZipArrayBuffer)

  // load the files into data urls with the metadata attached
  const files = await Promise.all(unzipped.files.map(async f => {
    const dataUrl = await fileToDataUrl(f)
    return {
      type: f.type,
      name: f.name,
      dataUrl
    }
  }))

  return files
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
  const keypair = await checkAndDeriveKeypair()
  const pubkey = keypair.publicKey
  const privkey = keypair.secretKey

  // encrypt symm key
  const encryptedSymmKeyData = encryptWithPubkey(pubkey, JSON.stringify(exportedSymmKey), 'x25519-xsalsa20-poly1305')
  const packed = JSON.stringify(encryptedSymmKeyData)

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
    encryptedSymmetricKey: packed,
    encryptedZip: encryptedZipBlob
  }
}

async function getNpmPackage (packageName) {
  if (PACKAGE_CACHE[packageName]) {
    return PACKAGE_CACHE[packageName]
  }

  const resp = await fetch('https://unpkg.com/' + packageName)
  if (!resp.ok) {
    console.log('error with response: ', resp)
    throw Error(resp.statusText)
  }
  const blob = await resp.blob()
  const dataUrl = await fileToDataUrl(blob)
  PACKAGE_CACHE[packageName] = dataUrl
  return dataUrl
}

export async function createHtmlLIT ({ title, encryptedSymmetricKey, html, css, npmPackages = [] }) {
  npmPackages.push('lit-js-sdk')
  let scriptTags = ''
  for (let i = 0; i < npmPackages; i++) {
    const scriptDataUrl = await getNpmPackage(npmPackages[i])
    const tag = `<script src="${scriptDataUrl}"></script>\n`
    scriptTags += tag
  }

  return `
<!DOCTYPE html>
<html>
  <head>
    <title>${title}</title>
    <style id="jss-server-side">${css}</style>
    ${scriptTags}
    <script>
      window.encryptedSymmetricKey = ${encryptedSymmetricKey}
    </script>
  </head>
  <body>
    <div id="root">${html}</div>
  </body>
</html>
  `
}
