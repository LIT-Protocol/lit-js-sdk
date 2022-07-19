import JSZip from "jszip";
import {
  fromString as uint8arrayFromString,
  toString as uint8arrayToString,
} from "uint8arrays";
import { formatEther, formatUnits } from "@ethersproject/units";
import {
  throwError,
  log,
  is,
  checkIfAuthSigRequiresChainParam,
} from "../lib/utils";

import {
  importSymmetricKey,
  generateSymmetricKey,
  encryptWithSymmetricKey,
  decryptWithSymmetricKey,
  canonicalAccessControlConditionFormatter,
  canonicalEVMContractConditionFormatter,
  canonicalSolRpcConditionFormatter,
  canonicalUnifiedAccessControlConditionFormatter,
} from "./crypto";

import { checkAndSignEVMAuthMessage, decimalPlaces } from "./eth";
import { checkAndSignSolAuthMessage } from "./sol";
import { checkAndSignCosmosAuthMessage } from "./cosmos";

import { wasmBlsSdkHelpers } from "../lib/bls-sdk";

import { fileToDataUrl } from "./browser";
import { ALL_LIT_CHAINS, NETWORK_PUB_KEY } from "../lib/constants";

const PACKAGE_CACHE = {};

/**
 * Check for an existing cryptographic authentication signature and create one of it does not exist.  This is used to prove ownership of a given crypto wallet address to the Lit nodes.  The result is stored in LocalStorage so the user doesn't have to sign every time they perform an operation.
 * @param {Object} params
 * @param {string} params.chain The chain you want to use.  Find the supported list of chains here: https://developer.litprotocol.com/docs/supportedChains
 * @param {Array<string>} params.resources Optional and only used with EVM chains.  A list of resources to be passed to Sign In with Ethereum.  These resources will be part of the Sign in with Ethereum signed message presented to the user.
 * @returns {AuthSig} The AuthSig created or retrieved
 */
export async function checkAndSignAuthMessage({ chain, resources }) {
  const chainInfo = ALL_LIT_CHAINS[chain];
  if (!chainInfo) {
    throwError({
      message: `Unsupported chain selected.  Please select one of: ${Object.keys(
        ALL_LIT_CHAINS
      )}`,
      name: "UnsupportedChainException",
      errorCode: "unsupported_chain",
    });
  }

  if (chainInfo.vmType === "EVM") {
    return checkAndSignEVMAuthMessage({ chain, resources });
  } else if (chainInfo.vmType === "SVM") {
    return checkAndSignSolAuthMessage({ chain });
  } else if (chainInfo.vmType === "CVM") {
    return checkAndSignCosmosAuthMessage({ chain });
  } else {
    throwError({
      message: `vmType not found for this chain: ${chain}.  This should not happen.  Unsupported chain selected.  Please select one of: ${Object.keys(
        ALL_LIT_CHAINS
      )}`,
      name: "UnsupportedChainException",
      errorCode: "unsupported_chain",
    });
  }
}

/**
 * Encrypt a string.  This is used to encrypt any string that is to be locked via the Lit Protocol.
 * @param {string} str The string to encrypt
 * @returns {Promise<Object>} A promise containing the encryptedString as a Blob and the symmetricKey used to encrypt it, as a Uint8Array.
 */
export async function encryptString(str) {
  // -- validate
  if (!is(str, "string", "str", "encryptString")) return;

  const encodedString = uint8arrayFromString(str, "utf8");

  const symmKey = await generateSymmetricKey();
  const encryptedString = await encryptWithSymmetricKey(
    symmKey,
    encodedString.buffer
  );

  const exportedSymmKey = new Uint8Array(
    await crypto.subtle.exportKey("raw", symmKey)
  );

  return {
    symmetricKey: exportedSymmKey,
    encryptedString,
    encryptedData: encryptedString,
  };
}

/**
 * Decrypt a string that was encrypted with the encryptString function.
 * @param {Blob} encryptedStringBlob The encrypted string as a Blob
 * @param {Uint8Array} symmKey The symmetric key used that will be used to decrypt this.
 * @returns {Promise<string>} A promise containing the decrypted string
 */
export async function decryptString(encryptedStringBlob, symmKey) {
  // -- validate
  if (!is(encryptedStringBlob, "Blob", "encryptedStringBlob", "decryptString"))
    return;
  if (!is(symmKey, "Uint8Array", "symmKey", "decryptString")) return;

  // import the decrypted symm key
  const importedSymmKey = await importSymmetricKey(symmKey);

  const decryptedStringArrayBuffer = await decryptWithSymmetricKey(
    encryptedStringBlob,
    importedSymmKey
  );

  return uint8arrayToString(new Uint8Array(decryptedStringArrayBuffer), "utf8");
}

/**
 * Zip and encrypt a string.  This is used to encrypt any string that is to be locked via the Lit Protocol.
 * @param {string} string The string to zip and encrypt
 * @returns {Promise<Object>} A promise containing the encryptedZip as a Blob and the symmetricKey used to encrypt it, as a Uint8Array.  The encrypted zip will contain a single file called "string.txt"
 */
export async function zipAndEncryptString(string) {
  if (!is(string, "string", "string", "zipAndEncryptString")) return;

  const zip = new JSZip();
  zip.file("string.txt", string);
  return encryptZip(zip);
}

/**
 * Zip and encrypt multiple files.
 * @param {array} files An array of the files you wish to zip and encrypt
 * @returns {Promise<Object>} A promise containing the encryptedZip as a Blob and the symmetricKey used to encrypt it, as a Uint8Array.  The encrypted zip will contain a folder "encryptedAssets" and all of the files will be inside it.
 */
export async function zipAndEncryptFiles(files) {
  // let's zip em
  const zip = new JSZip();
  for (let i = 0; i < files.length; i++) {
    if (!is(files[i], "File", `files[${i}]`, "zipAndEncryptFiles")) return;
    zip.folder("encryptedAssets").file(files[i].name, files[i]);
  }
  return encryptZip(zip);
}

/**
 * Decrypt and unzip a zip that was created using encryptZip, zipAndEncryptString, or zipAndEncryptFiles.
 * @param {Blob} encryptedZipBlob The encrypted zip as a Blob
 * @param {Uint8Array} symmKey The symmetric key used that will be used to decrypt this zip.
 * @returns {Promise<Object>} A promise containing a JSZip object indexed by the filenames of the zipped files.  For example, if you have a file called "meow.jpg" in the root of your zip, you could get it from the JSZip object by doing this: const imageBlob = await decryptedZip['meow.jpg'].async('blob')
 */
export async function decryptZip(encryptedZipBlob, symmKey) {
  if (!is(encryptedZipBlob, "Blob", "encryptedZipBlob", "decryptZip")) return;
  if (!is(symmKey, "Uint8Array", "symmKey", "decryptZip")) return;
  // const keypair = await checkAndDeriveKeypair()

  // log('Got keypair out of localstorage: ' + keypair)
  // const privkey = keypair.secretKey

  // let decryptedSymmKey = await decryptWithWeb3PrivateKey(symmKey)
  // if (!decryptedSymmKey) {
  //   // fallback to trying the private derived via signature
  //   log('probably not metamask')
  //   decryptedSymmKey = decryptWithPrivkey(symmKey, privkey)
  // }
  // log('decrypted', decryptedSymmKey)

  // import the decrypted symm key
  const importedSymmKey = await importSymmetricKey(symmKey);

  const decryptedZipArrayBuffer = await decryptWithSymmetricKey(
    encryptedZipBlob,
    importedSymmKey
  );

  // unpack the zip
  const zip = new JSZip();
  const unzipped = await zip.loadAsync(decryptedZipArrayBuffer);

  // load the files into data urls with the metadata attached
  // const files = await Promise.all(unzipped.files.map(async f => {
  //   // const dataUrl = await fileToDataUrl(f)
  //   return {
  //     type: f.type,
  //     name: f.name,
  //     file: f
  //   }
  // }))

  return unzipped.files;
}

/**
 * Encrypt a zip file created with JSZip using a new random symmetric key via WebCrypto.
 * @param {JSZip} zip The JSZip instance to encrypt
 * @returns {Promise<Object>} A promise containing the encryptedZip as a Blob and the symmetricKey used to encrypt it, as a Uint8Array string.
 */
export async function encryptZip(zip) {
  const zipBlob = await zip.generateAsync({ type: "blob" });
  const zipBlobArrayBuffer = await zipBlob.arrayBuffer();
  // log('blob', zipBlob)

  const symmKey = await generateSymmetricKey();
  const encryptedZipBlob = await encryptWithSymmetricKey(
    symmKey,
    zipBlobArrayBuffer
  );

  // to download the encrypted zip file for testing, uncomment this
  // saveAs(encryptedZipBlob, 'encrypted.bin')

  const exportedSymmKey = new Uint8Array(
    await crypto.subtle.exportKey("raw", symmKey)
  );
  // log('exportedSymmKey in hex', uint8arrayToString(exportedSymmKey, 'base16'))

  // encrypt the symmetric key with the
  // public key derived from the eth wallet
  // const keypair = await checkAndDeriveKeypair()
  // const pubkey = keypair.publicKey
  // const privkey = keypair.secretKey

  // encrypt symm key
  // const encryptedSymmKeyData = encryptWithPubkey(pubkey, JSON.stringify(exportedSymmKey), 'x25519-xsalsa20-poly1305')
  // const packed = JSON.stringify(encryptedSymmKeyData)

  //   log('packed symmetric key ', packed)
  //   const unpacked = JSON.parse(packed)
  //   // test decrypt
  //   const decryptedSymmKey = decryptWithPrivkey(unpacked, privkey)
  //   log('decrypted', decryptedSymmKey)
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
  //   log('Zip before and after decryption are equal: ', isEqual)
  //   if (!isEqual) {
  //     throw new Error('Decrypted zip does not match original zip.  Something is wrong.')
  //   }

  // to download the zip, for testing, uncomment this
  //   const decryptedBlob = new Blob(
  //     [decryptedZipArrayBuffer],
  //     { type: 'application/zip' }
  //   )
  //   log('decrypted blob', decryptedBlob)
  //
  //   saveAs(decryptedBlob, 'decrypted.zip')
  // log('saved')

  return {
    symmetricKey: exportedSymmKey,
    encryptedZip: encryptedZipBlob,
  };
}

/**
 * Encrypt a single file, save the key to the Lit network, and then zip it up with the metadata.
 * @param {Object} params
 * @param {Object} params.authSig The authSig of the user.  Returned via the checkAndSignAuthMessage function
 * @param {Array.<AccessControlCondition>} params.accessControlConditions The access control conditions that the user must meet to obtain this signed token.  This could be posession of an NFT, for example.  You must pass either accessControlConditions or evmContractConditions or solRpcConditions or unifiedAccessControlConditions.
 * @param {Array.<EVMContractCondition>} params.evmContractConditions  EVM Smart Contract access control conditions that the user must meet to obtain this signed token.  This could be posession of an NFT, for example.  This is different than accessControlConditions because accessControlConditions only supports a limited number of contract calls.  evmContractConditions supports any contract call.  You must pass either accessControlConditions or evmContractConditions or solRpcConditions or unifiedAccessControlConditions.
 * @param {Array.<SolRpcCondition>} params.solRpcConditions  Solana RPC call conditions that the user must meet to obtain this signed token.  This could be posession of an NFT, for example.
 * @param {Array.<AccessControlCondition|EVMContractCondition|SolRpcCondition>} params.unifiedAccessControlConditions  An array of unified access control conditions.  You may use AccessControlCondition, EVMContractCondition, or SolRpcCondition objects in this array, but make sure you add a conditionType for each one.  You must pass either accessControlConditions or evmContractConditions or solRpcConditions or unifiedAccessControlConditions.
 * @param {string} params.chain The chain name of the chain that this contract is deployed on.  See LIT_CHAINS for currently supported chains.
 * @param {File} params.file The file you wish to encrypt
 * @param {LitNodeClient} params.litNodeClient An instance of LitNodeClient that is already connected
 * @param {string} params.readme An optional readme text that will be inserted into readme.txt in the final zip file.  This is useful in case someone comes across this zip file and wants to know how to decrypt it.  This file could contain instructions and a URL to use to decrypt the file.
 * @returns {Promise<Object>} A promise containing an object with 3 keys: zipBlob, encryptedSymmetricKey, and symmetricKey.  zipBlob is a zip file that contains an encrypted file and the metadata needed to decrypt it via the Lit network.  encryptedSymmetricKey is the symmetric key needed to decrypt the content, encrypted with the Lit network public key.  You may wish to store encryptedSymmetricKey in your own database to support quicker re-encryption operations when adding additional access control conditions in the future, but this is entirely optional, and this key is already stored inside the zipBlob.  symmetricKey is the raw symmetric key used to encrypt the files.  DO NOT STORE IT.  It is provided in case you wish to create additional "OR" access control conditions for the same file.
 */
export async function encryptFileAndZipWithMetadata({
  authSig,
  accessControlConditions,
  evmContractConditions,
  solRpcConditions,
  unifiedAccessControlConditions,
  chain,
  file,
  litNodeClient,
  readme,
}) {
  // -- validate
  if (!is(authSig, "Object", "authSig", "encryptFileAndZipWithMetadata"))
    return;
  if (
    accessControlConditions &&
    !is(
      accessControlConditions,
      "Array",
      "accessControlConditions",
      "encryptFileAndZipWithMetadata"
    )
  )
    return;
  if (
    evmContractConditions &&
    !is(
      evmContractConditions,
      "Array",
      "evmContractConditions",
      "encryptFileAndZipWithMetadata"
    )
  )
    return;
  if (
    solRpcConditions &&
    !is(
      solRpcConditions,
      "Array",
      "solRpcConditions",
      "encryptFileAndZipWithMetadata"
    )
  )
    return;
  if (
    unifiedAccessControlConditions &&
    !is(
      unifiedAccessControlConditions,
      "Array",
      "unifiedAccessControlConditions",
      "encryptFileAndZipWithMetadata"
    )
  )
    return;
  if (
    !checkIfAuthSigRequiresChainParam(
      authSig,
      chain,
      "encryptFileAndZipWithMetadata"
    )
  )
    return;
  if (!is(file, "File", "file", "encryptFileAndZipWithMetadata")) return;
  if (
    readme &&
    !is(readme, "string", "readme", "encryptFileAndZipWithMetadata")
  )
    return;

  const symmetricKey = await generateSymmetricKey();
  const exportedSymmKey = new Uint8Array(
    await crypto.subtle.exportKey("raw", symmetricKey)
  );
  // log('exportedSymmKey in hex', uint8arrayToString(exportedSymmKey, 'base16'))

  const encryptedSymmetricKey = await litNodeClient.saveEncryptionKey({
    accessControlConditions,
    evmContractConditions,
    solRpcConditions,
    unifiedAccessControlConditions,
    symmetricKey: exportedSymmKey,
    authSig,
    chain,
  });
  log("encrypted key saved to Lit", encryptedSymmetricKey);

  // encrypt the file
  var fileAsArrayBuffer = await file.arrayBuffer();
  const encryptedZipBlob = await encryptWithSymmetricKey(
    symmetricKey,
    fileAsArrayBuffer
  );

  const zip = new JSZip();
  const metadata = metadataForFile({
    name: file.name,
    type: file.type,
    size: file.size,
    encryptedSymmetricKey,
    accessControlConditions,
    evmContractConditions,
    solRpcConditions,
    unifiedAccessControlConditions,
    chain,
  });

  zip.file("lit_protocol_metadata.json", JSON.stringify(metadata));
  if (readme) {
    zip.file("readme.txt", readme);
  }
  zip.folder("encryptedAssets").file(file.name, encryptedZipBlob);

  const zipBlob = await zip.generateAsync({ type: "blob" });

  return { zipBlob, encryptedSymmetricKey, symmetricKey: exportedSymmKey };
}

/**
 * Given a zip file with metadata inside it, unzip, load the metadata, and return the decrypted file and the metadata.  This zip file would have been created with the encryptFileAndZipWithMetadata function.
 * @param {Object} params
 * @param {Object} params.authSig The authSig of the user.  Returned via the checkAndSignAuthMessage function
 * @param {Blob} params.file The zip file blob with metadata inside it and the encrypted asset
 * @param {LitNodeClient} params.litNodeClient An instance of LitNodeClient that is already connected
 * @returns {Promise<Object>} A promise containing an object that contains decryptedFile and metadata properties.  The decryptedFile is an ArrayBuffer that is ready to use, and metadata is an object that contains all the properties of the file like it's name and size and type.
 */
export async function decryptZipFileWithMetadata({
  authSig,
  file,
  litNodeClient,
  additionalAccessControlConditions,
}) {
  // -- validate
  if (!is(authSig, "Object", "authSig", "decryptZipFileWithMetadata")) return;
  if (!is(file, "Blob", "file", "decryptZipFileWithMetadata")) return;

  const zip = await JSZip.loadAsync(file);
  const metadata = JSON.parse(
    await zip.file("lit_protocol_metadata.json").async("string")
  );
  log("zip metadata", metadata);

  let symmKey;
  try {
    symmKey = await litNodeClient.getEncryptionKey({
      accessControlConditions: metadata.accessControlConditions,
      evmContractConditions: metadata.evmContractConditions,
      solRpcConditions: metadata.solRpcConditions,
      unifiedAccessControlConditions: metadata.unifiedAccessControlConditions,
      toDecrypt: metadata.encryptedSymmetricKey,
      chain: metadata.chain,
      authSig,
    });
  } catch (e) {
    if (e.errorCode === "not_authorized") {
      // try more additionalAccessControlConditions
      if (!additionalAccessControlConditions) {
        throw e;
      }
      log("trying additionalAccessControlConditions");

      for (let i = 0; i < additionalAccessControlConditions.length; i++) {
        const accessControlConditions =
          additionalAccessControlConditions[i].accessControlConditions;
        log("trying additional condition", accessControlConditions);
        try {
          symmKey = await litNodeClient.getEncryptionKey({
            accessControlConditions: accessControlConditions,
            toDecrypt:
              additionalAccessControlConditions[i].encryptedSymmetricKey,
            chain: metadata.chain,
            authSig,
          });

          // // okay we got the additional symmkey, now we need to decrypt the symmkey and then use it to decrypt the original symmkey
          // const importedAdditionalSymmKey = await importSymmetricKey(symmKey)
          // symmKey = await decryptWithSymmetricKey(additionalAccessControlConditions[i].encryptedSymmetricKey, importedAdditionalSymmKey)

          break; // it worked, we can leave the loop and stop checking additional access control conditions
        } catch (e) {
          // swallow not_authorized because we are gonna try some more accessControlConditions
          if (e.errorCode !== "not_authorized") {
            throw e;
          }
        }
      }
      if (!symmKey) {
        // we tried all the access control conditions and none worked
        throw e;
      }
    } else {
      throw e;
    }
  }
  const importedSymmKey = await importSymmetricKey(symmKey);

  // log('symmetricKey', importedSymmKey)

  const encryptedFile = await zip
    .folder("encryptedAssets")
    .file(metadata.name)
    .async("blob");
  // log('encryptedFile', encryptedFile)

  const decryptedFile = await decryptWithSymmetricKey(
    encryptedFile,
    importedSymmKey
  );

  // log('decryptedFile', decryptedFile)

  return { decryptedFile, metadata };
}

/**
 * Encrypt a file without doing any zipping or packing.  This is useful for large files.  A 1gb file can be encrypted in only 2 seconds, for example.  A new random symmetric key will be created and returned along with the encrypted file.
 * @param {Object} params
 * @param {Blob|File} params.file The file you wish to encrypt
 * @returns {Promise<Object>} A promise containing an object with keys encryptedFile and symmetricKey.  encryptedFile is a Blob, and symmetricKey is a Uint8Array that can be used to decrypt the file.
 */
export async function encryptFile({ file }) {
  if (!is(file, "Blob", "file", "decryptFile", false)) {
    // if it's a file, we don't have to do anything, because a file is a subclass of Blob and it will just work.
    if (!is(file, "File", "file", "decryptFile", false)) {
      // so, check if it's a file above, and if not, then run the blob check again but this time throw an error.
      is(file, "Blob", "file", "decryptFile", true);
    }
  }
  // generate a random symmetric key
  const symmetricKey = await generateSymmetricKey();
  const exportedSymmKey = new Uint8Array(
    await crypto.subtle.exportKey("raw", symmetricKey)
  );

  // encrypt the file
  var fileAsArrayBuffer = await file.arrayBuffer();
  const encryptedFile = await encryptWithSymmetricKey(
    symmetricKey,
    fileAsArrayBuffer
  );

  return { encryptedFile, symmetricKey: exportedSymmKey };
}

/**
 * Decrypt a file that was encrypted with the encryptFile function, without doing any unzipping or unpacking.  This is useful for large files.  A 1gb file can be decrypted in only 1 second, for example.
 * @param {Object} params
 * @param {Blob|File} params.file The file you wish to decrypt
 * @param {Uint8Array} params.symmetricKey The symmetric key used that will be used to decrypt this.
 * @returns {Promise<Object>} A promise containing the decrypted file.  The file is an ArrayBuffer.
 */
export async function decryptFile({ file, symmetricKey }) {
  // -- validate
  if (!is(file, "Blob", "file", "decryptFile", false)) {
    // if it's a file, we don't have to do anything, because a file is a subclass of Blob and it will just work.
    if (!is(file, "File", "file", "decryptFile", false)) {
      // so, check if it's a file above, and if not, then run the blob check again but this time throw an error.
      is(file, "Blob", "file", "decryptFile", true);
    }
  }
  if (!is(symmetricKey, "Uint8Array", "symmetricKey", "decryptFile")) return;

  const importedSymmKey = await importSymmetricKey(symmetricKey);

  // decrypt the file
  const decryptedFile = await decryptWithSymmetricKey(file, importedSymmKey);

  return decryptedFile;
}

async function getNpmPackage(packageName) {
  // log('getting npm package: ' + packageName)
  if (PACKAGE_CACHE[packageName]) {
    // log('found in cache')
    return PACKAGE_CACHE[packageName];
  }

  const resp = await fetch("https://unpkg.com/" + packageName);
  if (!resp.ok) {
    log("error with response: ", resp);
    throw Error(resp.statusText);
  }
  const blob = await resp.blob();
  // log('got blob', blob)
  const dataUrl = await fileToDataUrl(blob);
  // log('got dataUrl', dataUrl)
  PACKAGE_CACHE[packageName] = dataUrl;
  return dataUrl;
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
 * @returns {Promise<string>} A promise containing the HTML string that is now a LIT.  You can send this HTML around and only token holders will be able to unlock and decrypt the content inside it.  Included in the HTML is this LIT JS SDK itself, the encrypted locked content, an automatic connection to the LIT nodes network, and a handler for a button with id "unlockButton" which will perform the unlock operation when clicked.
 */
export async function createHtmlLIT({
  title,
  htmlBody,
  css,
  encryptedZipDataUrl,
  accessControlConditions,
  encryptedSymmetricKey,
  chain,
  npmPackages = [],
}) {
  // uncomment this to embed the LIT JS SDK directly instead of retrieving it from unpkg when a user views the LIT
  // npmPackages.push('lit-js-sdk')
  // log('createHtmlLIT with npmPackages', npmPackages)
  let scriptTags = "";
  for (let i = 0; i < npmPackages.length; i++) {
    const scriptDataUrl = await getNpmPackage(npmPackages[i]);
    const tag = `<script src="${scriptDataUrl}"></script>\n`;
    scriptTags += tag;
  }

  const formattedAccessControlConditions = accessControlConditions.map((c) =>
    canonicalAccessControlConditionFormatter(c)
  );

  // log('scriptTags: ', scriptTags)

  return `
<!DOCTYPE html>
<html>
  <head>
    <title>${title}</title>
    <style>
      html, body, #root {
        height: 100%;
      }
    </style>
    <style id="jss-server-side">${css}</style>
    ${scriptTags}
    <script>
      var encryptedZipDataUrl = "${encryptedZipDataUrl}"
      var accessControlConditions = ${JSON.stringify(
        formattedAccessControlConditions
      )}
      var chain = "${chain}"
      var encryptedSymmetricKey = "${uint8arrayToString(
        encryptedSymmetricKey,
        "base16"
      )}"
      var locked = true
      var useLitPostMessageProxy = false
      var sandboxed = false

      document.addEventListener('lit-ready', function(){
        var unlockButton = document.getElementById('unlockButton')
        if (unlockButton) {
          unlockButton.disabled = false
        }

        var loadingSpinner = document.getElementById('loadingSpinner')
        if (loadingSpinner) {
          loadingSpinner.style = 'display: none;'
        }

        var loadingText = document.getElementById('loadingText')
        if (loadingText){
          loadingText.innerText = ''
        }
      })
    </script>
    <script onload='LitJsSdk.litJsSdkLoadedInALIT()' src="https://jscdn.litgateway.com/index.web.js"></script>
  </head>
  <body>
    <div id="root">${htmlBody}</div>
    <script>
      var unlockButton = document.getElementById('unlockButton')
      unlockButton.onclick = function() {
        if (window.sandboxed) {
          var loadingText = document.getElementById('loadingText')
          if (loadingText){
            loadingText.innerText = 'Could not unlock because OpenSea does not allow wallet access.  Click the arrow icon "View on Lit Protocol" in the top right to open this in a new window.'
            loadingText.style = 'color: rgba(255,100,100,1);'
          }
        } else {
          LitJsSdk.toggleLock()
        }
      }
      unlockButton.disabled = true
    </script>
  </body>
</html>
  `;
}

/**
 * Lock and unlock the encrypted content inside a LIT.  This content is only viewable by holders of the NFT that corresponds to this LIT.  Locked content will be decrypted and placed into the HTML element with id "mediaGridHolder".  The HTML element with the id "lockedHeader" will have it's text automatically changed to LOCKED or UNLOCKED to denote the state of the LIT.  Note that if you're creating a LIT using the createHtmlLIT function, you do not need to use this function, because this function is automatically bound to any button in your HTML with the id "unlockButton".
 * @returns {Promise} the promise will resolve when the LIT has been unlocked or an error message has been shown informing the user that they are not authorized to unlock the LIT
 */
export async function toggleLock() {
  const mediaGridHolder = document.getElementById("mediaGridHolder");
  const lockedHeader = document.getElementById("lockedHeader");

  if (window.locked) {
    // save public content before decryption, so we can toggle back to the
    // locked state in the future
    window.publicContent = mediaGridHolder.innerHTML;

    if (!window.useLitPostMessageProxy && !window.litNodeClient.ready) {
      alert(
        "The LIT network is still connecting.  Please try again in about 10 seconds."
      );
      return;
    }

    const authSig = await checkAndSignAuthMessage({ chain: window.chain });
    if (authSig.errorCode && authSig.errorCode === "wrong_chain") {
      alert(
        "You are connected to the wrong blockchain.  Please switch your metamask to " +
          window.chain
      );
      return;
    }

    // get the merkle proof
    // const { balanceStorageSlot } = LIT_CHAINS[window.chain]
    // let merkleProof = null
    // try {
    //   merkleProof = await getMerkleProof({ tokenAddress: window.tokenAddress, balanceStorageSlot, tokenId: window.tokenId })
    // } catch (e) {
    //   log(e)
    //   alert('Error - could not obtain merkle proof.  Some nodes do not support this operation yet.  Please try another ETH node.')
    //   return
    // }

    if (window.useLitPostMessageProxy) {
      // instead of asking the network for the key part, ask the parent frame
      // the parentframe will then call unlockLit() with the encryption key
      sendMessageToFrameParent({
        command: "getEncryptionKey",
        target: "LitNodeClient",
        params: {
          accessControlConditions: window.accessControlConditions,
          toDecrypt: window.encryptedSymmetricKey,
          authSig,
          chain: window.chain,
        },
      });
      return;
    }

    // get the encryption key
    const symmetricKey = await window.litNodeClient.getEncryptionKey({
      accessControlConditions: window.accessControlConditions,
      toDecrypt: window.encryptedSymmetricKey,
      authSig,
      chain: window.chain,
    });

    if (!symmetricKey) {
      return; // something went wrong, maybe user is unauthorized
    }

    await unlockLitWithKey({ symmetricKey });
  } else {
    mediaGridHolder.innerHTML = window.publicContent;
    lockedHeader.innerText = "LOCKED";
    window.locked = true;
  }
}

/**
 * Manually unlock a LIT with a symmetric key.  You can obtain this key by calling "checkAndSignAuthMessage" to get an authSig, then calling "LitNodeClient.getEncryptionKey" to get the key.  If you want to see an example, check out the implementation of "toggleLock" which does all those operations and then calls this function at the end (unlockLitWithKey)
 * @param {Object} params
 * @param {Uint8Array} params.symmetricKey The decryption key obtained by calling "LitNodeClient.getEncryptionKey"
 * @returns {promise} A promise that will resolve when the LIT is unlocked
 */
export async function unlockLitWithKey({ symmetricKey }) {
  if (!is(symmetricKey, "Uint8Array", "symmetricKey", "unlockLitWithKey"))
    return;
  const mediaGridHolder = document.getElementById("mediaGridHolder");
  const lockedHeader = document.getElementById("lockedHeader");

  // convert data url to blob
  const encryptedZipBlob = await (
    await fetch(window.encryptedZipDataUrl)
  ).blob();
  const decryptedFiles = await decryptZip(encryptedZipBlob, symmetricKey);
  const mediaGridHtmlBody = await decryptedFiles["string.txt"].async("text");
  mediaGridHolder.innerHTML = mediaGridHtmlBody;
  lockedHeader.innerText = "UNLOCKED";
  window.locked = false;
}

/**
 * Verify a JWT from the LIT network.  Use this for auth on your server.  For some background, users can define resources (URLs) for authorization via on-chain conditions using the saveSigningCondition function.  Other users can then request a signed JWT proving that their ETH account meets those on-chain conditions using the getSignedToken function.  Then, servers can verify that JWT using this function.  A successful verification proves that the user meets the on-chain conditions defined in the saveSigningCondition step.  For example, the on-chain condition could be posession of a specific NFT.
 * @param {Object} params
 * @param {string} params.jwt A JWT signed by the LIT network using the BLS12-381 algorithm
 * @returns {Object} An object with 4 keys: "verified": A boolean that represents whether or not the token verifies successfully.  A true result indicates that the token was successfully verified.  "header": the JWT header.  "payload": the JWT payload which includes the resource being authorized, etc.  "signature": A uint8array that represents the raw  signature of the JWT.
 */
export function verifyJwt({ jwt }) {
  if (!is(jwt, "string", "jwt", "verifyJwt")) return;
  log("verifyJwt", jwt);
  // verify that the wasm was loaded
  if (!globalThis.wasmExports) {
    log("wasmExports is not loaded.");
    // initWasmBlsSdk().then((exports) => {
    //   // log('wtf, window? ', typeof window !== 'undefined')
    //   window.wasmExports = exports;
    // });
  }

  const pubKey = uint8arrayFromString(NETWORK_PUB_KEY, "base16");
  // log("pubkey is ", pubKey);
  const jwtParts = jwt.split(".");
  const sig = uint8arrayFromString(jwtParts[2], "base64url");
  // log("sig is ", uint8arrayToString(sig, "base16"));
  const unsignedJwt = `${jwtParts[0]}.${jwtParts[1]}`;
  // log("unsignedJwt is ", unsignedJwt);
  const message = uint8arrayFromString(unsignedJwt);
  // log("message is ", message);

  // TODO check for expiration

  // p is public key uint8array
  // s is signature uint8array
  // m is message uint8array
  // function is: function (p, s, m)

  const verified = Boolean(wasmBlsSdkHelpers.verify(pubKey, sig, message));

  return {
    verified,
    header: JSON.parse(
      uint8arrayToString(uint8arrayFromString(jwtParts[0], "base64url"))
    ),
    payload: JSON.parse(
      uint8arrayToString(uint8arrayFromString(jwtParts[1], "base64url"))
    ),
    signature: sig,
  };
}

/**
 * Get all the metadata needed to decrypt something in the future.  If you're encrypting files with Lit and storing them in IPFS or Arweave, then this function will provide you with a properly formatted metadata object that you should save alongside the files.
 * @param {Object} params
 * @param {string} params.objectUrl The url to the object, like an IPFS or Arweave url.
 * @param {Array} params.accessControlConditions The array of access control conditions defined for the object
 * @param {string} params.chain The blockchain on which the access control conditions should be checked
 * @param {Uint8Array} params.encryptedSymmetricKey The encrypted symmetric key that was returned by the LitNodeClient.saveEncryptionKey function
 * @returns {Object} An object with 3 keys: "verified": A boolean that represents whether or not the token verifies successfully.  A true result indicates that the token was successfully verified.  "header": the JWT header.  "payload": the JWT payload which includes the resource being authorized, etc.
 */
function metadataForFile({
  name,
  type,
  size,
  accessControlConditions,
  evmContractConditions,
  solRpcConditions,
  unifiedAccessControlConditions,
  chain,
  encryptedSymmetricKey,
}) {
  return {
    name,
    type,
    size,
    accessControlConditions,
    evmContractConditions,
    solRpcConditions,
    unifiedAccessControlConditions,
    chain,
    encryptedSymmetricKey: uint8arrayToString(encryptedSymmetricKey, "base16"),
  };
}

function humanizeComparator(comparator) {
  if (comparator === ">") {
    return "more than";
  } else if (comparator === ">=") {
    return "at least";
  } else if (comparator === "=") {
    return "exactly";
  } else if (comparator === "<") {
    return "less than";
  } else if (comparator === "<=") {
    return "at most";
  } else if (comparator === "contains") {
    return "contains";
  }
}

/**
 * The human readable name for an access control condition
 * @param {Object} params
 * @param {Array} params.accessControlConditions The array of access control conditions that you want to humanize
 * @param {Array} params.evmContractConditions The array of evm contract conditions that you want to humanize
 * @param {Array} params.solRpcConditions The array of Solana RPC conditions that you want to humanize
 * @param {Array} params.unifiedAccessControlConditions The array of unified access control conditions that you want to humanize
 * @returns {Promise<string>} A promise containing a human readable description of the access control conditions
 */
export async function humanizeAccessControlConditions({
  accessControlConditions,
  evmContractConditions,
  solRpcConditions,
  unifiedAccessControlConditions,
  tokenList,
  myWalletAddress,
}) {
  if (accessControlConditions) {
    return humanizeEvmBasicAccessControlConditions({
      accessControlConditions,
      tokenList,
      myWalletAddress,
    });
  } else if (evmContractConditions) {
    return humanizeEvmContractConditions({
      evmContractConditions,
      tokenList,
      myWalletAddress,
    });
  } else if (solRpcConditions) {
    return humanizeSolRpcConditions({
      solRpcConditions,
      tokenList,
      myWalletAddress,
    });
  } else if (unifiedAccessControlConditions) {
    return humanizeUnifiedAccessControlConditions({
      unifiedAccessControlConditions,
      tokenList,
      myWalletAddress,
    });
  }
}

async function humanizeUnifiedAccessControlConditions({
  unifiedAccessControlConditions,
  tokenList,
  myWalletAddress,
}) {
  const promises = await Promise.all(
    unifiedAccessControlConditions.map(async (acc) => {
      if (Array.isArray(acc)) {
        // this is a group.  recurse.
        const group = await humanizeUnifiedAccessControlConditions({
          unifiedAccessControlConditions: acc,
          tokenList,
          myWalletAddress,
        });
        return `( ${group} )`;
      }

      if (acc.operator) {
        if (acc.operator.toLowerCase() === "and") {
          return " and ";
        } else if (acc.operator.toLowerCase() === "or") {
          return " or ";
        }
      }

      if (acc.conditionType === "evmBasic") {
        return humanizeEvmBasicAccessControlConditions({
          accessControlConditions: [acc],
          tokenList,
          myWalletAddress,
        });
      } else if (acc.conditionType === "evmContract") {
        return humanizeEvmContractConditions({
          evmContractConditions: [acc],
          tokenList,
          myWalletAddress,
        });
      } else if (acc.conditionType === "solRpc") {
        return humanizeSolRpcConditions({
          solRpcConditions: [acc],
          tokenList,
          myWalletAddress,
        });
      } else if (acc.conditionType === "cosmos") {
        return humanizeCosmosConditions({
          cosmosConditions: [acc],
          tokenList,
          myWalletAddress,
        });
      } else {
        throwError({
          message: `Unrecognized condition type: ${acc.conditionType}`,
          name: "InvalidUnifiedConditionType",
          errorCode: "invalid_unified_condition_type",
        });
      }
    })
  );
  return promises.join("");
}

async function humanizeEvmBasicAccessControlConditions({
  accessControlConditions,
  tokenList,
  myWalletAddress,
}) {
  log("humanizing evm basic access control conditions");
  log("myWalletAddress", myWalletAddress);
  log("accessControlConditions", accessControlConditions);
  let fixedConditions = accessControlConditions;

  // inject and operator if needed
  // this is done because before we supported operators,
  // we let users specify an entire array of conditions
  // that would be "AND"ed together.  this injects those ANDs
  if (accessControlConditions.length > 1) {
    let containsOperator = false;
    for (let i = 0; i < accessControlConditions.length; i++) {
      if (accessControlConditions[i].operator) {
        containsOperator = true;
      }
    }
    if (!containsOperator) {
      fixedConditions = [];

      // insert ANDs between conditions
      for (let i = 0; i < accessControlConditions.length; i++) {
        fixedConditions.push(accessControlConditions[i]);
        if (i < accessControlConditions.length - 1) {
          fixedConditions.push({
            operator: "and",
          });
        }
      }
    }
  }

  const promises = await Promise.all(
    fixedConditions.map(async (acc) => {
      if (Array.isArray(acc)) {
        // this is a group.  recurse.
        const group = await humanizeEvmBasicAccessControlConditions({
          accessControlConditions: acc,
          tokenList,
          myWalletAddress,
        });
        return `( ${group} )`;
      }

      if (acc.operator) {
        if (acc.operator.toLowerCase() === "and") {
          return " and ";
        } else if (acc.operator.toLowerCase() === "or") {
          return " or ";
        }
      }

      if (
        acc.standardContractType === "timestamp" &&
        acc.method === "eth_getBlockByNumber"
      ) {
        return `Latest mined block must be past the unix timestamp ${acc.returnValueTest.value}`;
      } else if (
        acc.standardContractType === "MolochDAOv2.1" &&
        acc.method === "members"
      ) {
        // molochDAOv2.1 membership
        return `Is a member of the DAO at ${acc.contractAddress}`;
      } else if (
        acc.standardContractType === "ERC1155" &&
        acc.method === "balanceOf"
      ) {
        // erc1155 owns an amount of specific tokens
        return `Owns ${humanizeComparator(acc.returnValueTest.comparator)} ${
          acc.returnValueTest.value
        } of ${acc.contractAddress} tokens with token id ${acc.parameters[1]}`;
      } else if (
        acc.standardContractType === "ERC1155" &&
        acc.method === "balanceOfBatch"
      ) {
        // erc1155 owns an amount of specific tokens from a batch of token ids
        return `Owns ${humanizeComparator(acc.returnValueTest.comparator)} ${
          acc.returnValueTest.value
        } of ${acc.contractAddress} tokens with token id ${acc.parameters[1]
          .split(",")
          .join(" or ")}`;
      } else if (
        acc.standardContractType === "ERC721" &&
        acc.method === "ownerOf"
      ) {
        // specific erc721
        return `Owner of tokenId ${acc.parameters[0]} from ${acc.contractAddress}`;
      } else if (
        acc.standardContractType === "ERC721" &&
        acc.method === "balanceOf" &&
        acc.contractAddress === "0x22C1f6050E56d2876009903609a2cC3fEf83B415" &&
        acc.returnValueTest.comparator === ">" &&
        acc.returnValueTest.value === "0"
      ) {
        // for POAP main contract where the user owns at least 1 poap
        return `Owns any POAP`;
      } else if (
        acc.standardContractType === "POAP" &&
        acc.method === "tokenURI"
      ) {
        // owns a POAP
        return `Owner of a ${acc.returnValueTest.value} POAP on ${acc.chain}`;
      } else if (
        acc.standardContractType === "POAP" &&
        acc.method === "eventId"
      ) {
        // owns a POAP
        return `Owner of a POAP from event ID ${acc.returnValueTest.value} on ${acc.chain}`;
      } else if (
        acc.standardContractType === "ERC721" &&
        acc.method === "balanceOf"
      ) {
        // any erc721 in collection
        return `Owns ${humanizeComparator(acc.returnValueTest.comparator)} ${
          acc.returnValueTest.value
        } of ${acc.contractAddress} tokens`;
      } else if (
        acc.standardContractType === "ERC20" &&
        acc.method === "balanceOf"
      ) {
        let tokenFromList;
        if (tokenList) {
          tokenFromList = tokenList.find(
            (t) => t.address === acc.contractAddress
          );
        }
        let decimals, name;
        if (tokenFromList) {
          decimals = tokenFromList.decimals;
          name = tokenFromList.symbol;
        } else {
          decimals = await decimalPlaces({
            contractAddress: acc.contractAddress,
            chain: acc.chain,
          });
        }
        log("decimals", decimals);
        return `Owns ${humanizeComparator(
          acc.returnValueTest.comparator
        )} ${formatUnits(acc.returnValueTest.value, decimals)} of ${
          name || acc.contractAddress
        } tokens`;
      } else if (
        acc.standardContractType === "" &&
        acc.method === "eth_getBalance"
      ) {
        return `Owns ${humanizeComparator(
          acc.returnValueTest.comparator
        )} ${formatEther(acc.returnValueTest.value)} ETH`;
      } else if (acc.standardContractType === "" && acc.method === "") {
        if (
          myWalletAddress &&
          acc.returnValueTest.value.toLowerCase() ===
            myWalletAddress.toLowerCase()
        ) {
          return `Controls your wallet (${myWalletAddress})`;
        } else {
          return `Controls wallet with address ${acc.returnValueTest.value}`;
        }
      }
    })
  );
  return promises.join("");
}

async function humanizeSolRpcConditions({
  solRpcConditions,
  tokenList,
  myWalletAddress,
}) {
  log("humanizing sol rpc conditions");
  log("myWalletAddress", myWalletAddress);
  log("solRpcConditions", solRpcConditions);

  const promises = await Promise.all(
    solRpcConditions.map(async (acc) => {
      if (Array.isArray(acc)) {
        // this is a group.  recurse.
        const group = await humanizeSolRpcConditions({
          solRpcConditions: acc,
          tokenList,
          myWalletAddress,
        });
        return `( ${group} )`;
      }

      if (acc.operator) {
        if (acc.operator.toLowerCase() === "and") {
          return " and ";
        } else if (acc.operator.toLowerCase() === "or") {
          return " or ";
        }
      }

      if (acc.method === "getBalance") {
        return `Owns ${humanizeComparator(
          acc.returnValueTest.comparator
        )} ${formatSol(acc.returnValueTest.value)} SOL`;
      } else if (acc.method === "") {
        if (
          myWalletAddress &&
          acc.returnValueTest.value.toLowerCase() ===
            myWalletAddress.toLowerCase()
        ) {
          return `Controls your wallet (${myWalletAddress})`;
        } else {
          return `Controls wallet with address ${acc.returnValueTest.value}`;
        }
      } else {
        let msg = `Solana RPC method ${acc.method}(${acc.params.join(
          ", "
        )}) should have a result of ${humanizeComparator(
          acc.returnValueTest.comparator
        )} ${acc.returnValueTest.value}`;
        if (acc.returnValueTest.key !== "") {
          msg += ` for key ${acc.returnValueTest.key}`;
        }
        return msg;
      }
    })
  );
  return promises.join("");
}

async function humanizeEvmContractConditions({
  evmContractConditions,
  tokenList,
  myWalletAddress,
}) {
  log("humanizing evm contract conditions");
  log("myWalletAddress", myWalletAddress);
  log("evmContractConditions", evmContractConditions);

  const promises = await Promise.all(
    evmContractConditions.map(async (acc) => {
      if (Array.isArray(acc)) {
        // this is a group.  recurse.
        const group = await humanizeEvmContractConditions({
          evmContractConditions: acc,
          tokenList,
          myWalletAddress,
        });
        return `( ${group} )`;
      }

      if (acc.operator) {
        if (acc.operator.toLowerCase() === "and") {
          return " and ";
        } else if (acc.operator.toLowerCase() === "or") {
          return " or ";
        }
      }

      let msg = `${acc.functionName}(${acc.functionParams.join(
        ", "
      )}) on contract address ${
        acc.contractAddress
      } should have a result of ${humanizeComparator(
        acc.returnValueTest.comparator
      )} ${acc.returnValueTest.value}`;
      if (acc.returnValueTest.key !== "") {
        msg += ` for key ${acc.returnValueTest.key}`;
      }
      return msg;
    })
  );
  return promises.join("");
}

async function humanizeCosmosConditions({
  cosmosConditions,
  tokenList,
  myWalletAddress,
}) {
  log("humanizing cosmos conditions");
  log("myWalletAddress", myWalletAddress);
  log("cosmosConditions", cosmosConditions);

  const promises = await Promise.all(
    cosmosConditions.map(async (acc) => {
      if (Array.isArray(acc)) {
        // this is a group.  recurse.
        const group = await humanizeCosmosConditions({
          accessControlConditions: acc,
          tokenList,
          myWalletAddress,
        });
        return `( ${group} )`;
      }

      if (acc.operator) {
        if (acc.operator.toLowerCase() === "and") {
          return " and ";
        } else if (acc.operator.toLowerCase() === "or") {
          return " or ";
        }
      }

      if (acc.path === "/cosmos/bank/v1beta1/balances/:userAddress") {
        return `Owns ${humanizeComparator(
          acc.returnValueTest.comparator
        )} ${formatAtom(acc.returnValueTest.value)} ATOM`;
      } else if (acc.path === ":userAddress") {
        if (
          myWalletAddress &&
          acc.returnValueTest.value.toLowerCase() ===
            myWalletAddress.toLowerCase()
        ) {
          return `Controls your wallet (${myWalletAddress})`;
        } else {
          return `Controls wallet with address ${acc.returnValueTest.value}`;
        }
      } else if (
        acc.chain === "kyve" &&
        acc.path === "/kyve/registry/v1beta1/funders_list/0"
      ) {
        return `Is a current KYVE funder`;
      } else {
        let msg = `Cosmos RPC request for ${
          acc.path
        } should have a result of ${humanizeComparator(
          acc.returnValueTest.comparator
        )} ${acc.returnValueTest.value}`;
        if (acc.returnValueTest.key !== "") {
          msg += ` for key ${acc.returnValueTest.key}`;
        }
        return msg;
      }
    })
  );
  return promises.join("");
}

function formatSol(amount) {
  return formatUnits(amount, 9);
}

function formatAtom(amount) {
  return formatUnits(amount, 6);
}

export async function getTokenList() {
  // erc20
  const erc20Url = "https://tokens.coingecko.com/uniswap/all.json";
  const erc20Promise = fetch(erc20Url).then((r) => r.json());

  // erc721
  const erc721Url =
    "https://raw.githubusercontent.com/0xsequence/token-directory/main/index/mainnet/erc721.json";
  const erc721Promise = fetch(erc721Url).then((r) => r.json());

  const [erc20s, erc721s] = await Promise.all([erc20Promise, erc721Promise]);
  const sorted = [...erc20s.tokens, ...erc721s.tokens].sort((a, b) =>
    a.name > b.name ? 1 : -1
  );
  return sorted;
}

export const sendMessageToFrameParent = (data) => {
  window.parent.postMessage(data, "*");
};
