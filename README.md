
# LIT Protocol JS SDK

The LIT Protocol provides a decentralized way to encrypt and lock content that can be unlocked and decrypted by satisfying some on-chain verifable conditions, such as ownership of an NFT.  Simply put, it enables the creation of locked NFTs that can only be unlocked by owners of that NFT.  LITs are HTML/JS/CSS web pages that can be interactive and dynamic.

## State of the network today

Right now, the LIT Protocol is in an alpha state.  It is unaudited and the nodes are not as distributed as they will be when we launch a mainnet.  The network is not ready to store high value things like crypto wallets or private keys, because the cryptoeconomic guarantees that will protect the network are not in place yet.  That said, it is highly unlikely that any locked or private content would leak or be exposed given that the architecture of the network is inherently secure and private.

## How does the LIT protocol work?

This SDK will encrypt your content, split the key, and upload key fragments to independent LIT Protocol nodes.  When someone wants to access the content, the SDK will send a signed message and a merkle proof that proves that they own the NFT associated with the content.  The LIT nodes will then send down the key fragements and the SDK will combine them and decrypt the content.

## Installation

Use yarn or npm to add the lit-js-sdk to your product:

```
yarn add lit-js-sdk
```

You can then import it like so:

```
import LitJsSdk from 'lit-js-sdk'
```

We also provide a web-ready package with all dependencies included at build/index.web.js.  You can import this into your HTML webpage using a script tag:

```
<script onload='litJsSdkLoaded()' src="https://jscdn.litgateway.com/index.web.js"></script>
```

You can then use all the sdk functions via LitJsSdk.default for example `LitJsSdk.default.toggleLock()`

Note that if you use a script tag like this, you will likely need to initialize a connection to the LIT Network using something like this:

```
function litJsSdkLoaded(){
   var litNodeClient = new LitJsSdk.default.LitNodeClient()
  litNodeClient.connect()
  window.litNodeClient = litNodeClient
}
```

## Using the LIT Protocol

An example application can be found here: https://github.com/LIT-Protocol/MintLIT

### Minting LITs

LITs are essentially super-powered NFTs.  To mint a LIT, you should mint (or already own) any ERC721 or ERC1155 NFT that will serve as the access control token for unlocking the LIT.

We provide pre-deployed ERC1155 NFT contracts on Polygon and Ethereum for your use.  Usage of these contracts is optional, and you may supply your own if desired.  You can find the addresses of these contracts here: https://github.com/LIT-Protocol/lit-js-sdk/blob/main/src/lib/constants.js#L74

To mint a token using our pre-deployed contracts, you can use the mintLIT function documented here: https://lit-protocol.github.io/lit-js-sdk/api_docs_html/index.html#mintlit

For example:
```
const { tokenId, tokenAddress, mintingAddress, txHash, errorCode, authSig } = await LitJsSdk.mintLIT({ chain, quantity })
```

Once your have your NFT, you can lock and associate content with it on the LIT network.  In our implementation in MintLIT, we render the locked content as an HTML string, embedding any media such as pictures or videos as data urls.  You can do this, or you can encrypt files directly without rendering them into a HTML string.  To encrypt a string, use the following function documented here: https://lit-protocol.github.io/lit-js-sdk/api_docs_html/index.html#zipandencryptstring

```
const { symmetricKey, encryptedZip } = await LitJsSdk.zipAndEncryptString(lockedFileMediaGridHtml)
```

We then pass that encrypted content to a function that creates an HTML webpage with an embedded unlock button.

```
const htmlString = LitJsSdk.createHtmlLIT({
  title,
  htmlBody,
  css,
  tokenAddress,
  tokenId,
  chain,
  encryptedZipDataUrl: await fileToDataUrl(encryptedZip)
})
```

You'll need to store your LIT somewhere, and we use IPFS via Pinata for this purpose.

```
const litHtmlBlob = new Blob(
  [htmlString],
  { type: 'text/html' }
)
const formData = new FormData()
formData.append('file', litHtmlBlob)

const uploadRespBody = await new Promise((resolve, reject) => {
  fetch('https://api.pinata.cloud/pinning/pinFileToIPFS', {
    method: 'POST',
    mode: 'cors',
    headers: {
      Authorization: `Bearer ${PINATA_API_KEY}`
    },
    body: formData
  }).then(response => response.json())
    .then(data => resolve(data))
    .catch(err => reject(err))
})
const ipfsCid = uploadRespBody.IpfsHash
const fileUrl = `https://ipfs.io/ipfs/${ipfsCid}`
```

Your LIT is now accessible at the fileUrl variable. Now you need to save the encryption key to the LIT nodes.  `litNodeClient` should be an instance of LitNodeClient that has connected to the network via the connect function.

```
await litNodeClient.saveEncryptionKey({
  tokenAddress,
  tokenId,
  symmetricKey,
  authSig,
  chain
})
```

Finally, you should store your token metadata somewhere, so that your LIT is backwards compatible with existing NFT websites.  We use Firebase for this on MintLIT and if you are using our NFT contracts, you are welcome to use our Firebase instance to store your metadata as well.

```
await createTokenMetadata({
  chain,
  tokenAddress,
  tokenId,
  title,
  description,
  socialMediaUrl,
  quantity,
  mintingAddress,
  fileUrl,
  ipfsCid,
  txHash
})
```

Now, you can send the NFT that corresponds to this LIT to anyone, and they can use the website at fileUrl to unlock and decrypt the content inside it.

### Unlocking LITs

To unlock a LIT, you must retrieve the encryption key from the server.  This SDK provides a convenience function to do this for you called `toggleLock`.  It will pull down the encryption key, and decrypt content located at `window.encryptedZipDataUrl`, and then load the content into a div with id `mediaGridHolder`.  You may use `toggleLock` or implement parts of it yourself if you have further customizations.  Here's how it works.

First, obtain an authSig from the user.  This will ask their metamask to sign a message proving they own the crypto address that presumably owns the NFT.  Pass the chain you're using.  Currently "polygon" and "ethereum" are supported

```
const authSig = await checkAndSignAuthMessage({chain: 'polygon'})
```

Next, obtain the symmetric key from the LIT network.  It's important that you have a connected LitNodeClient accessible at window.litNodeClient for this to work.

```
const symmetricKey = await window.litNodeClient.getEncryptionKey({
  tokenAddress: window.tokenAddress,
  tokenId: window.tokenId,
  authSig,
  chain: window.chain
})
```

Finally, decrypt the content and inject it into the webpage.  We provide a convenience function to unlock the LIT once you have the symmetric encryption key that does the same thing as the code below, located here: https://lit-protocol.github.io/lit-js-sdk/api_docs_html/index.html#unlocklitwithkey

```
// convert data url to blob
const encryptedZipBlob = await (await fetch(window.encryptedZipDataUrl)).blob()
// decrypt the zip
const decryptedFiles = await decryptZip(encryptedZipBlob, symmetricKey)
// pull out the data url that contains the now-decrypted HTML
const mediaGridHtmlBody = await decryptedFiles['string.txt'].async('text')
// load the content into a div so the user can see it
document.getElementById('mediaGridHolder').innerHTML = mediaGridHtmlBody
```


## API
You can find API documentation at https://lit-protocol.github.io/lit-js-sdk/api_docs_html/index.html

## Questions or Support

Email chris@litprotocol.com for help.
