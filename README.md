<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->
**Table of Contents**  *generated with [DocToc](https://github.com/thlorenz/doctoc)*

- [LIT Protocol JS SDK](#lit-protocol-js-sdk)
  - [State of the network today](#state-of-the-network-today)
  - [How does the LIT protocol work?](#how-does-the-lit-protocol-work)
    - [Static Content - Encrypting / locking](#static-content---encrypting--locking)
    - [Dynamic Content - Authorizing access to a resource via JWT](#dynamic-content---authorizing-access-to-a-resource-via-jwt)
  - [Installation](#installation)
  - [Using the LIT Protocol](#using-the-lit-protocol)
    - [Static Content - Minting LITs](#static-content---minting-lits)
    - [Static Content - Unlocking LITs](#static-content---unlocking-lits)
    - [Dynamic Content - Verifying a JWT that was signed by the Lit network](#dynamic-content---verifying-a-jwt-that-was-signed-by-the-lit-network)
    - [Dynamic Content - Provisoning access to a resource](#dynamic-content---provisoning-access-to-a-resource)
    - [Dynamic Content - Accessing a resource via a JWT](#dynamic-content---accessing-a-resource-via-a-jwt)
  - [Examples of access control conditions](#examples-of-access-control-conditions)
    - [Must posess at least one ERC1155 token with a given token id](#must-posess-at-least-one-erc1155-token-with-a-given-token-id)
    - [Must posess a specific ERC721 token (NFT)](#must-posess-a-specific-erc721-token-nft)
    - [Must posess any token in an ERC721 collection (NFT Collection)](#must-posess-any-token-in-an-erc721-collection-nft-collection)
    - [Must posess at least one ERC20 token](#must-posess-at-least-one-erc20-token)
    - [Must posess at least 0.00001 ETH](#must-posess-at-least-000001-eth)
  - [API](#api)
  - [Tests](#tests)
  - [Questions or Support](#questions-or-support)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->


# LIT Protocol JS SDK

The LIT Protocol is a decentralized access control protocol running on top of Ethereum and other EVM chains.  With LIT, you can do 4 main things: 
* Encrypt and lock static content behind an on chain condition (for example, posession of an NFT)
* Decrypt static content that was locked behind an on chain condition
* Authorize network signatures that provide access to dynamic content (for example, a server or network resource) behind an on chain condition
* Request a network signed JWT that provisions access and authorization to dynamic content behind an on chain condition. 
  
With this functionality, the LIT protocol enables the creation of locked NFTs that can only be unlocked by owners of that NFT.  It also enables provisioning access to a given server or network resource only to NFT owners.  Rather than a simple JPEG, LIT NFTs are HTML/JS/CSS web pages that can be interactive and dynamic.

## State of the network today

Right now, the LIT Protocol is in an alpha state and the creators are running all the nodes.  It is unaudited and the nodes are not distributed yet.  There are various security improvements to be made, and cryptoeconomic guarantees as a result of staking are not in place yet.  However, we believe it is highly unlikely that any locked or private content would leak or be exposed.  

## How does the LIT protocol work?

### Static Content - Encrypting / locking

This SDK will encrypt your content, and upload your conditions for decryption to each LIT node.  When someone wants to access the content, the SDK will request a message signature from the user's wallet that proves that they own the NFT associated with the content to each LIT node.  The LIT nodes will then send down the decryption shares and the SDK will combine them and decrypt the content.

### Dynamic Content - Authorizing access to a resource via JWT
This SDK has the ability to create the authorization conditions for a given resource and store them with the LIT nodes.  When someone requests a network signature because they are trying to access a resource (typically a server that serves some dynamic content), the SDK will request a message signature from the user's wallet that proves that they own the NFT associated with the resource to each LIT node.  The LIT nodes will each verify that the user owns the NFT, sign the JWT to create a signature share, then send down that signature share.  The SDK will combine the signature shares to obtain a signed JWT which can be presented to the resource to authenticate and authorize the user.


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

You can then use all the sdk functions via LitJsSdk for example `LitJsSdk.toggleLock()`

Note that if you use a script tag like this, you will likely need to initialize a connection to the LIT Network using something like the below code snippet.  The SDK requires an active connection to the LIT nodes to perform most functions (but, notably, a connection to the LIT nodes is not required if you are just verifying a JWT)

```
function litJsSdkLoaded(){
  var litNodeClient = new LitJsSdk.LitNodeClient()
  litNodeClient.connect()
  window.litNodeClient = litNodeClient
}
```

## Using the LIT Protocol

An example application that showcases the static content usecases can be found here: https://github.com/LIT-Protocol/MintLIT

### Static Content - Minting LITs

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

Now you need to encrypt the symmetric key, and save it to the LIT nodes.  `litNodeClient` should be an instance of LitNodeClient that has connected to the network via the connect function.

You must also define your access control conditions (the conditions under which someone can decrypt the content).  In the example below, we define a condition that requires the user holds at least 1 ERC1155 token with Token ID 9541 from the 0x3110c39b428221012934A7F617913b095BC1078C contract.

```
const accessControlConditions = [
  {
    contractAddress: '0x3110c39b428221012934A7F617913b095BC1078C',
    standardContractType: 'ERC1155',
    chain,
    method: 'balanceOf',
    parameters: [
      ':userAddress',
      '9541'
    ],
    returnValueTest: {
      comparator: '>',
      value: '0'
    }
  }
]

const encryptedSymmetricKey = await window.litNodeClient.saveEncryptionKey({
  accessControlConditions,
  symmetricKey,
  authSig,
  chain
})
```

We then pass that encrypted content to a function that creates an HTML webpage with an embedded unlock button.

```
const htmlString = LitJsSdk.createHtmlLIT({
    title,
    htmlBody,
    css,
    accessControlConditions,
    encryptedSymmetricKey,
    chain,
    encryptedZipDataUrl: await LitJsSdk.fileToDataUrl(encryptedZip)
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

Your LIT is now accessible at the fileUrl variable.

Finally, you should store your token metadata somewhere, so that your LIT is backwards compatible with existing NFT websites.  We use Firebase for this on MintLIT and if you are using our NFT contracts, you are welcome to use our Firebase instance to store your metadata as well.  You can find this createTokenMetadata function in this repo: https://github.com/LIT-Protocol/MintLIT

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

### Static Content - Unlocking LITs

To unlock a LIT, you must retrieve the encryption key shares from the nodes.  This SDK provides a convenience function to do this for you called `toggleLock`.  It will pull down the encryption key shares and combine them into the encryption key itself, and decrypt content located at `window.encryptedZipDataUrl`, and then load the content into a div with id `mediaGridHolder`.  You may use `toggleLock` or implement parts of it yourself if you have further customizations.  Here's how it works:

First, obtain an authSig from the user.  This will ask their metamask to sign a message proving they own the crypto address that presumably owns the NFT.  Pass the chain you're using.  

```
const authSig = await LitJsSdk.checkAndSignAuthMessage({chain: 'polygon'})
```

Next, obtain the symmetric key from the LIT network.  It's important that you have a connected LitNodeClient accessible at window.litNodeClient for this to work.

```
const symmetricKey = await window.litNodeClient.getEncryptionKey({
  accessControlConditions: window.accessControlConditions,
  toDecrypt: window.encryptedSymmetricKey,
  authSig,
  chain: window.chain
})
```

Finally, decrypt the content and inject it into the webpage.  We provide a convenience function to unlock the LIT once you have the symmetric encryption key that does the same thing as the code below, located here: https://lit-protocol.github.io/lit-js-sdk/api_docs_html/index.html#unlocklitwithkey

```
// convert data url to blob
const encryptedZipBlob = await (await fetch(window.encryptedZipDataUrl)).blob()
// decrypt the zip
const decryptedFiles = await LitJsSdk.decryptZip(encryptedZipBlob, symmetricKey)
// pull out the data url that contains the now-decrypted HTML
const mediaGridHtmlBody = await decryptedFiles['string.txt'].async('text')
// load the content into a div so the user can see it
document.getElementById('mediaGridHolder').innerHTML = mediaGridHtmlBody
```

### Dynamic Content - Verifying a JWT that was signed by the Lit network

This would typically be done on the server side (nodejs), but should work in the browser too.

First, import the SDK: 

```
 const LitJsSdk = require('lit-js-sdk')
```

Now, you must have a JWT to verify.  Usually this comes from the user who is trying to access the resource.  You can try the jwt harcoded in the example below, which may be expired but should at least return a proper header and payload.  In the real world, you should use jwt  presented by the user

```
const jwt = "eyJhbGciOiJCTFMxMi0zODEiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJMSVQiLCJzdWIiOiIweGRiZDM2MGYzMDA5N2ZiNmQ5MzhkY2M4YjdiNjI4NTRiMzYxNjBiNDUiLCJjaGFpbiI6ImZhbnRvbSIsImlhdCI6MTYyODAzMTM1OCwiZXhwIjoxNjI4MDc0NTU4LCJiYXNlVXJsIjoiaHR0cHM6Ly9teS1keW5hbWljLWNvbnRlbnQtc2VydmVyLmNvbSIsInBhdGgiOiIvYV9wYXRoLmh0bWwiLCJvcmdJZCI6IiJ9.lX_aBSgGVYWd2FL6elRHoPJ2nab0IkmmX600cwZPCyK_SazZ-pzBUGDDQ0clthPVAtoS7roHg14xpEJlcSJUZBA7VTlPiDCOrkie_Hmulj765qS44t3kxAYduLhNQ-VN"
const { verified, header, payload } = LitJsSdk.verifyJwt({jwt})
if (payload.baseUrl !== "this-website.com" || payload.path !== "/path-you-expected" || payload.orgId !== "") {
  // Reject this request!
  return false
}
```

The "verified" variable is a boolean that indicates whether or not the signature verified properly.  Note: YOU MUST CHECK THE PAYLOAD AGAINST THE CONTENT YOU ARE PROTECTING.  This means you need to look at "payload.baseUrl" which should match the hostname of the server, and you must also look at "payload.path" which should match the path being accessed.  If these do not match what you're expecting, you should reject the request.

### Dynamic Content - Provisoning access to a resource
Use this to put some dynamic content behind an on chain condition (for example, possession of an NFT).  This function will essentially store that condition and the resource that users who meet that condition should be authorized to access.  The resource could be a URL, for example.  The dynamic content server should then verify the JWT provided by the network on every request, which proves that the user meets the on chain condition.

The "saveSigningCondition" function of the LitNodeClient is what you want to use for this, which is documented here: https://lit-protocol.github.io/lit-js-sdk/api_docs_html/index.html#litnodeclientsavesigningcondition

Note that you need an active connection to the Lit Protocol nodes to use this function.  This connection can be made with the following code:

```
const litNodeClient = new LitJsSdk.LitNodeClient()
litNodeClient.connect()
```

Now, you should define you access control conditions.  In the example below, we define a condition that requires the user holds at least 1 ERC1155 token with Token ID 9541 from the 0x3110c39b428221012934A7F617913b095BC1078C contract.

```
const accessControlConditions = [
  {
    contractAddress: '0x3110c39b428221012934A7F617913b095BC1078C',
    standardContractType: 'ERC1155',
    chain,
    method: 'balanceOf',
    parameters: [
      ':userAddress',
      '9541'
    ],
    returnValueTest: {
      comparator: '>',
      value: '0'
    }
  }
]
```

Next, obtain an authSig from the user.  This will ask their metamask to sign a message proving they own the crypto address in their wallet.  Pass the chain you're using.  

```
const authSig = await LitJsSdk.checkAndSignAuthMessage({chain: 'polygon'})
```

Next, define the Resource ID of the resource you are granting access to.  This is typically a URL.

```
const resourceId = {
  baseUrl: 'my-dynamic-content-server.com',
  path: '/a_path.html',
  orgId: ""
}
```

Finally, you can save all this to the Lit nodes, and then users will be able to request a JWT that grants access to the resource.

```
await litNodeClient.saveSigningCondition({ accessControlConditions, chain, authSig, resourceId }) 
```

Make sure that you save the accessControlConditions and resourceId, because the user will have to present them when requesting a JWT that would grant them access.  You will typically want to store them wherever you will auth the user, so wherever your "log in" or "authorize" button would live.

### Dynamic Content - Accessing a resource via a JWT

Obtaining a signed JWT from the Lit network can be done via the getSignedToken function of the LitNodeClient documented here: https://lit-protocol.github.io/lit-js-sdk/api_docs_html/index.html#litnodeclientgetsignedtoken

Note that you need an active connection to the Lit Protocol nodes to use this function.  This connection can be made with the following code:

```
const litNodeClient = new LitJsSdk.LitNodeClient()
litNodeClient.connect()
```

First, obtain an authSig from the user.  This will ask their metamask to sign a message proving they own the crypto address in their wallet.  Pass the chain you're using.  

```
const authSig = await LitJsSdk.checkAndSignAuthMessage({chain: 'polygon'})
```

Now, using the accessControlConditions and resourceId you defined when provisoning access to the resource, you can use the getSignedToken function to get the token:

```
const jwt = await litNodeClient.getSignedToken({ accessControlConditions, chain, authSig, resourceId })
```

You can then present this JWT to a server, which can verify it using the verifyJwt function documented here https://lit-protocol.github.io/lit-js-sdk/api_docs_html/index.html#verifyjwt 

## Examples of access control conditions

### Must posess at least one ERC1155 token with a given token id
In this example, the token contract's address is 0x3110c39b428221012934A7F617913b095BC1078C and the token id we are checking for is 9541.

```
const accessControlConditions = [
  {
    contractAddress: '0x3110c39b428221012934A7F617913b095BC1078C',
    standardContractType: 'ERC1155',
    chain,
    method: 'balanceOf',
    parameters: [
      ':userAddress',
      '9541'
    ],
    returnValueTest: {
      comparator: '>',
      value: '0'
    }
  }
]
```

### Must posess a specific ERC721 token (NFT)
In this example, the token contract's address is 0x319ba3aab86e04a37053e984bd411b2c63bf229e and the token id we are checking for is 9541.

```
const accessControlConditions = [
  {
    contractAddress: '0x319ba3aab86e04a37053e984bd411b2c63bf229e',
    standardContractType: 'ERC721',
    chain,
    method: 'ownerOf',
    parameters: [
      '5954'
    ],
    returnValueTest: {
      comparator: '=',
      value: ':userAddress'
    }
  }
]
```

### Must posess any token in an ERC721 collection (NFT Collection)
In this example, the token contract's address is 0x319ba3aab86e04a37053e984bd411b2c63bf229e.

```
const accessControlConditions = [
  {
    contractAddress: '0x319ba3aab86e04a37053e984bd411b2c63bf229e',
    standardContractType: 'ERC721',
    chain,
    method: 'balanceOf',
    parameters: [
      ':userAddress'
    ],
    returnValueTest: {
      comparator: '>',
      value: '0'
    }
  }
]
```

### Must posess at least one ERC20 token
In this example, the token contract's address is 0x3110c39b428221012934A7F617913b095BC1078C.

```
const accessControlConditions = [
  {
    contractAddress: '0xc0ad7861fe8848002a3d9530999dd29f6b6cae75',
    standardContractType: 'ERC20',
    chain,
    method: 'balanceOf',
    parameters: [
      ':userAddress'
    ],
    returnValueTest: {
      comparator: '>',
      value: '0'
    }
  }
]
```

### Must posess at least 0.00001 ETH
In this example, we are checking the ETH balance of the user's address and making sure it's above 0.00001 ETH.  Note that the return value is in Wei, so we specified 0.00001 ETH as 10000000000000 Wei.

```
const accessControlConditions = [
  {
    contractAddress: '',
    standardContractType: '',
    chain,
    method: 'eth_getBalance',
    parameters: [
      ':userAddress',
      'latest'
    ],
    returnValueTest: {
      comparator: '>=',
      value: '10000000000000'
    }
  }
]
```


## API
You can find API documentation at https://lit-protocol.github.io/lit-js-sdk/api_docs_html/index.html

## Tests
Currently we have manual tests that you can run in the browser in manual_tests.html.  To run these, set up a HTTP server in the build folder.  We use python for this with the built in SimpleHTTPServer module by running "python2 -m SimpleHTTPServer" and then going to "http://localhost:8000/manual_tests.html" in a browser.

There is also an attempt at automated tests in the tests folder but running it with nodejs does not work because this project is bundled.  An attempt at bundling the tests as well is in esbuild-tests.js which should work someday, but the project depends on fetch and I gave up when trying to inject fetch into esbuild.

## Questions or Support

Email chris@litprotocol.com for help.
