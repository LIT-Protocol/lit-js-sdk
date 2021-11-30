<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->

- [LIT Protocol JS SDK](#lit-protocol-js-sdk)
  - [State of the network today](#state-of-the-network-today)
  - [How does the LIT protocol work?](#how-does-the-lit-protocol-work)
    - [Static Content - Encrypting / locking](#static-content---encrypting--locking)
    - [Dynamic Content - Authorizing access to a resource via JWT](#dynamic-content---authorizing-access-to-a-resource-via-jwt)
  - [Installation](#installation)
  - [Using the LIT Protocol](#using-the-lit-protocol)
    - [Example projects and code](#example-projects-and-code)
    - [Connecting to the network](#connecting-to-the-network)
    - [Static Content - Storing any static content and manually storing the metadata](#static-content---storing-any-static-content-and-manually-storing-the-metadata)
    - [Static Content - Decrypting any static content](#static-content---decrypting-any-static-content)
    - [Static Content - Minting HTML NFTs](#static-content---minting-html-nfts)
    - [Static Content - Unlocking LITs](#static-content---unlocking-lits)
    - [Dynamic Content - Verifying a JWT that was signed by the Lit network](#dynamic-content---verifying-a-jwt-that-was-signed-by-the-lit-network)
    - [Dynamic Content - Provisoning access to a resource](#dynamic-content---provisoning-access-to-a-resource)
    - [Dynamic Content - Accessing a resource via a JWT](#dynamic-content---accessing-a-resource-via-a-jwt)
    - [Signed Chain Data - Cross chain communication and authentication without provisioning access beforehand](#signed-chain-data---cross-chain-communication-and-authentication-without-provisioning-access-beforehand)
  - [Examples of access control conditions](#examples-of-access-control-conditions)
    - [Must posess at least one ERC1155 token with a given token id](#must-posess-at-least-one-erc1155-token-with-a-given-token-id)
    - [Must posess at least one ERC1155 token from a batch of token ids](#must-posess-at-least-one-erc1155-token-from-a-batch-of-token-ids)
    - [Must posess a specific ERC721 token (NFT)](#must-posess-a-specific-erc721-token-nft)
    - [Must posess any token in an ERC721 collection (NFT Collection)](#must-posess-any-token-in-an-erc721-collection-nft-collection)
    - [Must posess a POAP with a specific name](#must-posess-a-poap-with-a-specific-name)
    - [Must posess at least one ERC20 token](#must-posess-at-least-one-erc20-token)
    - [Must posess at least 0.00001 ETH](#must-posess-at-least-000001-eth)
    - [Must be a member of a DAO (MolochDAOv2.1, also supports DAOHaus)](#must-be-a-member-of-a-dao-molochdaov21-also-supports-daohaus)
    - [Must be a subscriber to a creator on creaton.io](#must-be-a-subscriber-to-a-creator-on-creatonio)
    - [A specific wallet address](#a-specific-wallet-address)
  - [SDK Error Handling](#sdk-error-handling)
    - [Not Authorized](#not-authorized)
    - [Wrong Network](#wrong-network)
  - [Wallet Error Handling](#wallet-error-handling)
  - [API](#api)
  - [Tests](#tests)
  - [Questions or Support](#questions-or-support)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

# LIT Protocol JS SDK

The LIT Protocol is a decentralized access control protocol running on top of Ethereum and other EVM chains. With LIT, you can do 4 main things:

- Encrypt and lock static content behind an on chain condition (for example, posession of an NFT)
- Decrypt static content that was locked behind an on chain condition
- Authorize network signatures that provide access to dynamic content (for example, a server or network resource) behind an on chain condition
- Request a network signed JWT that provisions access and authorization to dynamic content behind an on chain condition.

With this functionality, the LIT protocol enables the creation of locked NFTs that can only be unlocked by owners of that NFT. It also enables provisioning access to a given server or network resource only to NFT owners. Rather than a simple JPEG, LIT NFTs are HTML/JS/CSS web pages that can be interactive and dynamic.

## State of the network today

Right now, the LIT Protocol is in an alpha state and the creators are running all the nodes. It is unaudited and the nodes are not distributed yet. There are various security improvements to be made, and cryptoeconomic guarantees as a result of staking are not in place yet. However, we believe it is highly unlikely that any locked or private content would leak or be exposed.

## How does the LIT protocol work?

### Static Content - Encrypting / locking

This SDK will encrypt your content, and upload your conditions for decryption to each LIT node. When someone wants to access the content, the SDK will request a message signature from the user's wallet that proves that they own the NFT associated with the content to each LIT node. The LIT nodes will then send down the decryption shares and the SDK will combine them and decrypt the content.

### Dynamic Content - Authorizing access to a resource via JWT

This SDK has the ability to create the authorization conditions for a given resource and store them with the LIT nodes. When someone requests a network signature because they are trying to access a resource (typically a server that serves some dynamic content), the SDK will request a message signature from the user's wallet that proves that they own the NFT associated with the resource to each LIT node. The LIT nodes will each verify that the user owns the NFT, sign the JWT to create a signature share, then send down that signature share. The SDK will combine the signature shares to obtain a signed JWT which can be presented to the resource to authenticate and authorize the user.

**Example**

You can find a minimal example project that implements dynamic content authorization here: https://github.com/LIT-Protocol/lit-minimal-jwt-example

## Installation

Use yarn or npm to add the lit-js-sdk to your product:

```
yarn add lit-js-sdk
```

You can then import it like so:

```
import LitJsSdk from 'lit-js-sdk'
```

We also provide a web-ready package with all dependencies included at build/index.web.js. You can import this into your HTML webpage using a script tag:

```
<script onload='litJsSdkLoaded()' src="https://jscdn.litgateway.com/index.web.js"></script>
```

You can then use all the sdk functions via LitJsSdk for example `LitJsSdk.toggleLock()`

Note that if you use a script tag like this, you will likely need to initialize a connection to the LIT Network using something like the below code snippet. The SDK requires an active connection to the LIT nodes to perform most functions (but, notably, a connection to the LIT nodes is not required if you are just verifying a JWT)

```
function litJsSdkLoaded(){
  var litNodeClient = new LitJsSdk.LitNodeClient()
  litNodeClient.connect()
  window.litNodeClient = litNodeClient
}
```

## Using the LIT Protocol

### Example projects and code

- **Static Content** An example that showcases the static content usecases can be found here: https://github.com/LIT-Protocol/MintLIT

- **Dynamic Content** An example that implements dynamic content authorization can be found here: https://github.com/LIT-Protocol/lit-minimal-jwt-example

- **Dynamic Content via a React app** An example that shows how to protect an entire React app with a LIT JWT https://github.com/LIT-Protocol/lit-locked-react-app-minimal-example

### Connecting to the network

For most use cases, you will want an active connection to the Lit Protocol. In web apps, this is typically done on first page load and can be shared between all your pages.

To connect, use the code below. Note that client.connect() will return instantly, but that does not mean your are connected to the network. You must listen for the `lit-ready` event. In the code below, we make the litNodeClient available as a global variable so that it can be used throughout the web app.

```
const client = new LitJsSdk.LitNodeClient()
client.connect()
window.litNodeClient = client
```

**To listen for the "lit-ready" event which is fired when the network is fully connected:**

```
document.addEventListener('lit-ready', function (e) {
  console.log('LIT network is ready')
  setNetworkLoading(false) // replace this line with your own code that tells your app the network is ready
}, false)
```

### Static Content - Storing any static content and manually storing the metadata

You can use Lit to encrypt and store any static content. You have to store the content yourself, but Lit will store who is allowed to decrypt it and enforce this.

First, obtain an authSig from the user. This will ask their metamask to sign a message proving they own their crypto address. Pass the chain you're using.

```
const authSig = await LitJsSdk.checkAndSignAuthMessage({chain: 'ethereum'})
```

Next, pass the thing you want to encrypt. To encrypt a string, use the code below.

```
const { encryptedZip, symmetricKey } = await LitJsSdk.zipAndEncryptString(aStringThatYouWishToEncrypt);
```

Next, define the access control conditions where a user will be allowed to decrypt.

```
const accessControlConditions = [
  {
    contractAddress: '',
    standardContractType: '',
    chain: 'ethereum',
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

Now, you can save the encryption key with the access control condition, which tells the Lit protocol that users that meet this access control condition should be able to decrypt.

```
const encryptedSymmetricKey = await window.litNodeClient.saveEncryptionKey({
  accessControlConditions,
  symmetricKey,
  authSig,
  chain,
});

```

You now need to save the `accessControlConditions`, `encryptedSymmetricKey`, and the `encryptedZip`. You will present the `accessControlConditions` and `encryptedSymmetricKey` to obtain the decrypted symmetric key, which you can then use to decrypt the zip.

### Static Content - Decrypting any static content

If you followed the instructions above for "Static Content - Storing any static content and manually storing the metadata" then you should follow these instructions to decrypt the data you stored.

Make sure you have `accessControlConditions`, `encryptedSymmetricKey`, and the `encryptedZip` variables you created when you stored the content.

There are 2 steps - you must obtain the decrypted symmetric key from the Lit protocol, and then you must decrypt the zip file using it.

First, obtain an authSig from the user. This will ask their metamask to sign a message proving they own their crypto address. Pass the chain you're using.

```
const authSig = await LitJsSdk.checkAndSignAuthMessage({chain: 'ethereum'})
```

To obtain the decrypted symmetric key, use the code below:

```
const symmKey = window.litNodeClient.getEncryptionKey({
  accessControlConditions,
  toDecrypt: encryptedSymmetricKey,
  chain,
  authSig
})
```

Now, decrypt the zip:

```
const decryptedFiles = await decryptZip(encryptedZipBlob, symmetricKey);
const decryptedString = await decryptedFiles["string.txt"].async("text");
```

Now, your cleartext is located in the `decryptedString` variable.

### Static Content - Minting HTML NFTs

HTML NFTs are essentially super-powered NFTs. To mint an HTML NFT, you should mint (or already own) any ERC721 or ERC1155 NFT that will serve as the access control token for unlocking the NFT. In the past, we called HTML NFTs "LITs" (Locked Interactive Tokens) so if you see a reference in docs or code to "a LIT" that is referring to an HTML NFT.

We provide pre-deployed ERC1155 NFT contracts on Polygon and Ethereum for your use. Usage of these contracts is optional, and you may supply your own if desired. You can find the addresses of these contracts here: https://github.com/LIT-Protocol/lit-js-sdk/blob/main/src/lib/constants.js#L74

To mint a token using our pre-deployed contracts, you can use the mintLIT function documented here: https://lit-protocol.github.io/lit-js-sdk/api_docs_html/index.html#mintlit

For example:

```
const { tokenId, tokenAddress, mintingAddress, txHash, errorCode, authSig } = await LitJsSdk.mintLIT({ chain, quantity })
```

Once your have your NFT, you can lock and associate content with it on the LIT network. In our implementation in MintLIT, we render the locked content as an HTML string, embedding any media such as pictures or videos as data urls. You can do this, or you can encrypt files directly without rendering them into a HTML string. To encrypt a string, use the following function documented here: https://lit-protocol.github.io/lit-js-sdk/api_docs_html/index.html#zipandencryptstring

```
const { symmetricKey, encryptedZip } = await LitJsSdk.zipAndEncryptString(lockedFileMediaGridHtml)
```

Now you need to encrypt the symmetric key, and save it to the LIT nodes. `litNodeClient` should be an instance of LitNodeClient that has connected to the network via the connect function.

You must also define your access control conditions (the conditions under which someone can decrypt the content). In the example below, we define a condition that requires the user holds at least 1 ERC1155 token with Token ID 9541 from the 0x3110c39b428221012934A7F617913b095BC1078C contract.

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

Finally, you should store your token metadata somewhere, so that your LIT is backwards compatible with existing NFT websites. We use Firebase for this on MintLIT and if you are using our NFT contracts, you are welcome to use our Firebase instance to store your metadata as well. You can find this createTokenMetadata function in this repo: https://github.com/LIT-Protocol/MintLIT

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

To unlock a LIT, you must retrieve the encryption key shares from the nodes. This SDK provides a convenience function to do this for you called `toggleLock`. It will pull down the encryption key shares and combine them into the encryption key itself, and decrypt content located at `window.encryptedZipDataUrl`, and then load the content into a div with id `mediaGridHolder`. You may use `toggleLock` or implement parts of it yourself if you have further customizations. Here's how it works:

First, obtain an authSig from the user. This will ask their metamask to sign a message proving they own the crypto address that presumably owns the NFT. Pass the chain you're using.

```
const authSig = await LitJsSdk.checkAndSignAuthMessage({chain: 'polygon'})
```

Next, obtain the symmetric key from the LIT network. It's important that you have a connected LitNodeClient accessible at window.litNodeClient for this to work.

```
const symmetricKey = await window.litNodeClient.getEncryptionKey({
  accessControlConditions: window.accessControlConditions,
  toDecrypt: window.encryptedSymmetricKey,
  authSig,
  chain: window.chain
})
```

Finally, decrypt the content and inject it into the webpage. We provide a convenience function to unlock the LIT once you have the symmetric encryption key that does the same thing as the code below, located here: https://lit-protocol.github.io/lit-js-sdk/api_docs_html/index.html#unlocklitwithkey

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

**Heads up** You can find a minimal example project that implements dynamic content authorization here: https://github.com/LIT-Protocol/lit-minimal-jwt-example

Verifying a JWT would typically be done on the server side (nodejs), but should work in the browser too.

First, import the SDK:

```
 const LitJsSdk = require('lit-js-sdk')
```

Now, you must have a JWT to verify. Usually this comes from the user who is trying to access the resource. You can try the jwt harcoded in the example below, which may be expired but should at least return a proper header and payload. In the real world, you should use jwt presented by the user

```
const jwt = "eyJhbGciOiJCTFMxMi0zODEiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJMSVQiLCJzdWIiOiIweGRiZDM2MGYzMDA5N2ZiNmQ5MzhkY2M4YjdiNjI4NTRiMzYxNjBiNDUiLCJjaGFpbiI6ImZhbnRvbSIsImlhdCI6MTYyODAzMTM1OCwiZXhwIjoxNjI4MDc0NTU4LCJiYXNlVXJsIjoiaHR0cHM6Ly9teS1keW5hbWljLWNvbnRlbnQtc2VydmVyLmNvbSIsInBhdGgiOiIvYV9wYXRoLmh0bWwiLCJvcmdJZCI6IiJ9.lX_aBSgGVYWd2FL6elRHoPJ2nab0IkmmX600cwZPCyK_SazZ-pzBUGDDQ0clthPVAtoS7roHg14xpEJlcSJUZBA7VTlPiDCOrkie_Hmulj765qS44t3kxAYduLhNQ-VN"
const { verified, header, payload } = LitJsSdk.verifyJwt({jwt})
if (payload.baseUrl !== "this-website.com" || payload.path !== "/path-you-expected" || payload.orgId !== "" || payload.role !== "" || payload.extraData !== "") {
  // Reject this request!
  return false
}
```

The "verified" variable is a boolean that indicates whether or not the signature verified properly. Note: YOU MUST CHECK THE PAYLOAD AGAINST THE CONTENT YOU ARE PROTECTING. This means you need to look at "payload.baseUrl" which should match the hostname of the server, and you must also look at "payload.path" which should match the path being accessed. If these do not match what you're expecting, you should reject the request.

### Dynamic Content - Provisoning access to a resource

**Heads up** You can find a minimal example project that implements dynamic content authorization here: https://github.com/LIT-Protocol/lit-minimal-jwt-example

Use dynamic content provisoning to put some dynamic content behind an on chain condition (for example, possession of an NFT). This function will essentially store that condition and the resource that users who meet that condition should be authorized to access. The resource could be a URL, for example. The dynamic content server should then verify the JWT provided by the network on every request, which proves that the user meets the on chain condition.

The "saveSigningCondition" function of the LitNodeClient is what you want to use for this, which is documented here: https://lit-protocol.github.io/lit-js-sdk/api_docs_html/index.html#litnodeclientsavesigningcondition

Note that you need an active connection to the Lit Protocol nodes to use this function. This connection can be made with the following code:

```
const litNodeClient = new LitJsSdk.LitNodeClient()
litNodeClient.connect()
```

Now, you should define you access control conditions. In the example below, we define a condition that requires the user holds at least 1 ERC1155 token with Token ID 9541 from the 0x3110c39b428221012934A7F617913b095BC1078C contract.

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

Next, obtain an authSig from the user. This will ask their metamask to sign a message proving they own the crypto address in their wallet. Pass the chain you're using.

```
const authSig = await LitJsSdk.checkAndSignAuthMessage({chain: 'polygon'})
```

Next, define the Resource ID of the resource you are granting access to. This is typically a URL.

```
const resourceId = {
  baseUrl: 'my-dynamic-content-server.com',
  path: '/a_path.html',
  orgId: "",
  role: "",
  extraData: ""
}
```

Finally, you can save all this to the Lit nodes, and then users will be able to request a JWT that grants access to the resource.

```
await litNodeClient.saveSigningCondition({ accessControlConditions, chain, authSig, resourceId })
```

Make sure that you save the accessControlConditions and resourceId, because the user will have to present them when requesting a JWT that would grant them access. You will typically want to store them wherever you will auth the user, so wherever your "log in" or "authorize" button would live.

### Dynamic Content - Accessing a resource via a JWT

**Heads up** You can find a minimal example project that implements dynamic content authorization here: https://github.com/LIT-Protocol/lit-minimal-jwt-example

Obtaining a signed JWT from the Lit network can be done via the getSignedToken function of the LitNodeClient documented here: https://lit-protocol.github.io/lit-js-sdk/api_docs_html/index.html#litnodeclientgetsignedtoken

**Important** You must call `litNodeClient.saveSigningCondition` to save a signing condition before you can request a signature and access a resource via a JWT. See the docs above for "Dynamic Content - Provisoning access to a resource" to learn how to do this.

Note that you need an active connection to the Lit Protocol nodes to use this function. This connection can be made with the following code:

```
const litNodeClient = new LitJsSdk.LitNodeClient()
litNodeClient.connect()
```

First, obtain an authSig from the user. This will ask their metamask to sign a message proving they own the crypto address in their wallet. Pass the chain you're using.

```
const authSig = await LitJsSdk.checkAndSignAuthMessage({chain: 'polygon'})
```

Now, using the accessControlConditions and resourceId you defined when provisoning access to the resource, you can use the getSignedToken function to get the token:

```
const jwt = await litNodeClient.getSignedToken({ accessControlConditions, chain, authSig, resourceId })
```

You can then present this JWT to a server, which can verify it using the verifyJwt function documented here https://lit-protocol.github.io/lit-js-sdk/api_docs_html/index.html#verifyjwt

### Signed Chain Data - Cross chain communication and authentication without provisioning access beforehand

If you'd like to request that the Lit Network sign the result of a smart contract function call, you can do that using the `getSignedChainDataToken` function of the LitNodeClient.

This will perform a smart contract function RPC call, sign the response, and then return a JWT. You may send this JWT to a server, or, send it into a smart contract to enable a cross-chain communication use-case. Solidity code to verify the signature is not yet available.

To call a function, you need the smart contract ABI. For this example, we will use the Chainlink price oracle smart contract.

```
const aggregatorV3InterfaceABI = [
  {
    inputs: [],
    name: "decimals",
    outputs: [{ internalType: "uint8", name: "", type: "uint8" }],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [],
    name: "description",
    outputs: [{ internalType: "string", name: "", type: "string" }],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [
      { internalType: "uint80", name: "_roundId", type: "uint80" },
    ],
    name: "getRoundData",
    outputs: [
      { internalType: "uint80", name: "roundId", type: "uint80" },
      { internalType: "int256", name: "answer", type: "int256" },
      { internalType: "uint256", name: "startedAt", type: "uint256" },
      { internalType: "uint256", name: "updatedAt", type: "uint256" },
      {
        internalType: "uint80",
        name: "answeredInRound",
        type: "uint80",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [],
    name: "latestRoundData",
    outputs: [
      { internalType: "uint80", name: "roundId", type: "uint80" },
      { internalType: "int256", name: "answer", type: "int256" },
      { internalType: "uint256", name: "startedAt", type: "uint256" },
      { internalType: "uint256", name: "updatedAt", type: "uint256" },
      {
        internalType: "uint80",
        name: "answeredInRound",
        type: "uint80",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [],
    name: "version",
    outputs: [{ internalType: "uint256", name: "", type: "uint256" }],
    stateMutability: "view",
    type: "function",
  },
];
```

Next, you'll need the smart contract address

```
const addr = "0x5f4eC3Df9cbd43714FE2740f5E3616155c5b8419";
```

Encode the call data using the `encodeCallData` function

```
const callData = LitJsSdk.encodeCallData({
  abi: aggregatorV3InterfaceABI,
  functionName: "latestRoundData",
  functionParams: [],
});
```

Request the signed chain data token from the Lit Network. Note that this requires a connected LitNodeClient.

```
const jwt = await litNodeClient.getSignedChainDataToken({
  callRequests,
  chain: 'ethereum',
});
```

You can then extract the various parts of the JWT, and verify the signature, using the `verifyJwt` function.

```
const { verified, header, payload, signature } = LitJsSdk.verifyJwt({
  jwt,
});
```

The responses to the function calls live in the `payload.callResponses` array. You can decode them using the `decodeCallResult` function.

```
const decoded = LitJsSdk.decodeCallResult({
  abi: aggregatorV3InterfaceABI,
  functionName: "latestRoundData",
  data: payload.callResponses[0],
});
```

At this point, the function call response is in the `decoded` variable. For this smart contract call, the current price of ETH in USD is in `decoded.answer` as a BigNumber.

You can now verify the signature and be certain that the smart contract function call returned that result at the time it was called (if the signature is genuine).

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

### Must posess at least one ERC1155 token from a batch of token ids

In this example, the token contract's address is 0x10daa9f4c0f985430fde4959adb2c791ef2ccf83 and the token ids we are checking for are either 1, 2, 10003, or 10004.

```
const accessControlConditions = [
  {
    contractAddress: '0x10daa9f4c0f985430fde4959adb2c791ef2ccf83',
    standardContractType: 'ERC1155',
    chain,
    method: 'balanceOfBatch',
    parameters: [
      ':userAddress,:userAddress,:userAddress,:userAddress',
      '1,2,10003,10004'
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

### Must posess a POAP with a specific name

This is an integration with https://poap.xyz

It checks that a user holds a specific POAP. Enter the POAP name in the final returnValueTest value. In this example the POAP is "Burning Man 2021".

This actually performs two checks, so there are two access control conditions tested. The first checks that the user holds at least 1 POAP, but it could be from any POAP event. The second checks that the name of any of the user's POAPs is a match to the returnValueTest value.

You may use "contains" or "=" for the final returnValueTest comparator. For example, if there are POAPs issued every year for Burning Man, with names in the format of "Burning Man 2021" and "Burning Man 2022" but you just want to check that the user holds any Burning Man POAP, you could use "contains" "Burning Man" and all Burning Man POAPs would pass the test. If you wanted to check for a specific year like 2021, you could use "=" "Burning Man 2021"

Note that most POAPs live on the xDai chain so this example uses it.

```
const chain = "xdai";
var accessControlConditions = [
  {
    contractAddress: "0x22C1f6050E56d2876009903609a2cC3fEf83B415",
    standardContractType: "ERC721",
    chain,
    method: "balanceOf",
    parameters: [":userAddress"],
    returnValueTest: {
      comparator: ">",
      value: "0",
    },
  },
  {
    contractAddress: "0x22C1f6050E56d2876009903609a2cC3fEf83B415",
    standardContractType: "POAP",
    chain,
    method: "tokenURI",
    parameters: [],
    returnValueTest: {
      comparator: "contains",
      value: "Burning Man 2021",
    },
  },
];
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

In this example, we are checking the ETH balance of the user's address and making sure it's above 0.00001 ETH. Note that the return value is in Wei, so we specified 0.00001 ETH as 10000000000000 Wei.

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

### Must be a member of a DAO (MolochDAOv2.1, also supports DAOHaus)

In this example, we are checking that the user is a member of a MolochDAOv2.1. DAOHaus DAOs are also MolochDAOv2.1 and therefore are also supported. This checks that the user is a member of the DAO and also that they are not jailed. This example checks the DAO contract at 0x50D8EB685a9F262B13F28958aBc9670F06F819d9 on the xDai chain.

```
const accessControlConditions = [
  {
    contractAddress: '0x50D8EB685a9F262B13F28958aBc9670F06F819d9',
    standardContractType: 'MolochDAOv2.1',
    chain,
    method: 'members',
    parameters: [
      ':userAddress',
    ],
    returnValueTest: {
      comparator: '=',
      value: 'true'
    }
  }
]
```

### Must be a subscriber to a creator on creaton.io

In this example, we are checking that the user is a subscriber to a creator on creaton.io. This example checks the Creator contract at 0x50D8EB685a9F262B13F28958aBc9670F06F819d9 on the Mumbai chain.

```
const accessControlConditions = [
  {
    contractAddress: '0x77c0612bb672a52c60c7a71b898853570bd2bbbb',
    standardContractType: 'Creaton',
    chain,
    method: 'subscribers',
    parameters: [
      ':userAddress',
    ],
    returnValueTest: {
      comparator: '=',
      value: 'true'
    }
  }
]
```

### A specific wallet address

In this example, we are checking that the user is in posession of a specific wallet address 0x50e2dac5e78B5905CB09495547452cEE64426db2

```
const accessControlConditions = [
  {
    contractAddress: '',
    standardContractType: '',
    chain,
    method: '',
    parameters: [
      ':userAddress',
    ],
    returnValueTest: {
      comparator: '=',
      value: '0x50e2dac5e78B5905CB09495547452cEE64426db2'
    }
  }
]
```

## SDK Error Handling

Errors are thrown as exceptions when something has gone wrong. Errors are objects with a message, name, and errorCode. Possible codes are documented below.

### Not Authorized

- errorCode: not_authorized
- Reason: Thrown when the user does not have access to decrypt or is unauthorized to receive a JWT for an item.

### Wrong Network

- errorCode: wrong_network
- Reason: The user is on the wrong network. For example, this may mean the user has ethereum selected in their wallet but they were trying to use polygon for the current operation.

## Wallet Error Handling

Metamask and other wallets throw errors themselves. The format for those exceptions can be found here: https://docs.metamask.io/guide/ethereum-provider.html#errors

## API

You can find API documentation at https://lit-protocol.github.io/lit-js-sdk/api_docs_html/index.html

## Tests

Currently we have manual tests that you can run in the browser in manual_tests.html. To run these, set up a HTTP server in the build folder. We use python for this with the built in SimpleHTTPServer module by running "python2 -m SimpleHTTPServer" and then going to "http://localhost:8000/manual_tests.html" in a browser.

There is also an attempt at automated tests in the tests folder but running it with nodejs does not work because this project is bundled. An attempt at bundling the tests as well is in esbuild-tests.js which should work someday, but the project depends on fetch and I gave up when trying to inject fetch into esbuild.

## Questions or Support

Email chris@litprotocol.com for help.
