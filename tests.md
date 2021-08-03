# Manual Tests

Spin up an instance of this SDK somewhere to run these tests.  The easiest way to do this is to visit https://mintlit.com/ and open the developer console.  Note that the tests below assume that you have a wallet that holds the NFT specified in the accessControlConditions variable.  Substitute an NFT contract address and token id that you own if you want to test with your own wallet.

## Provisoning access to a resource
```
const chain = 'fantom'
const authSig = await LitJsSdk.checkAndSignAuthMessage({chain})
const accessControlConditions = [
  {
    contractAddress: '0x3110c39b428221012934A7F617913b095BC1078C',
    standardContractType: 'ERC1155',
    chain,
    method: 'balanceOf',
    parameters: [
      ':userAddress',
      '21'
    ],
    returnValueTest: {
      comparator: '>',
      value: '0'
    }
  }
]
const resourceId = {
  baseUrl: 'https://my-dynamic-content-server.com',
  path: '/a_path.html',
  orgId: ""
}
await litNodeClient.saveSigningCondition({ accessControlConditions, chain, authSig, resourceId })
```

## Requesting access to a resource via a signed JWT
```
const chain = 'fantom'
const authSig = await LitJsSdk.checkAndSignAuthMessage({chain})
const accessControlConditions = [
  {
    contractAddress: '0x3110c39b428221012934A7F617913b095BC1078C',
    standardContractType: 'ERC1155',
    chain,
    method: 'balanceOf',
    parameters: [
      ':userAddress',
      '21'
    ],
    returnValueTest: {
      comparator: '>',
      value: '0'
    }
  }
]
const resourceId = {
  baseUrl: 'https://my-dynamic-content-server.com',
  path: '/a_path.html',
  orgId: ""
}
const jwt = await litNodeClient.getSignedToken({ accessControlConditions, chain, authSig, resourceId })
```

## Verifying access to a resource via a signed JWT
```
const verified = LitJsSdk.verifyJwt({jwt})
```