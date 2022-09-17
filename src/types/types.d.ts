import { LIT_COSMOS_CHAINS, LIT_CHAINS, LIT_SVM_CHAINS } from "../lib/constants"

export type AuthSig  = {
    sig:string
    derivedVia:string
    signedMessage:string
    address:string
}

export type EncryptedString = {
    symmetricKey: Uint8Array,
    encryptedString:Blob,
    encryptedData: Blob,
}

export type LitChainsKeys = keyof typeof LIT_CHAINS;
export type LitSVMChainsKeys = keyof typeof LIT_SVM_CHAINS;
export type LitCosmosChainsKeys = keyof typeof LIT_COSMOS_CHAINS;

export type AllLitChainsKeys = LitChainsKeys | LitSVMChainsKeys | LitCosmosChainsKeys;

export type LitNodeClientConfig = {
    alertWhenUnauthorized: boolean,
    minNodeCount: number,
    debug: boolean,
    bootstrapUrls:string[]
    // bootstrapUrls: [
    //     "https://node2.litgateway.com:7370",
    //     "https://node2.litgateway.com:7371",
    //     "https://node2.litgateway.com:7372",
    //     "https://node2.litgateway.com:7373",
    //     "https://node2.litgateway.com:7374",
    //     "https://node2.litgateway.com:7375",
    //     "https://node2.litgateway.com:7376",
    //     "https://node2.litgateway.com:7377",
    //     "https://node2.litgateway.com:7378",
    //     "https://node2.litgateway.com:7379",
    //   ],
}

export type EncryptedZipWithKey = {
    symmetricKey: Uint8Array,
    encryptedZip: Blob,
}