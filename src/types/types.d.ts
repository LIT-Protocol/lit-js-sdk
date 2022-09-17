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
