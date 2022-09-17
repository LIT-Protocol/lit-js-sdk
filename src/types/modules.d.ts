import { LitNodeClientConfig } from "./types"

declare module "lit-connect-modal" {
    class LitConnectModal {
        constructor(providerOptions: any);
        getWalletProvider(): any 
    }

    export = LitConnectModal
}


export declare global{
    var wasmExports:any
    var litConfig:LitNodeClientConfig
    interface Window{
        locked:boolean
    }
}