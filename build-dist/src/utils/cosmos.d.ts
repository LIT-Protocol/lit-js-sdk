export declare const AUTH_SIGNATURE_BODY = "I am creating an account to use Lit Protocol at {{timestamp}}";
export declare function connectCosmosProvider({ chain }: any): Promise<{
    provider: any;
    account: any;
    chainId: any;
}>;
export declare function checkAndSignCosmosAuthMessage({ chain }: any): Promise<string | null>;
export declare function signAndSaveAuthMessage({ provider, account, chainId }: any): Promise<void>;
export declare function serializeSignDoc(signDoc: any): Uint8Array;
