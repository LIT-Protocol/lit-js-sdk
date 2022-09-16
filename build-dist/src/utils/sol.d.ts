export declare const AUTH_SIGNATURE_BODY = "I am creating an account to use Lit Protocol at {{timestamp}}";
export declare function connectSolProvider(): Promise<{
    provider: any;
    account: any;
}>;
export declare function checkAndSignSolAuthMessage({ chain }: any): Promise<string | null>;
export declare function signAndSaveAuthMessage({ provider, account }: any): Promise<{
    sig: string;
    derivedVia: string;
    signedMessage: string;
    address: any;
}>;
