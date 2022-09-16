export function printError(e: any): void;
export function mostCommonString(arr: any): any;
export function throwError({ message, name, errorCode }: {
    message: any;
    name: any;
    errorCode: any;
}): never;
export function log(...args: any[]): void;
export function getVarType(value: any): string;
export function checkType({ value, allowedTypes, paramName, functionName, throwOnError, }: any): boolean;
export function checkIfAuthSigRequiresChainParam(authSig: any, chain: any, functionName: any): boolean;
