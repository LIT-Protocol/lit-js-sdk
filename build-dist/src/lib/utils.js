"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.checkIfAuthSigRequiresChainParam = exports.checkType = exports.getVarType = exports.log = exports.throwError = exports.mostCommonString = exports.printError = void 0;
const constants_js_1 = require("./constants.js");
const printError = (e) => {
    console.log("Error Stack", e.stack);
    console.log("Error Name", e.name);
    console.log("Error Message", e.message);
};
exports.printError = printError;
const mostCommonString = (arr) => {
    return arr
        .sort((a, b) => arr.filter((v) => v === a).length - arr.filter((v) => v === b).length)
        .pop();
};
exports.mostCommonString = mostCommonString;
const throwError = ({ message, name, errorCode }) => {
    throw new (function () {
        this.message = message;
        this.name = name;
        this.errorCode = errorCode;
    })();
};
exports.throwError = throwError;
const log = (...args) => {
    if (globalThis &&
        globalThis.litConfig &&
        globalThis.litConfig.debug === false) {
        return;
    }
    args.unshift("[Lit-JS-SDK]");
    console.log(...args);
};
exports.log = log;
/**
 *
 * Get the type of a variable, could be an object instance type.
 * eg Uint8Array instance should return 'Uint8Array` as string
 * or simply a `string` or `int` type
 *
 * @param { * } value
 * @returns { String } type
 */
const getVarType = (value) => {
    return Object.prototype.toString.call(value).slice(8, -1);
    // // if it's an object
    // if (value instanceof Object) {
    //   if (value.constructor.name == "Object") {
    //     return "Object";
    //   }
    //   return value.constructor.name;
    // }
    // // if it's other type, like string and int
    // return typeof value;
};
exports.getVarType = getVarType;
/**
 *
 *  Check if the given value is the given type
 *  If not, throw `invalidParamType` error
 *
 * @param { * } value
 * @param { Array<String> } allowedTypes
 * @param { string } paramName
 * @param { string } functionName
 * @param { boolean } throwOnError
 * @returns { Boolean } true/false
 */
const checkType = ({ value, allowedTypes, paramName, functionName, throwOnError = true, }) => {
    if (!allowedTypes.includes((0, exports.getVarType)(value))) {
        let message = `Expecting ${allowedTypes.join(" or ")} type for parameter named ${paramName} in Lit-JS-SDK function ${functionName}(), but received "${(0, exports.getVarType)(value)}" type instead. value: ${value instanceof Object ? JSON.stringify(value) : value}`;
        if (throwOnError) {
            (0, exports.throwError)({
                message,
                name: "invalidParamType",
                errorCode: "invalid_param_type",
            });
        }
        return false;
    }
    return true;
};
exports.checkType = checkType;
const checkIfAuthSigRequiresChainParam = (authSig, chain, functionName) => {
    for (const key of constants_js_1.LIT_AUTH_SIG_CHAIN_KEYS) {
        if (key in authSig) {
            return true;
        }
    }
    // if we're here, then we need the chain param
    if (!(0, exports.checkType)({
        value: chain,
        allowedTypes: ["String"],
        paramName: "chain",
        functionName,
    }))
        return false;
    return true;
};
exports.checkIfAuthSigRequiresChainParam = checkIfAuthSigRequiresChainParam;
