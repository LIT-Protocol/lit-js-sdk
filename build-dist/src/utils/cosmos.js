"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.serializeSignDoc = exports.signAndSaveAuthMessage = exports.checkAndSignCosmosAuthMessage = exports.connectCosmosProvider = exports.AUTH_SIGNATURE_BODY = void 0;
const uint8arrays_1 = require("uint8arrays");
const utils_1 = require("../lib/utils");
const constants_1 = require("../lib/constants");
exports.AUTH_SIGNATURE_BODY = "I am creating an account to use Lit Protocol at {{timestamp}}";
function getProvider() {
    if ("keplr" in window) {
        // @ts-expect-error TS(2304): Cannot find name 'keplr'.
        return keplr;
    }
    else {
        (0, utils_1.throwError)({
            message: "No web3 wallet was found that works with Cosmos.  Install a Cosmos wallet or choose another chain",
            name: "NoWalletException",
            errorCode: "no_wallet",
        });
    }
}
function connectCosmosProvider({ chain }) {
    return __awaiter(this, void 0, void 0, function* () {
        // @ts-expect-error TS(7053): Element implicitly has an 'any' type because expre... Remove this comment to see the full error message
        const chainId = constants_1.LIT_COSMOS_CHAINS[chain].chainId;
        const keplr = getProvider();
        // Enabling before using the Keplr is recommended.
        // This method will ask the user whether to allow access if they haven't visited this website.
        // Also, it will request that the user unlock the wallet if the wallet is locked.
        yield keplr.enable(chainId);
        const offlineSigner = keplr.getOfflineSigner(chainId);
        // You can get the address/public keys by `getAccounts` method.
        // It can return the array of address/public key.
        // But, currently, Keplr extension manages only one address/public key pair.
        // XXX: This line is needed to set the sender address for SigningCosmosClient.
        const accounts = yield offlineSigner.getAccounts();
        // // Initialize the gaia api with the offline signer that is injected by Keplr extension.
        // const cosmJS = new SigningCosmosClient(
        //   "https://lcd-cosmoshub.keplr.app",
        //   accounts[0].address,
        //   offlineSigner
        // );
        // console.log("accounts[0]", accounts[0]);
        return { provider: keplr, account: accounts[0].address, chainId };
    });
}
exports.connectCosmosProvider = connectCosmosProvider;
function checkAndSignCosmosAuthMessage({ chain }) {
    return __awaiter(this, void 0, void 0, function* () {
        const { provider, account, chainId } = yield connectCosmosProvider({ chain });
        let authSig = localStorage.getItem("lit-auth-cosmos-signature");
        if (!authSig) {
            (0, utils_1.log)("signing auth message because sig is not in local storage");
            yield signAndSaveAuthMessage({ provider, account, chainId });
            authSig = localStorage.getItem("lit-auth-cosmos-signature");
        }
        // @ts-expect-error TS(2345): Argument of type 'string | null' is not assignable... Remove this comment to see the full error message
        authSig = JSON.parse(authSig);
        if (account !== authSig.address) {
            (0, utils_1.log)("signing auth message because account is not the same as the address in the auth sig");
            yield signAndSaveAuthMessage({ provider, account, chainId });
            authSig = localStorage.getItem("lit-auth-cosmos-signature");
            // @ts-expect-error TS(2345): Argument of type 'string | null' is not assignable... Remove this comment to see the full error message
            authSig = JSON.parse(authSig);
        }
        (0, utils_1.log)("authSig", authSig);
        return authSig;
    });
}
exports.checkAndSignCosmosAuthMessage = checkAndSignCosmosAuthMessage;
function signAndSaveAuthMessage({ provider, account, chainId }) {
    return __awaiter(this, void 0, void 0, function* () {
        const now = new Date().toISOString();
        const body = exports.AUTH_SIGNATURE_BODY.replace("{{timestamp}}", now);
        // const signed = provider.signArbitrary(chainId, account, body);
        // const data = new TextEncoder().encode(body);
        // console.log("data being signed", data);
        const signed = yield provider.signArbitrary(chainId, account, body);
        // const hexSig = uint8arrayToString(signed.signature, "base16");
        const data = (0, uint8arrays_1.toString)((0, uint8arrays_1.fromString)(body, "utf8"), "base64"); //Buffer.from(body).toString("base64");
        // console.log("signed", signed);
        // console.log("pubkey: ", signed.pub_key.value);
        // ok now we have to create the actual message
        const signDoc = {
            chain_id: "",
            account_number: "0",
            sequence: "0",
            fee: {
                gas: "0",
                amount: [],
            },
            msgs: [
                {
                    type: "sign/MsgSignData",
                    value: {
                        signer: account,
                        data,
                    },
                },
            ],
            memo: "",
        };
        const encodedSignedMsg = serializeSignDoc(signDoc);
        const digest = yield crypto.subtle.digest("SHA-256", encodedSignedMsg);
        // console.log("digest length", digest.byteLength);
        const digest_hex = (0, uint8arrays_1.toString)(new Uint8Array(digest), "base16");
        // console.log("digest_hex length", digest_hex.length);
        const authSig = {
            sig: signed.signature,
            derivedVia: "cosmos.signArbitrary",
            signedMessage: digest_hex,
            address: account,
        };
        localStorage.setItem("lit-auth-cosmos-signature", JSON.stringify(authSig));
    });
}
exports.signAndSaveAuthMessage = signAndSaveAuthMessage;
// @ts-expect-error TS(7023): 'sortedObject' implicitly has return type 'any' be... Remove this comment to see the full error message
function sortedObject(obj) {
    if (typeof obj !== "object" || obj === null) {
        return obj;
    }
    if (Array.isArray(obj)) {
        return obj.map(sortedObject);
    }
    const sortedKeys = Object.keys(obj).sort();
    const result = {};
    // NOTE: Use forEach instead of reduce for performance with large objects eg Wasm code
    sortedKeys.forEach((key) => {
        // @ts-expect-error TS(7053): Element implicitly has an 'any' type because expre... Remove this comment to see the full error message
        result[key] = sortedObject(obj[key]);
    });
    return result;
}
function serializeSignDoc(signDoc) {
    const sorted = JSON.stringify(sortedObject(signDoc));
    return (0, uint8arrays_1.fromString)(sorted, "utf8");
}
exports.serializeSignDoc = serializeSignDoc;
