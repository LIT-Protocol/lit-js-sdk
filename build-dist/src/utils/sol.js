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
exports.signAndSaveAuthMessage = exports.checkAndSignSolAuthMessage = exports.connectSolProvider = exports.AUTH_SIGNATURE_BODY = void 0;
const uint8arrays_1 = require("uint8arrays");
const utils_1 = require("../lib/utils");
exports.AUTH_SIGNATURE_BODY = "I am creating an account to use Lit Protocol at {{timestamp}}";
function getProvider() {
    if ("solana" in window) {
        return window.solana;
        // const provider = window.solana;
        // if (provider.isPhantom) {
        //   return provider;
        // }
    }
    else {
        (0, utils_1.throwError)({
            message: "No web3 wallet was found that works with Solana.  Install a Solana wallet or choose another chain",
            name: "NoWalletException",
            errorCode: "no_wallet",
        });
    }
}
function connectSolProvider() {
    return __awaiter(this, void 0, void 0, function* () {
        const provider = getProvider();
        yield provider.connect();
        const account = provider.publicKey.toBase58();
        return { provider, account };
    });
}
exports.connectSolProvider = connectSolProvider;
function checkAndSignSolAuthMessage({ chain }) {
    return __awaiter(this, void 0, void 0, function* () {
        // Connect to cluster
        // const connection = new solWeb3.Connection(
        //   solWeb3.clusterApiUrl("devnet"),
        //   "confirmed"
        // );
        const { provider, account } = yield connectSolProvider();
        let authSig = localStorage.getItem("lit-auth-sol-signature");
        if (!authSig) {
            (0, utils_1.log)("signing auth message because sig is not in local storage");
            yield signAndSaveAuthMessage({ provider, account });
            authSig = localStorage.getItem("lit-auth-sol-signature");
        }
        // @ts-expect-error TS(2345): Argument of type 'string | null' is not assignable... Remove this comment to see the full error message
        authSig = JSON.parse(authSig);
        if (account !== authSig.address) {
            (0, utils_1.log)("signing auth message because account is not the same as the address in the auth sig");
            yield signAndSaveAuthMessage({ provider, account });
            authSig = localStorage.getItem("lit-auth-sol-signature");
            // @ts-expect-error TS(2345): Argument of type 'string | null' is not assignable... Remove this comment to see the full error message
            authSig = JSON.parse(authSig);
        }
        (0, utils_1.log)("authSig", authSig);
        return authSig;
    });
}
exports.checkAndSignSolAuthMessage = checkAndSignSolAuthMessage;
function signAndSaveAuthMessage({ provider, account }) {
    return __awaiter(this, void 0, void 0, function* () {
        const now = new Date().toISOString();
        const body = exports.AUTH_SIGNATURE_BODY.replace("{{timestamp}}", now);
        const data = new TextEncoder().encode(body);
        const signed = yield provider.signMessage(data, "utf8");
        const hexSig = (0, uint8arrays_1.toString)(signed.signature, "base16");
        const authSig = {
            sig: hexSig,
            derivedVia: "solana.signMessage",
            signedMessage: body,
            address: provider.publicKey.toBase58(),
        };
        localStorage.setItem("lit-auth-sol-signature", JSON.stringify(authSig));
        return authSig;
    });
}
exports.signAndSaveAuthMessage = signAndSaveAuthMessage;
