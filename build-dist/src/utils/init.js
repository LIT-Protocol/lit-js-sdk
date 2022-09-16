"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.litJsSdkLoadedInALIT = void 0;
const lit_1 = require("./lit");
const litNodeClient_1 = __importDefault(require("./litNodeClient"));
const litJsSdkLoadedInALIT = () => {
    try {
        window.localStorage.getItem("test");
    }
    catch (e) {
        console.log("Could not use localstorage in a Lit. This usually means we are stuck in the opensea sandbox.");
        window.sandboxed = true;
        setTimeout(function () {
            if (typeof document !== "undefined") {
                document.dispatchEvent(new Event("lit-ready"));
            }
        }, 1000);
        return;
    }
    // @ts-expect-error TS(2554): Expected 1 arguments, but got 2.
    (0, lit_1.sendMessageToFrameParent)({ command: "LIT_SYN" }, "*");
    setTimeout(function () {
        if (!window.useLitPostMessageProxy) {
            // console.log(
            //   "inside lit - no parent frame lit node connection.  connecting ourselves."
            // );
            // we're on our own with no parent frame.  initiate our own connection to lit nodes
            // @ts-expect-error TS(2554): Expected 1 arguments, but got 0.
            const litNodeClient = new litNodeClient_1.default();
            litNodeClient.connect();
            window.litNodeClient = litNodeClient;
        }
        else {
            // console.log(
            //   "inside lit - parent frame is connected to lit nodes.  using that."
            // );
        }
    }, 1000);
};
exports.litJsSdkLoadedInALIT = litJsSdkLoadedInALIT;
