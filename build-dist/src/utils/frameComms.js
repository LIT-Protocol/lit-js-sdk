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
exports.inIframe = exports.listenForFrameParentMessages = exports.listenForChildFrameMessages = void 0;
const lit_1 = require("./lit");
const listenForChildFrameMessages = () => __awaiter(void 0, void 0, void 0, function* () {
    console.log("calling listenForChildFrameMessages from " + window.origin);
    // listen for requests from child frames
    window.addEventListener("message", (event) => __awaiter(void 0, void 0, void 0, function* () {
        // console.log('onMessage in sdk: ', event)
        let childFrameThatSentMessageIndex = false;
        for (let i = 0; i < frames.length; i++) {
            if (frames[i] === event.source) {
                // @ts-expect-error TS(2322): Type 'number' is not assignable to type 'boolean'.
                childFrameThatSentMessageIndex = i;
            }
        }
        if (childFrameThatSentMessageIndex !== false) {
            console.log("onMessage in parent: ", event);
            const { command, params } = event.data;
            if (command === "LIT_SYN") {
                // @ts-expect-error TS(2538): Type 'true' cannot be used as an index type.
                window.frames[childFrameThatSentMessageIndex].postMessage({ response: "LIT_ACK" }, "*");
                return;
            }
            //       if (command === 'signAndGetEncryptionKey') {
            //         authSig = await checkAndSignAuthMessage({ chain: params.chain })
            //         if (authSig.errorCode && authSig.errorCode === 'wrong_chain') {
            //           alert('You are connected to the wrong blockchain.  Please switch your metamask to ' + params.chain)
            //         }
            //
            //         // get the merkle proof
            //         const { balanceStorageSlot } = LIT_CHAINS[params.chain]
            //         try {
            //           merkleProof = await getMerkleProof({ tokenAddress: params.tokenAddress, balanceStorageSlot, tokenId: params.tokenId })
            //         } catch (e) {
            //           console.log(e)
            //           alert('Error - could not obtain merkle proof.  Some nodes do not support this operation yet.  Please try another ETH node.')
            //           return
            //         }
            //         const encryptionKey = await window.litNodeClient.getEncryptionKey({
            //           ...params, authSig, merkleProof
            //         })
            //         window.frames[childFrameThatSentMessageIndex].postMessage({ respondingToCommand: command, encryptionKey }, '*')
            //         return
            //       }
            if (event.data.target === "LitNodeClient") {
                // forward this on to the nodes
                if (command === "getEncryptionKey") {
                    const encryptionKey = yield window.litNodeClient.getEncryptionKey(Object.assign({}, params));
                    // @ts-expect-error TS(2538): Type 'true' cannot be used as an index type.
                    window.frames[childFrameThatSentMessageIndex].postMessage({ respondingToCommand: command, encryptionKey }, "*");
                }
            }
        }
    }), false);
});
exports.listenForChildFrameMessages = listenForChildFrameMessages;
const listenForFrameParentMessages = () => __awaiter(void 0, void 0, void 0, function* () {
    console.log("calling listenForFrameParentMessages from " + window.origin);
    // listen for requests from child frames
    window.addEventListener("message", (event) => __awaiter(void 0, void 0, void 0, function* () {
        const messageIsFromFrameParent = event.source === window.parent;
        if (messageIsFromFrameParent) {
            console.log("onMessage in frame: ", event);
        }
        // console.log('messageIsFromFrameParent: ', messageIsFromFrameParent)
        if (messageIsFromFrameParent) {
            const { response, respondingToCommand } = event.data;
            if (response === "LIT_ACK") {
                window.useLitPostMessageProxy = true;
                if (typeof document !== "undefined") {
                    document.dispatchEvent(new Event("lit-ready"));
                }
                return;
            }
            if (respondingToCommand === "getEncryptionKey") {
                const { encryptionKey } = event.data;
                (0, lit_1.unlockLitWithKey)({ symmetricKey: encryptionKey });
            }
        }
    }), false);
});
exports.listenForFrameParentMessages = listenForFrameParentMessages;
const inIframe = () => {
    try {
        return window.self !== window.top;
    }
    catch (e) {
        return true;
    }
};
exports.inIframe = inIframe;
