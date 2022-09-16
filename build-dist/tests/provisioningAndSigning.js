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
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const index_js_1 = __importDefault(require("../build/index.js"));
const litNodeClient = new index_js_1.default.LitNodeClient();
litNodeClient.connect();
const chain = 'polygon';
const provisionAndSign = (accessControlConditions) => __awaiter(void 0, void 0, void 0, function* () {
    let authSig = JSON.parse("{\"sig\":\"0x18a173d68d2f78cc5c13da0dfe36eec2a293285bee6d42547b9577bf26cdc985660ed3dddc4e75d422366cac07e8a9fc77669b10373bef9c7b8e4280252dfddf1b\",\"derivedVia\":\"web3.eth.personal.sign\",\"signedMessage\":\"I am creating an account to use LITs at 2021-08-04T20:14:04.918Z\",\"address\":\"0xdbd360f30097fb6d938dcc8b7b62854b36160b45\"}");
    let resourceId = {
        baseUrl: 'https://my-dynamic-content-server.com',
        path: randomUrlPath(),
        orgId: ""
    };
    yield litNodeClient.saveSigningCondition({
        accessControlConditions,
        chain,
        authSig,
        resourceId
    });
    let jwt = yield litNodeClient.getSignedToken({
        accessControlConditions,
        chain,
        authSig,
        resourceId
    });
    console.log(jwt);
    if (jwt) {
        return true;
    }
    return false;
});
const accessControlConditions = [
    [
        {
            contractAddress: '0x7C7757a9675f06F3BE4618bB68732c4aB25D2e88',
            standardContractType: 'ERC1155',
            chain,
            method: 'balanceOf',
            parameters: [
                ':userAddress',
                '8'
            ],
            returnValueTest: {
                comparator: '>',
                value: '0'
            }
        }
    ]
];
const runTests = () => __awaiter(void 0, void 0, void 0, function* () {
    for (let i = 0; i < accessControlConditions.length; i++) {
        const res = yield provisionAndSign(accessControlConditions[i]);
        if (res === false) {
            console.log('Error on access control conditions: ', accessControlConditions[i]);
            process.exit(1);
        }
    }
});
runTests();
