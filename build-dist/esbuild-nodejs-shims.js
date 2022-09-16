"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
// add fetch polyfill
const node_fetch_1 = __importDefault(require("node-fetch"));
const crypto_1 = require("crypto");
const cross_blob_1 = __importDefault(require("cross-blob"));
globalThis.fetch = node_fetch_1.default;
globalThis.crypto = crypto_1.webcrypto;
globalThis.Blob = cross_blob_1.default;
