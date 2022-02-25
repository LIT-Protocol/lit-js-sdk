// add fetch polyfill
import fetch from "node-fetch";
import { webcrypto } from "crypto";
import Blob from "cross-blob";

if (!globalThis.fetch) {
  globalThis.fetch = fetch;
  // globalThis.Headers = Headers;
  // globalThis.Request = Request;
  // globalThis.Response = Response;
}

if (!globalThis.crypto) {
  globalThis.crypto = webcrypto;
}

if (!globalThis.Blob) {
  globalThis.Blob = Blob;
}
