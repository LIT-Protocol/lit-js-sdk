// add fetch polyfill
import fetch from "node-fetch";
import { Crypto } from "@peculiar/webcrypto";

if (!globalThis.fetch) {
  globalThis.fetch = fetch;
  // globalThis.Headers = Headers;
  // globalThis.Request = Request;
  // globalThis.Response = Response;
}

if (!globalThis.crypto) {
  globalThis.crypto = new Crypto();
}
