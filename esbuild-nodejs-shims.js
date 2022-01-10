// add fetch polyfill
import fetch from "node-fetch";
if (!globalThis.fetch) {
  globalThis.fetch = fetch;
  // globalThis.Headers = Headers;
  // globalThis.Request = Request;
  // globalThis.Response = Response;
}
