import {
  fromString as uint8arrayFromString,
  toString as uint8arrayToString,
} from "uint8arrays";
import { throwError, log } from "../lib/utils";
import { LIT_COSMOS_CHAINS } from "../lib/constants";

export const AUTH_SIGNATURE_BODY =
  "I am creating an account to use Lit Protocol at {{timestamp}}";

function getProvider() {
  if ("keplr" in window) {
    return keplr;
  } else {
    throwError({
      message:
        "No web3 wallet was found that works with Cosmos.  Install a Cosmos wallet or choose another chain",
      name: "NoWalletException",
      errorCode: "no_wallet",
    });
  }
}

export async function connectCosmosProvider({ chain }) {
  const chainId = LIT_COSMOS_CHAINS[chain].chainId;

  const keplr = getProvider();

  // Enabling before using the Keplr is recommended.
  // This method will ask the user whether to allow access if they haven't visited this website.
  // Also, it will request that the user unlock the wallet if the wallet is locked.
  await keplr.enable(chainId);

  const offlineSigner = keplr.getOfflineSigner(chainId);

  // You can get the address/public keys by `getAccounts` method.
  // It can return the array of address/public key.
  // But, currently, Keplr extension manages only one address/public key pair.
  // XXX: This line is needed to set the sender address for SigningCosmosClient.
  const accounts = await offlineSigner.getAccounts();

  // // Initialize the gaia api with the offline signer that is injected by Keplr extension.
  // const cosmJS = new SigningCosmosClient(
  //   "https://lcd-cosmoshub.keplr.app",
  //   accounts[0].address,
  //   offlineSigner
  // );

  // console.log("accounts[0]", accounts[0]);

  return { provider: keplr, account: accounts[0].address, chainId };
}

export async function checkAndSignCosmosAuthMessage({ chain }) {
  const { provider, account, chainId } = await connectCosmosProvider({ chain });

  let authSig = localStorage.getItem("lit-auth-cosmos-signature");
  if (!authSig) {
    log("signing auth message because sig is not in local storage");
    await signAndSaveAuthMessage({ provider, account, chainId });
    authSig = localStorage.getItem("lit-auth-cosmos-signature");
  }
  authSig = JSON.parse(authSig);

  if (account !== authSig.address) {
    log(
      "signing auth message because account is not the same as the address in the auth sig"
    );
    await signAndSaveAuthMessage({ provider, account, chainId });
    authSig = localStorage.getItem("lit-auth-cosmos-signature");
    authSig = JSON.parse(authSig);
  }

  log("authSig", authSig);

  return authSig;
}

export async function signAndSaveAuthMessage({ provider, account, chainId }) {
  const now = new Date().toISOString();
  const body = AUTH_SIGNATURE_BODY.replace("{{timestamp}}", now);

  // const signed = provider.signArbitrary(chainId, account, body);

  // const data = new TextEncoder().encode(body);
  // console.log("data being signed", data);
  const signed = await provider.signArbitrary(chainId, account, body);
  // const hexSig = uint8arrayToString(signed.signature, "base16");

  const data = uint8arrayToString(uint8arrayFromString(body, "utf8"), "base64"); //Buffer.from(body).toString("base64");

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
  const digest = await crypto.subtle.digest("SHA-256", encodedSignedMsg);
  // console.log("digest length", digest.byteLength);
  const digest_hex = uint8arrayToString(new Uint8Array(digest), "base16");
  // console.log("digest_hex length", digest_hex.length);

  const authSig = {
    sig: signed.signature,
    derivedVia: "cosmos.signArbitrary",
    signedMessage: digest_hex,
    address: account,
  };

  localStorage.setItem("lit-auth-cosmos-signature", JSON.stringify(authSig));
}

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
    result[key] = sortedObject(obj[key]);
  });
  return result;
}

export function serializeSignDoc(signDoc) {
  const sorted = JSON.stringify(sortedObject(signDoc));
  return uint8arrayFromString(sorted, "utf8");
}
