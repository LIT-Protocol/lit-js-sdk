import {
  fromString as uint8arrayFromString,
  toString as uint8arrayToString,
} from "uint8arrays";
import { throwError, log } from "../lib/utils";
import { AuthSig, LitSVMChainsKeys } from "../types/types";

export const AUTH_SIGNATURE_BODY =
  "I am creating an account to use Lit Protocol at {{timestamp}}";

function getProvider() {
  if ("solana" in window) {
    return (window as any).solana;
    // const provider = window.solana;
    // if (provider.isPhantom) {
    //   return provider;
    // }
  } else {
    throwError({
      message:
        "No web3 wallet was found that works with Solana.  Install a Solana wallet or choose another chain",
      name: "NoWalletException",
      errorCode: "no_wallet",
    });
  }
}

export async function connectSolProvider() {
  const provider = getProvider();
  await provider.connect();
  const account = provider.publicKey.toBase58();
  return { provider, account };
}

export async function checkAndSignSolAuthMessage({
  chain
}: {chain:LitSVMChainsKeys}) {
  // Connect to cluster
  // const connection = new solWeb3.Connection(
  //   solWeb3.clusterApiUrl("devnet"),
  //   "confirmed"
  // );

  const { provider, account } = await connectSolProvider();

  let authSig = localStorage.getItem("lit-auth-sol-signature");
  if (!authSig) {
    log("signing auth message because sig is not in local storage");
    await signAndSaveAuthMessage({ provider, account });
    authSig = localStorage.getItem("lit-auth-sol-signature");
  }
  let authSigObj = JSON.parse(authSig!) as AuthSig;

  if (account !== authSigObj.address) {
    log(
      "signing auth message because account is not the same as the address in the auth sig"
    );
    await signAndSaveAuthMessage({ provider, account });
    authSig = localStorage.getItem("lit-auth-sol-signature");
    authSigObj = JSON.parse(authSig!) as AuthSig;

  }

  log("authSig", authSigObj);

  return authSigObj;
}

export async function signAndSaveAuthMessage({
  provider,
  account
}: any) {
  const now = new Date().toISOString();
  const body = AUTH_SIGNATURE_BODY.replace("{{timestamp}}", now);

  const data = new TextEncoder().encode(body);
  const signed = await provider.signMessage(data, "utf8");

  const hexSig = uint8arrayToString(signed.signature, "base16");

  const authSig = {
    sig: hexSig,
    derivedVia: "solana.signMessage",
    signedMessage: body,
    address: provider.publicKey.toBase58(),
  };

  localStorage.setItem("lit-auth-sol-signature", JSON.stringify(authSig));
  return authSig;
}
