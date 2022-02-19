import * as solWeb3 from "@solana/web3.js";
import { AUTH_SIGNATURE_BODY } from "./eth";
import { WalletAdapterNetwork } from "@solana/wallet-adapter-base";
import { PhantomWalletAdapter } from "@solana/wallet-adapter-phantom";
import uint8arrayFromString from "uint8arrays/from-string";
import uint8arrayToString from "uint8arrays/to-string";

function getProvider() {
  if ("solana" in window) {
    const provider = window.solana;
    if (provider.isPhantom) {
      return provider;
    }
  }
}

export async function checkAndSignAuthMessage({ chain }) {
  // Connect to cluster
  const connection = new solWeb3.Connection(
    solWeb3.clusterApiUrl("devnet"),
    "confirmed"
  );

  const provider = getProvider();
  await provider.connect();

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

  console.log("authSig", authSig);
}
