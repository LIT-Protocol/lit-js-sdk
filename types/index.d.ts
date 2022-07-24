declare module 'lit-js-sdk' {
  export interface ILitSdk {
    LitNodeClient: any;
    checkAndSignAuthMessage: (config: ICheckAndSignAuthMessageConfig) => Promise<IAuthSignature>;
  }

  const LitSdk: ILitSdk;
  export default LitSdk;

  export type TChain = 'ethereum' |
    'polygon' |
    'fantom' |
    'xdai' |
    'bsc' |
    'arbitrum' |
    'avalanche' |
    'fuji' |
    'harmony' |
    'kovan' |
    'mumbai' |
    'goerli' |
    'ropsten' |
    'rinkeby' |
    'cronos' |
    'optimism' |
    'celo' |
    'aurora' |
    'eluvio' |
    'alfajores' |
    'xdc' |
    'evmos' |
    'evmosTestnet' |
    'solana' |
    'solanaDevnet' |
    'solanaTestnet' |
    'cosmos' |
    'kyve';
  
  export interface ICheckAndSignAuthMessageConfig {
    chain: TChain;
  }

  export interface ILitClient {

  }

  export interface IAuthSignature {

  }
}