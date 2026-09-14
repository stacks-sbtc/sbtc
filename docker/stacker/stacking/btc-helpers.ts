import * as BTC from '@scure/btc-signer';
import { hex } from '@scure/base';
import { createAddress } from '@stacks/transactions';

export const REGTEST_NETWORK = {
  bech32: 'bcrt',
  pubKeyHash: 0x6f,
  scriptHash: 0xc4,
  wif: 0xef,
} as const;

// -- Script construction --

export function getUnlockBytes(pubKeyHex: string): Uint8Array {
  return BTC.Script.encode([hex.decode(pubKeyHex), 'CHECKSIG']);
}

export function serializeLockupScript({
  stacker,
  unlockBurnHeight,
  unlockBytes,
}: {
  stacker: string;
  unlockBurnHeight: bigint;
  unlockBytes: Uint8Array;
}): Uint8Array {
  const addr = createAddress(stacker);
  return BTC.Script.encode([
    new Uint8Array([5, addr.version, ...hex.decode(addr.hash160)]),
    'DROP',
    Number(unlockBurnHeight),
    'CHECKLOCKTIMEVERIFY',
    'DROP',
    unlockBytes,
  ]);
}

export function toWitnessOutput(script: Uint8Array): Uint8Array {
  return BTC.OutScript.encode(BTC.p2wsh({ type: 'wsh', script }));
}

// -- Unlock height calculation --

export function calculateUnlockBurnHeight(
  currentCycle: number,
  numCycles: number,
  rewardCycleLength: number,
): bigint {
  const startCycle = currentCycle + 1;
  const lastCycle = startCycle + numCycles;
  const lastCycleStartHeight = (lastCycle * rewardCycleLength) + 1;
  return BigInt(lastCycleStartHeight) + (BigInt(rewardCycleLength) / 2n);
}

// -- P2WSH address from lock script --

export function getLockingAddress(lockScript: Uint8Array): string {
  const p2wsh = BTC.p2wsh({
    script: lockScript,
    type: 'sh',
  }, REGTEST_NETWORK);
  return p2wsh.address!;
}

// -- Bitcoin RPC --

const host = process.env.BITCOIN_RPC_HOST ?? 'bitcoind';
const port = process.env.BITCOIN_RPC_PORT ?? '18443';
const user = process.env.BITCOIN_RPC_USER ?? 'btc';
const pass = process.env.BITCOIN_RPC_PASS ?? 'btc';

const auth = 'Basic ' + Buffer.from(`${user}:${pass}`).toString('base64');

export async function bitcoinRPC<T = any>(
  method: string,
  params: unknown[] = [],
  wallet?: string,
): Promise<T> {
  const base = `http://${host}:${port}`;
  const url = wallet ? `${base}/wallet/${wallet}` : base;
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: auth },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
  });
  const json: any = await res.json();
  if (json.error) throw new Error(`bitcoinRPC ${method}: ${JSON.stringify(json.error)}`);
  return json.result as T;
}

export async function createOrLoadWallet(name: string) {
  try {
    await bitcoinRPC('createwallet', [name, false, false, '', false, false, true]);
  } catch (e: any) {
    if (!e.message.includes('already exists')) throw e;
  }
}

export function getNewAddress(wallet: string) {
  return bitcoinRPC<string>('getnewaddress', ['staking'], wallet);
}

export interface Utxo {
  txid: string;
  vout: number;
  address: string;
  amount: number;
  confirmations: number;
  scriptPubKey: string;
}

export function listUnspent(wallet: string, minConf = 1) {
  return bitcoinRPC<Utxo[]>('listunspent', [minConf], wallet);
}

export function getRawTransaction(txid: string): Promise<string> {
  return bitcoinRPC<string>('getrawtransaction', [txid, false]);
}

export function sendRawTransaction(hex: string) {
  return bitcoinRPC<string>('sendrawtransaction', [hex]);
}

export function sendToAddress(wallet: string, address: string, amountBtc: number) {
  return bitcoinRPC<string>('sendtoaddress', [address, amountBtc], wallet);
}

export function getBlockCount() {
  return bitcoinRPC<number>('getblockcount');
}
