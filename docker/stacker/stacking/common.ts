import { StackingClient } from '@stacks/stacking';
import { STACKS_TESTNET, StacksNetwork } from '@stacks/network';
import { getAddressFromPrivateKey } from '@stacks/transactions';
import { getPublicKeyFromPrivate, publicKeyToBtcAddress } from '@stacks/encryption';
import type { NakamotoBlock, Transaction } from '@stacks/stacks-blockchain-api-types';
import pino, { Logger } from 'pino';

const serviceName = process.env.SERVICE_NAME || 'JS';
export let logger: Logger;
if (process.env.STACKS_LOG_JSON === '1') {
  logger = pino({
    level: process.env.LOG_LEVEL || 'info',
    name: serviceName,
  });
} else {
  logger = pino({
    name: serviceName,
    level: process.env.LOG_LEVEL || 'info',
    transport: {
      target: 'pino-pretty',
    },
    // @ts-ignore
    options: {
      colorize: true,
    },
  });
}

export const nodeUrl = `http://${process.env.STACKS_CORE_RPC_HOST}:${process.env.STACKS_CORE_RPC_PORT}`;
export const network: StacksNetwork = { ...STACKS_TESTNET, client: { baseUrl: nodeUrl } };

async function fetchJson<T>(path: string): Promise<T> {
  const url = `${nodeUrl}${path}`;
  const res = await fetch(url);
  if (!res.ok) {
    throw new Error(`GET ${url} failed: ${res.status} ${res.statusText}`);
  }
  return (await res.json()) as T;
}

export async function fetchLatestBlock(): Promise<NakamotoBlock> {
  return fetchJson<NakamotoBlock>('/extended/v2/blocks/latest');
}

export async function fetchLatestBlockTransactions(): Promise<Transaction[]> {
  const data = await fetchJson<{ results: Transaction[] }>(
    '/extended/v2/blocks/latest/transactions'
  );
  return data.results;
}

export const EPOCH_30_START = parseEnvInt('STACKS_30_HEIGHT', true);
export const EPOCH_25_START = parseEnvInt('STACKS_25_HEIGHT', true);
export const POX_PREPARE_LENGTH = parseEnvInt('POX_PREPARE_LENGTH', true);
export const POX_REWARD_LENGTH = parseEnvInt('POX_REWARD_LENGTH', true);

export const accounts = process.env.STACKING_KEYS!.split(',').map((privKey, index) => {
  const pubKey = getPublicKeyFromPrivate(privKey);
  const stxAddress = getAddressFromPrivateKey(privKey, STACKS_TESTNET);
  return {
    privKey,
    pubKey,
    stxAddress,
    btcAddr: publicKeyToBtcAddress(pubKey),
    signerPrivKey: privKey,
    signerPubKey: pubKey,
    targetSlots: index + 1,
    index,
    client: new StackingClient({ address: stxAddress, network }),
    logger: logger.child({
      account: stxAddress,
      index: index,
    }),
  };
});

export type Account = typeof accounts[0];

export const MAX_U128 = 2n ** 128n - 1n;
export const maxAmount = MAX_U128;

export async function waitForSetup() {
  try {
    await accounts[0].client.getPoxInfo();
  } catch (error) {
    const cause = (error as { cause?: { message?: string } })?.cause?.message;
    if (cause && /(ECONNREFUSED|ENOTFOUND|SyntaxError)/.test(cause)) {
      console.log(`Stacks node not ready, waiting...`);
    }
    await new Promise(resolve => setTimeout(resolve, 3000));
    return waitForSetup();
  }
}

export function parseEnvInt<T extends boolean = false>(
  envKey: string,
  required?: T
): T extends true ? number : number | undefined {
  let value = process.env[envKey];
  if (typeof value === 'undefined') {
    if (required) {
      throw new Error(`Missing required env var: ${envKey}`);
    }
    return undefined as T extends true ? number : number | undefined;
  }
  return parseInt(value, 10);
}

export function burnBlockToRewardCycle(burnBlock: number) {
  const cycleLength = BigInt(POX_REWARD_LENGTH);
  return Number(BigInt(burnBlock) / cycleLength) + 1;
}

export const EPOCH_30_START_CYCLE = burnBlockToRewardCycle(EPOCH_30_START);

export function isPreparePhase(burnBlock: number) {
  return POX_REWARD_LENGTH - (burnBlock % POX_REWARD_LENGTH) < POX_PREPARE_LENGTH;
}

export function didCrossPreparePhase(lastBurnHeight: number, newBurnHeight: number) {
  return isPreparePhase(newBurnHeight) && !isPreparePhase(lastBurnHeight);
}
