# sBTC Developer Integration Guide

A comprehensive guide for integrating sBTC (synthetic Bitcoin) into your Stacks applications.

## Table of Contents

1. [Introduction to sBTC](#introduction-to-sbtc)
2. [Architecture Overview](#architecture-overview)
3. [Deposit Flow Integration](#deposit-flow-integration)
4. [Withdrawal Flow Integration](#withdrawal-flow-integration)
5. [Balance Management](#balance-management)
6. [Security Best Practices](#security-best-practices)
7. [Testing Strategies](#testing-strategies)

## Introduction to sBTC

sBTC is a 1:1 Bitcoin-backed asset on Stacks that enables Bitcoin to be used in smart contracts. It provides:

- **True Bitcoin backing**: Every sBTC is backed 1:1 by actual BTC
- **Decentralized signing**: Multi-signature threshold scheme for security
- **Fast finality**: Transactions settle on Stacks blocks (~10 seconds)
- **Smart contract compatibility**: Use Bitcoin in DeFi, NFTs, and more

## Architecture Overview

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Bitcoin   │────▶│   Signers   │────▶│   Stacks    │
│   Network   │     │  (Threshold)│     │  Blockchain │
└─────────────┘     └─────────────┘     └─────────────┘
       │                   │                   │
       │                   │                   │
       ▼                   ▼                   ▼
   BTC Locked        Verify & Sign       sBTC Minted
```

### Key Components

1. **sBTC Contract**: The Clarity smart contract managing sBTC supply
2. **Signer Network**: Distributed signers that verify and process operations
3. **Deposit Address**: The multi-sig Bitcoin address holding locked BTC
4. **Emily API**: The coordinator service for sBTC operations

## Deposit Flow Integration

### Understanding the Deposit Process

1. User sends BTC to the sBTC deposit address
2. Signers verify the Bitcoin transaction
3. sBTC is minted to the user's Stacks address

### Implementation

```typescript
import { 
  makeSTXTokenTransfer,
  broadcastTransaction,
  standardPrincipalCV
} from '@stacks/transactions';
import { StacksMainnet } from '@stacks/network';

interface DepositRequest {
  bitcoinAddress: string;
  stacksAddress: string;
  amountSats: number;
}

interface DepositInfo {
  depositAddress: string;
  reclaim_script?: string;
  deposit_script?: string;
}

// Get deposit address for user
async function getDepositInfo(request: DepositRequest): Promise<DepositInfo> {
  const response = await fetch('https://emily.stacks.co/deposit', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      bitcoin_address: request.bitcoinAddress,
      stacks_address: request.stacksAddress,
      amount: request.amountSats
    })
  });

  if (!response.ok) {
    throw new Error(`Failed to get deposit info: ${response.status}`);
  }

  return response.json();
}

// Monitor deposit status
async function checkDepositStatus(
  txid: string
): Promise<'pending' | 'confirmed' | 'minted' | 'failed'> {
  const response = await fetch(`https://emily.stacks.co/deposit/${txid}/status`);
  const data = await response.json();
  return data.status;
}

// Complete example: Initiate deposit
async function initiateDeposit(
  bitcoinAddress: string,
  stacksAddress: string,
  amountBTC: number
) {
  const amountSats = Math.floor(amountBTC * 100_000_000);
  
  // Get deposit info
  const depositInfo = await getDepositInfo({
    bitcoinAddress,
    stacksAddress,
    amountSats
  });

  console.log('Send BTC to:', depositInfo.depositAddress);
  console.log('Amount:', amountBTC, 'BTC');
  
  return depositInfo;
}
```

### Client-Side Bitcoin Transaction

```typescript
import * as bitcoin from 'bitcoinjs-lib';

interface UTXO {
  txid: string;
  vout: number;
  value: number;
  scriptPubKey: string;
}

async function createDepositTransaction(
  utxos: UTXO[],
  depositAddress: string,
  amountSats: number,
  changeAddress: string,
  feeRate: number
): Promise<bitcoin.Transaction> {
  const network = bitcoin.networks.bitcoin;
  const psbt = new bitcoin.Psbt({ network });

  // Add inputs
  let totalInput = 0;
  for (const utxo of utxos) {
    psbt.addInput({
      hash: utxo.txid,
      index: utxo.vout,
      witnessUtxo: {
        script: Buffer.from(utxo.scriptPubKey, 'hex'),
        value: utxo.value
      }
    });
    totalInput += utxo.value;
  }

  // Calculate fee (assuming 1 input, 2 outputs)
  const estimatedSize = 140 + (utxos.length * 68) + 68; // P2WPKH
  const fee = Math.ceil(estimatedSize * feeRate);

  // Add deposit output
  psbt.addOutput({
    address: depositAddress,
    value: amountSats
  });

  // Add change output
  const change = totalInput - amountSats - fee;
  if (change > 546) { // Dust threshold
    psbt.addOutput({
      address: changeAddress,
      value: change
    });
  }

  return psbt;
}
```

## Withdrawal Flow Integration

### Understanding the Withdrawal Process

1. User calls the sBTC withdrawal function
2. sBTC is burned from user's balance
3. Signers create and broadcast Bitcoin transaction
4. User receives BTC at their Bitcoin address

### Implementation

```typescript
import {
  makeContractCall,
  PostConditionMode,
  FungibleConditionCode,
  makeStandardFungiblePostCondition,
  uintCV,
  bufferCV
} from '@stacks/transactions';

const SBTC_CONTRACT = 'SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4.sbtc-token';

interface WithdrawalRequest {
  amountSats: number;
  bitcoinAddress: string;
  senderKey: string;
}

async function initiateWithdrawal(request: WithdrawalRequest) {
  const network = new StacksMainnet();
  
  // Decode Bitcoin address to script
  const bitcoinScript = bitcoin.address.toOutputScript(
    request.bitcoinAddress,
    bitcoin.networks.bitcoin
  );

  // Create the withdrawal transaction
  const txOptions = {
    contractAddress: 'SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4',
    contractName: 'sbtc-token',
    functionName: 'withdraw',
    functionArgs: [
      uintCV(request.amountSats),
      bufferCV(bitcoinScript)
    ],
    senderKey: request.senderKey,
    network,
    postConditionMode: PostConditionMode.Deny,
    postConditions: [
      makeStandardFungiblePostCondition(
        'SP...', // Sender address
        FungibleConditionCode.Equal,
        request.amountSats,
        `${SBTC_CONTRACT}::sbtc`
      )
    ],
    fee: 10000n
  };

  const transaction = await makeContractCall(txOptions);
  const result = await broadcastTransaction(transaction, network);
  
  return result;
}

// Monitor withdrawal status
async function checkWithdrawalStatus(
  stacksTxId: string
): Promise<{
  status: 'pending' | 'processing' | 'completed' | 'failed';
  bitcoinTxId?: string;
}> {
  const response = await fetch(
    `https://emily.stacks.co/withdrawal/${stacksTxId}/status`
  );
  return response.json();
}
```

## Balance Management

### Checking sBTC Balance

```typescript
import { callReadOnlyFunction, cvToValue, standardPrincipalCV } from '@stacks/transactions';

async function getSBTCBalance(address: string): Promise<bigint> {
  const network = new StacksMainnet();
  
  const result = await callReadOnlyFunction({
    contractAddress: 'SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4',
    contractName: 'sbtc-token',
    functionName: 'get-balance',
    functionArgs: [standardPrincipalCV(address)],
    network,
    senderAddress: address
  });

  const balance = cvToValue(result);
  return BigInt(balance.value || 0);
}

// Format balance for display
function formatSBTC(satoshis: bigint): string {
  const btc = Number(satoshis) / 100_000_000;
  return btc.toFixed(8);
}

// Example usage
const balance = await getSBTCBalance('SP2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKNRV9EJ7');
console.log(`sBTC Balance: ${formatSBTC(balance)} sBTC`);
```

### Transfer sBTC

```typescript
async function transferSBTC(
  recipientAddress: string,
  amountSats: number,
  senderKey: string,
  memo?: string
) {
  const network = new StacksMainnet();
  
  const functionArgs = [
    uintCV(amountSats),
    standardPrincipalCV(senderKey), // From
    standardPrincipalCV(recipientAddress), // To
  ];

  if (memo) {
    functionArgs.push(someCV(bufferCV(Buffer.from(memo))));
  } else {
    functionArgs.push(noneCV());
  }

  const txOptions = {
    contractAddress: 'SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4',
    contractName: 'sbtc-token',
    functionName: 'transfer',
    functionArgs,
    senderKey,
    network,
    fee: 5000n
  };

  const transaction = await makeContractCall(txOptions);
  return broadcastTransaction(transaction, network);
}
```

## Security Best Practices

### 1. Verify Contract Addresses

```typescript
const OFFICIAL_SBTC_CONTRACTS = {
  mainnet: {
    token: 'SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4.sbtc-token',
    registry: 'SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4.sbtc-registry'
  },
  testnet: {
    token: 'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM.sbtc-token',
    registry: 'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM.sbtc-registry'
  }
};

function validateContractAddress(address: string, network: 'mainnet' | 'testnet'): boolean {
  const contracts = OFFICIAL_SBTC_CONTRACTS[network];
  return Object.values(contracts).includes(address);
}
```

### 2. Use Post-Conditions

```typescript
import { 
  makeStandardFungiblePostCondition,
  FungibleConditionCode,
  PostConditionMode 
} from '@stacks/transactions';

// Always use strict post-conditions to prevent unexpected token movements
function createSafeTransferPostConditions(
  senderAddress: string,
  amount: number
) {
  return [
    makeStandardFungiblePostCondition(
      senderAddress,
      FungibleConditionCode.Equal, // Exactly this amount
      amount,
      'SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4.sbtc-token::sbtc'
    )
  ];
}
```

### 3. Validate Bitcoin Addresses

```typescript
import * as bitcoin from 'bitcoinjs-lib';

function isValidBitcoinAddress(address: string): boolean {
  try {
    bitcoin.address.toOutputScript(address, bitcoin.networks.bitcoin);
    return true;
  } catch {
    return false;
  }
}

function isValidStacksAddress(address: string): boolean {
  // Check format: SP... or ST... followed by valid characters
  const mainnetRegex = /^SP[0-9A-Z]{33,41}$/;
  const testnetRegex = /^ST[0-9A-Z]{33,41}$/;
  return mainnetRegex.test(address) || testnetRegex.test(address);
}
```

### 4. Handle Errors Gracefully

```typescript
class SBTCError extends Error {
  constructor(
    public code: string,
    message: string,
    public details?: Record<string, any>
  ) {
    super(message);
    this.name = 'SBTCError';
  }
}

async function safeDeposit(params: DepositRequest): Promise<DepositInfo> {
  // Validate inputs
  if (!isValidBitcoinAddress(params.bitcoinAddress)) {
    throw new SBTCError('INVALID_BTC_ADDRESS', 'Invalid Bitcoin address');
  }
  
  if (!isValidStacksAddress(params.stacksAddress)) {
    throw new SBTCError('INVALID_STX_ADDRESS', 'Invalid Stacks address');
  }
  
  if (params.amountSats < 10000) { // Minimum deposit
    throw new SBTCError('AMOUNT_TOO_LOW', 'Minimum deposit is 10,000 sats');
  }

  try {
    return await getDepositInfo(params);
  } catch (error) {
    if (error instanceof Error) {
      throw new SBTCError('DEPOSIT_FAILED', error.message);
    }
    throw error;
  }
}
```

## Testing Strategies

### Unit Testing with Mocks

```typescript
import { describe, it, expect, vi } from 'vitest';

describe('sBTC Integration', () => {
  it('should get deposit info', async () => {
    // Mock the fetch call
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({
        depositAddress: 'bc1q...',
        reclaim_script: '...'
      })
    });

    const result = await getDepositInfo({
      bitcoinAddress: 'bc1qtest...',
      stacksAddress: 'SP2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKNRV9EJ7',
      amountSats: 100000
    });

    expect(result.depositAddress).toBeDefined();
  });

  it('should validate addresses', () => {
    expect(isValidStacksAddress('SP2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKNRV9EJ7')).toBe(true);
    expect(isValidStacksAddress('invalid')).toBe(false);
  });
});
```

### Integration Testing on Testnet

```typescript
const TESTNET_CONFIG = {
  network: new StacksTestnet(),
  sbtcContract: 'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM.sbtc-token',
  emilyApi: 'https://emily.testnet.stacks.co'
};

async function testDepositFlow() {
  // Use testnet faucet to get test STX
  console.log('Testing deposit flow on testnet...');
  
  const depositInfo = await getDepositInfo({
    bitcoinAddress: 'tb1q...', // Testnet address
    stacksAddress: 'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM',
    amountSats: 10000
  });

  console.log('Deposit address:', depositInfo.depositAddress);
  // Continue with Bitcoin testnet transaction...
}
```

## Additional Resources

- [sBTC Documentation](https://sbtc.tech)
- [Stacks.js SDK](https://stacks.js.org/)
- [Bitcoin Development](https://bitcoin.org/en/developer-documentation)
- [Clarity Language Reference](https://docs.stacks.co/clarity)

---

*This guide is maintained by the community. Contributions welcome!*
