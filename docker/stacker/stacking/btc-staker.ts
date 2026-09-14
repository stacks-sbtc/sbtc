import {
  makeContractCall,
  broadcastTransaction,
  AnchorMode,
  makeContractDeploy,
  PostConditionMode,
} from '@stacks/transactions';
import { readFileSync } from 'fs';
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';
import { hex } from '@scure/base';
import { PoxInfo } from '@stacks/stacking';
import {
  accounts,
  parseEnvInt,
  waitForSetup,
  logger,
  burnBlockToRewardCycle,
  network,
  POX_REWARD_LENGTH,
  type Account,
  EPOCH_40_START,
  WALLET_NAME,
  waitForTxConfirmed,
  EPOCH_30_START,
  fetchAccount,
  apiClient,
} from './common';
import {
  getUnlockBytes,
  serializeLockupScript,
  calculateUnlockBurnHeight,
  getLockingAddress,
  createOrLoadWallet,
  listUnspent,
  sendToAddress,
} from './btc-helpers';
import { signSignerKeyGrant, pox5, pox5Signer, clarigenClient } from './pox-5-helpers';
// PoX-5 activator for local devenv (ported from stx-labs infrastructure testnet
// btc-staker). Network-specific values are env-driven: SBTC_DEPLOYER_ADDRESS,
// STACKING_KEYS, etc. signer-manager.clar is vendored under contracts/ from
// stacks-core 4.0.2 (matching the stacks-node image).
// ─────────────────────────────────────────────────────────────────────────────

const __dirname = dirname(fileURLToPath(import.meta.url));

function loadSignerManagerSource(deployerAddress: string): string {
  const path = join(__dirname, 'contracts', 'signer-manager.clar');
  return readFileSync(path, 'utf8').replaceAll(
    'SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4',
    deployerAddress
  );
}

// Comma-separated list of addresses to fund via the API faucets, set via the
// BTC_FAUCET_FUND_ADDRESSES / STX_FAUCET_FUND_ADDRESSES env vars. Empty/unset = fund none.
const parseAddressList = (envKey: string) =>
  process.env[envKey]?.split(',').map(a => a.trim()).filter(Boolean) ?? [];

const BTC_FAUCET_FUND_ADDRESSES = parseAddressList('BTC_FAUCET_FUND_ADDRESSES');
const STX_FAUCET_FUND_ADDRESSES = parseAddressList('STX_FAUCET_FUND_ADDRESSES');

const SBTC_DEPLOYER_ADDRESS = (() => {
  const address = process.env.SBTC_DEPLOYER_ADDRESS;
  if (!address) {
    throw new Error('SBTC_DEPLOYER_ADDRESS is required');
  }
  return address;
})();

const stakingInterval = parseEnvInt('STACKING_INTERVAL', true);
const stakingCyclesPox5 = parseEnvInt('STACKING_CYCLES_POX_5', true);
const lockAmountSats = BigInt(parseEnvInt('BTC_LOCK_AMOUNT_SATS', false) ?? 10_000_000);

// Target locked amount (uSTX) for each signer. When a signer is already staked
// but locked BELOW this target, do a one-time stake-update `amount-increase` to
// reach it (raising signer weight). Idempotent: once locked >= target the branch
// is skipped, and the periodic stake-extend preserves the amount. 0/unset =
// disabled (keep the initial stake amount).
const stakingTargetUstx = BigInt(process.env.STACKING_TARGET_USTX ?? '0');

let txFee = parseEnvInt('STACKING_FEE', false) ?? 1_000_000;
const getNextTxFee = () => txFee++;

let btcWalletReady = false;
let loggedPreEpoch40 = false;

async function ensureBtcWalletReady(): Promise<boolean> {
  if (btcWalletReady) {
    return true;
  }
  await createOrLoadWallet(WALLET_NAME);
  const utxos = await listUnspent(WALLET_NAME, 1);
  const total = utxos.reduce((sum, u) => sum + u.amount, 0);
  if (total > 0) {
    btcWalletReady = true;
    logger.info({ wallet: WALLET_NAME, balance: total }, 'Bitcoin staking wallet funded');
    return true;
  }
  return false;
}

// -- L2: Stacks contract calls --

async function submitStake(account: Account, poxInfo: PoxInfo) {
  const stakeFnCall = pox5.stake({
    startBurnHt: poxInfo.current_burnchain_block_height!,
    amountUstx: 100_000_000000n,
    numCycles: stakingCyclesPox5,
    signerManager: account.signerManager,
    signerCalldata: null,
  });

  const tx = await makeContractCall({
    ...stakeFnCall,
    senderKey: account.privKey,
    network,
    fee: getNextTxFee(),
    nonce: (await fetchAccount(account.stxAddress)).nonce,
    postConditionMode: PostConditionMode.Allow,
  });
  const result = await broadcastTransaction({
    transaction: tx,
    network,
  });
  if ('reason' in result) {
    account.logger.error(
      {
        ...result,
      },
      `Error staking: ${result.reason}`
    );
    throw new Error(`Error staking: ${result.reason}`);
  }
  account.logger.info(
    { ...result, signerManager: account.signerManager },
    'pox-5 stake tx broadcast (via signer-manager)'
  );
  return result;
}

async function submitStakeExtend(account: Account) {
  const txOptions = {
    ...pox5.stakeUpdate({
      amountIncrease: 0n,
      cyclesToExtend: stakingCyclesPox5,
      signerManager: account.signerManager,
      oldSignerManager: account.signerManager,
      signerCalldata: null,
    }),
    senderKey: account.privKey,
    network,
    fee: getNextTxFee(),
    anchorMode: AnchorMode.Any,
    postConditionMode: PostConditionMode.Allow,
  };

  const tx = await makeContractCall(txOptions);
  const result = await broadcastTransaction({
    transaction: tx,
    network,
  });
  if ('reason' in result) {
    account.logger.error({ ...result }, `Error extending stake: ${result.reason}`);
    throw new Error(`Error extending stake: ${result.reason}`);
  }
  account.logger.info({ txid: result.txid }, 'L2 stake-extend tx broadcast');
  return result;
}

// stake-update with a non-zero amount-increase to raise the signer's locked
// amount (and thus its reward-set weight). Same call shape as submitStakeExtend;
// cyclesToExtend keeps the lock rolling forward. The increased weight takes
// effect from the next not-yet-anchored reward cycle.
async function submitStakeIncrease(account: Account, increaseBy: bigint) {
  const txOptions = {
    ...pox5.stakeUpdate({
      amountIncrease: increaseBy,
      cyclesToExtend: stakingCyclesPox5,
      signerManager: account.signerManager,
      oldSignerManager: account.signerManager,
      signerCalldata: null,
    }),
    senderKey: account.privKey,
    network,
    fee: getNextTxFee(),
    anchorMode: AnchorMode.Any,
    postConditionMode: PostConditionMode.Allow,
  };

  const tx = await makeContractCall(txOptions);
  const result = await broadcastTransaction({
    transaction: tx,
    network,
  });
  if ('reason' in result) {
    account.logger.error({ ...result }, `Error increasing stake: ${result.reason}`);
    throw new Error(`Error increasing stake: ${result.reason}`);
  }
  account.logger.info(
    { txid: result.txid, increaseBy: increaseBy.toString() },
    'L2 stake-increase tx broadcast'
  );
  return result;
}

// -- L1: Bitcoin locking transaction --

async function submitBtcLock(account: Account, unlockBurnHeight: bigint, unlockBytes: Uint8Array) {
  if (!(await ensureBtcWalletReady())) {
    account.logger.info('BTC staking wallet not funded yet, deferring L1 lock');
    return;
  }

  const lockScript = serializeLockupScript({
    stacker: account.stxAddress,
    unlockBurnHeight,
    unlockBytes,
  });

  const address = getLockingAddress(lockScript);
  const amountBtc = Number(lockAmountSats) / 1e8;

  const txid = await sendToAddress(WALLET_NAME, address, amountBtc);
  account.logger.info(
    { txid, address, amountBtc, unlockBurnHeight: unlockBurnHeight.toString() },
    'L1 BTC lock tx broadcast'
  );
  return txid;
}

async function ensureSignerManager(account: Account) {
  const authId = 2n;
  const signature = signSignerKeyGrant({
    signerManager: account.signerManager,
    authId,
    signerSk: hex.decode(account.signerPrivKey),
  });

  const signerManager = loadSignerManagerSource(SBTC_DEPLOYER_ADDRESS);
  const deployTx = await makeContractDeploy({
    senderKey: account.privKey,
    network,
    contractName: 'signer-manager',
    codeBody: signerManager,
  });
  const deployResult = await broadcastTransaction({
    transaction: deployTx,
    network,
  });
  const exists = 'reason' in deployResult && deployResult.reason === 'ContractAlreadyExists';
  if (!exists) {
    if ('reason' in deployResult) {
      throw new Error(`Error deploying signer manager: ${deployResult.reason}`);
    }
    account.logger.info({ ...deployResult, signerManager: account.signerManager }, 'Deployed signer-manager');
    await waitForTxConfirmed(deployResult.txid);
  } else {
    account.logger.info({ signerManager: account.signerManager }, 'signer-manager already deployed');
  }

  const signerKey = await clarigenClient.ro(pox5.getSignerInfo(account.signerManager));

  if (!signerKey) {
    const registerSelf = await makeContractCall({
      ...pox5Signer(account.signerManager).registerSelf({
        signerManager: account.signerManager,
        signerKey: hex.decode(account.signerPubKey),
        authId,
        signerSig: signature,
      }),
      nonce: (await fetchAccount(account.stxAddress)).nonce,
      senderKey: account.privKey,
      network,
    });
    const registerSelfResult = await broadcastTransaction({
      transaction: registerSelf,
      network,
    });
    if ('reason' in registerSelfResult) {
      throw new Error(`Error registering signer manager: ${registerSelfResult.reason}`);
    }
    account.logger.info(
      { ...registerSelfResult, signerManager: account.signerManager },
      'Registered signer-manager with pox-5'
    );
    await waitForTxConfirmed(registerSelfResult.txid);
  } else {
    account.logger.info({ signerManager: account.signerManager }, 'signer-manager already registered with pox-5');
  }
}

async function maybeCalculateRewards(account: Account) {
  const pox5Info = await clarigenClient.ro(pox5.getPoxInfo());
  if (!pox5Info.value) return;

  const cycleLength = pox5Info.value.rewardCycleLength;
  const firstBurnHeight = pox5Info.value.firstBurnchainBlockHeight;
  const currentBurnHeight = BigInt(
    (await account.client.getPoxInfo()).current_burnchain_block_height!
  );
  const distributionLength = cycleLength / 2n;
  const currentDistributionCycle = (currentBurnHeight - firstBurnHeight) / distributionLength;
  if (currentDistributionCycle === 0n) return;

  const calculationHeight = firstBurnHeight + currentDistributionCycle * distributionLength - 1n;
  const lastCalculationHeight = await clarigenClient.ro(pox5.getLastRewardComputeHeight());
  if (calculationHeight <= lastCalculationHeight) return;

  const calculationRewardCycle = (calculationHeight - firstBurnHeight) / cycleLength;
  const firstBondCycle = await clarigenClient.ro(pox5.getFirstPox5RewardCycle());
  const latestBondIndex =
    calculationRewardCycle <= firstBondCycle ? 0n : (calculationRewardCycle - firstBondCycle) / 2n;
  const bondPeriods = (
    await Promise.all(
      Array.from({ length: 6 }, async (_, offset) => {
        const bondIndex = latestBondIndex - BigInt(offset);
        if (bondIndex < 0n) return null;
        const bond = await clarigenClient.ro(pox5.getProtocolBond(bondIndex));
        if (!bond) return null;
        const bondStartHeight = firstBurnHeight + (firstBondCycle + bondIndex * 2n) * cycleLength;
        const bondEndHeight =
          firstBurnHeight + (firstBondCycle + (bondIndex + 6n) * 2n) * cycleLength;
        if (calculationHeight <= bondStartHeight || calculationHeight > bondEndHeight) return null;
        return { bondIndex, stxValueRatio: bond.stxValueRatio };
      })
    )
  )
    .filter((bond): bond is { bondIndex: bigint; stxValueRatio: bigint } => bond !== null)
    .sort((a, b) => {
      if (a.stxValueRatio === b.stxValueRatio) return a.bondIndex < b.bondIndex ? -1 : 1;
      return a.stxValueRatio > b.stxValueRatio ? -1 : 1;
    })
    .map(bond => bond.bondIndex);

  const tx = await makeContractCall({
    ...pox5.calculateRewards({ bondPeriods }),
    senderKey: account.privKey,
    network,
    fee: getNextTxFee(),
    nonce: (await fetchAccount(account.stxAddress)).nonce,
  });
  const result = await broadcastTransaction({
    transaction: tx,
    network,
  });
  if ('reason' in result) {
    account.logger.error(
      { ...result, calculationHeight: calculationHeight.toString() },
      `Error calculating rewards: ${result.reason}`
    );
    throw new Error(`Error calculating rewards: ${result.reason}`);
  }
  account.logger.info(
    {
      txid: result.txid,
      calculationHeight: calculationHeight.toString(),
      bondPeriods: bondPeriods.map(String),
    },
    'calculate-rewards tx broadcast'
  );
  await waitForTxConfirmed(result.txid);
}

// -- Main loop --

const grantedSignerKeys = new Set<string>();
const fundedBtcAddresses = new Set<string>();
const fundedStxAddresses = new Set<string>();

async function run() {
  const poxInfo = await accounts[0]!.client.getPoxInfo();

  if (poxInfo.current_burnchain_block_height! > EPOCH_30_START + 1) {
    for (const address of BTC_FAUCET_FUND_ADDRESSES) {
      if (fundedBtcAddresses.has(address)) continue;
      const btcFaucet = await apiClient.POST('/extended/v1/faucets/btc', {
        params: {
          query: { address, xlarge: true },
        },
        body: null,
        // The faucet expects no request body; drop the default JSON content-type
        // header so the server doesn't reject the empty body (returns 500).
        headers: { 'Content-Type': null },
      });
      if (btcFaucet.error) {
        logger.error(
          `BTC faucet request failed for ${address} (status ${btcFaucet.response.status}): ${JSON.stringify(btcFaucet.error)}`
        );
      } else {
        logger.info({ btc: btcFaucet.data, address }, 'BTC faucet request succeeded');
        fundedBtcAddresses.add(address);
      }
    }
    for (const address of STX_FAUCET_FUND_ADDRESSES) {
      if (fundedStxAddresses.has(address)) continue;
      const stxFaucet = await apiClient.POST('/extended/v1/faucets/stx', {
        params: {
          query: { address },
        },
        body: null,
        // The faucet expects no request body; drop the default JSON content-type
        // header so the server doesn't reject the empty body (returns 500).
        headers: { 'Content-Type': null },
      });
      if (stxFaucet.error) {
        logger.error(
          `STX faucet request failed for ${address} (status ${stxFaucet.response.status}): ${JSON.stringify(stxFaucet.error)}`
        );
      } else {
        logger.info({ stx: stxFaucet.data, address }, 'STX faucet request succeeded');
        fundedStxAddresses.add(address);
      }
    }
  }
  if (poxInfo.current_burnchain_block_height! < EPOCH_40_START) {
    if (!loggedPreEpoch40) {
      logger.info(
        {
          burnHeight: poxInfo.current_burnchain_block_height,
          epoch40Start: EPOCH_40_START,
        },
        'Waiting for epoch 4.0 (PoX-5) before deploying signer-manager and staking'
      );
      loggedPreEpoch40 = true;
    }
    return;
  }
  loggedPreEpoch40 = false;

  const currentCycle = poxInfo.reward_cycle_id;

  await maybeCalculateRewards(accounts[0]!);

  const accountInfos = await Promise.all(
    accounts.map(async a => {
      const info = await fetchAccount(a.stxAddress);
      return { ...a, ...info };
    })
  );

  const nowCycle = burnBlockToRewardCycle(poxInfo.current_burnchain_block_height ?? 0);

  const txIdsToWait: string[] = [];

  for (const account of accountInfos) {
    const unlockBytes = getUnlockBytes(account.pubKey);
    const unlockBurnHeight = calculateUnlockBurnHeight(
      currentCycle,
      stakingCyclesPox5,
      POX_REWARD_LENGTH
    );

    if (!grantedSignerKeys.has(account.signerManager)) {
      await ensureSignerManager(account);
      grantedSignerKeys.add(account.signerManager);
    }

    if (account.lockedAmount === 0n) {
      account.logger.info(
        {
          account: account.index,
          rewardCycle: poxInfo.reward_cycle_id,
          unlockBurnHeight: unlockBurnHeight.toString(),
          signerManager: account.signerManager,
        },
        'Account unlocked, staking via signer-manager...'
      );

      const stakeResult = await submitStake(account, poxInfo);
      txIdsToWait.push(stakeResult.txid);

      await submitBtcLock(account, unlockBurnHeight, unlockBytes);
      continue;
    }

    // One-time top-up: if staked below the configured target, increase the
    // locked amount to the target (raises signer weight). Idempotent — skipped
    // once locked >= target.
    if (stakingTargetUstx > 0n && account.lockedAmount < stakingTargetUstx) {
      const increaseBy = stakingTargetUstx - account.lockedAmount;
      account.logger.info(
        {
          locked: account.lockedAmount.toString(),
          target: stakingTargetUstx.toString(),
          increaseBy: increaseBy.toString(),
        },
        'Increasing stake to target...'
      );

      const stakeIncreaseResult = await submitStakeIncrease(account, increaseBy);
      txIdsToWait.push(stakeIncreaseResult.txid);

      await submitBtcLock(account, unlockBurnHeight, unlockBytes);
      continue;
    }

    const unlockCycle = burnBlockToRewardCycle(account.unlockHeight);

    if (unlockCycle === nowCycle + 1) {
      account.logger.info(
        { unlockHeight: account.unlockHeight, nowCycle, unlockCycle },
        'Extending stake...'
      );

      const stakeExtendResult = await submitStakeExtend(account);
      txIdsToWait.push(stakeExtendResult.txid);

      await submitBtcLock(account, unlockBurnHeight, unlockBytes);
      continue;
    }

    // account.logger.info({ nowCycle, unlockCycle }, 'Staked through next cycle, skipping');
  }
  await Promise.all(txIdsToWait.map(waitForTxConfirmed));
}

async function loop() {
  await waitForSetup();

  while (true) {
    try {
      await run();
    } catch (e) {
      logger.error(e, 'Error in btc-staker loop');
    }
    await new Promise(r => setTimeout(r, stakingInterval * 1000));
  }
}

loop();
