
import type { TypedAbiArg, TypedAbiFunction, TypedAbiMap, TypedAbiVariable, Response } from '@clarigen/core';

export const contracts = {
  pox5: {
  "functions": {
    addSignerToSetForCycle: {"name":"add-signer-to-set-for-cycle","access":"private","args":[{"name":"signer","type":"principal"},{"name":"cycle","type":"uint128"}],"outputs":{"type":{"response":{"ok":"bool","error":"uint128"}}}} as TypedAbiFunction<[signer: TypedAbiArg<string, "signer">, cycle: TypedAbiArg<number | bigint, "cycle">], Response<boolean, bigint>>,
    addStakerToBond: {"name":"add-staker-to-bond","access":"private","args":[{"name":"staker-item","type":{"tuple":[{"name":"max-sats","type":"uint128"},{"name":"staker","type":"principal"}]}},{"name":"accumulator-res","type":{"response":{"ok":{"tuple":[{"name":"bond-index","type":"uint128"},{"name":"sum-max-sats","type":"uint128"}]},"error":"uint128"}}}],"outputs":{"type":{"response":{"ok":{"tuple":[{"name":"bond-index","type":"uint128"},{"name":"sum-max-sats","type":"uint128"}]},"error":"uint128"}}}} as TypedAbiFunction<[stakerItem: TypedAbiArg<{
  "maxSats": number | bigint;
  "staker": string;
}, "stakerItem">, accumulatorRes: TypedAbiArg<Response<{
  "bondIndex": number | bigint;
  "sumMaxSats": number | bigint;
}, number | bigint>, "accumulatorRes">], Response<{
  "bondIndex": bigint;
  "sumMaxSats": bigint;
}, bigint>>,
    addStakerToSignerCycles: {"name":"add-staker-to-signer-cycles","access":"private","args":[{"name":"staker","type":"principal"},{"name":"signer","type":"principal"},{"name":"first-reward-cycle","type":"uint128"},{"name":"num-cycles","type":"uint128"},{"name":"amount-ustx","type":"uint128"},{"name":"is-stx-staking","type":"bool"}],"outputs":{"type":{"response":{"ok":{"tuple":[{"name":"amount-ustx","type":"uint128"},{"name":"first-reward-cycle","type":"uint128"},{"name":"is-stx-staking","type":"bool"},{"name":"signer","type":"principal"},{"name":"staker","type":"principal"}]},"error":"uint128"}}}} as TypedAbiFunction<[staker: TypedAbiArg<string, "staker">, signer: TypedAbiArg<string, "signer">, firstRewardCycle: TypedAbiArg<number | bigint, "firstRewardCycle">, numCycles: TypedAbiArg<number | bigint, "numCycles">, amountUstx: TypedAbiArg<number | bigint, "amountUstx">, isStxStaking: TypedAbiArg<boolean, "isStxStaking">], Response<{
  "amountUstx": bigint;
  "firstRewardCycle": bigint;
  "isStxStaking": boolean;
  "signer": string;
  "staker": string;
}, bigint>>,
    addStakerToSignerForCycle: {"name":"add-staker-to-signer-for-cycle","access":"private","args":[{"name":"cycle-index","type":"uint128"},{"name":"accumulator-res","type":{"response":{"ok":{"tuple":[{"name":"amount-ustx","type":"uint128"},{"name":"first-reward-cycle","type":"uint128"},{"name":"is-stx-staking","type":"bool"},{"name":"signer","type":"principal"},{"name":"staker","type":"principal"}]},"error":"uint128"}}}],"outputs":{"type":{"response":{"ok":{"tuple":[{"name":"amount-ustx","type":"uint128"},{"name":"first-reward-cycle","type":"uint128"},{"name":"is-stx-staking","type":"bool"},{"name":"signer","type":"principal"},{"name":"staker","type":"principal"}]},"error":"uint128"}}}} as TypedAbiFunction<[cycleIndex: TypedAbiArg<number | bigint, "cycleIndex">, accumulatorRes: TypedAbiArg<Response<{
  "amountUstx": number | bigint;
  "firstRewardCycle": number | bigint;
  "isStxStaking": boolean;
  "signer": string;
  "staker": string;
}, number | bigint>, "accumulatorRes">], Response<{
  "amountUstx": bigint;
  "firstRewardCycle": bigint;
  "isStxStaking": boolean;
  "signer": string;
  "staker": string;
}, bigint>>,
    assertActiveBondIncluded: {"name":"assert-active-bond-included","access":"private","args":[{"name":"offset","type":"uint128"},{"name":"acc-res","type":{"response":{"ok":{"tuple":[{"name":"bond-periods","type":{"list":{"type":"uint128","length":6}}},{"name":"calculation-height","type":"uint128"},{"name":"latest-bond-index","type":"uint128"}]},"error":"uint128"}}}],"outputs":{"type":{"response":{"ok":{"tuple":[{"name":"bond-periods","type":{"list":{"type":"uint128","length":6}}},{"name":"calculation-height","type":"uint128"},{"name":"latest-bond-index","type":"uint128"}]},"error":"uint128"}}}} as TypedAbiFunction<[offset: TypedAbiArg<number | bigint, "offset">, accRes: TypedAbiArg<Response<{
  "bondPeriods": number | bigint[];
  "calculationHeight": number | bigint;
  "latestBondIndex": number | bigint;
}, number | bigint>, "accRes">], Response<{
  "bondPeriods": bigint[];
  "calculationHeight": bigint;
  "latestBondIndex": bigint;
}, bigint>>,
    calculateBondRewards: {"name":"calculate-bond-rewards","access":"private","args":[{"name":"bond-index","type":"uint128"},{"name":"accumulator-res","type":{"response":{"ok":{"tuple":[{"name":"available-rewards","type":"uint128"},{"name":"calculation-height","type":"uint128"},{"name":"last-bond-index","type":{"optional":"uint128"}},{"name":"last-bond-stx-value-ratio","type":{"optional":"uint128"}}]},"error":"uint128"}}}],"outputs":{"type":{"response":{"ok":{"tuple":[{"name":"available-rewards","type":"uint128"},{"name":"calculation-height","type":"uint128"},{"name":"last-bond-index","type":{"optional":"uint128"}},{"name":"last-bond-stx-value-ratio","type":{"optional":"uint128"}}]},"error":"uint128"}}}} as TypedAbiFunction<[bondIndex: TypedAbiArg<number | bigint, "bondIndex">, accumulatorRes: TypedAbiArg<Response<{
  "availableRewards": number | bigint;
  "calculationHeight": number | bigint;
  "lastBondIndex": number | bigint | null;
  "lastBondStxValueRatio": number | bigint | null;
}, number | bigint>, "accumulatorRes">], Response<{
  "availableRewards": bigint;
  "calculationHeight": bigint;
  "lastBondIndex": bigint | null;
  "lastBondStxValueRatio": bigint | null;
}, bigint>>,
    lockSbtc: {"name":"lock-sbtc","access":"private","args":[{"name":"amount","type":"uint128"}],"outputs":{"type":{"response":{"ok":"uint128","error":"uint128"}}}} as TypedAbiFunction<[amount: TypedAbiArg<number | bigint, "amount">], Response<bigint, bigint>>,
    matchUintInList: {"name":"match-uint-in-list","access":"private","args":[{"name":"item","type":"uint128"},{"name":"acc","type":{"tuple":[{"name":"found","type":"bool"},{"name":"needle","type":"uint128"}]}}],"outputs":{"type":{"tuple":[{"name":"found","type":"bool"},{"name":"needle","type":"uint128"}]}}} as TypedAbiFunction<[item: TypedAbiArg<number | bigint, "item">, acc: TypedAbiArg<{
  "found": boolean;
  "needle": number | bigint;
}, "acc">], {
  "found": boolean;
  "needle": bigint;
}>,
    removeStakerFromCycles: {"name":"remove-staker-from-cycles","access":"private","args":[{"name":"staker","type":"principal"},{"name":"first-reward-cycle","type":"uint128"},{"name":"num-cycles","type":"uint128"},{"name":"is-stx-staking","type":"bool"}],"outputs":{"type":{"response":{"ok":{"tuple":[{"name":"first-reward-cycle","type":"uint128"},{"name":"is-stx-staking","type":"bool"},{"name":"staker","type":"principal"}]},"error":"uint128"}}}} as TypedAbiFunction<[staker: TypedAbiArg<string, "staker">, firstRewardCycle: TypedAbiArg<number | bigint, "firstRewardCycle">, numCycles: TypedAbiArg<number | bigint, "numCycles">, isStxStaking: TypedAbiArg<boolean, "isStxStaking">], Response<{
  "firstRewardCycle": bigint;
  "isStxStaking": boolean;
  "staker": string;
}, bigint>>,
    removeStakerFromSetForCycle: {"name":"remove-staker-from-set-for-cycle","access":"private","args":[{"name":"signer","type":"principal"},{"name":"cycle","type":"uint128"}],"outputs":{"type":{"response":{"ok":"bool","error":"uint128"}}}} as TypedAbiFunction<[signer: TypedAbiArg<string, "signer">, cycle: TypedAbiArg<number | bigint, "cycle">], Response<boolean, bigint>>,
    removeStakerFromSignerForCycle: {"name":"remove-staker-from-signer-for-cycle","access":"private","args":[{"name":"cycle-index","type":"uint128"},{"name":"accumulator-res","type":{"response":{"ok":{"tuple":[{"name":"first-reward-cycle","type":"uint128"},{"name":"is-stx-staking","type":"bool"},{"name":"staker","type":"principal"}]},"error":"uint128"}}}],"outputs":{"type":{"response":{"ok":{"tuple":[{"name":"first-reward-cycle","type":"uint128"},{"name":"is-stx-staking","type":"bool"},{"name":"staker","type":"principal"}]},"error":"uint128"}}}} as TypedAbiFunction<[cycleIndex: TypedAbiArg<number | bigint, "cycleIndex">, accumulatorRes: TypedAbiArg<Response<{
  "firstRewardCycle": number | bigint;
  "isStxStaking": boolean;
  "staker": string;
}, number | bigint>, "accumulatorRes">], Response<{
  "firstRewardCycle": bigint;
  "isStxStaking": boolean;
  "staker": string;
}, bigint>>,
    reverseBuff16: {"name":"reverse-buff16","access":"private","args":[{"name":"input","type":{"buffer":{"length":16}}}],"outputs":{"type":{"buffer":{"length":17}}}} as TypedAbiFunction<[input: TypedAbiArg<Uint8Array, "input">], Uint8Array>,
    settleRewards: {"name":"settle-rewards","access":"private","args":[{"name":"signer","type":"principal"},{"name":"is-bond","type":"bool"},{"name":"index","type":"uint128"}],"outputs":{"type":{"tuple":[{"name":"earned","type":"uint128"},{"name":"rewards-per-token","type":"uint128"}]}}} as TypedAbiFunction<[signer: TypedAbiArg<string, "signer">, isBond: TypedAbiArg<boolean, "isBond">, index: TypedAbiArg<number | bigint, "index">], {
  "earned": bigint;
  "rewardsPerToken": bigint;
}>,
    updateClaimableBondRewards: {"name":"update-claimable-bond-rewards","access":"private","args":[{"name":"bond-index","type":"uint128"},{"name":"accumulator","type":{"tuple":[{"name":"bond-rewards","type":{"list":{"type":{"tuple":[{"name":"bond-index","type":"uint128"},{"name":"earned","type":"uint128"},{"name":"rewards-per-token","type":"uint128"}]},"length":6}}},{"name":"signer","type":"principal"},{"name":"total","type":"uint128"}]}}],"outputs":{"type":{"tuple":[{"name":"bond-rewards","type":{"list":{"type":{"tuple":[{"name":"bond-index","type":"uint128"},{"name":"earned","type":"uint128"},{"name":"rewards-per-token","type":"uint128"}]},"length":6}}},{"name":"signer","type":"principal"},{"name":"total","type":"uint128"}]}}} as TypedAbiFunction<[bondIndex: TypedAbiArg<number | bigint, "bondIndex">, accumulator: TypedAbiArg<{
  "bondRewards": {
  "bondIndex": number | bigint;
  "earned": number | bigint;
  "rewardsPerToken": number | bigint;
}[];
  "signer": string;
  "total": number | bigint;
}, "accumulator">], {
  "bondRewards": {
  "bondIndex": bigint;
  "earned": bigint;
  "rewardsPerToken": bigint;
}[];
  "signer": string;
  "total": bigint;
}>,
    updateClaimableRewards: {"name":"update-claimable-rewards","access":"private","args":[{"name":"signer","type":"principal"},{"name":"is-bond","type":"bool"},{"name":"index","type":"uint128"}],"outputs":{"type":{"tuple":[{"name":"earned","type":"uint128"},{"name":"rewards-per-token","type":"uint128"}]}}} as TypedAbiFunction<[signer: TypedAbiArg<string, "signer">, isBond: TypedAbiArg<boolean, "isBond">, index: TypedAbiArg<number | bigint, "index">], {
  "earned": bigint;
  "rewardsPerToken": bigint;
}>,
    validateL1Lockup: {"name":"validate-l1-lockup","access":"private","args":[{"name":"lockup","type":{"tuple":[{"name":"amount","type":"uint128"},{"name":"header","type":{"buffer":{"length":80}}},{"name":"height","type":"uint128"},{"name":"leaf-hashes","type":{"list":{"type":{"buffer":{"length":32}},"length":14}}},{"name":"output-index","type":"uint128"},{"name":"tx","type":{"buffer":{"length":100000}}},{"name":"tx-count","type":"uint128"},{"name":"tx-index","type":"uint128"}]}},{"name":"accumulator-res","type":{"response":{"ok":{"tuple":[{"name":"expected-script-hash","type":{"buffer":{"length":34}}},{"name":"sum","type":"uint128"}]},"error":"uint128"}}}],"outputs":{"type":{"response":{"ok":{"tuple":[{"name":"expected-script-hash","type":{"buffer":{"length":34}}},{"name":"sum","type":"uint128"}]},"error":"uint128"}}}} as TypedAbiFunction<[lockup: TypedAbiArg<{
  "amount": number | bigint;
  "header": Uint8Array;
  "height": number | bigint;
  "leafHashes": Uint8Array[];
  "outputIndex": number | bigint;
  "tx": Uint8Array;
  "txCount": number | bigint;
  "txIndex": number | bigint;
}, "lockup">, accumulatorRes: TypedAbiArg<Response<{
  "expectedScriptHash": Uint8Array;
  "sum": number | bigint;
}, number | bigint>, "accumulatorRes">], Response<{
  "expectedScriptHash": Uint8Array;
  "sum": bigint;
}, bigint>>,
    verifyL1Lockups: {"name":"verify-l1-lockups","access":"private","args":[{"name":"staker","type":"principal"},{"name":"bond-index","type":"uint128"},{"name":"lockups","type":{"tuple":[{"name":"outputs","type":{"list":{"type":{"tuple":[{"name":"amount","type":"uint128"},{"name":"header","type":{"buffer":{"length":80}}},{"name":"height","type":"uint128"},{"name":"leaf-hashes","type":{"list":{"type":{"buffer":{"length":32}},"length":14}}},{"name":"output-index","type":"uint128"},{"name":"tx","type":{"buffer":{"length":100000}}},{"name":"tx-count","type":"uint128"},{"name":"tx-index","type":"uint128"}]},"length":10}}},{"name":"unlock-bytes","type":{"buffer":{"length":683}}}]}}],"outputs":{"type":{"response":{"ok":"uint128","error":"uint128"}}}} as TypedAbiFunction<[staker: TypedAbiArg<string, "staker">, bondIndex: TypedAbiArg<number | bigint, "bondIndex">, lockups: TypedAbiArg<{
  "outputs": {
  "amount": number | bigint;
  "header": Uint8Array;
  "height": number | bigint;
  "leafHashes": Uint8Array[];
  "outputIndex": number | bigint;
  "tx": Uint8Array;
  "txCount": number | bigint;
  "txIndex": number | bigint;
}[];
  "unlockBytes": Uint8Array;
}, "lockups">], Response<bigint, bigint>>,
    allowContractCaller: {"name":"allow-contract-caller","access":"public","args":[{"name":"caller","type":"principal"},{"name":"until-burn-ht","type":{"optional":"uint128"}}],"outputs":{"type":{"response":{"ok":"bool","error":"uint128"}}}} as TypedAbiFunction<[caller: TypedAbiArg<string, "caller">, untilBurnHt: TypedAbiArg<number | bigint | null, "untilBurnHt">], Response<boolean, bigint>>,
    announceL1EarlyExit: {"name":"announce-l1-early-exit","access":"public","args":[{"name":"staker","type":"principal"},{"name":"old-signer-manager","type":"trait_reference"}],"outputs":{"type":{"response":{"ok":"bool","error":"uint128"}}}} as TypedAbiFunction<[staker: TypedAbiArg<string, "staker">, oldSignerManager: TypedAbiArg<string, "oldSignerManager">], Response<boolean, bigint>>,
    calculateRewards: {"name":"calculate-rewards","access":"public","args":[{"name":"bond-periods","type":{"list":{"type":"uint128","length":6}}}],"outputs":{"type":{"response":{"ok":"bool","error":"uint128"}}}} as TypedAbiFunction<[bondPeriods: TypedAbiArg<number | bigint[], "bondPeriods">], Response<boolean, bigint>>,
    claimRewards: {"name":"claim-rewards","access":"public","args":[{"name":"bond-periods","type":{"list":{"type":"uint128","length":6}}},{"name":"reward-cycle","type":"uint128"}],"outputs":{"type":{"response":{"ok":{"tuple":[{"name":"bond-rewards","type":{"list":{"type":{"tuple":[{"name":"bond-index","type":"uint128"},{"name":"earned","type":"uint128"},{"name":"rewards-per-token","type":"uint128"}]},"length":6}}},{"name":"bond-totals","type":"uint128"},{"name":"stx-rewards","type":{"tuple":[{"name":"earned","type":"uint128"},{"name":"rewards-per-token","type":"uint128"}]}},{"name":"total-rewards","type":"uint128"}]},"error":"uint128"}}}} as TypedAbiFunction<[bondPeriods: TypedAbiArg<number | bigint[], "bondPeriods">, rewardCycle: TypedAbiArg<number | bigint, "rewardCycle">], Response<{
  "bondRewards": {
  "bondIndex": bigint;
  "earned": bigint;
  "rewardsPerToken": bigint;
}[];
  "bondTotals": bigint;
  "stxRewards": {
  "earned": bigint;
  "rewardsPerToken": bigint;
};
  "totalRewards": bigint;
}, bigint>>,
    disallowContractCaller: {"name":"disallow-contract-caller","access":"public","args":[{"name":"caller","type":"principal"}],"outputs":{"type":{"response":{"ok":"bool","error":"uint128"}}}} as TypedAbiFunction<[caller: TypedAbiArg<string, "caller">], Response<boolean, bigint>>,
    grantSignerKey: {"name":"grant-signer-key","access":"public","args":[{"name":"signer-key","type":{"buffer":{"length":33}}},{"name":"signer-manager","type":"principal"},{"name":"auth-id","type":"uint128"},{"name":"signer-sig","type":{"buffer":{"length":65}}}],"outputs":{"type":{"response":{"ok":"bool","error":"uint128"}}}} as TypedAbiFunction<[signerKey: TypedAbiArg<Uint8Array, "signerKey">, signerManager: TypedAbiArg<string, "signerManager">, authId: TypedAbiArg<number | bigint, "authId">, signerSig: TypedAbiArg<Uint8Array, "signerSig">], Response<boolean, bigint>>,
    registerForBond: {"name":"register-for-bond","access":"public","args":[{"name":"bond-index","type":"uint128"},{"name":"signer-manager","type":"trait_reference"},{"name":"amount-ustx","type":"uint128"},{"name":"btc-lockup","type":{"response":{"ok":{"tuple":[{"name":"outputs","type":{"list":{"type":{"tuple":[{"name":"amount","type":"uint128"},{"name":"header","type":{"buffer":{"length":80}}},{"name":"height","type":"uint128"},{"name":"leaf-hashes","type":{"list":{"type":{"buffer":{"length":32}},"length":14}}},{"name":"output-index","type":"uint128"},{"name":"tx","type":{"buffer":{"length":100000}}},{"name":"tx-count","type":"uint128"},{"name":"tx-index","type":"uint128"}]},"length":10}}},{"name":"unlock-bytes","type":{"buffer":{"length":683}}}]},"error":"uint128"}}},{"name":"signer-calldata","type":{"optional":{"buffer":{"length":500}}}}],"outputs":{"type":{"response":{"ok":{"tuple":[{"name":"amount-ustx","type":"uint128"},{"name":"bond-index","type":"uint128"},{"name":"first-reward-cycle","type":"uint128"},{"name":"signer","type":"principal"},{"name":"staker","type":"principal"},{"name":"unlock-burn-height","type":"uint128"},{"name":"unlock-cycle","type":"uint128"}]},"error":"uint128"}}}} as TypedAbiFunction<[bondIndex: TypedAbiArg<number | bigint, "bondIndex">, signerManager: TypedAbiArg<string, "signerManager">, amountUstx: TypedAbiArg<number | bigint, "amountUstx">, btcLockup: TypedAbiArg<Response<{
  "outputs": {
  "amount": number | bigint;
  "header": Uint8Array;
  "height": number | bigint;
  "leafHashes": Uint8Array[];
  "outputIndex": number | bigint;
  "tx": Uint8Array;
  "txCount": number | bigint;
  "txIndex": number | bigint;
}[];
  "unlockBytes": Uint8Array;
}, number | bigint>, "btcLockup">, signerCalldata: TypedAbiArg<Uint8Array | null, "signerCalldata">], Response<{
  "amountUstx": bigint;
  "bondIndex": bigint;
  "firstRewardCycle": bigint;
  "signer": string;
  "staker": string;
  "unlockBurnHeight": bigint;
  "unlockCycle": bigint;
}, bigint>>,
    registerSigner: {"name":"register-signer","access":"public","args":[{"name":"signer-manager","type":"trait_reference"},{"name":"signer-key","type":{"buffer":{"length":33}}}],"outputs":{"type":{"response":{"ok":{"tuple":[{"name":"signer","type":"principal"},{"name":"signer-key","type":{"buffer":{"length":33}}}]},"error":"uint128"}}}} as TypedAbiFunction<[signerManager: TypedAbiArg<string, "signerManager">, signerKey: TypedAbiArg<Uint8Array, "signerKey">], Response<{
  "signer": string;
  "signerKey": Uint8Array;
}, bigint>>,
    revokeSignerGrant: {"name":"revoke-signer-grant","access":"public","args":[{"name":"signer-manager","type":"principal"},{"name":"signer-key","type":{"buffer":{"length":33}}}],"outputs":{"type":{"response":{"ok":"bool","error":"uint128"}}}} as TypedAbiFunction<[signerManager: TypedAbiArg<string, "signerManager">, signerKey: TypedAbiArg<Uint8Array, "signerKey">], Response<boolean, bigint>>,
    setBondAdmin: {"name":"set-bond-admin","access":"public","args":[{"name":"new-admin","type":"principal"}],"outputs":{"type":{"response":{"ok":"bool","error":"uint128"}}}} as TypedAbiFunction<[newAdmin: TypedAbiArg<string, "newAdmin">], Response<boolean, bigint>>,
    setBurnchainParameters: {"name":"set-burnchain-parameters","access":"public","args":[{"name":"first-burn-height","type":"uint128"},{"name":"prepare-cycle-length","type":"uint128"},{"name":"reward-cycle-length","type":"uint128"},{"name":"begin-pox5-reward-cycle","type":"uint128"}],"outputs":{"type":{"response":{"ok":"bool","error":"none"}}}} as TypedAbiFunction<[firstBurnHeight: TypedAbiArg<number | bigint, "firstBurnHeight">, prepareCycleLength: TypedAbiArg<number | bigint, "prepareCycleLength">, rewardCycleLength: TypedAbiArg<number | bigint, "rewardCycleLength">, beginPox5RewardCycle: TypedAbiArg<number | bigint, "beginPox5RewardCycle">], Response<boolean, null>>,
    setupBond: {"name":"setup-bond","access":"public","args":[{"name":"bond-index","type":"uint128"},{"name":"target-rate","type":"uint128"},{"name":"stx-value-ratio","type":"uint128"},{"name":"min-ustx-ratio","type":"uint128"},{"name":"early-unlock-bytes","type":{"buffer":{"length":683}}},{"name":"early-unlock-admin","type":"principal"},{"name":"allowlist","type":{"list":{"type":{"tuple":[{"name":"max-sats","type":"uint128"},{"name":"staker","type":"principal"}]},"length":1000}}}],"outputs":{"type":{"response":{"ok":{"tuple":[{"name":"bond-index","type":"uint128"},{"name":"early-unlock-bytes","type":{"buffer":{"length":683}}},{"name":"max-allocation-sats","type":"uint128"},{"name":"min-ustx-ratio","type":"uint128"},{"name":"stx-value-ratio","type":"uint128"},{"name":"target-rate","type":"uint128"}]},"error":"uint128"}}}} as TypedAbiFunction<[bondIndex: TypedAbiArg<number | bigint, "bondIndex">, targetRate: TypedAbiArg<number | bigint, "targetRate">, stxValueRatio: TypedAbiArg<number | bigint, "stxValueRatio">, minUstxRatio: TypedAbiArg<number | bigint, "minUstxRatio">, earlyUnlockBytes: TypedAbiArg<Uint8Array, "earlyUnlockBytes">, earlyUnlockAdmin: TypedAbiArg<string, "earlyUnlockAdmin">, allowlist: TypedAbiArg<{
  "maxSats": number | bigint;
  "staker": string;
}[], "allowlist">], Response<{
  "bondIndex": bigint;
  "earlyUnlockBytes": Uint8Array;
  "maxAllocationSats": bigint;
  "minUstxRatio": bigint;
  "stxValueRatio": bigint;
  "targetRate": bigint;
}, bigint>>,
    stake: {"name":"stake","access":"public","args":[{"name":"signer-manager","type":"trait_reference"},{"name":"amount-ustx","type":"uint128"},{"name":"num-cycles","type":"uint128"},{"name":"start-burn-ht","type":"uint128"},{"name":"signer-calldata","type":{"optional":{"buffer":{"length":500}}}}],"outputs":{"type":{"response":{"ok":{"tuple":[{"name":"amount-ustx","type":"uint128"},{"name":"first-reward-cycle","type":"uint128"},{"name":"num-cycle","type":"uint128"},{"name":"signer","type":"principal"},{"name":"staker","type":"principal"},{"name":"unlock-burn-height","type":"uint128"},{"name":"unlock-cycle","type":"uint128"}]},"error":"uint128"}}}} as TypedAbiFunction<[signerManager: TypedAbiArg<string, "signerManager">, amountUstx: TypedAbiArg<number | bigint, "amountUstx">, numCycles: TypedAbiArg<number | bigint, "numCycles">, startBurnHt: TypedAbiArg<number | bigint, "startBurnHt">, signerCalldata: TypedAbiArg<Uint8Array | null, "signerCalldata">], Response<{
  "amountUstx": bigint;
  "firstRewardCycle": bigint;
  "numCycle": bigint;
  "signer": string;
  "staker": string;
  "unlockBurnHeight": bigint;
  "unlockCycle": bigint;
}, bigint>>,
    stakeUpdate: {"name":"stake-update","access":"public","args":[{"name":"signer-manager","type":"trait_reference"},{"name":"old-signer-manager","type":"trait_reference"},{"name":"cycles-to-extend","type":"uint128"},{"name":"amount-increase","type":"uint128"},{"name":"signer-calldata","type":{"optional":{"buffer":{"length":500}}}}],"outputs":{"type":{"response":{"ok":{"tuple":[{"name":"amount-ustx","type":"uint128"},{"name":"num-cycles","type":"uint128"},{"name":"prev-unlock-height","type":"uint128"},{"name":"signer","type":"principal"},{"name":"staker","type":"principal"},{"name":"unlock-burn-height","type":"uint128"},{"name":"unlock-cycle","type":"uint128"}]},"error":"uint128"}}}} as TypedAbiFunction<[signerManager: TypedAbiArg<string, "signerManager">, oldSignerManager: TypedAbiArg<string, "oldSignerManager">, cyclesToExtend: TypedAbiArg<number | bigint, "cyclesToExtend">, amountIncrease: TypedAbiArg<number | bigint, "amountIncrease">, signerCalldata: TypedAbiArg<Uint8Array | null, "signerCalldata">], Response<{
  "amountUstx": bigint;
  "numCycles": bigint;
  "prevUnlockHeight": bigint;
  "signer": string;
  "staker": string;
  "unlockBurnHeight": bigint;
  "unlockCycle": bigint;
}, bigint>>,
    unstake: {"name":"unstake","access":"public","args":[{"name":"old-signer-manager","type":"trait_reference"}],"outputs":{"type":{"response":{"ok":{"tuple":[{"name":"amount-ustx","type":"uint128"},{"name":"first-reward-cycle","type":"uint128"},{"name":"staker","type":"principal"},{"name":"unlock-burn-height","type":"uint128"},{"name":"unlock-cycle","type":"uint128"}]},"error":"uint128"}}}} as TypedAbiFunction<[oldSignerManager: TypedAbiArg<string, "oldSignerManager">], Response<{
  "amountUstx": bigint;
  "firstRewardCycle": bigint;
  "staker": string;
  "unlockBurnHeight": bigint;
  "unlockCycle": bigint;
}, bigint>>,
    unstakeSbtc: {"name":"unstake-sbtc","access":"public","args":[{"name":"signer-manager","type":"trait_reference"},{"name":"amount-to-withdrawal-sats","type":"uint128"}],"outputs":{"type":{"response":{"ok":{"tuple":[{"name":"new-amount-sats","type":"uint128"},{"name":"signer","type":"principal"},{"name":"staker","type":"principal"}]},"error":"uint128"}}}} as TypedAbiFunction<[signerManager: TypedAbiArg<string, "signerManager">, amountToWithdrawalSats: TypedAbiArg<number | bigint, "amountToWithdrawalSats">], Response<{
  "newAmountSats": bigint;
  "signer": string;
  "staker": string;
}, bigint>>,
    updateBondRegistration: {"name":"update-bond-registration","access":"public","args":[{"name":"signer-manager","type":"trait_reference"},{"name":"old-signer-manager","type":"trait_reference"},{"name":"signer-calldata","type":{"optional":{"buffer":{"length":500}}}}],"outputs":{"type":{"response":{"ok":"bool","error":"uint128"}}}} as TypedAbiFunction<[signerManager: TypedAbiArg<string, "signerManager">, oldSignerManager: TypedAbiArg<string, "oldSignerManager">, signerCalldata: TypedAbiArg<Uint8Array | null, "signerCalldata">], Response<boolean, bigint>>,
    assertAllActiveBondsIncluded: {"name":"assert-all-active-bonds-included","access":"read_only","args":[{"name":"bond-periods","type":{"list":{"type":"uint128","length":6}}},{"name":"calculation-height","type":"uint128"}],"outputs":{"type":{"response":{"ok":"bool","error":"uint128"}}}} as TypedAbiFunction<[bondPeriods: TypedAbiArg<number | bigint[], "bondPeriods">, calculationHeight: TypedAbiArg<number | bigint, "calculationHeight">], Response<boolean, bigint>>,
    bondPeriodToBurnHeight: {"name":"bond-period-to-burn-height","access":"read_only","args":[{"name":"bond-index","type":"uint128"}],"outputs":{"type":"uint128"}} as TypedAbiFunction<[bondIndex: TypedAbiArg<number | bigint, "bondIndex">], bigint>,
    bondPeriodToRewardCycle: {"name":"bond-period-to-reward-cycle","access":"read_only","args":[{"name":"bond-index","type":"uint128"}],"outputs":{"type":"uint128"}} as TypedAbiFunction<[bondIndex: TypedAbiArg<number | bigint, "bondIndex">], bigint>,
    burnHeightToDistributionIndex: {"name":"burn-height-to-distribution-index","access":"read_only","args":[{"name":"height","type":"uint128"}],"outputs":{"type":"uint128"}} as TypedAbiFunction<[height: TypedAbiArg<number | bigint, "height">], bigint>,
    burnHeightToRewardCycle: {"name":"burn-height-to-reward-cycle","access":"read_only","args":[{"name":"height","type":"uint128"}],"outputs":{"type":"uint128"}} as TypedAbiFunction<[height: TypedAbiArg<number | bigint, "height">], bigint>,
    checkCallerAllowed: {"name":"check-caller-allowed","access":"read_only","args":[],"outputs":{"type":{"response":{"ok":"bool","error":"uint128"}}}} as TypedAbiFunction<[], Response<boolean, bigint>>,
    checkPoxLockPeriod: {"name":"check-pox-lock-period","access":"read_only","args":[{"name":"lock-period","type":"uint128"}],"outputs":{"type":"bool"}} as TypedAbiFunction<[lockPeriod: TypedAbiArg<number | bigint, "lockPeriod">], boolean>,
    constructLockupOutputScript: {"name":"construct-lockup-output-script","access":"read_only","args":[{"name":"staker","type":"principal"},{"name":"unlock-burn-height","type":"uint128"},{"name":"unlock-bytes","type":{"buffer":{"length":683}}},{"name":"early-unlock-bytes","type":{"buffer":{"length":683}}}],"outputs":{"type":{"buffer":{"length":34}}}} as TypedAbiFunction<[staker: TypedAbiArg<string, "staker">, unlockBurnHeight: TypedAbiArg<number | bigint, "unlockBurnHeight">, unlockBytes: TypedAbiArg<Uint8Array, "unlockBytes">, earlyUnlockBytes: TypedAbiArg<Uint8Array, "earlyUnlockBytes">], Uint8Array>,
    constructLockupScript: {"name":"construct-lockup-script","access":"read_only","args":[{"name":"staker","type":"principal"},{"name":"unlock-burn-height","type":"uint128"},{"name":"unlock-bytes","type":{"buffer":{"length":683}}},{"name":"early-unlock-bytes","type":{"buffer":{"length":683}}}],"outputs":{"type":{"buffer":{"length":4109}}}} as TypedAbiFunction<[staker: TypedAbiArg<string, "staker">, unlockBurnHeight: TypedAbiArg<number | bigint, "unlockBurnHeight">, unlockBytes: TypedAbiArg<Uint8Array, "unlockBytes">, earlyUnlockBytes: TypedAbiArg<Uint8Array, "earlyUnlockBytes">], Uint8Array>,
    currentDistributionCycle: {"name":"current-distribution-cycle","access":"read_only","args":[],"outputs":{"type":"uint128"}} as TypedAbiFunction<[], bigint>,
    currentPoxRewardCycle: {"name":"current-pox-reward-cycle","access":"read_only","args":[],"outputs":{"type":"uint128"}} as TypedAbiFunction<[], bigint>,
    distributionCycleToBurnHeight: {"name":"distribution-cycle-to-burn-height","access":"read_only","args":[{"name":"cycle","type":"uint128"}],"outputs":{"type":"uint128"}} as TypedAbiFunction<[cycle: TypedAbiArg<number | bigint, "cycle">], bigint>,
    getAmountDelegatedForSigner: {"name":"get-amount-delegated-for-signer","access":"read_only","args":[{"name":"signer","type":"principal"},{"name":"cycle","type":"uint128"}],"outputs":{"type":"uint128"}} as TypedAbiFunction<[signer: TypedAbiArg<string, "signer">, cycle: TypedAbiArg<number | bigint, "cycle">], bigint>,
    getBcHHash: {"name":"get-bc-h-hash","access":"read_only","args":[{"name":"bh","type":"uint128"}],"outputs":{"type":{"optional":{"buffer":{"length":32}}}}} as TypedAbiFunction<[bh: TypedAbiArg<number | bigint, "bh">], Uint8Array | null>,
    getBondAllowance: {"name":"get-bond-allowance","access":"read_only","args":[{"name":"bond-index","type":"uint128"},{"name":"staker","type":"principal"}],"outputs":{"type":{"optional":"uint128"}}} as TypedAbiFunction<[bondIndex: TypedAbiArg<number | bigint, "bondIndex">, staker: TypedAbiArg<string, "staker">], bigint | null>,
    getBondL1UnlockHeight: {"name":"get-bond-l1-unlock-height","access":"read_only","args":[{"name":"bond-index","type":"uint128"}],"outputs":{"type":"uint128"}} as TypedAbiFunction<[bondIndex: TypedAbiArg<number | bigint, "bondIndex">], bigint>,
    getBondMembership: {"name":"get-bond-membership","access":"read_only","args":[{"name":"staker","type":"principal"}],"outputs":{"type":{"optional":{"tuple":[{"name":"amount-ustx","type":"uint128"},{"name":"bond-index","type":"uint128"},{"name":"is-l1-lock","type":"bool"},{"name":"signer","type":"principal"}]}}}} as TypedAbiFunction<[staker: TypedAbiArg<string, "staker">], {
  "amountUstx": bigint;
  "bondIndex": bigint;
  "isL1Lock": boolean;
  "signer": string;
} | null>,
    getEarned: {"name":"get-earned","access":"read_only","args":[{"name":"signer","type":"principal"},{"name":"is-bond","type":"bool"},{"name":"index","type":"uint128"}],"outputs":{"type":"uint128"}} as TypedAbiFunction<[signer: TypedAbiArg<string, "signer">, isBond: TypedAbiArg<boolean, "isBond">, index: TypedAbiArg<number | bigint, "index">], bigint>,
    getFirstPox5RewardCycle: {"name":"get-first-pox-5-reward-cycle","access":"read_only","args":[],"outputs":{"type":"uint128"}} as TypedAbiFunction<[], bigint>,
    getLastAccountedRewardsOnly: {"name":"get-last-accounted-rewards-only","access":"read_only","args":[],"outputs":{"type":"uint128"}} as TypedAbiFunction<[], bigint>,
    getLastRewardComputeHeight: {"name":"get-last-reward-compute-height","access":"read_only","args":[],"outputs":{"type":"uint128"}} as TypedAbiFunction<[], bigint>,
    getNewRewards: {"name":"get-new-rewards","access":"read_only","args":[],"outputs":{"type":"uint128"}} as TypedAbiFunction<[], bigint>,
    getPoxInfo: {"name":"get-pox-info","access":"read_only","args":[],"outputs":{"type":{"response":{"ok":{"tuple":[{"name":"first-burnchain-block-height","type":"uint128"},{"name":"min-amount-ustx","type":"uint128"},{"name":"prepare-cycle-length","type":"uint128"},{"name":"reward-cycle-id","type":"uint128"},{"name":"reward-cycle-length","type":"uint128"},{"name":"total-liquid-supply-ustx","type":"uint128"}]},"error":"none"}}}} as TypedAbiFunction<[], Response<{
  "firstBurnchainBlockHeight": bigint;
  "minAmountUstx": bigint;
  "prepareCycleLength": bigint;
  "rewardCycleId": bigint;
  "rewardCycleLength": bigint;
  "totalLiquidSupplyUstx": bigint;
}, null>>,
    getProtocolBond: {"name":"get-protocol-bond","access":"read_only","args":[{"name":"bond-index","type":"uint128"}],"outputs":{"type":{"optional":{"tuple":[{"name":"early-unlock-admin","type":"principal"},{"name":"early-unlock-bytes","type":{"buffer":{"length":683}}},{"name":"min-ustx-ratio","type":"uint128"},{"name":"stx-value-ratio","type":"uint128"},{"name":"target-rate","type":"uint128"}]}}}} as TypedAbiFunction<[bondIndex: TypedAbiArg<number | bigint, "bondIndex">], {
  "earlyUnlockAdmin": string;
  "earlyUnlockBytes": Uint8Array;
  "minUstxRatio": bigint;
  "stxValueRatio": bigint;
  "targetRate": bigint;
} | null>,
    getReserveBalance: {"name":"get-reserve-balance","access":"read_only","args":[],"outputs":{"type":"uint128"}} as TypedAbiFunction<[], bigint>,
    getReversedTxid: {"name":"get-reversed-txid","access":"read_only","args":[{"name":"tx","type":{"buffer":{"length":100000}}}],"outputs":{"type":{"buffer":{"length":32}}}} as TypedAbiFunction<[tx: TypedAbiArg<Uint8Array, "tx">], Uint8Array>,
    getRewards: {"name":"get-rewards","access":"read_only","args":[],"outputs":{"type":"uint128"}} as TypedAbiFunction<[], bigint>,
    getRewardsPerTokenForCycle: {"name":"get-rewards-per-token-for-cycle","access":"read_only","args":[{"name":"is-bond","type":"bool"},{"name":"index","type":"uint128"}],"outputs":{"type":"uint128"}} as TypedAbiFunction<[isBond: TypedAbiArg<boolean, "isBond">, index: TypedAbiArg<number | bigint, "index">], bigint>,
    getSignerCycleMembership: {"name":"get-signer-cycle-membership","access":"read_only","args":[{"name":"staker","type":"principal"},{"name":"cycle","type":"uint128"}],"outputs":{"type":{"optional":{"tuple":[{"name":"amount-ustx","type":"uint128"},{"name":"signer","type":"principal"}]}}}} as TypedAbiFunction<[staker: TypedAbiArg<string, "staker">, cycle: TypedAbiArg<number | bigint, "cycle">], {
  "amountUstx": bigint;
  "signer": string;
} | null>,
    getSignerGrantMessageHash: {"name":"get-signer-grant-message-hash","access":"read_only","args":[{"name":"signer-manager","type":"principal"},{"name":"auth-id","type":"uint128"}],"outputs":{"type":{"buffer":{"length":32}}}} as TypedAbiFunction<[signerManager: TypedAbiArg<string, "signerManager">, authId: TypedAbiArg<number | bigint, "authId">], Uint8Array>,
    getSignerInfo: {"name":"get-signer-info","access":"read_only","args":[{"name":"signer","type":"principal"}],"outputs":{"type":{"optional":{"buffer":{"length":33}}}}} as TypedAbiFunction<[signer: TypedAbiArg<string, "signer">], Uint8Array | null>,
    getSignerPendingStakedUstxPerCycle: {"name":"get-signer-pending-staked-ustx-per-cycle","access":"read_only","args":[{"name":"signer","type":"principal"},{"name":"cycle","type":"uint128"}],"outputs":{"type":"uint128"}} as TypedAbiFunction<[signer: TypedAbiArg<string, "signer">, cycle: TypedAbiArg<number | bigint, "cycle">], bigint>,
    getSignerRewardsPerTokenSettledForCycle: {"name":"get-signer-rewards-per-token-settled-for-cycle","access":"read_only","args":[{"name":"signer","type":"principal"},{"name":"is-bond","type":"bool"},{"name":"index","type":"uint128"}],"outputs":{"type":"uint128"}} as TypedAbiFunction<[signer: TypedAbiArg<string, "signer">, isBond: TypedAbiArg<boolean, "isBond">, index: TypedAbiArg<number | bigint, "index">], bigint>,
    getSignerSetFirstItemForCycle: {"name":"get-signer-set-first-item-for-cycle","access":"read_only","args":[{"name":"cycle","type":"uint128"}],"outputs":{"type":{"optional":"principal"}}} as TypedAbiFunction<[cycle: TypedAbiArg<number | bigint, "cycle">], string | null>,
    getSignerSetItemForCycle: {"name":"get-signer-set-item-for-cycle","access":"read_only","args":[{"name":"signer","type":"principal"},{"name":"cycle","type":"uint128"}],"outputs":{"type":{"optional":{"tuple":[{"name":"next","type":{"optional":"principal"}},{"name":"prev","type":{"optional":"principal"}}]}}}} as TypedAbiFunction<[signer: TypedAbiArg<string, "signer">, cycle: TypedAbiArg<number | bigint, "cycle">], {
  "next": string | null;
  "prev": string | null;
} | null>,
    getSignerSetLastItemForCycle: {"name":"get-signer-set-last-item-for-cycle","access":"read_only","args":[{"name":"cycle","type":"uint128"}],"outputs":{"type":{"optional":"principal"}}} as TypedAbiFunction<[cycle: TypedAbiArg<number | bigint, "cycle">], string | null>,
    getSignerSetNextItemForCycle: {"name":"get-signer-set-next-item-for-cycle","access":"read_only","args":[{"name":"signer","type":"principal"},{"name":"cycle","type":"uint128"}],"outputs":{"type":{"optional":"principal"}}} as TypedAbiFunction<[signer: TypedAbiArg<string, "signer">, cycle: TypedAbiArg<number | bigint, "cycle">], string | null>,
    getSignerSetPrevItemForCycle: {"name":"get-signer-set-prev-item-for-cycle","access":"read_only","args":[{"name":"signer","type":"principal"},{"name":"cycle","type":"uint128"}],"outputs":{"type":{"optional":"principal"}}} as TypedAbiFunction<[signer: TypedAbiArg<string, "signer">, cycle: TypedAbiArg<number | bigint, "cycle">], string | null>,
    getSignerSharesStakedForCycle: {"name":"get-signer-shares-staked-for-cycle","access":"read_only","args":[{"name":"signer","type":"principal"},{"name":"is-bond","type":"bool"},{"name":"index","type":"uint128"}],"outputs":{"type":"uint128"}} as TypedAbiFunction<[signer: TypedAbiArg<string, "signer">, isBond: TypedAbiArg<boolean, "isBond">, index: TypedAbiArg<number | bigint, "index">], bigint>,
    getSignerUnclaimedRewardsForCycle: {"name":"get-signer-unclaimed-rewards-for-cycle","access":"read_only","args":[{"name":"signer","type":"principal"},{"name":"is-bond","type":"bool"},{"name":"index","type":"uint128"}],"outputs":{"type":"uint128"}} as TypedAbiFunction<[signer: TypedAbiArg<string, "signer">, isBond: TypedAbiArg<boolean, "isBond">, index: TypedAbiArg<number | bigint, "index">], bigint>,
    getStakerInfo: {"name":"get-staker-info","access":"read_only","args":[{"name":"staker","type":"principal"}],"outputs":{"type":{"optional":{"tuple":[{"name":"amount-ustx","type":"uint128"},{"name":"first-reward-cycle","type":"uint128"},{"name":"num-cycles","type":"uint128"},{"name":"signer","type":"principal"}]}}}} as TypedAbiFunction<[staker: TypedAbiArg<string, "staker">], {
  "amountUstx": bigint;
  "firstRewardCycle": bigint;
  "numCycles": bigint;
  "signer": string;
} | null>,
    getStakerSharesStakedForCycle: {"name":"get-staker-shares-staked-for-cycle","access":"read_only","args":[{"name":"staker","type":"principal"},{"name":"is-bond","type":"bool"},{"name":"index","type":"uint128"},{"name":"signer","type":"principal"}],"outputs":{"type":"uint128"}} as TypedAbiFunction<[staker: TypedAbiArg<string, "staker">, isBond: TypedAbiArg<boolean, "isBond">, index: TypedAbiArg<number | bigint, "index">, signer: TypedAbiArg<string, "signer">], bigint>,
    getTotalSbtcStaked: {"name":"get-total-sbtc-staked","access":"read_only","args":[],"outputs":{"type":"uint128"}} as TypedAbiFunction<[], bigint>,
    getTotalSbtcStakedForBond: {"name":"get-total-sbtc-staked-for-bond","access":"read_only","args":[{"name":"bond-index","type":"uint128"}],"outputs":{"type":"uint128"}} as TypedAbiFunction<[bondIndex: TypedAbiArg<number | bigint, "bondIndex">], bigint>,
    getTotalSharesStakedForCycle: {"name":"get-total-shares-staked-for-cycle","access":"read_only","args":[{"name":"is-bond","type":"bool"},{"name":"index","type":"uint128"}],"outputs":{"type":"uint128"}} as TypedAbiFunction<[isBond: TypedAbiArg<boolean, "isBond">, index: TypedAbiArg<number | bigint, "index">], bigint>,
    getTotalUstxStacked: {"name":"get-total-ustx-stacked","access":"read_only","args":[{"name":"reward-cycle","type":"uint128"}],"outputs":{"type":"uint128"}} as TypedAbiFunction<[rewardCycle: TypedAbiArg<number | bigint, "rewardCycle">], bigint>,
    getUstxDelegatedForCycle: {"name":"get-ustx-delegated-for-cycle","access":"read_only","args":[{"name":"reward-cycle","type":"uint128"}],"outputs":{"type":"uint128"}} as TypedAbiFunction<[rewardCycle: TypedAbiArg<number | bigint, "rewardCycle">], bigint>,
    isBondActiveAtHeight: {"name":"is-bond-active-at-height","access":"read_only","args":[{"name":"bond-index","type":"uint128"},{"name":"calculation-height","type":"uint128"}],"outputs":{"type":"bool"}} as TypedAbiFunction<[bondIndex: TypedAbiArg<number | bigint, "bondIndex">, calculationHeight: TypedAbiArg<number | bigint, "calculationHeight">], boolean>,
    isInPreparePhase: {"name":"is-in-prepare-phase","access":"read_only","args":[{"name":"current-cycle","type":"uint128"}],"outputs":{"type":"bool"}} as TypedAbiFunction<[currentCycle: TypedAbiArg<number | bigint, "currentCycle">], boolean>,
    minUstxForSatsAmount: {"name":"min-ustx-for-sats-amount","access":"read_only","args":[{"name":"sats-amount","type":"uint128"},{"name":"stx-value-ratio","type":"uint128"},{"name":"min-ustx-ratio","type":"uint128"}],"outputs":{"type":"uint128"}} as TypedAbiFunction<[satsAmount: TypedAbiArg<number | bigint, "satsAmount">, stxValueRatio: TypedAbiArg<number | bigint, "stxValueRatio">, minUstxRatio: TypedAbiArg<number | bigint, "minUstxRatio">], bigint>,
    parseBlockHeader: {"name":"parse-block-header","access":"read_only","args":[{"name":"headerbuff","type":{"buffer":{"length":80}}}],"outputs":{"type":{"response":{"ok":{"tuple":[{"name":"merkle-root","type":{"buffer":{"length":32}}},{"name":"nbits","type":"uint128"},{"name":"nonce","type":"uint128"},{"name":"parent","type":{"buffer":{"length":32}}},{"name":"timestamp","type":"uint128"},{"name":"version","type":"uint128"}]},"error":"uint128"}}}} as TypedAbiFunction<[headerbuff: TypedAbiArg<Uint8Array, "headerbuff">], Response<{
  "merkleRoot": Uint8Array;
  "nbits": bigint;
  "nonce": bigint;
  "parent": Uint8Array;
  "timestamp": bigint;
  "version": bigint;
}, bigint>>,
    pushCScriptNum: {"name":"push-c-script-num","access":"read_only","args":[{"name":"n","type":"uint128"}],"outputs":{"type":{"buffer":{"length":1027}}}} as TypedAbiFunction<[n: TypedAbiArg<number | bigint, "n">], Uint8Array>,
    pushScriptBytes: {"name":"push-script-bytes","access":"read_only","args":[{"name":"bytes","type":{"buffer":{"length":1024}}}],"outputs":{"type":{"buffer":{"length":1027}}}} as TypedAbiFunction<[bytes: TypedAbiArg<Uint8Array, "bytes">], Uint8Array>,
    readHashslice: {"name":"read-hashslice","access":"read_only","args":[{"name":"old-ctx","type":{"tuple":[{"name":"index","type":"uint128"},{"name":"txbuff","type":{"buffer":{"length":4096}}}]}}],"outputs":{"type":{"response":{"ok":{"tuple":[{"name":"ctx","type":{"tuple":[{"name":"index","type":"uint128"},{"name":"txbuff","type":{"buffer":{"length":4096}}}]}},{"name":"hashslice","type":{"buffer":{"length":32}}}]},"error":"uint128"}}}} as TypedAbiFunction<[oldCtx: TypedAbiArg<{
  "index": number | bigint;
  "txbuff": Uint8Array;
}, "oldCtx">], Response<{
  "ctx": {
  "index": bigint;
  "txbuff": Uint8Array;
};
  "hashslice": Uint8Array;
}, bigint>>,
    readUint32: {"name":"read-uint32","access":"read_only","args":[{"name":"ctx","type":{"tuple":[{"name":"index","type":"uint128"},{"name":"txbuff","type":{"buffer":{"length":4096}}}]}}],"outputs":{"type":{"response":{"ok":{"tuple":[{"name":"ctx","type":{"tuple":[{"name":"index","type":"uint128"},{"name":"txbuff","type":{"buffer":{"length":4096}}}]}},{"name":"uint32","type":"uint128"}]},"error":"uint128"}}}} as TypedAbiFunction<[ctx: TypedAbiArg<{
  "index": number | bigint;
  "txbuff": Uint8Array;
}, "ctx">], Response<{
  "ctx": {
  "index": bigint;
  "txbuff": Uint8Array;
};
  "uint32": bigint;
}, bigint>>,
    reverseBuff32: {"name":"reverse-buff32","access":"read_only","args":[{"name":"input","type":{"buffer":{"length":32}}}],"outputs":{"type":{"buffer":{"length":32}}}} as TypedAbiFunction<[input: TypedAbiArg<Uint8Array, "input">], Uint8Array>,
    rewardCycleToBurnHeight: {"name":"reward-cycle-to-burn-height","access":"read_only","args":[{"name":"cycle","type":"uint128"}],"outputs":{"type":"uint128"}} as TypedAbiFunction<[cycle: TypedAbiArg<number | bigint, "cycle">], bigint>,
    rewardCycleToUnlockHeight: {"name":"reward-cycle-to-unlock-height","access":"read_only","args":[{"name":"cycle","type":"uint128"}],"outputs":{"type":"uint128"}} as TypedAbiFunction<[cycle: TypedAbiArg<number | bigint, "cycle">], bigint>,
    serializeCScriptNum: {"name":"serialize-c-script-num","access":"read_only","args":[{"name":"n","type":"uint128"}],"outputs":{"type":{"buffer":{"length":5}}}} as TypedAbiFunction<[n: TypedAbiArg<number | bigint, "n">], Uint8Array>,
    signerSetContainsForCycle: {"name":"signer-set-contains-for-cycle","access":"read_only","args":[{"name":"signer","type":"principal"},{"name":"cycle","type":"uint128"}],"outputs":{"type":"bool"}} as TypedAbiFunction<[signer: TypedAbiArg<string, "signer">, cycle: TypedAbiArg<number | bigint, "cycle">], boolean>,
    uintToBuffLe: {"name":"uint-to-buff-le","access":"read_only","args":[{"name":"n","type":"uint128"}],"outputs":{"type":{"buffer":{"length":2}}}} as TypedAbiFunction<[n: TypedAbiArg<number | bigint, "n">], Uint8Array>,
    verifyBlockHeader: {"name":"verify-block-header","access":"read_only","args":[{"name":"headerbuff","type":{"buffer":{"length":80}}},{"name":"expected-block-height","type":"uint128"}],"outputs":{"type":"bool"}} as TypedAbiFunction<[headerbuff: TypedAbiArg<Uint8Array, "headerbuff">, expectedBlockHeight: TypedAbiArg<number | bigint, "expectedBlockHeight">], boolean>,
    verifySignerKeyGrant: {"name":"verify-signer-key-grant","access":"read_only","args":[{"name":"signer-manager","type":"principal"},{"name":"signer-key","type":{"buffer":{"length":33}}}],"outputs":{"type":{"response":{"ok":"bool","error":"uint128"}}}} as TypedAbiFunction<[signerManager: TypedAbiArg<string, "signerManager">, signerKey: TypedAbiArg<Uint8Array, "signerKey">], Response<boolean, bigint>>
  },
  "maps": {
    allowanceContractCallers: {"name":"allowance-contract-callers","key":{"tuple":[{"name":"contract-caller","type":"principal"},{"name":"sender","type":"principal"}]},"value":{"optional":"uint128"}} as TypedAbiMap<{
  "contractCaller": string;
  "sender": string;
}, bigint | null>,
    protocolBondAllowances: {"name":"protocol-bond-allowances","key":{"tuple":[{"name":"bond-index","type":"uint128"},{"name":"staker","type":"principal"}]},"value":"uint128"} as TypedAbiMap<{
  "bondIndex": number | bigint;
  "staker": string;
}, bigint>,
    protocolBondMemberships: {"name":"protocol-bond-memberships","key":"principal","value":{"tuple":[{"name":"amount-ustx","type":"uint128"},{"name":"bond-index","type":"uint128"},{"name":"is-l1-lock","type":"bool"},{"name":"signer","type":"principal"}]}} as TypedAbiMap<string, {
  "amountUstx": bigint;
  "bondIndex": bigint;
  "isL1Lock": boolean;
  "signer": string;
}>,
    protocolBonds: {"name":"protocol-bonds","key":"uint128","value":{"tuple":[{"name":"early-unlock-admin","type":"principal"},{"name":"early-unlock-bytes","type":{"buffer":{"length":683}}},{"name":"min-ustx-ratio","type":"uint128"},{"name":"stx-value-ratio","type":"uint128"},{"name":"target-rate","type":"uint128"}]}} as TypedAbiMap<number | bigint, {
  "earlyUnlockAdmin": string;
  "earlyUnlockBytes": Uint8Array;
  "minUstxRatio": bigint;
  "stxValueRatio": bigint;
  "targetRate": bigint;
}>,
    protocolBondsTotalStaked: {"name":"protocol-bonds-total-staked","key":"uint128","value":"uint128"} as TypedAbiMap<number | bigint, bigint>,
    rewardsPerTokenForCycle: {"name":"rewards-per-token-for-cycle","key":{"tuple":[{"name":"index","type":"uint128"},{"name":"is-bond","type":"bool"}]},"value":"uint128"} as TypedAbiMap<{
  "index": number | bigint;
  "isBond": boolean;
}, bigint>,
    signerDelegatedPerCycle: {"name":"signer-delegated-per-cycle","key":{"tuple":[{"name":"cycle","type":"uint128"},{"name":"signer","type":"principal"}]},"value":"uint128"} as TypedAbiMap<{
  "cycle": number | bigint;
  "signer": string;
}, bigint>,
    signerKeyGrants: {"name":"signer-key-grants","key":{"tuple":[{"name":"signer-key","type":{"buffer":{"length":33}}},{"name":"signer-manager","type":"principal"}]},"value":"bool"} as TypedAbiMap<{
  "signerKey": Uint8Array;
  "signerManager": string;
}, boolean>,
    signerPendingStakedUstxPerCycle: {"name":"signer-pending-staked-ustx-per-cycle","key":{"tuple":[{"name":"cycle","type":"uint128"},{"name":"signer","type":"principal"}]},"value":"uint128"} as TypedAbiMap<{
  "cycle": number | bigint;
  "signer": string;
}, bigint>,
    signerRewardsPerTokenSettledForCycle: {"name":"signer-rewards-per-token-settled-for-cycle","key":{"tuple":[{"name":"index","type":"uint128"},{"name":"is-bond","type":"bool"},{"name":"signer","type":"principal"}]},"value":"uint128"} as TypedAbiMap<{
  "index": number | bigint;
  "isBond": boolean;
  "signer": string;
}, bigint>,
    signerSetLlFirstForCycle: {"name":"signer-set-ll-first-for-cycle","key":"uint128","value":"principal"} as TypedAbiMap<number | bigint, string>,
    signerSetLlForCycle: {"name":"signer-set-ll-for-cycle","key":{"tuple":[{"name":"cycle","type":"uint128"},{"name":"signer","type":"principal"}]},"value":{"tuple":[{"name":"next","type":{"optional":"principal"}},{"name":"prev","type":{"optional":"principal"}}]}} as TypedAbiMap<{
  "cycle": number | bigint;
  "signer": string;
}, {
  "next": string | null;
  "prev": string | null;
}>,
    signerSetLlLastForCycle: {"name":"signer-set-ll-last-for-cycle","key":"uint128","value":"principal"} as TypedAbiMap<number | bigint, string>,
    signerSharesStakedForCycle: {"name":"signer-shares-staked-for-cycle","key":{"tuple":[{"name":"index","type":"uint128"},{"name":"is-bond","type":"bool"},{"name":"signer","type":"principal"}]},"value":"uint128"} as TypedAbiMap<{
  "index": number | bigint;
  "isBond": boolean;
  "signer": string;
}, bigint>,
    signerUnclaimedRewardsForCycle: {"name":"signer-unclaimed-rewards-for-cycle","key":{"tuple":[{"name":"index","type":"uint128"},{"name":"is-bond","type":"bool"},{"name":"signer","type":"principal"}]},"value":"uint128"} as TypedAbiMap<{
  "index": number | bigint;
  "isBond": boolean;
  "signer": string;
}, bigint>,
    signers: {"name":"signers","key":"principal","value":{"buffer":{"length":33}}} as TypedAbiMap<string, Uint8Array>,
    stakerInfo: {"name":"staker-info","key":"principal","value":{"tuple":[{"name":"amount-ustx","type":"uint128"},{"name":"first-reward-cycle","type":"uint128"},{"name":"num-cycles","type":"uint128"},{"name":"signer","type":"principal"}]}} as TypedAbiMap<string, {
  "amountUstx": bigint;
  "firstRewardCycle": bigint;
  "numCycles": bigint;
  "signer": string;
}>,
    stakerSharesStakedForCycle: {"name":"staker-shares-staked-for-cycle","key":{"tuple":[{"name":"index","type":"uint128"},{"name":"is-bond","type":"bool"},{"name":"signer","type":"principal"},{"name":"staker","type":"principal"}]},"value":"uint128"} as TypedAbiMap<{
  "index": number | bigint;
  "isBond": boolean;
  "signer": string;
  "staker": string;
}, bigint>,
    stakerSignerCycleMemberships: {"name":"staker-signer-cycle-memberships","key":{"tuple":[{"name":"cycle","type":"uint128"},{"name":"staker","type":"principal"}]},"value":{"tuple":[{"name":"amount-ustx","type":"uint128"},{"name":"signer","type":"principal"}]}} as TypedAbiMap<{
  "cycle": number | bigint;
  "staker": string;
}, {
  "amountUstx": bigint;
  "signer": string;
}>,
    totalSharesStakedForCycle: {"name":"total-shares-staked-for-cycle","key":{"tuple":[{"name":"index","type":"uint128"},{"name":"is-bond","type":"bool"}]},"value":"uint128"} as TypedAbiMap<{
  "index": number | bigint;
  "isBond": boolean;
}, bigint>,
    usedSignerKeyGrants: {"name":"used-signer-key-grants","key":{"tuple":[{"name":"auth-id","type":"uint128"},{"name":"signer-key","type":{"buffer":{"length":33}}},{"name":"signer-manager","type":"principal"}]},"value":"bool"} as TypedAbiMap<{
  "authId": number | bigint;
  "signerKey": Uint8Array;
  "signerManager": string;
}, boolean>,
    ustxDelegatedPerCycle: {"name":"ustx-delegated-per-cycle","key":"uint128","value":"uint128"} as TypedAbiMap<number | bigint, bigint>
  },
  "variables": {
    BOND_GAP_CYCLES: {
  name: 'BOND_GAP_CYCLES',
  type: 'uint128',
  access: 'constant'
} as TypedAbiVariable<bigint>,
    BOND_LENGTH_CYCLES: {
  name: 'BOND_LENGTH_CYCLES',
  type: 'uint128',
  access: 'constant'
} as TypedAbiVariable<bigint>,
    ERR_ACTIVE_BOND_NOT_INCLUDED: {
  name: 'ERR_ACTIVE_BOND_NOT_INCLUDED',
  type: {
    response: {
      ok: 'none',
      error: 'uint128'
    }
  },
  access: 'constant'
} as TypedAbiVariable<Response<null, bigint>>,
    ERR_ALREADY_REGISTERED: {
  name: 'ERR_ALREADY_REGISTERED',
  type: {
    response: {
      ok: 'none',
      error: 'uint128'
    }
  },
  access: 'constant'
} as TypedAbiVariable<Response<null, bigint>>,
    ERR_ALREADY_STAKED: {
  name: 'ERR_ALREADY_STAKED',
  type: {
    response: {
      ok: 'none',
      error: 'uint128'
    }
  },
  access: 'constant'
} as TypedAbiVariable<Response<null, bigint>>,
    ERR_BOND_ALREADY_SETUP: {
  name: 'ERR_BOND_ALREADY_SETUP',
  type: {
    response: {
      ok: 'none',
      error: 'uint128'
    }
  },
  access: 'constant'
} as TypedAbiVariable<Response<null, bigint>>,
    ERR_BOND_ALREADY_STARTED: {
  name: 'ERR_BOND_ALREADY_STARTED',
  type: {
    response: {
      ok: 'none',
      error: 'uint128'
    }
  },
  access: 'constant'
} as TypedAbiVariable<Response<null, bigint>>,
    ERR_BOND_NOT_ACTIVE: {
  name: 'ERR_BOND_NOT_ACTIVE',
  type: {
    response: {
      ok: 'none',
      error: 'uint128'
    }
  },
  access: 'constant'
} as TypedAbiVariable<Response<null, bigint>>,
    ERR_BOND_NOT_FOUND: {
  name: 'ERR_BOND_NOT_FOUND',
  type: {
    response: {
      ok: 'none',
      error: 'uint128'
    }
  },
  access: 'constant'
} as TypedAbiVariable<Response<null, bigint>>,
    eRR_CANNOT_ANNOUNCE_L1_EARLY_UNLOCK: {
  name: 'ERR_CANNOT_ANNOUNCE_L1_EARLY_UNLOCK',
  type: {
    response: {
      ok: 'none',
      error: 'uint128'
    }
  },
  access: 'constant'
} as TypedAbiVariable<Response<null, bigint>>,
    ERR_CANNOT_SETUP_BOND_TOO_LATE: {
  name: 'ERR_CANNOT_SETUP_BOND_TOO_LATE',
  type: {
    response: {
      ok: 'none',
      error: 'uint128'
    }
  },
  access: 'constant'
} as TypedAbiVariable<Response<null, bigint>>,
    ERR_CANNOT_SETUP_BOND_TOO_SOON: {
  name: 'ERR_CANNOT_SETUP_BOND_TOO_SOON',
  type: {
    response: {
      ok: 'none',
      error: 'uint128'
    }
  },
  access: 'constant'
} as TypedAbiVariable<Response<null, bigint>>,
    ERR_CANNOT_UNSTAKE_SBTC: {
  name: 'ERR_CANNOT_UNSTAKE_SBTC',
  type: {
    response: {
      ok: 'none',
      error: 'uint128'
    }
  },
  access: 'constant'
} as TypedAbiVariable<Response<null, bigint>>,
    ERR_DISTRIBUTION_ALREADY_COMPUTED: {
  name: 'ERR_DISTRIBUTION_ALREADY_COMPUTED',
  type: {
    response: {
      ok: 'none',
      error: 'uint128'
    }
  },
  access: 'constant'
} as TypedAbiVariable<Response<null, bigint>>,
    ERR_INSUFFICIENT_STX: {
  name: 'ERR_INSUFFICIENT_STX',
  type: {
    response: {
      ok: 'none',
      error: 'uint128'
    }
  },
  access: 'constant'
} as TypedAbiVariable<Response<null, bigint>>,
    ERR_INVALID_BOND_PERIOD_ORDERING: {
  name: 'ERR_INVALID_BOND_PERIOD_ORDERING',
  type: {
    response: {
      ok: 'none',
      error: 'uint128'
    }
  },
  access: 'constant'
} as TypedAbiVariable<Response<null, bigint>>,
    ERR_INVALID_BTC_HEADER: {
  name: 'ERR_INVALID_BTC_HEADER',
  type: {
    response: {
      ok: 'none',
      error: 'uint128'
    }
  },
  access: 'constant'
} as TypedAbiVariable<Response<null, bigint>>,
    ERR_INVALID_LOCKUP_AMOUNT: {
  name: 'ERR_INVALID_LOCKUP_AMOUNT',
  type: {
    response: {
      ok: 'none',
      error: 'uint128'
    }
  },
  access: 'constant'
} as TypedAbiVariable<Response<null, bigint>>,
    ERR_INVALID_LOCKUP_SCRIPT: {
  name: 'ERR_INVALID_LOCKUP_SCRIPT',
  type: {
    response: {
      ok: 'none',
      error: 'uint128'
    }
  },
  access: 'constant'
} as TypedAbiVariable<Response<null, bigint>>,
    ERR_INVALID_MERKLE_PROOF: {
  name: 'ERR_INVALID_MERKLE_PROOF',
  type: {
    response: {
      ok: 'none',
      error: 'uint128'
    }
  },
  access: 'constant'
} as TypedAbiVariable<Response<null, bigint>>,
    ERR_INVALID_NUM_CYCLES: {
  name: 'ERR_INVALID_NUM_CYCLES',
  type: {
    response: {
      ok: 'none',
      error: 'uint128'
    }
  },
  access: 'constant'
} as TypedAbiVariable<Response<null, bigint>>,
    ERR_INVALID_OLD_SIGNER_MANAGER: {
  name: 'ERR_INVALID_OLD_SIGNER_MANAGER',
  type: {
    response: {
      ok: 'none',
      error: 'uint128'
    }
  },
  access: 'constant'
} as TypedAbiVariable<Response<null, bigint>>,
    ERR_INVALID_SIGNATURE_PUBKEY: {
  name: 'ERR_INVALID_SIGNATURE_PUBKEY',
  type: {
    response: {
      ok: 'none',
      error: 'uint128'
    }
  },
  access: 'constant'
} as TypedAbiVariable<Response<null, bigint>>,
    ERR_INVALID_SIGNATURE_RECOVER: {
  name: 'ERR_INVALID_SIGNATURE_RECOVER',
  type: {
    response: {
      ok: 'none',
      error: 'uint128'
    }
  },
  access: 'constant'
} as TypedAbiVariable<Response<null, bigint>>,
    ERR_INVALID_START_BURN_HEIGHT: {
  name: 'ERR_INVALID_START_BURN_HEIGHT',
  type: {
    response: {
      ok: 'none',
      error: 'uint128'
    }
  },
  access: 'constant'
} as TypedAbiVariable<Response<null, bigint>>,
    ERR_INVALID_UNSTAKE_SBTC_AMOUNT: {
  name: 'ERR_INVALID_UNSTAKE_SBTC_AMOUNT',
  type: {
    response: {
      ok: 'none',
      error: 'uint128'
    }
  },
  access: 'constant'
} as TypedAbiVariable<Response<null, bigint>>,
    ERR_NOT_ALLOWLISTED: {
  name: 'ERR_NOT_ALLOWLISTED',
  type: {
    response: {
      ok: 'none',
      error: 'uint128'
    }
  },
  access: 'constant'
} as TypedAbiVariable<Response<null, bigint>>,
    ERR_NOT_BOND_PARTICIPANT: {
  name: 'ERR_NOT_BOND_PARTICIPANT',
  type: {
    response: {
      ok: 'none',
      error: 'uint128'
    }
  },
  access: 'constant'
} as TypedAbiVariable<Response<null, bigint>>,
    ERR_NOT_STAKING: {
  name: 'ERR_NOT_STAKING',
  type: {
    response: {
      ok: 'none',
      error: 'uint128'
    }
  },
  access: 'constant'
} as TypedAbiVariable<Response<null, bigint>>,
    ERR_NO_CLAIMABLE_REWARDS: {
  name: 'ERR_NO_CLAIMABLE_REWARDS',
  type: {
    response: {
      ok: 'none',
      error: 'uint128'
    }
  },
  access: 'constant'
} as TypedAbiVariable<Response<null, bigint>>,
    ERR_READ_TX_OUT_OF_BOUNDS: {
  name: 'ERR_READ_TX_OUT_OF_BOUNDS',
  type: {
    response: {
      ok: 'none',
      error: 'uint128'
    }
  },
  access: 'constant'
} as TypedAbiVariable<Response<null, bigint>>,
    ERR_SIGNER_KEY_GRANT_NOT_FOUND: {
  name: 'ERR_SIGNER_KEY_GRANT_NOT_FOUND',
  type: {
    response: {
      ok: 'none',
      error: 'uint128'
    }
  },
  access: 'constant'
} as TypedAbiVariable<Response<null, bigint>>,
    ERR_SIGNER_KEY_GRANT_USED: {
  name: 'ERR_SIGNER_KEY_GRANT_USED',
  type: {
    response: {
      ok: 'none',
      error: 'uint128'
    }
  },
  access: 'constant'
} as TypedAbiVariable<Response<null, bigint>>,
    ERR_SIGNER_NOT_FOUND: {
  name: 'ERR_SIGNER_NOT_FOUND',
  type: {
    response: {
      ok: 'none',
      error: 'uint128'
    }
  },
  access: 'constant'
} as TypedAbiVariable<Response<null, bigint>>,
    ERR_STAKER_ALREADY_ADDED: {
  name: 'ERR_STAKER_ALREADY_ADDED',
  type: {
    response: {
      ok: 'none',
      error: 'uint128'
    }
  },
  access: 'constant'
} as TypedAbiVariable<Response<null, bigint>>,
    ERR_TOO_MUCH_SATS: {
  name: 'ERR_TOO_MUCH_SATS',
  type: {
    response: {
      ok: 'none',
      error: 'uint128'
    }
  },
  access: 'constant'
} as TypedAbiVariable<Response<null, bigint>>,
    ERR_UNAUTHORIZED: {
  name: 'ERR_UNAUTHORIZED',
  type: {
    response: {
      ok: 'none',
      error: 'uint128'
    }
  },
  access: 'constant'
} as TypedAbiVariable<Response<null, bigint>>,
    ERR_UNAUTHORIZED_CALLER: {
  name: 'ERR_UNAUTHORIZED_CALLER',
  type: {
    response: {
      ok: 'none',
      error: 'uint128'
    }
  },
  access: 'constant'
} as TypedAbiVariable<Response<null, bigint>>,
    ERR_UNAUTHORIZED_SIGNER_REGISTRATION: {
  name: 'ERR_UNAUTHORIZED_SIGNER_REGISTRATION',
  type: {
    response: {
      ok: 'none',
      error: 'uint128'
    }
  },
  access: 'constant'
} as TypedAbiVariable<Response<null, bigint>>,
    ERR_UNSTAKE_IN_PREPARE_PHASE: {
  name: 'ERR_UNSTAKE_IN_PREPARE_PHASE',
  type: {
    response: {
      ok: 'none',
      error: 'uint128'
    }
  },
  access: 'constant'
} as TypedAbiVariable<Response<null, bigint>>,
    ERR_UPDATE_BOND_SAME_SIGNER: {
  name: 'ERR_UPDATE_BOND_SAME_SIGNER',
  type: {
    response: {
      ok: 'none',
      error: 'uint128'
    }
  },
  access: 'constant'
} as TypedAbiVariable<Response<null, bigint>>,
    MAX_NUM_CYCLES: {
  name: 'MAX_NUM_CYCLES',
  type: 'uint128',
  access: 'constant'
} as TypedAbiVariable<bigint>,
    pOX_5_SIGNER_DOMAIN: {
  name: 'POX_5_SIGNER_DOMAIN',
  type: {
    tuple: [
      {
        name: 'chain-id',
        type: 'uint128'
      },
      {
        name: 'name',
        type: {
          'string-ascii': {
            length: 12
          }
        }
      },
      {
        name: 'version',
        type: {
          'string-ascii': {
            length: 5
          }
        }
      }
    ]
  },
  access: 'constant'
} as TypedAbiVariable<{
  "chainId": bigint;
  "name": string;
  "version": string;
}>,
    PRECISION: {
  name: 'PRECISION',
  type: 'uint128',
  access: 'constant'
} as TypedAbiVariable<bigint>,
    RESERVE_RATIO: {
  name: 'RESERVE_RATIO',
  type: 'uint128',
  access: 'constant'
} as TypedAbiVariable<bigint>,
    SIGNER_SET_MIN_USTX: {
  name: 'SIGNER_SET_MIN_USTX',
  type: 'uint128',
  access: 'constant'
} as TypedAbiVariable<bigint>,
    sIP018_MSG_PREFIX: {
  name: 'SIP018_MSG_PREFIX',
  type: {
    buffer: {
      length: 6
    }
  },
  access: 'constant'
} as TypedAbiVariable<Uint8Array>,
    STACKS_ADDR_VERSION_MAINNET: {
  name: 'STACKS_ADDR_VERSION_MAINNET',
  type: {
    buffer: {
      length: 1
    }
  },
  access: 'constant'
} as TypedAbiVariable<Uint8Array>,
    STACKS_ADDR_VERSION_TESTNET: {
  name: 'STACKS_ADDR_VERSION_TESTNET',
  type: {
    buffer: {
      length: 1
    }
  },
  access: 'constant'
} as TypedAbiVariable<Uint8Array>,
    bondAdmin: {
  name: 'bond-admin',
  type: 'principal',
  access: 'variable'
} as TypedAbiVariable<string>,
    configured: {
  name: 'configured',
  type: 'bool',
  access: 'variable'
} as TypedAbiVariable<boolean>,
    firstBondPeriodCycle: {
  name: 'first-bond-period-cycle',
  type: 'uint128',
  access: 'variable'
} as TypedAbiVariable<bigint>,
    firstBurnchainBlockHeight: {
  name: 'first-burnchain-block-height',
  type: 'uint128',
  access: 'variable'
} as TypedAbiVariable<bigint>,
    firstPox5RewardCycle: {
  name: 'first-pox-5-reward-cycle',
  type: 'uint128',
  access: 'variable'
} as TypedAbiVariable<bigint>,
    lastAccountedRewardsOnly: {
  name: 'last-accounted-rewards-only',
  type: 'uint128',
  access: 'variable'
} as TypedAbiVariable<bigint>,
    lastRewardComputeHeight: {
  name: 'last-reward-compute-height',
  type: 'uint128',
  access: 'variable'
} as TypedAbiVariable<bigint>,
    poxPrepareCycleLength: {
  name: 'pox-prepare-cycle-length',
  type: 'uint128',
  access: 'variable'
} as TypedAbiVariable<bigint>,
    poxRewardCycleLength: {
  name: 'pox-reward-cycle-length',
  type: 'uint128',
  access: 'variable'
} as TypedAbiVariable<bigint>,
    reserveBalance: {
  name: 'reserve-balance',
  type: 'uint128',
  access: 'variable'
} as TypedAbiVariable<bigint>,
    totalSbtcStaked: {
  name: 'total-sbtc-staked',
  type: 'uint128',
  access: 'variable'
} as TypedAbiVariable<bigint>
  },
  constants: {
  BOND_GAP_CYCLES: 2n,
  BOND_LENGTH_CYCLES: 12n,
  ERR_ACTIVE_BOND_NOT_INCLUDED: {
    isOk: false,
    value: 33n
  },
  ERR_ALREADY_REGISTERED: {
    isOk: false,
    value: 9n
  },
  ERR_ALREADY_STAKED: {
    isOk: false,
    value: 19n
  },
  ERR_BOND_ALREADY_SETUP: {
    isOk: false,
    value: 4n
  },
  ERR_BOND_ALREADY_STARTED: {
    isOk: false,
    value: 43n
  },
  ERR_BOND_NOT_ACTIVE: {
    isOk: false,
    value: 31n
  },
  ERR_BOND_NOT_FOUND: {
    isOk: false,
    value: 7n
  },
  eRR_CANNOT_ANNOUNCE_L1_EARLY_UNLOCK: {
    isOk: false,
    value: 35n
  },
  ERR_CANNOT_SETUP_BOND_TOO_LATE: {
    isOk: false,
    value: 3n
  },
  ERR_CANNOT_SETUP_BOND_TOO_SOON: {
    isOk: false,
    value: 2n
  },
  ERR_CANNOT_UNSTAKE_SBTC: {
    isOk: false,
    value: 38n
  },
  ERR_DISTRIBUTION_ALREADY_COMPUTED: {
    isOk: false,
    value: 30n
  },
  ERR_INSUFFICIENT_STX: {
    isOk: false,
    value: 8n
  },
  ERR_INVALID_BOND_PERIOD_ORDERING: {
    isOk: false,
    value: 29n
  },
  ERR_INVALID_BTC_HEADER: {
    isOk: false,
    value: 40n
  },
  ERR_INVALID_LOCKUP_AMOUNT: {
    isOk: false,
    value: 45n
  },
  ERR_INVALID_LOCKUP_SCRIPT: {
    isOk: false,
    value: 42n
  },
  ERR_INVALID_MERKLE_PROOF: {
    isOk: false,
    value: 41n
  },
  ERR_INVALID_NUM_CYCLES: {
    isOk: false,
    value: 20n
  },
  ERR_INVALID_OLD_SIGNER_MANAGER: {
    isOk: false,
    value: 36n
  },
  ERR_INVALID_SIGNATURE_PUBKEY: {
    isOk: false,
    value: 14n
  },
  ERR_INVALID_SIGNATURE_RECOVER: {
    isOk: false,
    value: 13n
  },
  ERR_INVALID_START_BURN_HEIGHT: {
    isOk: false,
    value: 24n
  },
  ERR_INVALID_UNSTAKE_SBTC_AMOUNT: {
    isOk: false,
    value: 37n
  },
  ERR_NOT_ALLOWLISTED: {
    isOk: false,
    value: 11n
  },
  ERR_NOT_BOND_PARTICIPANT: {
    isOk: false,
    value: 34n
  },
  ERR_NOT_STAKING: {
    isOk: false,
    value: 27n
  },
  ERR_NO_CLAIMABLE_REWARDS: {
    isOk: false,
    value: 32n
  },
  ERR_READ_TX_OUT_OF_BOUNDS: {
    isOk: false,
    value: 39n
  },
  ERR_SIGNER_KEY_GRANT_NOT_FOUND: {
    isOk: false,
    value: 17n
  },
  ERR_SIGNER_KEY_GRANT_USED: {
    isOk: false,
    value: 12n
  },
  ERR_SIGNER_NOT_FOUND: {
    isOk: false,
    value: 23n
  },
  ERR_STAKER_ALREADY_ADDED: {
    isOk: false,
    value: 5n
  },
  ERR_TOO_MUCH_SATS: {
    isOk: false,
    value: 10n
  },
  ERR_UNAUTHORIZED: {
    isOk: false,
    value: 1n
  },
  ERR_UNAUTHORIZED_CALLER: {
    isOk: false,
    value: 22n
  },
  ERR_UNAUTHORIZED_SIGNER_REGISTRATION: {
    isOk: false,
    value: 26n
  },
  ERR_UNSTAKE_IN_PREPARE_PHASE: {
    isOk: false,
    value: 28n
  },
  ERR_UPDATE_BOND_SAME_SIGNER: {
    isOk: false,
    value: 44n
  },
  MAX_NUM_CYCLES: 96n,
  pOX_5_SIGNER_DOMAIN: {
    chainId: 2_147_483_648n,
    name: 'pox-5-signer',
    version: '1.0.0'
  },
  PRECISION: 1_000_000_000_000_000_000n,
  RESERVE_RATIO: 1_500n,
  SIGNER_SET_MIN_USTX: 50_000_000_000n,
  sIP018_MSG_PREFIX: Uint8Array.from([83,73,80,48,49,56]),
  STACKS_ADDR_VERSION_MAINNET: Uint8Array.from([22]),
  STACKS_ADDR_VERSION_TESTNET: Uint8Array.from([26]),
  bondAdmin: 'SP000000000000000000002Q6VF78',
  configured: false,
  firstBondPeriodCycle: 0n,
  firstBurnchainBlockHeight: 0n,
  firstPox5RewardCycle: 0n,
  lastAccountedRewardsOnly: 0n,
  lastRewardComputeHeight: 0n,
  poxPrepareCycleLength: 50n,
  poxRewardCycleLength: 1_050n,
  reserveBalance: 0n,
  totalSbtcStaked: 0n
},
  "non_fungible_tokens": [
    
  ],
  "fungible_tokens":[],"epoch":"Epoch40","clarity_version":"Clarity6",
  contractName: 'pox-5',
  },
pox5Signer: {
  "functions": {
    checkpointStakerForIndex: {"name":"checkpoint-staker-for-index","access":"private","args":[{"name":"index-offset","type":"uint128"},{"name":"acc-res","type":{"response":{"ok":{"tuple":[{"name":"first-index","type":"uint128"},{"name":"is-bond","type":"bool"},{"name":"staker","type":"principal"}]},"error":"uint128"}}}],"outputs":{"type":{"response":{"ok":{"tuple":[{"name":"first-index","type":"uint128"},{"name":"is-bond","type":"bool"},{"name":"staker","type":"principal"}]},"error":"uint128"}}}} as TypedAbiFunction<[indexOffset: TypedAbiArg<number | bigint, "indexOffset">, accRes: TypedAbiArg<Response<{
  "firstIndex": number | bigint;
  "isBond": boolean;
  "staker": string;
}, number | bigint>, "accRes">], Response<{
  "firstIndex": bigint;
  "isBond": boolean;
  "staker": string;
}, bigint>>,
    settleStakerRewards: {"name":"settle-staker-rewards","access":"private","args":[{"name":"staker","type":"principal"},{"name":"is-bond","type":"bool"},{"name":"index","type":"uint128"}],"outputs":{"type":{"tuple":[{"name":"earned","type":"uint128"},{"name":"rewards-per-token","type":"uint128"}]}}} as TypedAbiFunction<[staker: TypedAbiArg<string, "staker">, isBond: TypedAbiArg<boolean, "isBond">, index: TypedAbiArg<number | bigint, "index">], {
  "earned": bigint;
  "rewardsPerToken": bigint;
}>,
    updateBondRewardsInfo: {"name":"update-bond-rewards-info","access":"private","args":[{"name":"bond-info","type":{"tuple":[{"name":"bond-index","type":"uint128"},{"name":"earned","type":"uint128"},{"name":"rewards-per-token","type":"uint128"}]}},{"name":"acc","type":"bool"}],"outputs":{"type":"bool"}} as TypedAbiFunction<[bondInfo: TypedAbiArg<{
  "bondIndex": number | bigint;
  "earned": number | bigint;
  "rewardsPerToken": number | bigint;
}, "bondInfo">, acc: TypedAbiArg<boolean, "acc">], boolean>,
    updateRewardsInfo: {"name":"update-rewards-info","access":"private","args":[{"name":"rewards-per-share","type":"uint128"},{"name":"is-bond","type":"bool"},{"name":"index","type":"uint128"}],"outputs":{"type":"bool"}} as TypedAbiFunction<[rewardsPerShare: TypedAbiArg<number | bigint, "rewardsPerShare">, isBond: TypedAbiArg<boolean, "isBond">, index: TypedAbiArg<number | bigint, "index">], boolean>,
    checkpointStaker: {"name":"checkpoint-staker","access":"public","args":[{"name":"staker","type":"principal"},{"name":"first-index","type":"uint128"},{"name":"num-indexes","type":"uint128"},{"name":"is-bond","type":"bool"}],"outputs":{"type":{"response":{"ok":"bool","error":"uint128"}}}} as TypedAbiFunction<[staker: TypedAbiArg<string, "staker">, firstIndex: TypedAbiArg<number | bigint, "firstIndex">, numIndexes: TypedAbiArg<number | bigint, "numIndexes">, isBond: TypedAbiArg<boolean, "isBond">], Response<boolean, bigint>>,
    claimRewards: {"name":"claim-rewards","access":"public","args":[{"name":"bond-periods","type":{"list":{"type":"uint128","length":6}}},{"name":"reward-cycle","type":"uint128"}],"outputs":{"type":{"response":{"ok":{"tuple":[{"name":"bond-rewards","type":{"list":{"type":{"tuple":[{"name":"bond-index","type":"uint128"},{"name":"earned","type":"uint128"},{"name":"rewards-per-token","type":"uint128"}]},"length":6}}},{"name":"bond-totals","type":"uint128"},{"name":"stx-rewards","type":{"tuple":[{"name":"earned","type":"uint128"},{"name":"rewards-per-token","type":"uint128"}]}},{"name":"total-rewards","type":"uint128"}]},"error":"uint128"}}}} as TypedAbiFunction<[bondPeriods: TypedAbiArg<number | bigint[], "bondPeriods">, rewardCycle: TypedAbiArg<number | bigint, "rewardCycle">], Response<{
  "bondRewards": {
  "bondIndex": bigint;
  "earned": bigint;
  "rewardsPerToken": bigint;
}[];
  "bondTotals": bigint;
  "stxRewards": {
  "earned": bigint;
  "rewardsPerToken": bigint;
};
  "totalRewards": bigint;
}, bigint>>,
    claimStakerRewards: {"name":"claim-staker-rewards","access":"public","args":[{"name":"is-bond","type":"bool"},{"name":"index","type":"uint128"}],"outputs":{"type":{"response":{"ok":"uint128","error":"uint128"}}}} as TypedAbiFunction<[isBond: TypedAbiArg<boolean, "isBond">, index: TypedAbiArg<number | bigint, "index">], Response<bigint, bigint>>,
    registerSelf: {"name":"register-self","access":"public","args":[{"name":"signer-manager","type":"trait_reference"},{"name":"signer-key","type":{"buffer":{"length":33}}},{"name":"auth-id","type":"uint128"},{"name":"signer-sig","type":{"buffer":{"length":65}}}],"outputs":{"type":{"response":{"ok":{"tuple":[{"name":"signer","type":"principal"},{"name":"signer-key","type":{"buffer":{"length":33}}}]},"error":"uint128"}}}} as TypedAbiFunction<[signerManager: TypedAbiArg<string, "signerManager">, signerKey: TypedAbiArg<Uint8Array, "signerKey">, authId: TypedAbiArg<number | bigint, "authId">, signerSig: TypedAbiArg<Uint8Array, "signerSig">], Response<{
  "signer": string;
  "signerKey": Uint8Array;
}, bigint>>,
    validateStake_x: {"name":"validate-stake!","access":"public","args":[{"name":"staker","type":"principal"},{"name":"first-index","type":"uint128"},{"name":"num-indexes","type":"uint128"},{"name":"amount-ustx","type":"uint128"},{"name":"amount-sats","type":"uint128"},{"name":"is-bond","type":"bool"},{"name":"signer-calldata","type":{"optional":{"buffer":{"length":500}}}}],"outputs":{"type":{"response":{"ok":"bool","error":"none"}}}} as TypedAbiFunction<[staker: TypedAbiArg<string, "staker">, firstIndex: TypedAbiArg<number | bigint, "firstIndex">, numIndexes: TypedAbiArg<number | bigint, "numIndexes">, amountUstx: TypedAbiArg<number | bigint, "amountUstx">, amountSats: TypedAbiArg<number | bigint, "amountSats">, isBond: TypedAbiArg<boolean, "isBond">, signerCalldata: TypedAbiArg<Uint8Array | null, "signerCalldata">], Response<boolean, null>>,
    getEarnedStakerRewards: {"name":"get-earned-staker-rewards","access":"read_only","args":[{"name":"staker","type":"principal"},{"name":"is-bond","type":"bool"},{"name":"index","type":"uint128"}],"outputs":{"type":"uint128"}} as TypedAbiFunction<[staker: TypedAbiArg<string, "staker">, isBond: TypedAbiArg<boolean, "isBond">, index: TypedAbiArg<number | bigint, "index">], bigint>,
    getRewardsPerTokenForCycle: {"name":"get-rewards-per-token-for-cycle","access":"read_only","args":[{"name":"is-bond","type":"bool"},{"name":"index","type":"uint128"}],"outputs":{"type":"uint128"}} as TypedAbiFunction<[isBond: TypedAbiArg<boolean, "isBond">, index: TypedAbiArg<number | bigint, "index">], bigint>,
    getStakerRewardsPerTokenSettledForCycle: {"name":"get-staker-rewards-per-token-settled-for-cycle","access":"read_only","args":[{"name":"staker","type":"principal"},{"name":"is-bond","type":"bool"},{"name":"index","type":"uint128"}],"outputs":{"type":"uint128"}} as TypedAbiFunction<[staker: TypedAbiArg<string, "staker">, isBond: TypedAbiArg<boolean, "isBond">, index: TypedAbiArg<number | bigint, "index">], bigint>,
    getStakerUnclaimedRewardsForCycle: {"name":"get-staker-unclaimed-rewards-for-cycle","access":"read_only","args":[{"name":"staker","type":"principal"},{"name":"is-bond","type":"bool"},{"name":"index","type":"uint128"}],"outputs":{"type":"uint128"}} as TypedAbiFunction<[staker: TypedAbiArg<string, "staker">, isBond: TypedAbiArg<boolean, "isBond">, index: TypedAbiArg<number | bigint, "index">], bigint>
  },
  "maps": {
    rewardsPerTokenForCycle: {"name":"rewards-per-token-for-cycle","key":{"tuple":[{"name":"index","type":"uint128"},{"name":"is-bond","type":"bool"}]},"value":"uint128"} as TypedAbiMap<{
  "index": number | bigint;
  "isBond": boolean;
}, bigint>,
    stakerRewardsPerTokenSettledForCycle: {"name":"staker-rewards-per-token-settled-for-cycle","key":{"tuple":[{"name":"index","type":"uint128"},{"name":"is-bond","type":"bool"},{"name":"staker","type":"principal"}]},"value":"uint128"} as TypedAbiMap<{
  "index": number | bigint;
  "isBond": boolean;
  "staker": string;
}, bigint>,
    stakerUnclaimedRewardsForCycle: {"name":"staker-unclaimed-rewards-for-cycle","key":{"tuple":[{"name":"index","type":"uint128"},{"name":"is-bond","type":"bool"},{"name":"staker","type":"principal"}]},"value":"uint128"} as TypedAbiMap<{
  "index": number | bigint;
  "isBond": boolean;
  "staker": string;
}, bigint>
  },
  "variables": {
    ERR_NO_CLAIMABLE_REWARDS: {
  name: 'ERR_NO_CLAIMABLE_REWARDS',
  type: {
    response: {
      ok: 'none',
      error: 'uint128'
    }
  },
  access: 'constant'
} as TypedAbiVariable<Response<null, bigint>>,
    PRECISION: {
  name: 'PRECISION',
  type: 'uint128',
  access: 'constant'
} as TypedAbiVariable<bigint>
  },
  constants: {
  ERR_NO_CLAIMABLE_REWARDS: {
    isOk: false,
    value: 1_001n
  },
  PRECISION: 1_000_000_000_000_000_000n
},
  "non_fungible_tokens": [
    
  ],
  "fungible_tokens":[],"epoch":"Epoch40","clarity_version":"Clarity6",
  contractName: 'pox-5-signer',
  },
sbtcRegistry: {
  "functions": {
    incrementLastWithdrawalRequestId: {"name":"increment-last-withdrawal-request-id","access":"private","args":[],"outputs":{"type":"uint128"}} as TypedAbiFunction<[], bigint>,
    completeDeposit: {"name":"complete-deposit","access":"public","args":[{"name":"txid","type":{"buffer":{"length":32}}},{"name":"vout-index","type":"uint128"},{"name":"amount","type":"uint128"},{"name":"recipient","type":"principal"},{"name":"burn-hash","type":{"buffer":{"length":32}}},{"name":"burn-height","type":"uint128"},{"name":"sweep-txid","type":{"buffer":{"length":32}}}],"outputs":{"type":{"response":{"ok":"bool","error":"uint128"}}}} as TypedAbiFunction<[txid: TypedAbiArg<Uint8Array, "txid">, voutIndex: TypedAbiArg<number | bigint, "voutIndex">, amount: TypedAbiArg<number | bigint, "amount">, recipient: TypedAbiArg<string, "recipient">, burnHash: TypedAbiArg<Uint8Array, "burnHash">, burnHeight: TypedAbiArg<number | bigint, "burnHeight">, sweepTxid: TypedAbiArg<Uint8Array, "sweepTxid">], Response<boolean, bigint>>,
    completeWithdrawalAccept: {"name":"complete-withdrawal-accept","access":"public","args":[{"name":"request-id","type":"uint128"},{"name":"bitcoin-txid","type":{"buffer":{"length":32}}},{"name":"output-index","type":"uint128"},{"name":"signer-bitmap","type":"uint128"},{"name":"fee","type":"uint128"},{"name":"burn-hash","type":{"buffer":{"length":32}}},{"name":"burn-height","type":"uint128"},{"name":"sweep-txid","type":{"buffer":{"length":32}}}],"outputs":{"type":{"response":{"ok":"bool","error":"uint128"}}}} as TypedAbiFunction<[requestId: TypedAbiArg<number | bigint, "requestId">, bitcoinTxid: TypedAbiArg<Uint8Array, "bitcoinTxid">, outputIndex: TypedAbiArg<number | bigint, "outputIndex">, signerBitmap: TypedAbiArg<number | bigint, "signerBitmap">, fee: TypedAbiArg<number | bigint, "fee">, burnHash: TypedAbiArg<Uint8Array, "burnHash">, burnHeight: TypedAbiArg<number | bigint, "burnHeight">, sweepTxid: TypedAbiArg<Uint8Array, "sweepTxid">], Response<boolean, bigint>>,
    completeWithdrawalReject: {"name":"complete-withdrawal-reject","access":"public","args":[{"name":"request-id","type":"uint128"},{"name":"signer-bitmap","type":"uint128"}],"outputs":{"type":{"response":{"ok":"bool","error":"uint128"}}}} as TypedAbiFunction<[requestId: TypedAbiArg<number | bigint, "requestId">, signerBitmap: TypedAbiArg<number | bigint, "signerBitmap">], Response<boolean, bigint>>,
    createWithdrawalRequest: {"name":"create-withdrawal-request","access":"public","args":[{"name":"amount","type":"uint128"},{"name":"max-fee","type":"uint128"},{"name":"sender","type":"principal"},{"name":"recipient","type":{"tuple":[{"name":"hashbytes","type":{"buffer":{"length":32}}},{"name":"version","type":{"buffer":{"length":1}}}]}},{"name":"height","type":"uint128"}],"outputs":{"type":{"response":{"ok":"uint128","error":"uint128"}}}} as TypedAbiFunction<[amount: TypedAbiArg<number | bigint, "amount">, maxFee: TypedAbiArg<number | bigint, "maxFee">, sender: TypedAbiArg<string, "sender">, recipient: TypedAbiArg<{
  "hashbytes": Uint8Array;
  "version": Uint8Array;
}, "recipient">, height: TypedAbiArg<number | bigint, "height">], Response<bigint, bigint>>,
    rotateKeys: {"name":"rotate-keys","access":"public","args":[{"name":"new-keys","type":{"list":{"type":{"buffer":{"length":33}},"length":128}}},{"name":"new-address","type":"principal"},{"name":"new-aggregate-pubkey","type":{"buffer":{"length":33}}},{"name":"new-signature-threshold","type":"uint128"}],"outputs":{"type":{"response":{"ok":"bool","error":"uint128"}}}} as TypedAbiFunction<[newKeys: TypedAbiArg<Uint8Array[], "newKeys">, newAddress: TypedAbiArg<string, "newAddress">, newAggregatePubkey: TypedAbiArg<Uint8Array, "newAggregatePubkey">, newSignatureThreshold: TypedAbiArg<number | bigint, "newSignatureThreshold">], Response<boolean, bigint>>,
    updateProtocolContract: {"name":"update-protocol-contract","access":"public","args":[{"name":"contract-type","type":{"buffer":{"length":1}}},{"name":"new-contract","type":"principal"}],"outputs":{"type":{"response":{"ok":"bool","error":"uint128"}}}} as TypedAbiFunction<[contractType: TypedAbiArg<Uint8Array, "contractType">, newContract: TypedAbiArg<string, "newContract">], Response<boolean, bigint>>,
    getActiveProtocol: {"name":"get-active-protocol","access":"read_only","args":[{"name":"contract-flag","type":{"buffer":{"length":1}}}],"outputs":{"type":{"optional":"principal"}}} as TypedAbiFunction<[contractFlag: TypedAbiArg<Uint8Array, "contractFlag">], string | null>,
    getCompletedDeposit: {"name":"get-completed-deposit","access":"read_only","args":[{"name":"txid","type":{"buffer":{"length":32}}},{"name":"vout-index","type":"uint128"}],"outputs":{"type":{"optional":{"tuple":[{"name":"amount","type":"uint128"},{"name":"recipient","type":"principal"},{"name":"sweep-burn-hash","type":{"buffer":{"length":32}}},{"name":"sweep-burn-height","type":"uint128"},{"name":"sweep-txid","type":{"buffer":{"length":32}}}]}}}} as TypedAbiFunction<[txid: TypedAbiArg<Uint8Array, "txid">, voutIndex: TypedAbiArg<number | bigint, "voutIndex">], {
  "amount": bigint;
  "recipient": string;
  "sweepBurnHash": Uint8Array;
  "sweepBurnHeight": bigint;
  "sweepTxid": Uint8Array;
} | null>,
    getCompletedWithdrawalSweepData: {"name":"get-completed-withdrawal-sweep-data","access":"read_only","args":[{"name":"id","type":"uint128"}],"outputs":{"type":{"optional":{"tuple":[{"name":"sweep-burn-hash","type":{"buffer":{"length":32}}},{"name":"sweep-burn-height","type":"uint128"},{"name":"sweep-txid","type":{"buffer":{"length":32}}}]}}}} as TypedAbiFunction<[id: TypedAbiArg<number | bigint, "id">], {
  "sweepBurnHash": Uint8Array;
  "sweepBurnHeight": bigint;
  "sweepTxid": Uint8Array;
} | null>,
    getCurrentAggregatePubkey: {"name":"get-current-aggregate-pubkey","access":"read_only","args":[],"outputs":{"type":{"buffer":{"length":33}}}} as TypedAbiFunction<[], Uint8Array>,
    getCurrentSignerData: {"name":"get-current-signer-data","access":"read_only","args":[],"outputs":{"type":{"tuple":[{"name":"current-aggregate-pubkey","type":{"buffer":{"length":33}}},{"name":"current-signature-threshold","type":"uint128"},{"name":"current-signer-principal","type":"principal"},{"name":"current-signer-set","type":{"list":{"type":{"buffer":{"length":33}},"length":128}}}]}}} as TypedAbiFunction<[], {
  "currentAggregatePubkey": Uint8Array;
  "currentSignatureThreshold": bigint;
  "currentSignerPrincipal": string;
  "currentSignerSet": Uint8Array[];
}>,
    getCurrentSignerPrincipal: {"name":"get-current-signer-principal","access":"read_only","args":[],"outputs":{"type":"principal"}} as TypedAbiFunction<[], string>,
    getCurrentSignerSet: {"name":"get-current-signer-set","access":"read_only","args":[],"outputs":{"type":{"list":{"type":{"buffer":{"length":33}},"length":128}}}} as TypedAbiFunction<[], Uint8Array[]>,
    getDepositStatus: {"name":"get-deposit-status","access":"read_only","args":[{"name":"txid","type":{"buffer":{"length":32}}},{"name":"vout-index","type":"uint128"}],"outputs":{"type":{"optional":"bool"}}} as TypedAbiFunction<[txid: TypedAbiArg<Uint8Array, "txid">, voutIndex: TypedAbiArg<number | bigint, "voutIndex">], boolean | null>,
    getWithdrawalRequest: {"name":"get-withdrawal-request","access":"read_only","args":[{"name":"id","type":"uint128"}],"outputs":{"type":{"optional":{"tuple":[{"name":"amount","type":"uint128"},{"name":"block-height","type":"uint128"},{"name":"max-fee","type":"uint128"},{"name":"recipient","type":{"tuple":[{"name":"hashbytes","type":{"buffer":{"length":32}}},{"name":"version","type":{"buffer":{"length":1}}}]}},{"name":"sender","type":"principal"},{"name":"status","type":{"optional":"bool"}}]}}}} as TypedAbiFunction<[id: TypedAbiArg<number | bigint, "id">], {
  "amount": bigint;
  "blockHeight": bigint;
  "maxFee": bigint;
  "recipient": {
  "hashbytes": Uint8Array;
  "version": Uint8Array;
};
  "sender": string;
  "status": boolean | null;
} | null>,
    isProtocolCaller: {"name":"is-protocol-caller","access":"read_only","args":[{"name":"contract-flag","type":{"buffer":{"length":1}}},{"name":"contract","type":"principal"}],"outputs":{"type":{"response":{"ok":"bool","error":"uint128"}}}} as TypedAbiFunction<[contractFlag: TypedAbiArg<Uint8Array, "contractFlag">, contract: TypedAbiArg<string, "contract">], Response<boolean, bigint>>
  },
  "maps": {
    activeProtocolContracts: {"name":"active-protocol-contracts","key":{"buffer":{"length":1}},"value":"principal"} as TypedAbiMap<Uint8Array, string>,
    activeProtocolRoles: {"name":"active-protocol-roles","key":"principal","value":{"buffer":{"length":1}}} as TypedAbiMap<string, Uint8Array>,
    aggregatePubkeys: {"name":"aggregate-pubkeys","key":{"buffer":{"length":33}},"value":"bool"} as TypedAbiMap<Uint8Array, boolean>,
    completedDeposits: {"name":"completed-deposits","key":{"tuple":[{"name":"txid","type":{"buffer":{"length":32}}},{"name":"vout-index","type":"uint128"}]},"value":{"tuple":[{"name":"amount","type":"uint128"},{"name":"recipient","type":"principal"},{"name":"sweep-burn-hash","type":{"buffer":{"length":32}}},{"name":"sweep-burn-height","type":"uint128"},{"name":"sweep-txid","type":{"buffer":{"length":32}}}]}} as TypedAbiMap<{
  "txid": Uint8Array;
  "voutIndex": number | bigint;
}, {
  "amount": bigint;
  "recipient": string;
  "sweepBurnHash": Uint8Array;
  "sweepBurnHeight": bigint;
  "sweepTxid": Uint8Array;
}>,
    completedWithdrawalSweep: {"name":"completed-withdrawal-sweep","key":"uint128","value":{"tuple":[{"name":"sweep-burn-hash","type":{"buffer":{"length":32}}},{"name":"sweep-burn-height","type":"uint128"},{"name":"sweep-txid","type":{"buffer":{"length":32}}}]}} as TypedAbiMap<number | bigint, {
  "sweepBurnHash": Uint8Array;
  "sweepBurnHeight": bigint;
  "sweepTxid": Uint8Array;
}>,
    depositStatus: {"name":"deposit-status","key":{"tuple":[{"name":"txid","type":{"buffer":{"length":32}}},{"name":"vout-index","type":"uint128"}]},"value":"bool"} as TypedAbiMap<{
  "txid": Uint8Array;
  "voutIndex": number | bigint;
}, boolean>,
    withdrawalRequests: {"name":"withdrawal-requests","key":"uint128","value":{"tuple":[{"name":"amount","type":"uint128"},{"name":"block-height","type":"uint128"},{"name":"max-fee","type":"uint128"},{"name":"recipient","type":{"tuple":[{"name":"hashbytes","type":{"buffer":{"length":32}}},{"name":"version","type":{"buffer":{"length":1}}}]}},{"name":"sender","type":"principal"}]}} as TypedAbiMap<number | bigint, {
  "amount": bigint;
  "blockHeight": bigint;
  "maxFee": bigint;
  "recipient": {
  "hashbytes": Uint8Array;
  "version": Uint8Array;
};
  "sender": string;
}>,
    withdrawalStatus: {"name":"withdrawal-status","key":"uint128","value":"bool"} as TypedAbiMap<number | bigint, boolean>
  },
  "variables": {
    ERR_AGG_PUBKEY_REPLAY: {
  name: 'ERR_AGG_PUBKEY_REPLAY',
  type: {
    response: {
      ok: 'none',
      error: 'uint128'
    }
  },
  access: 'constant'
} as TypedAbiVariable<Response<null, bigint>>,
    ERR_INVALID_REQUEST_ID: {
  name: 'ERR_INVALID_REQUEST_ID',
  type: {
    response: {
      ok: 'none',
      error: 'uint128'
    }
  },
  access: 'constant'
} as TypedAbiVariable<Response<null, bigint>>,
    ERR_UNAUTHORIZED: {
  name: 'ERR_UNAUTHORIZED',
  type: {
    response: {
      ok: 'none',
      error: 'uint128'
    }
  },
  access: 'constant'
} as TypedAbiVariable<Response<null, bigint>>,
    depositRole: {
  name: 'deposit-role',
  type: {
    buffer: {
      length: 1
    }
  },
  access: 'constant'
} as TypedAbiVariable<Uint8Array>,
    governanceRole: {
  name: 'governance-role',
  type: {
    buffer: {
      length: 1
    }
  },
  access: 'constant'
} as TypedAbiVariable<Uint8Array>,
    withdrawalRole: {
  name: 'withdrawal-role',
  type: {
    buffer: {
      length: 1
    }
  },
  access: 'constant'
} as TypedAbiVariable<Uint8Array>,
    currentAggregatePubkey: {
  name: 'current-aggregate-pubkey',
  type: {
    buffer: {
      length: 33
    }
  },
  access: 'variable'
} as TypedAbiVariable<Uint8Array>,
    currentSignatureThreshold: {
  name: 'current-signature-threshold',
  type: 'uint128',
  access: 'variable'
} as TypedAbiVariable<bigint>,
    currentSignerPrincipal: {
  name: 'current-signer-principal',
  type: 'principal',
  access: 'variable'
} as TypedAbiVariable<string>,
    currentSignerSet: {
  name: 'current-signer-set',
  type: {
    list: {
      type: {
        buffer: {
          length: 33
        }
      },
      length: 128
    }
  },
  access: 'variable'
} as TypedAbiVariable<Uint8Array[]>,
    lastWithdrawalRequestId: {
  name: 'last-withdrawal-request-id',
  type: 'uint128',
  access: 'variable'
} as TypedAbiVariable<bigint>
  },
  constants: {},
  "non_fungible_tokens": [
    
  ],
  "fungible_tokens":[],"epoch":"Epoch30","clarity_version":"Clarity3",
  contractName: 'sbtc-registry',
  },
sbtcToken: {
  "functions": {
    protocolMintManyIter: {"name":"protocol-mint-many-iter","access":"private","args":[{"name":"item","type":{"tuple":[{"name":"amount","type":"uint128"},{"name":"recipient","type":"principal"}]}}],"outputs":{"type":{"response":{"ok":"bool","error":"uint128"}}}} as TypedAbiFunction<[item: TypedAbiArg<{
  "amount": number | bigint;
  "recipient": string;
}, "item">], Response<boolean, bigint>>,
    transferManyIter: {"name":"transfer-many-iter","access":"private","args":[{"name":"individual-transfer","type":{"tuple":[{"name":"amount","type":"uint128"},{"name":"memo","type":{"optional":{"buffer":{"length":34}}}},{"name":"sender","type":"principal"},{"name":"to","type":"principal"}]}},{"name":"result","type":{"response":{"ok":"uint128","error":"uint128"}}}],"outputs":{"type":{"response":{"ok":"uint128","error":"uint128"}}}} as TypedAbiFunction<[individualTransfer: TypedAbiArg<{
  "amount": number | bigint;
  "memo": Uint8Array | null;
  "sender": string;
  "to": string;
}, "individualTransfer">, result: TypedAbiArg<Response<number | bigint, number | bigint>, "result">], Response<bigint, bigint>>,
    protocolBurn: {"name":"protocol-burn","access":"public","args":[{"name":"amount","type":"uint128"},{"name":"owner","type":"principal"},{"name":"contract-flag","type":{"buffer":{"length":1}}}],"outputs":{"type":{"response":{"ok":"bool","error":"uint128"}}}} as TypedAbiFunction<[amount: TypedAbiArg<number | bigint, "amount">, owner: TypedAbiArg<string, "owner">, contractFlag: TypedAbiArg<Uint8Array, "contractFlag">], Response<boolean, bigint>>,
    protocolBurnLocked: {"name":"protocol-burn-locked","access":"public","args":[{"name":"amount","type":"uint128"},{"name":"owner","type":"principal"},{"name":"contract-flag","type":{"buffer":{"length":1}}}],"outputs":{"type":{"response":{"ok":"bool","error":"uint128"}}}} as TypedAbiFunction<[amount: TypedAbiArg<number | bigint, "amount">, owner: TypedAbiArg<string, "owner">, contractFlag: TypedAbiArg<Uint8Array, "contractFlag">], Response<boolean, bigint>>,
    protocolLock: {"name":"protocol-lock","access":"public","args":[{"name":"amount","type":"uint128"},{"name":"owner","type":"principal"},{"name":"contract-flag","type":{"buffer":{"length":1}}}],"outputs":{"type":{"response":{"ok":"bool","error":"uint128"}}}} as TypedAbiFunction<[amount: TypedAbiArg<number | bigint, "amount">, owner: TypedAbiArg<string, "owner">, contractFlag: TypedAbiArg<Uint8Array, "contractFlag">], Response<boolean, bigint>>,
    protocolMint: {"name":"protocol-mint","access":"public","args":[{"name":"amount","type":"uint128"},{"name":"recipient","type":"principal"},{"name":"contract-flag","type":{"buffer":{"length":1}}}],"outputs":{"type":{"response":{"ok":"bool","error":"uint128"}}}} as TypedAbiFunction<[amount: TypedAbiArg<number | bigint, "amount">, recipient: TypedAbiArg<string, "recipient">, contractFlag: TypedAbiArg<Uint8Array, "contractFlag">], Response<boolean, bigint>>,
    protocolMintMany: {"name":"protocol-mint-many","access":"public","args":[{"name":"recipients","type":{"list":{"type":{"tuple":[{"name":"amount","type":"uint128"},{"name":"recipient","type":"principal"}]},"length":200}}},{"name":"contract-flag","type":{"buffer":{"length":1}}}],"outputs":{"type":{"response":{"ok":{"list":{"type":{"response":{"ok":"bool","error":"uint128"}},"length":200}},"error":"uint128"}}}} as TypedAbiFunction<[recipients: TypedAbiArg<{
  "amount": number | bigint;
  "recipient": string;
}[], "recipients">, contractFlag: TypedAbiArg<Uint8Array, "contractFlag">], Response<Response<boolean, bigint>[], bigint>>,
    protocolSetName: {"name":"protocol-set-name","access":"public","args":[{"name":"new-name","type":{"string-ascii":{"length":32}}},{"name":"contract-flag","type":{"buffer":{"length":1}}}],"outputs":{"type":{"response":{"ok":"bool","error":"uint128"}}}} as TypedAbiFunction<[newName: TypedAbiArg<string, "newName">, contractFlag: TypedAbiArg<Uint8Array, "contractFlag">], Response<boolean, bigint>>,
    protocolSetSymbol: {"name":"protocol-set-symbol","access":"public","args":[{"name":"new-symbol","type":{"string-ascii":{"length":10}}},{"name":"contract-flag","type":{"buffer":{"length":1}}}],"outputs":{"type":{"response":{"ok":"bool","error":"uint128"}}}} as TypedAbiFunction<[newSymbol: TypedAbiArg<string, "newSymbol">, contractFlag: TypedAbiArg<Uint8Array, "contractFlag">], Response<boolean, bigint>>,
    protocolSetTokenUri: {"name":"protocol-set-token-uri","access":"public","args":[{"name":"new-uri","type":{"optional":{"string-utf8":{"length":256}}}},{"name":"contract-flag","type":{"buffer":{"length":1}}}],"outputs":{"type":{"response":{"ok":"bool","error":"uint128"}}}} as TypedAbiFunction<[newUri: TypedAbiArg<string | null, "newUri">, contractFlag: TypedAbiArg<Uint8Array, "contractFlag">], Response<boolean, bigint>>,
    protocolUnlock: {"name":"protocol-unlock","access":"public","args":[{"name":"amount","type":"uint128"},{"name":"owner","type":"principal"},{"name":"contract-flag","type":{"buffer":{"length":1}}}],"outputs":{"type":{"response":{"ok":"bool","error":"uint128"}}}} as TypedAbiFunction<[amount: TypedAbiArg<number | bigint, "amount">, owner: TypedAbiArg<string, "owner">, contractFlag: TypedAbiArg<Uint8Array, "contractFlag">], Response<boolean, bigint>>,
    transfer: {"name":"transfer","access":"public","args":[{"name":"amount","type":"uint128"},{"name":"sender","type":"principal"},{"name":"recipient","type":"principal"},{"name":"memo","type":{"optional":{"buffer":{"length":34}}}}],"outputs":{"type":{"response":{"ok":"bool","error":"uint128"}}}} as TypedAbiFunction<[amount: TypedAbiArg<number | bigint, "amount">, sender: TypedAbiArg<string, "sender">, recipient: TypedAbiArg<string, "recipient">, memo: TypedAbiArg<Uint8Array | null, "memo">], Response<boolean, bigint>>,
    transferMany: {"name":"transfer-many","access":"public","args":[{"name":"recipients","type":{"list":{"type":{"tuple":[{"name":"amount","type":"uint128"},{"name":"memo","type":{"optional":{"buffer":{"length":34}}}},{"name":"sender","type":"principal"},{"name":"to","type":"principal"}]},"length":200}}}],"outputs":{"type":{"response":{"ok":"uint128","error":"uint128"}}}} as TypedAbiFunction<[recipients: TypedAbiArg<{
  "amount": number | bigint;
  "memo": Uint8Array | null;
  "sender": string;
  "to": string;
}[], "recipients">], Response<bigint, bigint>>,
    getBalance: {"name":"get-balance","access":"read_only","args":[{"name":"who","type":"principal"}],"outputs":{"type":{"response":{"ok":"uint128","error":"none"}}}} as TypedAbiFunction<[who: TypedAbiArg<string, "who">], Response<bigint, null>>,
    getBalanceAvailable: {"name":"get-balance-available","access":"read_only","args":[{"name":"who","type":"principal"}],"outputs":{"type":{"response":{"ok":"uint128","error":"none"}}}} as TypedAbiFunction<[who: TypedAbiArg<string, "who">], Response<bigint, null>>,
    getBalanceLocked: {"name":"get-balance-locked","access":"read_only","args":[{"name":"who","type":"principal"}],"outputs":{"type":{"response":{"ok":"uint128","error":"none"}}}} as TypedAbiFunction<[who: TypedAbiArg<string, "who">], Response<bigint, null>>,
    getCurrentAggregatePubkey: {"name":"get-current-aggregate-pubkey","access":"read_only","args":[],"outputs":{"type":{"buffer":{"length":33}}}} as TypedAbiFunction<[], Uint8Array>,
    getDecimals: {"name":"get-decimals","access":"read_only","args":[],"outputs":{"type":{"response":{"ok":"uint128","error":"none"}}}} as TypedAbiFunction<[], Response<bigint, null>>,
    getName: {"name":"get-name","access":"read_only","args":[],"outputs":{"type":{"response":{"ok":{"string-ascii":{"length":32}},"error":"none"}}}} as TypedAbiFunction<[], Response<string, null>>,
    getSymbol: {"name":"get-symbol","access":"read_only","args":[],"outputs":{"type":{"response":{"ok":{"string-ascii":{"length":10}},"error":"none"}}}} as TypedAbiFunction<[], Response<string, null>>,
    getTokenUri: {"name":"get-token-uri","access":"read_only","args":[],"outputs":{"type":{"response":{"ok":{"optional":{"string-utf8":{"length":256}}},"error":"none"}}}} as TypedAbiFunction<[], Response<string | null, null>>,
    getTotalSupply: {"name":"get-total-supply","access":"read_only","args":[],"outputs":{"type":{"response":{"ok":"uint128","error":"none"}}}} as TypedAbiFunction<[], Response<bigint, null>>
  },
  "maps": {
    
  },
  "variables": {
    ERR_NOT_OWNER: {
  name: 'ERR_NOT_OWNER',
  type: {
    response: {
      ok: 'none',
      error: 'uint128'
    }
  },
  access: 'constant'
} as TypedAbiVariable<Response<null, bigint>>,
    ERR_TRANSFER_INDEX_PREFIX: {
  name: 'ERR_TRANSFER_INDEX_PREFIX',
  type: 'uint128',
  access: 'constant'
} as TypedAbiVariable<bigint>,
    tokenDecimals: {
  name: 'token-decimals',
  type: 'uint128',
  access: 'constant'
} as TypedAbiVariable<bigint>,
    tokenName: {
  name: 'token-name',
  type: {
    'string-ascii': {
      length: 32
    }
  },
  access: 'variable'
} as TypedAbiVariable<string>,
    tokenSymbol: {
  name: 'token-symbol',
  type: {
    'string-ascii': {
      length: 10
    }
  },
  access: 'variable'
} as TypedAbiVariable<string>,
    tokenUri: {
  name: 'token-uri',
  type: {
    optional: {
      'string-utf8': {
        length: 256
      }
    }
  },
  access: 'variable'
} as TypedAbiVariable<string | null>
  },
  constants: {},
  "non_fungible_tokens": [
    
  ],
  "fungible_tokens":[{"name":"sbtc-token"},{"name":"sbtc-token-locked"}],"epoch":"Epoch30","clarity_version":"Clarity3",
  contractName: 'sbtc-token',
  },
sbtcWithdrawal: {
  "functions": {
    completeIndividualWithdrawalHelper: {"name":"complete-individual-withdrawal-helper","access":"private","args":[{"name":"withdrawal","type":{"tuple":[{"name":"bitcoin-txid","type":{"optional":{"buffer":{"length":32}}}},{"name":"burn-hash","type":{"buffer":{"length":32}}},{"name":"burn-height","type":"uint128"},{"name":"fee","type":{"optional":"uint128"}},{"name":"output-index","type":{"optional":"uint128"}},{"name":"request-id","type":"uint128"},{"name":"signer-bitmap","type":"uint128"},{"name":"status","type":"bool"},{"name":"sweep-txid","type":{"optional":{"buffer":{"length":32}}}}]}},{"name":"helper-response","type":{"response":{"ok":"uint128","error":"uint128"}}}],"outputs":{"type":{"response":{"ok":"uint128","error":"uint128"}}}} as TypedAbiFunction<[withdrawal: TypedAbiArg<{
  "bitcoinTxid": Uint8Array | null;
  "burnHash": Uint8Array;
  "burnHeight": number | bigint;
  "fee": number | bigint | null;
  "outputIndex": number | bigint | null;
  "requestId": number | bigint;
  "signerBitmap": number | bigint;
  "status": boolean;
  "sweepTxid": Uint8Array | null;
}, "withdrawal">, helperResponse: TypedAbiArg<Response<number | bigint, number | bigint>, "helperResponse">], Response<bigint, bigint>>,
    acceptWithdrawalRequest: {"name":"accept-withdrawal-request","access":"public","args":[{"name":"request-id","type":"uint128"},{"name":"bitcoin-txid","type":{"buffer":{"length":32}}},{"name":"signer-bitmap","type":"uint128"},{"name":"output-index","type":"uint128"},{"name":"fee","type":"uint128"},{"name":"burn-hash","type":{"buffer":{"length":32}}},{"name":"burn-height","type":"uint128"},{"name":"sweep-txid","type":{"buffer":{"length":32}}}],"outputs":{"type":{"response":{"ok":"bool","error":"uint128"}}}} as TypedAbiFunction<[requestId: TypedAbiArg<number | bigint, "requestId">, bitcoinTxid: TypedAbiArg<Uint8Array, "bitcoinTxid">, signerBitmap: TypedAbiArg<number | bigint, "signerBitmap">, outputIndex: TypedAbiArg<number | bigint, "outputIndex">, fee: TypedAbiArg<number | bigint, "fee">, burnHash: TypedAbiArg<Uint8Array, "burnHash">, burnHeight: TypedAbiArg<number | bigint, "burnHeight">, sweepTxid: TypedAbiArg<Uint8Array, "sweepTxid">], Response<boolean, bigint>>,
    completeWithdrawals: {"name":"complete-withdrawals","access":"public","args":[{"name":"withdrawals","type":{"list":{"type":{"tuple":[{"name":"bitcoin-txid","type":{"optional":{"buffer":{"length":32}}}},{"name":"burn-hash","type":{"buffer":{"length":32}}},{"name":"burn-height","type":"uint128"},{"name":"fee","type":{"optional":"uint128"}},{"name":"output-index","type":{"optional":"uint128"}},{"name":"request-id","type":"uint128"},{"name":"signer-bitmap","type":"uint128"},{"name":"status","type":"bool"},{"name":"sweep-txid","type":{"optional":{"buffer":{"length":32}}}}]},"length":600}}}],"outputs":{"type":{"response":{"ok":"uint128","error":"uint128"}}}} as TypedAbiFunction<[withdrawals: TypedAbiArg<{
  "bitcoinTxid": Uint8Array | null;
  "burnHash": Uint8Array;
  "burnHeight": number | bigint;
  "fee": number | bigint | null;
  "outputIndex": number | bigint | null;
  "requestId": number | bigint;
  "signerBitmap": number | bigint;
  "status": boolean;
  "sweepTxid": Uint8Array | null;
}[], "withdrawals">], Response<bigint, bigint>>,
    initiateWithdrawalRequest: {"name":"initiate-withdrawal-request","access":"public","args":[{"name":"amount","type":"uint128"},{"name":"recipient","type":{"tuple":[{"name":"hashbytes","type":{"buffer":{"length":32}}},{"name":"version","type":{"buffer":{"length":1}}}]}},{"name":"max-fee","type":"uint128"}],"outputs":{"type":{"response":{"ok":"uint128","error":"uint128"}}}} as TypedAbiFunction<[amount: TypedAbiArg<number | bigint, "amount">, recipient: TypedAbiArg<{
  "hashbytes": Uint8Array;
  "version": Uint8Array;
}, "recipient">, maxFee: TypedAbiArg<number | bigint, "maxFee">], Response<bigint, bigint>>,
    rejectWithdrawalRequest: {"name":"reject-withdrawal-request","access":"public","args":[{"name":"request-id","type":"uint128"},{"name":"signer-bitmap","type":"uint128"}],"outputs":{"type":{"response":{"ok":"bool","error":"uint128"}}}} as TypedAbiFunction<[requestId: TypedAbiArg<number | bigint, "requestId">, signerBitmap: TypedAbiArg<number | bigint, "signerBitmap">], Response<boolean, bigint>>,
    getBurnHeader: {"name":"get-burn-header","access":"read_only","args":[{"name":"height","type":"uint128"}],"outputs":{"type":{"optional":{"buffer":{"length":32}}}}} as TypedAbiFunction<[height: TypedAbiArg<number | bigint, "height">], Uint8Array | null>,
    validateRecipient: {"name":"validate-recipient","access":"read_only","args":[{"name":"recipient","type":{"tuple":[{"name":"hashbytes","type":{"buffer":{"length":32}}},{"name":"version","type":{"buffer":{"length":1}}}]}}],"outputs":{"type":{"response":{"ok":"bool","error":"uint128"}}}} as TypedAbiFunction<[recipient: TypedAbiArg<{
  "hashbytes": Uint8Array;
  "version": Uint8Array;
}, "recipient">], Response<boolean, bigint>>
  },
  "maps": {
    
  },
  "variables": {
    DUST_LIMIT: {
  name: 'DUST_LIMIT',
  type: 'uint128',
  access: 'constant'
} as TypedAbiVariable<bigint>,
    ERR_ALREADY_PROCESSED: {
  name: 'ERR_ALREADY_PROCESSED',
  type: {
    response: {
      ok: 'none',
      error: 'uint128'
    }
  },
  access: 'constant'
} as TypedAbiVariable<Response<null, bigint>>,
    ERR_DUST_LIMIT: {
  name: 'ERR_DUST_LIMIT',
  type: {
    response: {
      ok: 'none',
      error: 'uint128'
    }
  },
  access: 'constant'
} as TypedAbiVariable<Response<null, bigint>>,
    ERR_FEE_TOO_HIGH: {
  name: 'ERR_FEE_TOO_HIGH',
  type: {
    response: {
      ok: 'none',
      error: 'uint128'
    }
  },
  access: 'constant'
} as TypedAbiVariable<Response<null, bigint>>,
    ERR_INVALID_ADDR_HASHBYTES: {
  name: 'ERR_INVALID_ADDR_HASHBYTES',
  type: {
    response: {
      ok: 'none',
      error: 'uint128'
    }
  },
  access: 'constant'
} as TypedAbiVariable<Response<null, bigint>>,
    ERR_INVALID_ADDR_VERSION: {
  name: 'ERR_INVALID_ADDR_VERSION',
  type: {
    response: {
      ok: 'none',
      error: 'uint128'
    }
  },
  access: 'constant'
} as TypedAbiVariable<Response<null, bigint>>,
    ERR_INVALID_BURN_HASH: {
  name: 'ERR_INVALID_BURN_HASH',
  type: {
    response: {
      ok: 'none',
      error: 'uint128'
    }
  },
  access: 'constant'
} as TypedAbiVariable<Response<null, bigint>>,
    ERR_INVALID_CALLER: {
  name: 'ERR_INVALID_CALLER',
  type: {
    response: {
      ok: 'none',
      error: 'uint128'
    }
  },
  access: 'constant'
} as TypedAbiVariable<Response<null, bigint>>,
    ERR_INVALID_REQUEST: {
  name: 'ERR_INVALID_REQUEST',
  type: {
    response: {
      ok: 'none',
      error: 'uint128'
    }
  },
  access: 'constant'
} as TypedAbiVariable<Response<null, bigint>>,
    ERR_WITHDRAWAL_INDEX: {
  name: 'ERR_WITHDRAWAL_INDEX',
  type: {
    response: {
      ok: 'none',
      error: 'uint128'
    }
  },
  access: 'constant'
} as TypedAbiVariable<Response<null, bigint>>,
    ERR_WITHDRAWAL_INDEX_PREFIX: {
  name: 'ERR_WITHDRAWAL_INDEX_PREFIX',
  type: 'uint128',
  access: 'constant'
} as TypedAbiVariable<bigint>,
    MAX_ADDRESS_VERSION: {
  name: 'MAX_ADDRESS_VERSION',
  type: 'uint128',
  access: 'constant'
} as TypedAbiVariable<bigint>,
    mAX_ADDRESS_VERSION_BUFF_20: {
  name: 'MAX_ADDRESS_VERSION_BUFF_20',
  type: 'uint128',
  access: 'constant'
} as TypedAbiVariable<bigint>,
    mAX_ADDRESS_VERSION_BUFF_32: {
  name: 'MAX_ADDRESS_VERSION_BUFF_32',
  type: 'uint128',
  access: 'constant'
} as TypedAbiVariable<bigint>,
    withdrawRole: {
  name: 'withdraw-role',
  type: {
    buffer: {
      length: 1
    }
  },
  access: 'constant'
} as TypedAbiVariable<Uint8Array>
  },
  constants: {},
  "non_fungible_tokens": [
    
  ],
  "fungible_tokens":[],"epoch":"Epoch30","clarity_version":"Clarity3",
  contractName: 'sbtc-withdrawal',
  }
} as const;

export const accounts = {"deployer":{"address":"ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM","balance":"100000000000000"},"wallet_1":{"address":"ST1SJ3DTE5DN7X54YDH5D64R3BCB6A2AG2ZQ8YPD5","balance":"100000000000000"},"wallet_10":{"address":"ST3FFKYTTB975A3JC3F99MM7TXZJ406R3GKE6JV56","balance":"200000000000000"},"wallet_2":{"address":"ST2CY5V39NHDPWSXMW9QDT3HC3GD6Q6XX4CFRK9AG","balance":"100000000000000"},"wallet_3":{"address":"ST2JHG361ZXG51QTKY2NQCVBPPRRE2KZB1HR05NNC","balance":"100000000000000"},"wallet_4":{"address":"ST2NEB84ASENDXKYGJPQW86YXQCEFEX2ZQPG87ND","balance":"100000000000000"},"wallet_5":{"address":"ST2REHHS5J3CERCRBEPMGH7921Q6PYKAADT7JP2VB","balance":"100000000000000"},"wallet_6":{"address":"ST3AM1A56AK2C1XAFJ4115ZSV26EB49BVQ10MGCS0","balance":"100000000000000"},"wallet_7":{"address":"ST3PF13W7Z0RRM42A8VZRVFQ75SV1K26RXEP8YGKJ","balance":"100000000000000"},"wallet_8":{"address":"ST3NBRSFKX28FQ2ZJ1MAKX58HKHSDGNV5N7R21XCP","balance":"100000000000000"},"wallet_9":{"address":"STNHKEPYEPJ8ET55ZZ0M5A34J0R3N5FM2CMMMAZ6","balance":"100000000000000"}} as const;

export const identifiers = {"pox5":"ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM.pox-5","pox5Signer":"ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM.pox-5-signer","sbtcRegistry":"SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4.sbtc-registry","sbtcToken":"SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4.sbtc-token","sbtcWithdrawal":"SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4.sbtc-withdrawal"} as const

export const simnet = {
  accounts,
  contracts,
  identifiers,
} as const;


export const deployments = {"pox5":{"devnet":"ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM.pox-5","simnet":"ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM.pox-5","testnet":null,"mainnet":null},"pox5Signer":{"devnet":"ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM.pox-5-signer","simnet":"ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM.pox-5-signer","testnet":null,"mainnet":null},"sbtcRegistry":{"devnet":"SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4.sbtc-registry","simnet":"SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4.sbtc-registry","testnet":null,"mainnet":null},"sbtcToken":{"devnet":"SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4.sbtc-token","simnet":"SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4.sbtc-token","testnet":null,"mainnet":null},"sbtcWithdrawal":{"devnet":"ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM.sbtc-withdrawal","simnet":"SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4.sbtc-withdrawal","testnet":null,"mainnet":"SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4.sbtc-withdrawal"}} as const;

export const project = {
  contracts,
  deployments,
} as const;
  