import * as btc from "@scure/btc-signer";
import { HDKey } from "@scure/bip32";
import { PubT, concatBytes, sha256, validatePubkey } from "@scure/btc-signer/utils.js";
import {
  ClarityType,
  deserializeCV,
  principalCV,
  serializeCV,
  type ClarityValue,
} from "@stacks/transactions";
import {
  MAINNET,
  REGTEST,
  UNSPENDABLE_PUB,
  buildSbtcDepositScript,
  buildSbtcReclaimScript,
} from "sbtc";

export type NetworkName = "mainnet" | "testnet";
export type DepositVersion = "v1" | "v2";

const V2_UNSPENDABLE_PUB = hexToBytes(
  "4a30b2e461b280c0b13a03799096ab1256589153fc4b9c8cead16dc0b6420697",
);
const SIGNER_CHAIN_CODE_DOMAIN = new TextEncoder().encode("sbtc/signer/chain-code/v1");
const MAX_SIGNERS = 16;

export const SBTC_DEPLOYERS: Record<NetworkName, string> = {
  mainnet: "SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4",
  testnet: "SN3VMHXEN64ZZF71JQ5VESXDWTR301XTTXGF4J8F1",
};

interface ComputeDepositBase {
  network: NetworkName;
  recipient: string;
  maxFee: number;
}

/**
 * A v2 signer key set as stored in the registry: the signers' compressed
 * identity keys and the number of signatures required.
 */
export interface SignerKeySetData {
  signerIdentityKeys: string[];
  signaturesRequired: number;
}

export type DepositSigningInput =
  | { version: "v1"; signersPublicKey: string }
  | ({ version: "v2" } & SignerKeySetData);

export type ComputeDepositInput = ComputeDepositBase &
  DepositSigningInput &
  (
    | {
        reclaimPublicKey: string;
        lockTime: number;
        reclaimScript?: never;
      }
    | {
        reclaimScript: string;
        reclaimPublicKey?: never;
        lockTime?: never;
      }
  );

/**
 * The keys that can spend the deposit leaf: the v1 aggregate key, or the v2
 * x-only Bitcoin keys derived from the registry signer keys, in script order.
 */
export type DepositSigners =
  | { version: "v1"; signersPublicKey: string }
  | { version: "v2"; signingKeys: string[]; signaturesRequired: number };

export type DepositResult = DepositSigners & {
  address: string;
  depositScript: string;
  reclaimScript: string;
};

/** Why a registry field could not be used. */
export interface RegistryFieldError {
  error: string;
}

/**
 * Signer data read from the sBTC registry.
 *
 * A v1 deposit needs only the aggregate key and a v2 deposit needs only the
 * key set, so each field records why it is unusable instead of failing the
 * whole read.
 */
export interface RegistrySignerData {
  aggregatePublicKey: string | RegistryFieldError;
  keySet: SignerKeySetData | RegistryFieldError;
}

export function normalizeHex(value: string): string {
  return value.trim().replace(/^0x/i, "").toLowerCase();
}

export function normalizeXOnlyPublicKey(value: string): string {
  const key = normalizeHex(value);
  if (!/^(?:[0-9a-f]{64}|(?:02|03)[0-9a-f]{64})$/.test(key)) {
    throw new Error("Enter a 32-byte x-only or 33-byte compressed public key in hex.");
  }
  const xOnly = key.length === 66 ? key.slice(2) : key;
  try {
    validatePubkey(hexToBytes(xOnly), PubT.schnorr);
  } catch {
    throw new Error("Enter a valid secp256k1 public key.");
  }
  return xOnly;
}

export function normalizeCompressedPublicKey(value: string): string {
  const key = normalizeHex(value);
  if (!/^(?:02|03)[0-9a-f]{64}$/.test(key)) {
    throw new Error("Expected a 33-byte compressed secp256k1 public key.");
  }
  try {
    validatePubkey(hexToBytes(key), PubT.ecdsa);
  } catch {
    throw new Error("Expected a valid compressed secp256k1 public key.");
  }
  return key;
}

export function hexToBytes(value: string): Uint8Array {
  const hex = normalizeHex(value);
  if (!hex || hex.length % 2 !== 0 || !/^[0-9a-f]+$/.test(hex)) {
    throw new Error("Enter a complete, even-length hexadecimal script.");
  }
  return Uint8Array.from(hex.match(/.{2}/g)!.map((byte) => Number.parseInt(byte, 16)));
}

function bytesToHex(value: Uint8Array): string {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function compareBytes(left: Uint8Array, right: Uint8Array): number {
  for (let index = 0; index < Math.min(left.length, right.length); index += 1) {
    if (left[index] !== right[index]) return left[index]! - right[index]!;
  }
  return left.length - right.length;
}

function uint64Be(value: number): Uint8Array {
  const result = new Uint8Array(8);
  new DataView(result.buffer).setBigUint64(0, BigInt(value));
  return result;
}

function deriveSignerKey(publicKey: string): Uint8Array {
  const identityKey = hexToBytes(normalizeCompressedPublicKey(publicKey));
  const chainCode = sha256(concatBytes(SIGNER_CHAIN_CODE_DOMAIN, identityKey));
  const derived = new HDKey({ publicKey: identityKey, chainCode })
    .deriveChild(0)
    .deriveChild(0).publicKey;
  if (!derived) throw new Error("Could not derive a signer Bitcoin key.");
  return derived.slice(1);
}

export function buildV2DepositScript({
  maxFee,
  recipient,
  signerIdentityKeys,
  signaturesRequired,
}: {
  maxFee: number;
  recipient: string;
  signerIdentityKeys: string[];
  signaturesRequired: number;
}): { depositScript: Uint8Array; signingKeys: Uint8Array[] } {
  // Like the signers' key set, repeated keys collapse into one entry.
  const uniqueKeys = new Map(
    signerIdentityKeys.map(deriveSignerKey).map((key) => [bytesToHex(key), key] as const),
  );
  const signingKeys = [...uniqueKeys.values()].sort(compareBytes);
  if (signingKeys.length > MAX_SIGNERS) {
    throw new Error(`Version 2 deposits allow at most ${MAX_SIGNERS} signer keys.`);
  }
  if (
    !Number.isInteger(signaturesRequired) ||
    signaturesRequired < 1 ||
    signaturesRequired > signingKeys.length
  ) {
    throw new Error("The signature threshold must be between 1 and the signer count.");
  }

  const recipientBytes = hexToBytes(serializeCV(principalCV(recipient)));
  const preimage = sha256(concatBytes(uint64Be(maxFee), recipientBytes));
  const commitment = sha256(preimage);
  const script: btc.ScriptType = [
    "SIZE",
    btc.ScriptNum().encode(32n),
    "EQUALVERIFY",
    "SHA256",
    commitment,
    "EQUALVERIFY",
  ];
  signingKeys.forEach((key, index) => {
    script.push(key, index === 0 ? "CHECKSIG" : "CHECKSIGADD");
  });
  script.push(signaturesRequired, "NUMEQUAL");
  return { depositScript: btc.Script.encode(script), signingKeys };
}

export function scriptToAsm(script: string): string {
  try {
    const bytes = hexToBytes(script);
    const operations: string[] = [];
    let offset = 0;

    const readLength = (byteCount: number): number => {
      if (offset + byteCount > bytes.length) throw new Error("Truncated push length");
      let length = 0;
      for (let index = 0; index < byteCount; index += 1) {
        length += bytes[offset + index]! * 2 ** (8 * index);
      }
      offset += byteCount;
      return length;
    };

    const readPush = (length: number): void => {
      if (offset + length > bytes.length) throw new Error("Truncated push data");
      operations.push(bytesToHex(bytes.slice(offset, offset + length)));
      offset += length;
    };

    while (offset < bytes.length) {
      const opcode = bytes[offset]!;
      offset += 1;

      if (opcode >= 1 && opcode <= 75) {
        operations.push(`OP_PUSHBYTES_${opcode}`);
        readPush(opcode);
        continue;
      }
      if (opcode === btc.OP.PUSHDATA1) {
        operations.push("OP_PUSHDATA1");
        readPush(readLength(1));
        continue;
      }
      if (opcode === btc.OP.PUSHDATA2) {
        operations.push("OP_PUSHDATA2");
        readPush(readLength(2));
        continue;
      }
      if (opcode === btc.OP.PUSHDATA4) {
        operations.push("OP_PUSHDATA4");
        readPush(readLength(4));
        continue;
      }

      const name = Object.entries(btc.OP).find(([, value]) => value === opcode)?.[0];
      if (!name) throw new Error("Unknown opcode");
      operations.push(name.startsWith("OP_") ? name : `OP_${name}`);
    }

    return operations.join(" ");
  } catch {
    return "Unable to decode script";
  }
}

const ASM_LINE_ENDERS = new Set([
  "OP_DROP",
  "OP_EQUALVERIFY",
  "OP_CHECKSIG",
  "OP_CHECKSIGADD",
  "OP_NUMEQUAL",
]);

/** Break single-line ASM into one line per script clause for display. */
export function formatAsmLines(asm: string): string {
  return asm
    .split(" ")
    .map((token, index, tokens) => {
      if (index === tokens.length - 1) return token;
      return `${token}${ASM_LINE_ENDERS.has(token) ? "\n" : " "}`;
    })
    .join("");
}

function buildReclaimScript(input: ComputeDepositInput): Uint8Array {
  if (input.reclaimScript !== undefined) return hexToBytes(input.reclaimScript);
  if (!input.reclaimPublicKey) throw new Error("Enter a reclaim public key.");
  if (!Number.isInteger(input.lockTime) || input.lockTime < 0 || input.lockTime > 65_535) {
    throw new Error("Lock time must be a whole number from 0 through 65,535 blocks.");
  }
  return buildSbtcReclaimScript({
    reclaimLockTime: input.lockTime,
    reclaimPublicKey: normalizeXOnlyPublicKey(input.reclaimPublicKey),
  });
}

function buildSigningLeaf(
  input: ComputeDepositInput,
  recipient: string,
): { depositScript: Uint8Array; internalKey: Uint8Array; signers: DepositSigners } {
  if (input.version === "v1") {
    const signersPublicKey = normalizeXOnlyPublicKey(input.signersPublicKey);
    return {
      depositScript: buildSbtcDepositScript({
        maxSignerFee: input.maxFee,
        stacksAddress: recipient,
        signersPublicKey,
      }),
      internalKey: UNSPENDABLE_PUB,
      signers: { version: "v1", signersPublicKey },
    };
  }

  const { depositScript, signingKeys } = buildV2DepositScript({
    maxFee: input.maxFee,
    recipient,
    signerIdentityKeys: input.signerIdentityKeys,
    signaturesRequired: input.signaturesRequired,
  });
  return {
    depositScript,
    internalKey: V2_UNSPENDABLE_PUB,
    signers: {
      version: "v2",
      signingKeys: signingKeys.map(bytesToHex),
      signaturesRequired: input.signaturesRequired,
    },
  };
}

export function computeDepositAddress(input: ComputeDepositInput): DepositResult {
  const network = input.network === "mainnet" ? MAINNET : REGTEST;
  const recipient = input.recipient.trim();
  const expectedPrefix = input.network === "mainnet" ? /^(SP|SM)/ : /^(ST|SN)/;
  if (!expectedPrefix.test(recipient)) {
    throw new Error(`Enter a ${input.network} Stacks recipient.`);
  }
  // The SDK checks the address checksum, but splits contract principals at
  // periods without validating the name or rejecting trailing components.
  if (!/^(?:SP|SM|ST|SN)[0-9A-Z]+(?:\.[a-zA-Z][a-zA-Z0-9_-]{0,39})?$/.test(recipient)) {
    throw new Error("Enter a valid Stacks principal, including a valid contract name if supplied.");
  }
  if (!Number.isSafeInteger(input.maxFee) || input.maxFee < 0) {
    throw new Error("Maximum fee must be a non-negative whole number.");
  }

  const reclaimScript = buildReclaimScript(input);
  const { depositScript, internalKey, signers } = buildSigningLeaf(input, recipient);
  const output = btc.p2tr(
    internalKey,
    [{ script: depositScript }, { script: reclaimScript }],
    network,
    true,
  );
  if (!output.address) throw new Error("The Taproot deposit address could not be constructed.");
  return {
    ...signers,
    address: output.address,
    depositScript: bytesToHex(depositScript),
    reclaimScript: bytesToHex(reclaimScript),
  };
}

function parseSignerKeySet(signerSet: ClarityValue, threshold: ClarityValue): SignerKeySetData {
  if (signerSet.type !== ClarityType.List || threshold.type !== ClarityType.UInt) {
    throw new Error("The sBTC registry signer set or threshold is missing.");
  }
  const keys = signerSet.value.map((entry) => {
    if (entry.type !== ClarityType.Buffer) {
      throw new Error("The sBTC registry signer set contained a non-buffer value.");
    }
    try {
      return normalizeCompressedPublicKey(entry.value);
    } catch {
      throw new Error("The sBTC registry signer set contains an invalid public key.");
    }
  });
  const signerIdentityKeys = [...new Set(keys)];
  const signaturesRequired = Number(threshold.value);
  if (
    !Number.isSafeInteger(signaturesRequired) ||
    signaturesRequired < 1 ||
    signaturesRequired > signerIdentityKeys.length
  ) {
    throw new Error("The sBTC registry signature threshold is invalid.");
  }
  return { signerIdentityKeys, signaturesRequired };
}

export function parseRegistrySignerData(value: ClarityValue): RegistrySignerData {
  if (value.type !== ClarityType.Tuple) {
    throw new Error("The sBTC registry signer data was not a tuple.");
  }
  const aggregateKey = value.value["current-aggregate-pubkey"];
  const signerSet = value.value["current-signer-set"];
  const threshold = value.value["current-signature-threshold"];
  if (!aggregateKey || !signerSet || !threshold || aggregateKey.type !== ClarityType.Buffer) {
    throw new Error("The sBTC registry signer data is incomplete.");
  }

  return {
    aggregatePublicKey: parseRegistryField(() => parseAggregateKey(aggregateKey.value)),
    keySet: parseRegistryField(() => parseSignerKeySet(signerSet, threshold)),
  };
}

function parseAggregateKey(value: string): string {
  const key = normalizeHex(value);
  if (key === "00") throw new Error("The sBTC registry has no aggregate key.");
  // The first key rotation after v1 signing is disabled writes 0xff followed
  // by a Bitcoin block hash in place of the aggregate key.
  if (key.length === 66 && key.startsWith("ff")) {
    throw new Error(
      "The sBTC registry no longer has a version 1 aggregate key. " +
        "Choose version 2 or enter an aggregate public key.",
    );
  }
  try {
    return normalizeXOnlyPublicKey(key);
  } catch {
    throw new Error("The sBTC registry aggregate key is not a valid public key.");
  }
}

/** Run a registry field parser, recording a failure instead of throwing. */
function parseRegistryField<T>(parse: () => T): T | RegistryFieldError {
  try {
    return parse();
  } catch (cause) {
    return { error: cause instanceof Error ? cause.message : String(cause) };
  }
}

/** Return a parsed registry field, or throw why it cannot be used. */
export function requireRegistryField<T>(field: T | RegistryFieldError): T {
  if (typeof field === "object" && field !== null && "error" in field) {
    throw new Error(field.error);
  }
  return field;
}

export async function fetchRegistrySignerData(
  network: NetworkName,
  stacksApiUrl: string,
): Promise<RegistrySignerData> {
  const baseUrl = stacksApiUrl.trim().replace(/\/$/, "");
  const deployer = SBTC_DEPLOYERS[network];
  const url = `${baseUrl}/v2/contracts/call-read/${deployer}/sbtc-registry/get-current-signer-data`;
  let response: Response;
  try {
    response = await fetch(url, {
      method: "POST",
      headers: { Accept: "application/json", "Content-Type": "application/json" },
      body: JSON.stringify({ sender: deployer, arguments: [] }),
    });
  } catch {
    throw new Error(`Could not reach the Stacks API at ${baseUrl}.`);
  }
  if (!response.ok) {
    throw new Error(`The Stacks API returned HTTP ${response.status} for the sBTC registry.`);
  }

  const body: unknown = await response.json().catch(() => undefined);
  const { okay, result, cause } = (body ?? {}) as {
    okay?: boolean;
    result?: unknown;
    cause?: unknown;
  };
  if (okay !== true || typeof result !== "string") {
    const detail = typeof cause === "string" ? `: ${cause}` : ".";
    throw new Error(`The Stacks API could not read the sBTC registry${detail}`);
  }
  return parseRegistrySignerData(deserializeCV(result));
}

export function findWalletValues(
  addresses: Array<{ address: string; publicKey: string; symbol?: string; purpose?: string }>,
  network: NetworkName,
): { recipient: string; reclaimPublicKey: string } {
  const stacksPrefix = network === "mainnet" ? /^(SP|SM)/ : /^(ST|SN)/;
  const bitcoinPrefixes = network === "mainnet" ? ["bc1q"] : ["tb1q", "bcrt1q"];
  const recipient = addresses.find((entry) => stacksPrefix.test(entry.address));
  const isP2wpkh = (entry: (typeof addresses)[number]) =>
    bitcoinPrefixes.some((prefix) => entry.address.toLowerCase().startsWith(prefix));
  const payment =
    addresses.find((entry) => entry.purpose === "payment" && isP2wpkh(entry)) ??
    addresses.find(isP2wpkh);

  if (!recipient) throw new Error(`The wallet did not return a ${network} Stacks address.`);
  if (!payment?.publicKey) {
    throw new Error(`The wallet did not return a ${network} P2WPKH address and public key.`);
  }
  return {
    recipient: recipient.address,
    reclaimPublicKey: normalizeXOnlyPublicKey(payment.publicKey),
  };
}
