import { AppClient, WalletPolicy, PsbtV2 } from '@ledgerhq/ledger-bitcoin';
import Transport from '@ledgerhq/hw-transport-node-hid';
import * as bitcoinjs from 'bitcoinjs-lib';
import { BIP32Factory } from 'bip32';
import * as secp256k1 from '@bitcoinerlab/secp256k1';
import { compileMiniscript } from '@bitcoinerlab/miniscript';
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';

const __dirname = dirname(fileURLToPath(import.meta.url));
const bip32 = BIP32Factory(secp256k1);

// ---------------------------------------------------------------------------
// Hardcoded test configuration. All knobs that need to be reproducible across
// the --generate and --spend commands live here.
// ---------------------------------------------------------------------------

// testnet4 shares address / xpub prefixes with testnet3.
const NETWORK = bitcoinjs.networks.testnet;

// CLTV unlock height for the staker timelock branch. Picked far enough in the
// past that any block on testnet4 satisfies it, so the timelock branch is
// always spendable.
const CLTV_HEIGHT = 1000;

// Deterministic seed for the covenant key. Anyone running this script with the
// same constants ends up with the same address.
const COVENANT_SEED_HEX = '000102030405060708090a0b0c0d0e0f';
const COVENANT_ORIGIN_PATH = "48'/1'/0'/2'";

// BIP-48 wsh path on testnet for the staker key on the Ledger.
const STAKER_ORIGIN_PATH = "48'/1'/0'/2'";

// 32-byte preimage used to compute H committed in the script. The miniscript
// `sha256(H)` fragment compiles to a 32-byte size check, so the preimage must
// be 32 bytes even though the design doc spec'd 20.
const PREIMAGE_HEX = '00'.repeat(32);

const POLICY_NAME = 'sBTC stake test';
const STATE_FILE = resolve(__dirname, 'cltv-wallet.json');
const MEMPOOL_API = 'https://mempool.space/testnet4/api';
const SIGHASH_ALL = 0x01;
const ENABLE_LOCKTIME_SEQUENCE = 0xfffffffe;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function sha256(buf) {
    return createHash('sha256').update(buf).digest();
}

function preimageHashHex() {
    return sha256(Buffer.from(PREIMAGE_HEX, 'hex')).toString('hex');
}

function deriveCovenant() {
    const seed = Buffer.from(COVENANT_SEED_HEX, 'hex');
    const root = bip32.fromSeed(seed, NETWORK);
    const node = root.derivePath('m/' + COVENANT_ORIGIN_PATH);
    return {
        masterFingerprint: root.fingerprint, // Buffer
        xpub: node.neutered().toBase58(),
        pubkeyAt: (change, index) => node.derive(change).derive(index).publicKey,
    };
}

function deriveStakerPubkey(xpub, change, index) {
    return bip32.fromBase58(xpub, NETWORK).derive(change).derive(index).publicKey;
}

// Ledger wallet-policy template for Option 3. Uses @0/@1 placeholders the
// device will substitute with the keyRoots at registration / signing time.
function buildLedgerTemplate() {
    return (
        `wsh(and_v(v:pk(@0/**),` +
        `and_v(v:or_i(and_v(v:sha256(${preimageHashHex()}),1),1),` +
        `or_i(after(${CLTV_HEIGHT}),pk(@1/**)))))`
    );
}

function buildKeyRoot({ fingerprintHex, originPath, xpub }) {
    return `[${fingerprintHex}/${originPath}]${xpub}`;
}

// Build the concrete witness script for given (change, index). The miniscript
// library only compiles when key positions are placeholders (@0, @1), so we
// compile that abstract form and substitute hex pubkeys in the resulting ASM.
// `compileMiniscript` returns ASM even when `issane=false` — that's what we
// need here, since the Option-3 optional-sha256 form is intentionally
// not-sane by miniscript rules but is still a valid Bitcoin script.
function buildWitnessScript({ stakerPubkey, covenantPubkey }) {
    const ms =
        `and_v(v:pk(@0),` +
        `and_v(v:or_i(and_v(v:sha256(${preimageHashHex()}),1),1),` +
        `or_i(after(${CLTV_HEIGHT}),pk(@1))))`;
    const { asm } = compileMiniscript(ms);
    if (asm.includes('analysis error')) {
        throw new Error(`miniscript compile failed: ${asm}`);
    }
    const cleaned = asm
        .trim()
        .replace(/\s+/g, ' ')
        .replaceAll('<@0>', `<${stakerPubkey.toString('hex')}>`)
        .replaceAll('<@1>', `<${covenantPubkey.toString('hex')}>`)
        // Convert bare decimal literals (e.g. "1") to encoded hex. `<...>`
        // already wraps pushdata, so leave those alone.
        .replace(/(<[^>]+>)|\b\d+\b/g, (m) =>
            m.startsWith('<') ? m : bitcoinjs.script.number.encode(Number(m)).toString('hex')
        )
        // fromASM expects bare hex pushes, no angle brackets.
        .replace(/[<>]/g, '');
    return bitcoinjs.script.fromASM(cleaned);
}

function p2wshFromScript(witnessScript) {
    const p = bitcoinjs.payments.p2wsh({
        redeem: { output: witnessScript, network: NETWORK },
        network: NETWORK,
    });
    return { address: p.address, scriptPubKey: p.output };
}

// Encode a witness stack into BIP-141 finalScriptWitness wire format (varint
// count, then each item length-prefixed).
function serializeWitness(stack) {
    const parts = [];
    const writeVarint = (n) => {
        if (n < 0xfd) parts.push(Buffer.from([n]));
        else if (n <= 0xffff) {
            const b = Buffer.alloc(3);
            b[0] = 0xfd;
            b.writeUInt16LE(n, 1);
            parts.push(b);
        } else {
            const b = Buffer.alloc(5);
            b[0] = 0xfe;
            b.writeUInt32LE(n, 1);
            parts.push(b);
        }
    };
    writeVarint(stack.length);
    for (const item of stack) {
        writeVarint(item.length);
        parts.push(item);
    }
    return Buffer.concat(parts);
}

function serializeStateForJson(state) {
    return {
        ...state,
        masterFingerprint: state.masterFingerprint?.toString('hex'),
        policyId: state.policyId?.toString('hex'),
        policyHmac: state.policyHmac?.toString('hex'),
    };
}

function parseStateFromJson(raw) {
    return {
        ...raw,
        masterFingerprint: raw.masterFingerprint ? Buffer.from(raw.masterFingerprint, 'hex') : undefined,
        policyId: raw.policyId ? Buffer.from(raw.policyId, 'hex') : undefined,
        policyHmac: raw.policyHmac ? Buffer.from(raw.policyHmac, 'hex') : undefined,
    };
}

function loadState() {
    if (!existsSync(STATE_FILE)) return null;
    return parseStateFromJson(JSON.parse(readFileSync(STATE_FILE, 'utf8')));
}

function saveState(state) {
    writeFileSync(STATE_FILE, JSON.stringify(serializeStateForJson(state), null, 2));
}

async function withLedger(fn) {
    let transport;
    try {
        transport = await Transport.default.create();
        const app = new AppClient(transport);
        return await fn(app);
    } finally {
        if (transport) await transport.close();
    }
}

async function fetchTxHex(txid) {
    const res = await fetch(`${MEMPOOL_API}/tx/${txid}/hex`);
    if (!res.ok) throw new Error(`mempool.space returned ${res.status} fetching ${txid}`);
    return (await res.text()).trim();
}

async function broadcastTx(rawHex) {
    const res = await fetch(`${MEMPOOL_API}/tx`, {
        method: 'POST',
        headers: { 'content-type': 'text/plain' },
        body: rawHex,
    });
    const body = (await res.text()).trim();
    if (!res.ok) throw new Error(`broadcast failed: ${res.status} ${body}`);
    return body;
}

// ---------------------------------------------------------------------------
// --generate: register the Option-3 wallet policy and print the address.
// ---------------------------------------------------------------------------

async function cmdGenerate({ change, index }) {
    return withLedger(async (app) => {
        console.log('Fetching master fingerprint from Ledger...');
        const fingerprintHex = await app.getMasterFingerprint();
        const masterFingerprint = Buffer.from(fingerprintHex, 'hex');
        console.log(`  Master fingerprint: ${fingerprintHex}`);

        console.log(`Fetching staker xpub at m/${STAKER_ORIGIN_PATH}...`);
        const stakerXpub = await app.getExtendedPubkey('m/' + STAKER_ORIGIN_PATH);
        console.log(`  Staker xpub: ${stakerXpub}`);

        const covenant = deriveCovenant();
        console.log(`Covenant xpub (deterministic): ${covenant.xpub}`);
        console.log(`Covenant fingerprint:          ${covenant.masterFingerprint.toString('hex')}`);

        const template = buildLedgerTemplate();
        const keyRoots = [
            buildKeyRoot({ fingerprintHex, originPath: STAKER_ORIGIN_PATH, xpub: stakerXpub }),
            buildKeyRoot({
                fingerprintHex: covenant.masterFingerprint.toString('hex'),
                originPath: COVENANT_ORIGIN_PATH,
                xpub: covenant.xpub,
            }),
        ];

        console.log('\nLedger wallet policy:');
        console.log(`  Name:     ${POLICY_NAME}`);
        console.log(`  Template: ${template}`);
        console.log('  Keys:');
        keyRoots.forEach((k, i) => console.log(`    [@${i}] ${k}`));

        const walletPolicy = new WalletPolicy(POLICY_NAME, template, keyRoots);

        // Compute the address locally first so we always have it, even if the
        // device rejects registration.
        const stakerPubkey = deriveStakerPubkey(stakerXpub, change, index);
        const covenantPubkey = covenant.pubkeyAt(change, index);
        const witnessScript = buildWitnessScript({ stakerPubkey, covenantPubkey });
        const { address, scriptPubKey } = p2wshFromScript(witnessScript);
        console.log(`\nComputed address (locally, ${change}/${index}): ${address}`);

        console.log('\nRegistering wallet policy on Ledger. Confirm each screen on the device...');
        let policyId, policyHmac;
        try {
            [policyId, policyHmac] = await app.registerWallet(walletPolicy);
            console.log(`  Policy id:   ${policyId.toString('hex')}`);
            console.log(`  Policy hmac: ${policyHmac.toString('hex')}`);
        } catch (err) {
            console.error('\n!! Ledger rejected the policy registration.');
            console.error(`   ${err.message}`);
            console.error(
                '   This likely means the device considers the Option-3 miniscript not-sane.\n' +
                '   The address above is still valid; you can fund it, but you will not be able to\n' +
                '   spend it with this Ledger flow.'
            );
            saveState({
                change,
                index,
                cltvHeight: CLTV_HEIGHT,
                preimageHex: PREIMAGE_HEX,
                preimageHashHex: preimageHashHex(),
                stakerOriginPath: STAKER_ORIGIN_PATH,
                stakerXpub,
                covenantOriginPath: COVENANT_ORIGIN_PATH,
                covenantXpub: covenant.xpub,
                covenantFingerprint: covenant.masterFingerprint.toString('hex'),
                masterFingerprint,
                policyName: POLICY_NAME,
                policyTemplate: template,
                policyKeyRoots: keyRoots,
                address,
                scriptPubKeyHex: scriptPubKey.toString('hex'),
                witnessScriptHex: witnessScript.toString('hex'),
                registered: false,
            });
            return;
        }

        // Ask the device to display the address so the user can compare it
        // visually against the locally-computed one above.
        console.log('\nAsking Ledger to display the address for verification...');
        const ledgerAddress = await app.getWalletAddress(walletPolicy, policyHmac, change, index, true);
        console.log(`  Ledger says: ${ledgerAddress}`);
        if (ledgerAddress !== address) {
            console.error(
                `!! Ledger address (${ledgerAddress}) differs from locally computed (${address}).`
            );
        }

        saveState({
            change,
            index,
            cltvHeight: CLTV_HEIGHT,
            preimageHex: PREIMAGE_HEX,
            preimageHashHex: preimageHashHex(),
            stakerOriginPath: STAKER_ORIGIN_PATH,
            stakerXpub,
            covenantOriginPath: COVENANT_ORIGIN_PATH,
            covenantXpub: covenant.xpub,
            covenantFingerprint: covenant.masterFingerprint.toString('hex'),
            masterFingerprint,
            policyName: POLICY_NAME,
            policyTemplate: template,
            policyKeyRoots: keyRoots,
            policyId,
            policyHmac,
            address,
            scriptPubKeyHex: scriptPubKey.toString('hex'),
            witnessScriptHex: witnessScript.toString('hex'),
            registered: true,
        });
        console.log(`\nState written to ${STATE_FILE}`);
        console.log(`\nFund ${address} on testnet4, then run:`);
        console.log(`  node index.js --spend --txid <TXID> --vout <VOUT> --amount <SATS> --to <DEST> --fee <SATS>`);
    });
}

// ---------------------------------------------------------------------------
// --spend: build a PSBT, sign on the Ledger, finalize the witness manually,
// and broadcast to testnet4. Always spends via the timelock branch.
// ---------------------------------------------------------------------------

async function cmdSpend({ txid, vout, amount, to, fee, txHexArg }) {
    const state = loadState();
    if (!state) throw new Error(`no ${STATE_FILE} — run --generate first`);
    if (!state.registered) {
        throw new Error(
            'state file shows the policy was never registered on this Ledger — re-run --generate first'
        );
    }

    return withLedger(async (app) => {
        const stakerPubkey = deriveStakerPubkey(state.stakerXpub, state.change, state.index);
        const covenant = deriveCovenant();
        const covenantPubkey = covenant.pubkeyAt(state.change, state.index);
        const witnessScript = Buffer.from(state.witnessScriptHex, 'hex');
        const scriptPubKey = Buffer.from(state.scriptPubKeyHex, 'hex');

        const sendAmount = amount - fee;
        if (sendAmount <= 0) throw new Error(`amount (${amount}) must exceed fee (${fee})`);

        const psbt = new bitcoinjs.Psbt({ network: NETWORK });
        psbt.setVersion(2);
        psbt.setLocktime(CLTV_HEIGHT);

        const input = {
            hash: Buffer.from(txid, 'hex').reverse(),
            index: vout,
            sequence: ENABLE_LOCKTIME_SEQUENCE,
            witnessUtxo: { script: scriptPubKey, value: amount },
            witnessScript,
            bip32Derivation: [
                {
                    masterFingerprint: state.masterFingerprint,
                    pubkey: stakerPubkey,
                    path: `m/${state.stakerOriginPath}/${state.change}/${state.index}`,
                },
                {
                    masterFingerprint: Buffer.from(state.covenantFingerprint, 'hex'),
                    pubkey: covenantPubkey,
                    path: `m/${state.covenantOriginPath}/${state.change}/${state.index}`,
                },
            ],
        };

        // Some Ledger firmware revisions also want the full prev-tx for segwit
        // inputs. Fetch it (or accept it via --txhex) so signPsbt has it
        // available in case it's needed.
        const prevTxHex = txHexArg ?? (await fetchTxHex(txid));
        input.nonWitnessUtxo = Buffer.from(prevTxHex, 'hex');

        psbt.addInput(input);
        psbt.addOutput({
            address: to,
            value: sendAmount,
        });

        console.log('Unsigned PSBT (base64):');
        console.log(`  ${psbt.toBase64()}`);
        console.log(`\nLocktime: ${psbt.locktime}, sequence: 0x${ENABLE_LOCKTIME_SEQUENCE.toString(16)}`);
        console.log(`Input: ${txid}:${vout} (${amount} sats)`);
        console.log(`Output: ${sendAmount} sats to ${to} (fee ${fee} sats)`);

        const walletPolicy = new WalletPolicy(
            state.policyName,
            state.policyTemplate,
            state.policyKeyRoots
        );
        const psbtV2 = new PsbtV2().fromBitcoinJS(psbt);

        console.log('\nRequesting Ledger signature. Confirm on the device...');
        const partialSigs = await app.signPsbt(psbtV2, walletPolicy, state.policyHmac);
        if (partialSigs.length === 0) throw new Error('Ledger returned no signatures');

        const stakerSig = partialSigs.find(([_, ps]) => ps.pubkey.equals(stakerPubkey));
        if (!stakerSig) {
            throw new Error(
                `Ledger did not return a signature for staker pubkey ${stakerPubkey.toString('hex')}`
            );
        }
        const [, partialSig] = stakerSig;
        let signatureWithSighash = partialSig.signature;
        if (signatureWithSighash[signatureWithSighash.length - 1] !== SIGHASH_ALL) {
            // The Ledger app returns DER+sighash; if a firmware ever omits the
            // sighash byte, append it ourselves.
            signatureWithSighash = Buffer.concat([signatureWithSighash, Buffer.from([SIGHASH_ALL])]);
        }
        console.log(`  Got signature (${signatureWithSighash.length} bytes).`);

        // Witness for the timelock branch (skip the H reveal):
        //   [ outer_if=true=0x01, inner_if=false=empty, sig, witnessScript ]
        const witness = [
            Buffer.from([0x01]),
            Buffer.alloc(0),
            signatureWithSighash,
            witnessScript,
        ];

        psbt.updateInput(0, { finalScriptWitness: serializeWitness(witness) });
        // Skip bitcoinjs's heuristic fee check — the caller specified the fee
        // explicitly via --fee, so we trust it.
        const tx = psbt.extractTransaction(true);
        const txHexOut = tx.toHex();
        console.log('\nSigned transaction:');
        console.log(`  txid: ${tx.getId()}`);
        console.log(`  hex:  ${txHexOut}`);

        console.log('\nBroadcasting via mempool.space testnet4...');
        const broadcasted = await broadcastTx(txHexOut);
        console.log(`Broadcasted: ${broadcasted}`);
        console.log(`https://mempool.space/testnet4/tx/${broadcasted}`);
    });
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

function usage() {
    console.log(`Usage:
  Generate the locking address (registers the policy on your Ledger):
    node index.js --generate [--change 0] [--index 0]

  Spend the locked funds via the timelock branch:
    node index.js --spend --txid <hex> --vout <n> --amount <sats> --to <addr> --fee <sats> [--txhex <hex>]

  Notes:
    - Network: testnet4. Open the Bitcoin Test app on the Ledger.
    - CLTV unlock height is hardcoded to ${CLTV_HEIGHT} (already in the past on testnet4).
    - Covenant xpub is derived deterministically from a hardcoded seed.
    - State (descriptor, policy HMAC) is persisted to ${STATE_FILE}.
`);
}

async function main() {
    const { values } = parseArgs({
        options: {
            generate: { type: 'boolean' },
            spend: { type: 'boolean' },
            change: { type: 'string' },
            index: { type: 'string' },
            txid: { type: 'string' },
            vout: { type: 'string' },
            amount: { type: 'string' },
            to: { type: 'string' },
            fee: { type: 'string' },
            txhex: { type: 'string' },
            help: { type: 'boolean' },
        },
    });

    if (values.help || (!values.generate && !values.spend)) {
        usage();
        return;
    }

    if (values.generate && values.spend) {
        throw new Error('pick exactly one of --generate or --spend');
    }

    if (values.generate) {
        await cmdGenerate({
            change: Number(values.change ?? 0),
            index: Number(values.index ?? 0),
        });
        return;
    }

    for (const k of ['txid', 'vout', 'amount', 'to', 'fee']) {
        if (values[k] === undefined) throw new Error(`--spend requires --${k}`);
    }
    await cmdSpend({
        txid: values.txid,
        vout: Number(values.vout),
        amount: Number(values.amount),
        to: values.to,
        fee: Number(values.fee),
        txHexArg: values.txhex,
    });
}

main()
    .then(() => process.exit(0))
    .catch((err) => {
        console.error('\nError:', err.message ?? err);
        if (err?.stack) console.error(err.stack);
        if (typeof err?.message === 'string' && err.message.includes('No device found')) {
            console.error('\nMake sure your Ledger is connected, unlocked, and the Bitcoin Test app is open.');
        }
        process.exit(1);
    });
