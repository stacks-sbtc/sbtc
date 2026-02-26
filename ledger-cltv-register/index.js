import { bech32, bech32m } from 'bech32';
import { AppClient, WalletPolicy } from '@ledgerhq/ledger-bitcoin';
import Transport from '@ledgerhq/hw-transport-node-hid';

/** Convert a testnet (tb1...) or mainnet (bc1...) bech32 address to regtest (bcrt1...). */
function toRegtestAddress(addr) {
    if (addr.startsWith('bcrt1')) return addr;
    try {
        const { words } = addr.startsWith('tb1p') || addr.startsWith('bc1p')
            ? bech32m.decode(addr)
            : bech32.decode(addr);
        return addr.startsWith('tb1p') || addr.startsWith('bc1p')
            ? bech32m.encode('bcrt', words)
            : bech32.encode('bcrt', words);
    } catch (e) {
        return null;
    }
}

/**
 * Register a wallet policy on a Ledger Nano S device with the miniscript:
 * wsh(and_v(v:after(360),pkh(key)))
 * 
 * This creates a P2WSH address with:
 * - A relative timelock of 360 blocks (CLTV)
 * - A public key hash requirement
 */
async function registerWalletPolicy() {
    let transport;
    
    try {
        console.log('Connecting to Ledger device...');
        transport = await Transport.default.create();
        
        const app = new AppClient(transport);
        
        // Get the master key fingerprint
        console.log('Getting master key fingerprint...');
        const fpr = await app.getMasterFingerprint();
        console.log(`Master key fingerprint: ${fpr.toString('hex')}`);
        
        // Get the extended public key for the key used in the policy
        // Default: testnet/regtest (m/44'/1'). Set USE_MAINNET=1 for mainnet (Bitcoin app).
        const useMainnet = process.env.USE_MAINNET === '1';
        const derivationPath = useMainnet ? "m/44'/0'/0'" : "m/44'/1'/0'";
        console.log(`Getting extended public key for path: ${derivationPath} (${useMainnet ? 'mainnet' : 'testnet/regtest'})`);
        const pubkey = await app.getExtendedPubkey(derivationPath);
        
        // Format the key info: [fingerprint/path]pubkey
        const keyInfo = `[${fpr}/${derivationPath.replace('m/', '')}]${pubkey}`;
        console.log(`Key info: ${keyInfo}`);
        
        // Create the wallet policy with the miniscript template
        // wsh(and_v(v:after(360),pkh(key)))
        // This means: wrapped script hash of (AND of: relative timelock 360 blocks AND public key hash)
        const policyName = "CLTV Wallet";
        const policyTemplate = "wsh(and_v(v:after(360),pkh(@0/**)))";
        
        console.log(`\nRegistering wallet policy:`);
        console.log(`  Name: ${policyName}`);
        console.log(`  Template: ${policyTemplate}`);
        console.log(`  Keys: [${keyInfo}]`);
        
        const walletPolicy = new WalletPolicy(
            policyName,
            policyTemplate,
            [keyInfo]
        );
        
        // Register the wallet policy on the device
        // The device will prompt the user to confirm
        console.log('\nPlease confirm on your Ledger device...');
        const [policyId, policyHmac] = await app.registerWallet(walletPolicy);
        
        console.log('\n✅ Wallet policy registered successfully!');
        console.log(`Policy ID: ${policyId.toString('hex')}`);
        console.log(`Policy HMAC: ${policyHmac.toString('hex')}`);
        // Full descriptor (template with keys substituted)
        const fullDescriptor = policyTemplate.replace('@0/**', keyInfo);
        console.log('Descriptor:', fullDescriptor);
        console.log('\n⚠️  IMPORTANT: Store the Policy HMAC securely!');
        console.log('You will need it for future operations with this wallet policy.');
        
        // Verify the policy ID matches
        const computedPolicyId = walletPolicy.getId();
        if (policyId.compare(computedPolicyId) !== 0) {
            throw new Error('Policy ID mismatch!');
        }
        
        // Optionally get an address for the registered wallet
        console.log('\nDeriving address for the registered wallet...');
        const address = await app.getWalletAddress(
            walletPolicy,
            policyHmac,
            0, // change index
            0, // address index
            true // show address on device
        );
        console.log(`Address (Ledger display): ${address}`);
        if (!useMainnet) {
            const regtestAddr = toRegtestAddress(address);
            if (regtestAddr) {
                console.log(`Regtest address (use for Bitcoin Core -regtest): ${regtestAddr}`);
            }
        }
        
    } catch (error) {
        console.error('\n❌ Error:', error.message);
        if (error.message.includes('No device found')) {
            console.error('\nMake sure your Ledger Nano S is:');
            console.error('  1. Connected via USB');
            console.error('  2. Unlocked');
            console.error('  3. Bitcoin Testnet app is open (default); or Bitcoin app for USE_MAINNET=1');
        }
        if (error.message.includes('0x6a82') || error.message.includes('UNKNOWN_ERROR')) {
            console.error('\nIf you see 0x6a82: use Bitcoin Testnet app for default (testnet/regtest), or Bitcoin app + USE_MAINNET=1 for mainnet.');
        }
        process.exit(1);
    } finally {
        if (transport) {
            await transport.close();
        }
    }
}

// Run the registration
registerWalletPolicy()
    .then(() => {
        console.log('\nDone!');
        process.exit(0);
    })
    .catch((error) => {
        console.error('Fatal error:', error);
        process.exit(1);
    });
